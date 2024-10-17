//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the operating system.
//!
//! Be careful when you see `__switch` ASM function in `switch.S`. Control flow around this function
//! might not be what you expect.

mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::config::MAX_SYSCALL_NUM;
use crate::loader::{get_app_data, get_num_app};
use crate::mm::{MapPermission, PageTableEntry, VPNRange, VirtAddr, VirtPageNum};
use crate::sync::UPSafeCell;
use crate::timer::get_time_ms;
use crate::trap::TrapContext;
use alloc::vec::Vec;
use lazy_static::*;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;

/// The task manager, where all the tasks are managed.
///
/// Functions implemented on `TaskManager` deals with all task state transitions
/// and task context switching. For convenience, you can find wrappers around it
/// in the module level.
///
/// Most of `TaskManager` are hidden behind the field `inner`, to defer
/// borrowing checks to runtime. You can see examples on how to use `inner` in
/// existing functions on `TaskManager`.
pub struct TaskManager {
    /// total number of tasks
    num_app: usize,
    /// use inner value to get mutable access
    inner: UPSafeCell<TaskManagerInner>,
}

/// The task manager inner in 'UPSafeCell'
struct TaskManagerInner {
    /// task list
    tasks: Vec<TaskControlBlock>,
    /// id of current `Running` task
    current_task: usize,
}

lazy_static! {
    /// a `TaskManager` global instance through lazy_static!
    pub static ref TASK_MANAGER: TaskManager = {
        println!("init TASK_MANAGER");
        let num_app = get_num_app();
        println!("num_app = {}", num_app);
        let mut tasks: Vec<TaskControlBlock> = Vec::new();
        for i in 0..num_app {
            tasks.push(TaskControlBlock::new(get_app_data(i), i));
        }
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                })
            },
        }
    };
}

impl TaskManager {
    /// Run the first task in task list.
    ///
    /// Generally, the first task in task list is an idle task (we call it zero process later).
    /// But in ch4, we load apps statically, so the first task is a real app.
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next_task = &mut inner.tasks[0];
        next_task.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
        next_task.start_time = Some(get_time_ms());
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(&mut _unused as *mut _, next_task_cx_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    /// Change the status of current `Running` task into `Ready`.
    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Ready;
    }

    /// Change the status of current `Running` task into `Exited`.
    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Exited;
    }

    /// Find next task to run and return task id.
    ///
    /// In this case, we only return the first `Ready` task in task list.
    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    /// Get the current 'Running' task's token.
    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_user_token()
    }

    /// Get the current 'Running' task's trap contexts.
    fn get_current_trap_cx(&self) -> &'static mut TrapContext {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_trap_cx()
    }

    /// Change the current 'Running' task's program break
    pub fn change_current_program_brk(&self, size: i32) -> Option<usize> {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].change_program_brk(size)
    }

    /// Switch current `Running` task to the task we have found,
    /// or there is no `Ready` task and we can exit with all applications completed
    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            if inner.tasks[next].start_time.is_none() {
                inner.tasks[next].start_time = Some(get_time_ms());
            }
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }

    /// When a syscall is called, we need to increase the syscall_times
    fn count_syscall(&self, syscall_id: usize) {
        if syscall_id < MAX_SYSCALL_NUM{
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[current].syscall_times[syscall_id] += 1;
        }
    }

    /// Get the syscall times for the current task
    fn get_syscall_times(&self) -> [u32; MAX_SYSCALL_NUM] {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].syscall_times
    }

    /// Get the task status of current task
    fn get_task_status(&self) -> TaskStatus{
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status
    }

    /// Get the task run time 
    fn get_run_time(&self) -> usize {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let current_time = get_time_ms();
        if let Some(start_time) = inner.tasks[current].start_time {
            return current_time - start_time;
        } else {
            return 0;
        }
    } 

    fn get_current_pte(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].memory_set.translate(vpn)
    }

    fn create_new_map_area(&self, start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].memory_set.insert_framed_area(start_va, end_va, permission);
    }

    fn unmap_area(&self, _start: usize, _len: usize) -> isize {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let start_vpn = VirtAddr::from(_start).floor();
        let end_vpn = VirtAddr::from(_start + _len).ceil();
        let vpn_ranges = VPNRange::new(start_vpn, end_vpn);
        for vpn in vpn_ranges {
            if let Some(pte) = inner.tasks[current].memory_set.translate(vpn) {
                if !pte.is_valid() {
                    return -1;
                }
                inner.tasks[current].memory_set.get_page_table().unmap(vpn);
            } else {
                return -1;
            }  
        }
        println!("Test unmap_for End");
        0
    }
}

/// Run the first task in task list.
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// Switch current `Running` task to the task we have found,
/// or there is no `Ready` task and we can exit with all applications completed
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// Change the status of current `Running` task into `Ready`.
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// Change the status of current `Running` task into `Exited`.
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// Suspend the current 'Running' task and run the next task in task list.
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

/// Count the syscall times of syscall_id
pub fn count_syscall(syscall_id: usize) {
    TASK_MANAGER.count_syscall(syscall_id);
}

/// Get the syscall times 
pub fn get_syscall_times() -> [u32; MAX_SYSCALL_NUM] {
    TASK_MANAGER.get_syscall_times()
}

/// Get the task status
pub fn get_task_status() -> TaskStatus {
    TASK_MANAGER.get_task_status()
}

/// Get the task run time
pub fn get_run_time() -> usize {
    TASK_MANAGER.get_run_time()
}

/// Get the current 'Running' task's token.
pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

/// Get the current 'Running' task's trap contexts.
pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

/// Change the current 'Running' task's program break
pub fn change_program_brk(size: i32) -> Option<usize> {
    TASK_MANAGER.change_current_program_brk(size)
}

/// get current task's page table entry
pub fn get_current_pte(vpn: VirtPageNum) -> Option<PageTableEntry> {
    TASK_MANAGER.get_current_pte(vpn)
}

/// create new map area
pub fn create_new_map_area(start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
    TASK_MANAGER.create_new_map_area(start_va, end_va, permission);
}

/// unmap area 
pub fn unmap_area(_start: usize, _len: usize) -> isize {
    TASK_MANAGER.unmap_area(_start, _len)
}