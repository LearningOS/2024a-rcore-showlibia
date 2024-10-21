//!Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.

use super::__switch;
use super::{fetch_task, TaskStatus};
use super::{TaskContext, TaskControlBlock};
use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{MapPermission, PageTableEntry, VPNRange, VirtAddr, VirtPageNum};
use crate::sync::UPSafeCell;
use crate::timer::get_time_ms;
use crate::trap::TrapContext;
use alloc::sync::Arc;
use lazy_static::*;

/// Processor management structure
pub struct Processor {
    ///The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,

    ///The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}

impl Processor {
    ///Create an empty Processor
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: TaskContext::zero_init(),
        }
    }

    ///Get mutable reference to `idle_task_cx`
    fn get_idle_task_cx_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_cx as *mut _
    }

    ///Get current task in moving semanteme
    pub fn take_current(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.current.take()
    }

    ///Get current task in cloning semanteme
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.current.as_ref().map(Arc::clone)
    }

        /// When a syscall is called, we need to increase the syscall_times
    fn count_syscall(&self, syscall_id: usize) {
        if syscall_id < MAX_SYSCALL_NUM {
            let task = self.current().unwrap();
            let mut inner = task.inner_exclusive_access();
            inner.syscall_times[syscall_id] += 1;
        }
    }

    /// Get the syscall times for the current task
    fn get_syscall_times(&self) -> [u32; MAX_SYSCALL_NUM] {
        let task = self.current().unwrap();
        let inner = task.inner_exclusive_access();
        inner.syscall_times
    }

    /// Get the task status of current task
    fn get_task_status(&self) -> TaskStatus {
        let task = self.current().unwrap();
        let inner = task.inner_exclusive_access();
        inner.task_status
    }

    /// Get the task run time
    fn get_run_time(&self) -> usize {
        let task = self.current().unwrap();
        let inner = task.inner_exclusive_access();
        let current_time = get_time_ms();
        if inner.start_time != 0 {
            return current_time - inner.start_time;
        } else {
            return 0;
        }
    }

    /// Get current page table entry
    fn get_current_pte(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        let task = self.current().unwrap();
        let inner = task.inner_exclusive_access();
        inner.memory_set.translate(vpn)
    }

    /// Create new map area
    fn create_new_map_area(&self, start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
        let task = self.current().unwrap();
        let mut inner = task.inner_exclusive_access();
        inner
            .memory_set
            .insert_framed_area(start_va, end_va, permission);
    }

    /// unmap the area
    fn unmap_area(&self, _start: usize, _len: usize) -> isize {
        let task = self.current().unwrap();
        let mut inner = task.inner_exclusive_access();
        let start_vpn = VirtAddr::from(_start).floor();
        let end_vpn = VirtAddr::from(_start + _len).ceil();
        let vpn_ranges = VPNRange::new(start_vpn, end_vpn);
        for vpn in vpn_ranges {
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if !pte.is_valid() {
                    return -1;
                }
                inner.memory_set.get_page_table().unmap(vpn);
            } else {
                return -1;
            }
        }
        0
    }
}

lazy_static! {
    pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
}

///The main part of process execution and scheduling
///Loop `fetch_task` to get the process that needs to run, and switch the process through `__switch`
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.inner_exclusive_access();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;
            if task_inner.start_time == 0 {
                task_inner.start_time = get_time_ms()
            }
            // release coming task_inner manually
            drop(task_inner);
            // release coming task TCB manually
            processor.current = Some(task);
            // release processor manually
            drop(processor);
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr);
            }
        } else {
            warn!("no tasks available in run_tasks");
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// Get the current user token(addr of page table)
pub fn current_user_token() -> usize {
    let task = current_task().unwrap();
    task.get_user_token()
}

///Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapContext {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

///Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}

/// When a syscall is called, we need to increase the syscall_times
pub fn count_syscall(syscall_id: usize) {
    PROCESSOR.exclusive_access().count_syscall(syscall_id)
}

/// Get the syscall times for the current task
pub fn get_syscall_times() -> [u32; MAX_SYSCALL_NUM] {
    PROCESSOR.exclusive_access().get_syscall_times()
}

/// Get the task status of current task
pub fn get_task_status() -> TaskStatus {
    PROCESSOR.exclusive_access().get_task_status()
}

/// Get the task run time
pub fn get_run_time() -> usize {
    PROCESSOR.exclusive_access().get_run_time()
}

/// Get current page table entry
pub fn get_current_pte(vpn: VirtPageNum) -> Option<PageTableEntry> {
    PROCESSOR.exclusive_access().get_current_pte(vpn)
}

/// Create new map area
pub fn create_new_map_area(start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
    PROCESSOR
        .exclusive_access()
        .create_new_map_area(start_va, end_va, permission);
}

/// unmap the area
pub fn unmap_area(_start: usize, _len: usize) -> isize {
    PROCESSOR.exclusive_access().unmap_area(_start, _len)
}