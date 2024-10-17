//! Process management syscalls

use crate::{
    config::{MAX_SYSCALL_NUM, MEMORY_END, PAGE_SIZE}, mm::{translated_byte_buffer, MapPermission, VPNRange, VirtAddr}, task::{
        change_program_brk, create_new_map_area, current_user_token, exit_current_and_run_next, get_current_pte, get_run_time, get_syscall_times, get_task_status, suspend_current_and_run_next, unmap_area, TaskStatus
    }, timer::get_time_us
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    // trace!("kernel: sys_get_time");
    let us = get_time_us();
    let buffer = translated_byte_buffer(current_user_token(), _ts as * const u8, core::mem::size_of::<TimeVal>());
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let time_val_ptr = &time_val as *const TimeVal;
    for (i, b) in buffer.into_iter().enumerate() {
        let b_len = b.len();
        unsafe {
            b.copy_from_slice(core::slice::from_raw_parts(
                time_val_ptr.wrapping_byte_add(i * b_len) as *const u8,
                b_len
            ));
        }
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    // trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    let buffer = translated_byte_buffer(current_user_token(), _ti as * const u8, core::mem::size_of::<TaskInfo>());
    unsafe {
        *_ti = TaskInfo {
            status: get_task_status(),
            syscall_times: get_syscall_times(),
            time: get_run_time(),
        }
    }
    let task_info_ptr = _ti as *const TaskInfo;
    for (i, b) in buffer.into_iter().enumerate() {
        let b_len = b.len();
        unsafe {
            b.copy_from_slice(core::slice::from_raw_parts(
                task_info_ptr.wrapping_byte_add(i * b_len) as *const u8,
                b_len
            ));
        }
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    // trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    if _start % PAGE_SIZE != 0 ||
        _port & !0x7 != 0 ||
        _port & 0x7 == 0 ||
        _start >= MEMORY_END {
            return -1;
        }
    let start_vpn = VirtAddr::from(_start).floor();
    let end_vpn = VirtAddr::from(_start + _len).ceil();
    let vpn_ranges = VPNRange::new(start_vpn, end_vpn);
    for vpn in vpn_ranges {
        if let Some(pte) = get_current_pte(vpn) {
            if pte.is_valid() {
                return -1;
            }
        }
    }
    create_new_map_area(
        start_vpn.into(),
        end_vpn.into(),
        MapPermission::from_bits_truncate((_port << 1) as u8) | MapPermission::U
        );
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    // trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    if _start % PAGE_SIZE != 0 || _start >= MEMORY_END {
        return -1;
    }
    unmap_area(_start, _len)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
