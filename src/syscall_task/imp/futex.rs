//! 支持 futex 相关的 syscall

extern crate alloc;
use axhal::mem::VirtAddr;
use axprocess::{
    current_process, current_task, futex::FutexRobustList,
};

use axfutex::*;

use crate::{FutexFlags, RobustList, SyscallError, SyscallResult, TimeSecs};

/// To do the futex operation
///
/// It may create, remove the futex wait task or requeue the futex wait task
pub fn futex(
    vaddr: VirtAddr,
    futex_op: i32,
    val: u32,
    timeout: usize,
    vaddr2: VirtAddr,
    val2: u32,
    _val3: u32,
) -> Result<usize, SyscallError> {
    let cmd = FutexFlags::new(futex_op);
    match cmd {
        FutexFlags::Wait => futex_wait(vaddr, futex_op as u32, val, timeout, _val3).map_err(|e| e.into()),
        FutexFlags::Wake => futex_wake(vaddr, futex_op as u32, val, _val3).map_err(|e| e.into()),
        FutexFlags::Requeue => futex_requeue(vaddr, futex_op as u32, vaddr2, futex_op as u32, val, val2, None, 0).map_err(|e| e.into()),
        _ => {
            return Err(SyscallError::ENOSYS);
        }
    }
}

/// # Arguments
/// * vaddr: usize
/// * futex_op: i32
/// * futex_val: u32
/// * time_out_val: usize
/// * vaddr2: usize
/// * val3: u32
pub fn syscall_futex(args: [usize; 6]) -> SyscallResult {
    let vaddr = args[0];
    let futex_op = args[1] as i32;
    let futex_val = args[2] as u32;
    let time_out_val = args[3];
    let vaddr2 = args[4];
    let val3 = args[5] as u32;
    let process = current_process();
    let timeout = if time_out_val != 0 && process.manual_alloc_for_lazy(time_out_val.into()).is_ok()
    {
        let time_sepc: TimeSecs = unsafe { *(time_out_val as *const TimeSecs) };
        time_sepc.turn_to_nanos()
    } else {
        // usize::MAX
        0
    };
    // 释放锁，防止任务无法被调度
    match futex(
        vaddr.into(),
        futex_op,
        futex_val,
        timeout,
        vaddr2.into(),
        time_out_val as u32,
        val3,
    ) {
        Ok(ans) => Ok(ans as isize),
        Err(errno) => Err(errno),
    }
}

/// 内核只发挥存储的作用
/// 但要保证head对应的地址已经被分配
/// # Arguments
/// * head: usize
/// * len: usize
pub fn syscall_set_robust_list(args: [usize; 6]) -> SyscallResult {
    let head = args[0];
    let len = args[1];
    let process = current_process();
    if len != core::mem::size_of::<RobustList>() {
        return Err(SyscallError::EINVAL);
    }
    let curr_id = current_task().id().as_u64();
    if process.manual_alloc_for_lazy(head.into()).is_ok() {
        let mut robust_list = process.robust_list.lock();
        robust_list.insert(curr_id, FutexRobustList::new(head, len));
        Ok(0)
    } else {
        Err(SyscallError::EINVAL)
    }
}

/// 取出对应线程的robust list
/// # Arguments
/// * pid: i32
/// * head: *mut usize
/// * len: *mut usize
pub fn syscall_get_robust_list(args: [usize; 6]) -> SyscallResult {
    let pid = args[0] as i32;
    let head = args[1] as *mut usize;
    let len = args[2] as *mut usize;

    if pid == 0 {
        let process = current_process();
        let curr_id = current_task().id().as_u64();
        if process
            .manual_alloc_for_lazy((head as usize).into())
            .is_ok()
        {
            let robust_list = process.robust_list.lock();
            if robust_list.contains_key(&curr_id) {
                let list = robust_list.get(&curr_id).unwrap();
                unsafe {
                    *head = list.head;
                    *len = list.len;
                }
            } else {
                return Err(SyscallError::EPERM);
            }
            return Ok(0);
        }
        return Err(SyscallError::EPERM);
    }
    Err(SyscallError::EPERM)
}
