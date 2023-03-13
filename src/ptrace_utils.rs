use std::{
    ffi::{c_long, c_void},
    os::unix::process::CommandExt,
    process::Command,
};

use byteorder::{LittleEndian, WriteBytesExt};
use nix::{
    libc::user_regs_struct,
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};

use crate::utf8;

// TODO: put in a limit here and truncate?
pub fn read_string(child_pid: Pid, addr: u64) -> String {
    let mut buf = vec![];
    let mut pos = 0;
    // `ptrace::read` only reads a word at a time from the process' memory
    let word_size = 8;
    let addr = addr as *mut c_void;

    'read_string: loop {
        let mut bytes = vec![];
        let addr = unsafe { addr.offset(pos) };

        let res: c_long;

        match ptrace::read(child_pid, addr) {
            Ok(c_long) => res = c_long,
            Err(_) => break 'read_string,
        }

        bytes.write_i64::<LittleEndian>(res).unwrap(); // TODO: handle

        for b in bytes {
            if b != 0 {
                buf.push(b);
            } else {
                break 'read_string;
            }
        }

        pos += word_size;
    }

    utf8::replace_nonprintable(&buf)
}

pub fn trace_child(
    mut cmd: Command,
    post_syscall: impl Fn(Pid, user_regs_struct),
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        cmd.pre_exec(|| {
            use nix::sys::ptrace::traceme;
            traceme().map_err(|e| e.into())
        });
    }

    let child = cmd.spawn()?;
    let child_pid = Pid::from_raw(child.id() as _);

    _ = waitpid(child_pid, None)?;
    post_syscall(child_pid, ptrace::getregs(child_pid)?);

    let mut is_sys_exit = false;
    loop {
        ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if is_sys_exit {
            let regs = match ptrace::getregs(child_pid) {
                Ok(regs) => regs,
                Err(_) => break,
            };

            post_syscall(child_pid, regs);
        }
        is_sys_exit = !is_sys_exit;
    }

    Ok(())
}
