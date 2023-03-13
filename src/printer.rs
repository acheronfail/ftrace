use std::{collections::HashMap, fs::read_link, path::PathBuf};

use nix::{libc::user_regs_struct, unistd::Pid};
use owo_colors::OwoColorize;

use crate::{ptrace_utils, syscall::SyscallInfo};

pub fn print_syscall(
    syscall_table: &HashMap<u64, SyscallInfo>,
    child_pid: Pid,
    regs: user_regs_struct,
    width: usize,
) {
    let syscall_info = syscall_table.get(&regs.orig_rax).expect("Unknown syscall!");
    let syscall_name = syscall_info.name.green();
    // TODO: update syscall json data with return code conventions
    let syscall_result = regs.rax;
    match syscall_info.params() {
        None => eprintln!(
            "{:>width$}() = {:x}",
            syscall_name,
            syscall_result,
            width = width
        ),
        Some(signatures) => {
            // TODO: iter signatures and check which suits best
            let params = &signatures[0];
            // https://stackoverflow.com/a/2538212/5552584
            let registers = [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9];

            eprint!("{:>width$}(", syscall_name, width = width);
            for (i, param) in params.iter().enumerate() {
                if i > 0 {
                    eprint!(", ");
                }

                let value = registers[i];
                // TODO: read enums: how to know when it's an enum, and what to map it to?
                // eprintln!("{:x}", AT_FDCWD);
                // TODO: strace even reads structs, e.g.:
                //       prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
                match (&param.name[..], &param.r#type[..]) {
                    // TODO: a better way of recognising strings! 😂
                    // TODO: handle things like `getrandom` which return bytes, not strings?
                    (_, t) if t.contains("char ") => print_string(child_pid, value),
                    // things that look like file descriptors
                    ("fd", "int") | ("fd", "unsigned int") | ("fd", "unsigned long") => {
                        print_fd(child_pid, value)
                    }
                    // probably an address, and it's null
                    (_, "unsigned long") if value == 0 => {
                        eprint!("{}", "NULL".green())
                    }
                    // not sure, just print the value of the register
                    _ => eprint!("0x{:x}", value),
                }
            }

            eprintln!(") = 0x{:x}", syscall_result);
        }
    }
}

fn print_string(child_pid: Pid, value: u64) {
    eprint!(
        r#""{}""#,
        ptrace_utils::read_string(child_pid, value).green()
    )
}

fn print_fd(child_pid: Pid, value: u64) {
    match value {
        0 => eprint!("{}", "STDIN".green()),
        1 => eprint!("{}", "STDOUT".green()),
        2 => eprint!("{}", "STDERR".green()),
        fd => {
            // FIXME: this fails when the syscall is `close` because we're running after it's complete (fd is gone)
            // we could (a) monitor all syscalls that create fds, and keep track of them, or (b) leave it as is (fail silently)
            let proc_link = PathBuf::from(format!("/proc/{}/fd/{}", child_pid.as_raw(), fd));
            match read_link(proc_link) {
                Ok(p) => {
                    eprint!("{}", format!("{}:{}", fd, p.display()).green())
                }
                Err(_) => eprint!("{}", fd.red()),
            }
        }
    }
}
