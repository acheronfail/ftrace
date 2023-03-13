//! TODO

use std::{
    collections::HashMap, ffi::c_void, fs::read_link, os::unix::process::CommandExt, path::PathBuf,
    process::Command,
};

use byteorder::{LittleEndian, WriteBytesExt};
use nix::{
    libc::{c_long, user_regs_struct, AT_FDCWD},
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use owo_colors::OwoColorize;
use syscall::SyscallInfo;

mod syscall;
mod utf8;

// TODO: put in a limit here and truncate?
fn read_string(child_pid: Pid, addr: u64) -> String {
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

fn print_syscall(
    syscall_table: &HashMap<u64, SyscallInfo>,
    child_pid: Pid,
    regs: user_regs_struct,
    width: usize,
) {
    let syscall_info = syscall_table.get(&regs.orig_rax).expect("Unknown syscall!");
    let syscall_name = syscall_info.name.bright_green();
    let syscall_result = regs.rax.blue();
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
                match (&param.name[..], &param.r#type[..]) {
                    // TODO: a better way of recognising strings! 😂
                    // TODO: handle things like `getrandom` which return bytes, not strings?
                    (_, t) if t.contains("char ") => {
                        eprint!(r#""{}""#, read_string(child_pid, value).yellow())
                    }
                    // things that look like file descriptors
                    ("fd", "int") | ("fd", "unsigned int") | ("fd", "unsigned long") => {
                        match value {
                            0 => eprint!("{}", "STDIN".red()),
                            1 => eprint!("{}", "STDOUT".red()),
                            2 => eprint!("{}", "STDERR".red()),
                            fd => {
                                // FIXME: this fails when the syscall is `close` because we're running after it's complete (fd is gone)
                                // we could (a) monitor all syscalls that create fds, and keep track of them, or (b) leave it as is (fail silently)
                                let proc_link = PathBuf::from(format!(
                                    "/proc/{}/fd/{}",
                                    child_pid.as_raw(),
                                    fd
                                ));
                                match read_link(proc_link) {
                                    Ok(p) => eprint!("{}", format!("{}:{}", fd, p.display()).red()),
                                    Err(_) => eprint!("{}", fd.red()),
                                }
                            }
                        }
                    }
                    _ => eprint!("{:x}", value),
                }
            }

            eprintln!(") = {:x}", syscall_result);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let syscalls: Vec<SyscallInfo> = serde_json::from_str(include_str!("syscalls.json"))?;
    let syscall_table: HashMap<u64, SyscallInfo> =
        syscalls.into_iter().map(|info| (info.id, info)).collect();
    let longest_syscall_name = syscall_table
        .iter()
        .map(|(_, info)| info.name.len())
        .max_by(|a, b| usize::cmp(a, b))
        .unwrap();

    // TODO: argument parsing

    let mut cmd = Command::new("cat");
    cmd.arg("/etc/hosts");

    unsafe {
        cmd.pre_exec(|| {
            use nix::sys::ptrace::traceme;
            traceme().map_err(|e| e.into())
        });
    }

    let child = cmd.spawn()?;
    let child_pid = Pid::from_raw(child.id() as _);

    _ = waitpid(child_pid, None)?;
    print_syscall(
        &syscall_table,
        child_pid,
        ptrace::getregs(child_pid)?,
        longest_syscall_name,
    );

    let mut is_sys_exit = false;
    loop {
        ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if is_sys_exit {
            let regs = match ptrace::getregs(child_pid) {
                Ok(regs) => regs,
                Err(_) => break,
            };

            // TODO: argument parsing of syscall functions that take files
            print_syscall(&syscall_table, child_pid, regs, longest_syscall_name);
        }
        is_sys_exit = !is_sys_exit;
    }

    Ok(())
}
