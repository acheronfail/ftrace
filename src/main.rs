//! TODO

use std::{
    collections::HashMap, ffi::c_void, fmt::format, os::unix::process::CommandExt, process::Command,
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

fn read_string(child_pid: Pid, addr: u64) -> String {
    let mut s = String::new();
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
                s.push(b as char);
            } else {
                break 'read_string;
            }
        }

        pos += word_size;
    }

    s
}

// fn print_param(child_pid: Pid, syscall_info: &SyscallInfo, register: u64) -> String {
//     if ()
// }

fn print_syscall(
    syscall_table: &HashMap<u64, SyscallInfo>,
    child_pid: Pid,
    regs: user_regs_struct,
    width: usize,
) {
    // TODO: read enums: how to know?
    // eprintln!("{:x}", AT_FDCWD);

    let syscall_info = syscall_table.get(&regs.orig_rax).expect("Unknown syscall!");
    let syscall_name = syscall_info.name.bright_green();
    let syscall_result = regs.rax.blue();
    match syscall_info.param_types() {
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
            for (i, r#type) in params.iter().enumerate() {
                if i > 0 {
                    eprint!(", ");
                }

                let value = registers[i];
                // TODO: a better way of recognising strings! 😂
                if r#type.contains("char ") {
                    // FIXME: why is it a string? is it a string? do I not understand "char" C types?
                    if syscall_info.name == "getrandom" {
                        eprint!("SKIPPED");
                    } else {
                        eprint!(r#""{}""#, read_string(child_pid, value).yellow());
                    }
                } else {
                    eprint!("{:x}", value)
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
