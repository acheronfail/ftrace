//! TODO

use std::{collections::HashMap, ffi::c_void, os::unix::process::CommandExt, process::Command};

use byteorder::{LittleEndian, WriteBytesExt};
use nix::{
    libc::{c_long, user_regs_struct, AT_FDCWD},
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use owo_colors::OwoColorize;

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

fn print_syscall(
    syscall_table: &HashMap<u64, String>,
    child_pid: Pid,
    regs: user_regs_struct,
    width: usize,
) {
    if regs.orig_rax != 257 {
        return;
    }

    // TODO: read enums: how to know?
    eprintln!("{:x}", AT_FDCWD);

    // TODO: read string arg; make this generic across calls
    if regs.orig_rax == 257 {
        let s = read_string(child_pid, regs.rsi);
        eprintln!("{:?}", s.red());
    }

    eprintln!(
        "{:>width$}({:x}, {:x}, {:x}, ...) = {:x}",
        syscall_table[&regs.orig_rax].bright_green(),
        regs.rdi.cyan(),
        regs.rsi.cyan(),
        regs.rdx.cyan(),
        regs.rax.yellow(),
        width = width
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // FIXME: use new syscalls.json file!
    let syscall_table: HashMap<u64, String> = serde_json::from_str(include_str!("syscalls.json"))?;
    let longest_syscall_name = 3;
    // let longest_syscall_name = syscall_table
    //     .iter()
    //     .map(|(_, value)| value.len())
    //     .max_by(|a, b| usize::cmp(a, b))
    //     .unwrap();

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
