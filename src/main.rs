//! _Like `strace`, but lists files the program accesses. Inspired by [tracefile]._
//!
//! This tool's primary purpose is to assist in discovering which files/directories a program
//! accesses during its lifetime. It works by making use of [`strace`] and parsing its output to
//! find out which files and folders were accessed.
//!
//! It supports various options, such as filtering based on file type (file, directory, symlink,
//! pipe, socket, executable, etc).
//!
//! ## Usage
//!
//! See what files `ls` accesses during a normal run:
//! ```bash
//! ftrace -- ls
//! ```
//!
//! See all executable files:
//! ```bash
//! ftrace --type f --type x -- ls
//! ```
//!
//! See _all paths that the program **tried to access**_ (even ones that didn't exist). This is
//! sometimes useful to understand a search algorithm that a program uses to find linked libraries,
//! etc.
//! ```bash
//! ftrace --non-existent -- ls
//! ```
//!
//! Attach to an already running process (note that this requires elevated privileges):
//! ```bash
//! ftrace --pid 1729
//! ```
//!
//! ### Caveats
//!
//! Since [`strace`] outputs via STDERR, if the program being run also emits output over STDERR it
//! can confuse `ftrace`. For this reason any line that `ftrace` doesn't recognise is ignored and not
//! parsed. You can print lines that weren't recognised with the `--invalid` flag.
//!
//! # Installation
//!
//! First and foremost, make sure you've installed [`strace`] on your system.
//! It's almost always in your distribution's package manager.
//!
//! ### Precompiled binaries
//!
//! <!-- See the [releases] page for pre-compiled binaries. -->
//! Coming Soon! (GitHub actions is yet to be configured for this repository.)
//!
//! ### Via Cargo
//!
//! **NOTE**: The minimum Rust version required is `1.46.0`.
//!
//! ```bash
//! cargo install ftrace
//! ```
//!
//! ### From Source (via Cargo)
//!
//! **NOTE**: The minimum Rust version required is `1.46.0`.
//!
//! ```bash
//! git clone https://github.com/acheronfail/ftrace/
//! cd ftrace
//! cargo install --path .
//! ```
//!
//! [`strace`]: https://strace.io/
//! [tracefile]: https://gitlab.com/ole.tange/tangetools/tree/master/tracefile

use std::{collections::HashMap, os::unix::process::CommandExt, process::Command, ffi::c_void};

use byteorder::{LittleEndian, WriteBytesExt};
use nix::{
    libc::{user_regs_struct, c_long, AT_FDCWD},
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use owo_colors::OwoColorize;

fn print_syscall(syscall_table: &HashMap<u64, String>, child_pid: Pid, regs: user_regs_struct, width: usize) {

    if regs.orig_rax != 257 {
        return
    }

    // TODO: read enums: how to know?
    eprintln!("{:x}", AT_FDCWD);

    // TODO: read string arg; make this generic across calls
    if regs.orig_rax == 257 {
        let mut s = String::new();
        let mut count = 0;
        let word_size = 8;

        let addr = regs.rsi as *mut c_void;

        'read_string: loop {
            let mut bytes = vec![];
            let addr = unsafe { addr.offset(count) };

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

            count += word_size;
        }

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
    let syscall_table: HashMap<u64, String> = serde_json::from_str(include_str!("syscall.json"))?;
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
