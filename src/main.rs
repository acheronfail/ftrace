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

use std::{collections::HashMap, os::unix::process::CommandExt, process::Command};

use nix::{
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use owo_colors::OwoColorize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let syscall_table: HashMap<u64, String> = serde_json::from_str(include_str!("syscall.json"))?;
    let longest_syscall_name = syscall_table
        .iter()
        .map(|(_, value)| value.len())
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

    let res = waitpid(child_pid, None)?;
    eprintln!("waitpid: {:?}", res.yellow());

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

            eprintln!(
                "{:>width$}({:x}, {:x}, {:x}, ...) = {:x}",
                syscall_table[&regs.orig_rax].bright_green(),
                regs.rdi.cyan(),
                regs.rsi.cyan(),
                regs.rdx.cyan(),
                regs.rax.yellow(),
                width = longest_syscall_name
            );
        }
        is_sys_exit = !is_sys_exit;
    }

    Ok(())
}
