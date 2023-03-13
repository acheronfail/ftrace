//! TODO: crate documentation

use std::{collections::HashMap, process::Command};

use syscall::SyscallInfo;

mod printer;
mod ptrace_utils;
mod syscall;
mod utf8;

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

    ptrace_utils::trace_child(cmd, |child_pid, regs| {
        printer::print_syscall(&syscall_table, child_pid, regs, longest_syscall_name)
    })?;

    Ok(())
}
