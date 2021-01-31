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

mod analysis;
mod cli;
mod fs;
mod macros;
mod parse;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, process};

use anyhow::Result;
use clap::crate_name;
use flexi_logger::{opt_format, Logger};
use termcolor::{Color, ColorChoice, WriteColor};
use which::which;

use parse::{decode_hex, StraceToken};

// TODO: support strace's file descriptor decoding? (--decode-fds=all|-yy)

fn init_logging() -> Result<PathBuf> {
    let log_dir = env::temp_dir().join(format!(".{}", crate_name!()));
    Logger::with_env()
        .log_to_file()
        .directory(&log_dir)
        .format(opt_format)
        .start()?;

    log::trace!("--- LOGGER INITIALISED ---");

    Ok(log_dir)
}

fn main() -> Result<()> {
    let log_dir = match init_logging() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Failed to initialise logger: {}", e);
            process::exit(1);
        }
    };

    macro_rules! exit_with_error {
        ($( $eprintln_arg:expr ),*) => {{
            log::error!($( $eprintln_arg ),*);
            p!(false, None, $( $eprintln_arg ),*);
            p!(false, None, "Logs available at: {}", log_dir.display());
            process::exit(1);
        }};
    };

    let strace_path = match which("strace") {
        Ok(path) => path,
        Err(e) => exit_with_error!("Failed to find `strace` binary: {}", e),
    };

    let app_args = cli::Args::parse();
    log::trace!("{:?}", app_args);

    let mut child = Command::new(strace_path)
        // follow and trace the process's forks
        .arg("--follow-forks")
        // monitor all statuses: even though this is almost the same as the default behaviour, by specifying this
        // `strace` will wait for each syscall to end before printing it. This means that we don't have to parse and
        // deal with `<unfinished... >` and `<... resume XXX>` logs
        .arg("--status=successful,failed,unfinished,unavailable,detached")
        // include timestamps with microsecond precision
        .arg("-ttt")
        // print all strings with hexadecimal escapes
        .arg("--strings-in-hex")
        // only trace file syscalls since that's what we're interested in
        .arg("--trace=%file")
        // as from `man strace`: Use this option to get all of the gory details
        .arg("--no-abbrev")
        // the user-provided command
        .args(&app_args.cmd)
        // the user-provided pid
        .args(
            &app_args
                .pid
                .map(|pid| vec![format!("--attach={}", pid)])
                .unwrap_or(vec![]),
        )
        // `strace` logs via stderr
        // NOTE: if the spawned/attached process also logs via stderr then we'll see that data too
        .stderr(Stdio::piped())
        // ignore the command's stderr
        .stdout(Stdio::null())
        .spawn()?;

    let reader = BufReader::new(child.stderr.as_mut().unwrap());
    for line in reader.lines() {
        let line = line?;
        log::trace!("RAW LINE: {}", line);
        match parse::strace_line(&line) {
            Ok(strace) => {
                log::debug!("PARSED LINE: {}", strace);
                if let StraceToken::PermissionDenied(pid) = strace.inner {
                    p!(
                        app_args.color,
                        Color::Yellow,
                        "{}\n{}",
                        format!("Could not attach to pid: {}, permission denied.", pid),
                        "Try re-running the command with elevated permissons."
                    );
                    break;
                }

                let app_args = &app_args;
                let file_types = app_args.file_types();
                strace.walk(&move |token| {
                    if let StraceToken::Call {
                        name, result, args, ..
                    } = token
                    {
                        // call expressions without results are inline call expressions, so skip them
                        let result = match result {
                            Some(result) => result,
                            None => return true,
                        };

                        let fn_info = &analysis::FN_MAP[name];
                        let color = match fn_info.did_succeed(*result) {
                            Some(true) => Color::Green,
                            Some(false) => {
                                if app_args.non_existent {
                                    Color::Yellow
                                } else {
                                    return true;
                                }
                            }
                            None => Color::White,
                        };

                        // NOTE: handle special case for `execve`: the first argument is the binary being executed, and
                        // the second argument is the binary's `argv` (which does not contain paths for file accesses)
                        let maybe_paths = if *name == "execve" {
                            if let StraceToken::String(s) = &args[0] {
                                vec![*s]
                            } else {
                                vec![]
                            }
                        } else {
                            token.strs()
                        };

                        for s in maybe_paths {
                            let s = decode_hex(s);
                            if let Some(file_types) = file_types {
                                let path = Path::new(&s);
                                match path.metadata() {
                                    Ok(meta) => {
                                        let ft = meta.file_type();
                                        if (file_types.files && !fs::is_file(&path))
                                            || (file_types.directories && !fs::is_dir(&path))
                                            || (file_types.symlinks && !fs::is_symlink(&path))
                                            || (file_types.sockets && !fs::is_socket(&ft))
                                            || (file_types.pipes && !fs::is_pipe(&ft))
                                            || (file_types.executables && !fs::is_executable(&meta))
                                            || (file_types.empty && !fs::is_empty(&path))
                                        {
                                            continue;
                                        }
                                    }
                                    // NOTE: skip here because the string was probably not a valid path?
                                    Err(_) => continue,
                                }
                            }

                            p!(app_args.color, color, "{}", s);
                        }

                        false
                    } else {
                        true
                    }
                });
            }
            #[allow(unused)]
            Err(e) => {
                log::warn!("INVALID LINE: {}", line);
                if app_args.invalid_lines {
                    #[cfg(not(debug_assertions))]
                    p!(app_args.color, Color::Red, "PARSE_ERR: {}", line);
                    #[cfg(debug_assertions)]
                    p!(app_args.color, Color::Red, "{}", e);
                }
            }
        }
    }

    p!(app_args.color, None);

    match child.wait() {
        Ok(exit_status) => {
            let msg = format!(
                "strace exited with code: {}",
                exit_status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or("???".to_string())
            );

            if !exit_status.success() {
                exit_with_error!("{}", msg);
            } else {
                log::trace!("{}", msg);
            }
        }
        Err(e) => exit_with_error!("An error occurred while waiting for process to end: {}", e),
    }

    Ok(())
}
