pub mod strace_line;
pub mod strace_token;
pub mod string;
pub mod timestamp;

use pest_derive::*;

pub use strace_line::StraceLine;
pub use strace_token::StraceToken;

#[derive(Parser)]
#[grammar = "strace.pest"]
pub struct StraceParser;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::strace_line::StraceLine;
    use super::strace_token::StraceToken::*;

    fn p(line: &str) -> StraceLine {
        StraceLine::from_str(line).unwrap()
    }

    /// Asserts deserialisation and then serialisation
    macro_rules! assert_serde {
        ($line:expr) => {
            assert_eq!(StraceLine::serialize(&p($line)), $line);
        };
    }

    #[test]
    fn serde() {
        assert_serde!(r#"openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#);
        assert_serde!(
            r#"1611916273.692217 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#
        );
        assert_serde!(
            r#"[pid 1823469] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#
        );
        assert_serde!(
            r#"[pid 1823469] 1611916273.692217 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#
        );

        assert_serde!(
            r#"access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)"#
        );
        assert_serde!(
            r#"1611916273.692217 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)"#
        );
        assert_serde!(
            r#"[pid 1823469] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)"#
        );
        assert_serde!(
            r#"[pid 1823469] 1611916273.692217 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)"#
        );

        assert_serde!(r#"+++ exited with 42 +++"#);
        assert_serde!(r#"1611916273.692217 +++ exited with 42 +++"#);
        assert_serde!(r#"[pid 1823469] +++ exited with 42 +++"#);
        assert_serde!(r#"[pid 1823469] 1611916273.692217 +++ exited with 42 +++"#);

        assert_serde!(r#"/usr/bin/strace: Process 42 attached"#);
    }

    #[test]
    fn process_attached() {
        assert_eq!(
            p(r#"/usr/bin/strace: Process 1807404 attached"#).inner,
            ProcessAttach(1807404)
        );
    }

    #[test]
    fn process_detached() {
        assert_eq!(
            p(r#"strace: Process 1807404 detached"#).inner,
            ProcessDetach(1807404)
        );
    }

    #[test]
    fn process_exit() {
        assert_eq!(
            p(r#"+++ exited with 0 +++"#),
            StraceLine {
                pid: None,
                time: None,
                inner: Exit(0)
            }
        );
        assert_eq!(
            p(r#"+++ exited with 42 +++"#),
            StraceLine {
                pid: None,
                time: None,
                inner: Exit(42)
            }
        );
        assert_eq!(
            p(r#"+++ exited with -1 +++"#),
            StraceLine {
                pid: None,
                time: None,
                inner: Exit(-1)
            }
        );
        assert_eq!(
            p(r#"1611916273.692217 +++ exited with -1 +++"#),
            StraceLine {
                pid: None,
                time: Some(Duration::from_micros(1611916273692217)),
                inner: Exit(-1)
            }
        );
        assert_eq!(
            p(r#"[pid 1823469] +++ exited with -1 +++"#),
            StraceLine {
                pid: Some(1823469),
                time: None,
                inner: Exit(-1)
            }
        );
        assert_eq!(
            p(r#"[pid 1823469] 1611916273.692217 +++ exited with -1 +++"#),
            StraceLine {
                pid: Some(1823469),
                time: Some(Duration::from_micros(1611916273692217)),
                inner: Exit(-1)
            }
        );
    }

    #[test]
    fn or_expression() {
        assert_eq!(
            p(r#"openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#).inner,
            Call {
                name: "openat",
                args: vec![
                    Expr(vec![Ident("AT_FDCWD")]),
                    String("/etc/ld.so.cache"),
                    Expr(vec![Ident("O_RDONLY"), Op("|"), Ident("O_CLOEXEC")])
                ],
                result: Some(3),
                info: None,
            }
        );
    }

    #[test]
    fn trailing_info() {
        assert_eq!(
            p(r#"access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)"#)
                .inner,
            Call {
                name: "access",
                args: vec![String("/etc/ld.so.preload"), Expr(vec![Ident("R_OK")])],
                result: Some(-1),
                info: Some("ENOENT (No such file or directory)")
            }
        );
    }

    #[test]
    fn call_args_comment() {
        assert_eq!(
            p(r#"execve("/usr/bin/ls", ["ls"], 0x7ffea94d6768 /* 71 vars */) = 0"#).inner,
            Call {
                name: "execve",
                args: vec![
                    String("/usr/bin/ls"),
                    Array(vec![String("ls")]),
                    Expr(vec![Number(0x7ffea94d6768)])
                ],
                result: Some(0),
                info: None
            }
        );
    }

    #[test]
    fn call_args_empty_comment() {
        assert_eq!(
            p(r#"execve("/usr/bin/ls", ["ls"], 0x7ffea94d6768 /**/) = 0"#).inner,
            Call {
                name: "execve",
                args: vec![
                    String("/usr/bin/ls"),
                    Array(vec![String("ls")]),
                    Expr(vec![Number(0x7ffea94d6768)])
                ],
                result: Some(0),
                info: None
            }
        );
    }

    #[test]
    fn call_args_with_hash() {
        assert_eq!(
            p(r#"fstat(3, {st_mode=S_IFREG|0644, st_size=282443, ...}) = 0"#).inner,
            Call {
                name: "fstat",
                args: vec![
                    Expr(vec![Number(3)]),
                    Hash(vec![
                        (
                            "st_mode",
                            Expr(vec![Ident("S_IFREG"), Op("|"), Number(0o644)])
                        ),
                        ("st_size", Expr(vec![Number(282443)]))
                    ])
                ],
                result: Some(0),
                info: None
            }
        )
    }

    #[test]
    fn call_args_string_ellipse() {
        assert_eq!(
            p(
                r#"readlink("\x2f\x65\x74\x63\x2f\x6c\x6f\x63\x61\x6c\x74\x69\x6d\x65", "\x2f\x75\x73\x72\x2f\x73\x68\x61\x72\x65\x2f\x7a\x6f\x6e\x65\x69\x6e\x66\x6f\x2f\x41\x75\x73\x74\x72\x61\x6c\x69\x61\x2f\x53\x79"..., 256) = 36"#
            ).inner,
            Call {
                name: "readlink",
                args: vec![
                    String(r"\x2f\x65\x74\x63\x2f\x6c\x6f\x63\x61\x6c\x74\x69\x6d\x65"),
                    String(
                        r"\x2f\x75\x73\x72\x2f\x73\x68\x61\x72\x65\x2f\x7a\x6f\x6e\x65\x69\x6e\x66\x6f\x2f\x41\x75\x73\x74\x72\x61\x6c\x69\x61\x2f\x53\x79"
                    ),
                    Expr(vec![Number(256)])
                ],
                result: Some(36),
                info: None
            }
        );
    }

    #[test]
    fn call_args_hash_nested_call() {
        assert_eq!(
            p(
                r#"stat("\x2f\x64\x65\x76\x2f\x64\x72\x69\x2f\x63\x61\x72\x64\x30", {st_mode=S_IFCHR|0660, st_rdev=makedev(0xe2, 0)}) = 0"#
            ).inner,
            Call {
                name: "stat",
                args: vec![
                    String(r"\x2f\x64\x65\x76\x2f\x64\x72\x69\x2f\x63\x61\x72\x64\x30"),
                    Hash(vec![
                        (
                            "st_mode",
                            Expr(vec![Ident("S_IFCHR"), Op("|"), Number(0o660)])
                        ),
                        (
                            "st_rdev",
                            Expr(vec![Call {
                                name: "makedev",
                                args: vec![Expr(vec![Number(0xe2)]), Expr(vec![Number(0)])],
                                result: None,
                                info: None
                            }])
                        ),
                    ])
                ],
                result: Some(0),
                info: None
            }
        );
    }

    #[test]
    fn prefix_timestamp() {
        assert_eq!(
            p(r#"1611916273.692217 access("/etc/ld.so.preload", R_OK) = -1"#),
            StraceLine {
                pid: None,
                time: Some(Duration::from_micros(1611916273692217)),
                inner: Call {
                    name: "access",
                    args: vec![String("/etc/ld.so.preload"), Expr(vec![Ident("R_OK")])],
                    result: Some(-1),
                    info: None
                }
            }
        )
    }

    #[test]
    fn prefix_pid() {
        assert_eq!(
            p(r#"[pid 1823469] access("/etc/ld.so.preload", R_OK) = -1"#),
            StraceLine {
                pid: Some(1823469),
                time: None,
                inner: Call {
                    name: "access",
                    args: vec![String("/etc/ld.so.preload"), Expr(vec![Ident("R_OK")])],
                    result: Some(-1),
                    info: None
                }
            }
        )
    }

    #[test]
    fn prefix_pid_and_timestamp() {
        assert_eq!(
            p(r#"[pid 1823469] 1611916273.692217 access("/etc/ld.so.preload", R_OK) = -1"#),
            StraceLine {
                pid: Some(1823469),
                time: Some(Duration::from_micros(1611916273692217)),
                inner: Call {
                    name: "access",
                    args: vec![String("/etc/ld.so.preload"), Expr(vec![Ident("R_OK")])],
                    result: Some(-1),
                    info: None
                }
            }
        )
    }

    #[test]
    fn signals() {
        assert_eq!(p(r#"--- SIGALRM ... ---"#).inner, Signal("SIGALRM", vec![]));
        assert_eq!(
            p(r#"--- SIGINT {si_signo=SIGINT, si_code=SI_KERNEL} ---"#).inner,
            Signal(
                "SIGINT",
                vec![Hash(vec![
                    ("si_signo", Expr(vec![Ident("SIGINT")])),
                    ("si_code", Expr(vec![Ident("SI_KERNEL")]))
                ])]
            )
        );
        assert_eq!(
            p(r#"--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1783018, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---"#).inner,
            Signal("SIGCHLD", vec![
                Hash(vec![
                    ("si_signo", Expr(vec![Ident("SIGCHLD")])),
                    ("si_code", Expr(vec![Ident("CLD_EXITED")])),
                    ("si_pid", Expr(vec![Number(1783018)])),
                    ("si_uid", Expr(vec![Number(1000)])),
                    ("si_status", Expr(vec![Number(0)])),
                    ("si_utime", Expr(vec![Number(0)])),
                    ("si_stime", Expr(vec![Number(0)])),
                ])
            ])
        );
    }

    #[test]
    fn signals_truncated() {
        assert_eq!(
            p(r#"--- SIGINT {si_signo=SIGINT, si_code=SI_USER, si_pid=...} ---"#).inner,
            Signal(
                "SIGINT",
                vec![Hash(vec![
                    ("si_signo", Expr(vec![Ident("SIGINT")])),
                    ("si_code", Expr(vec![Ident("SI_USER")])),
                    ("si_pid", Truncated),
                ])]
            )
        );
    }

    #[test]
    fn process_killed() {
        assert_eq!(p(r#"+++ killed by SIGINT +++"#).inner, Kill("SIGINT"));
    }

    #[test]
    fn call_args_bit_set() {
        assert_eq!(
            p(r#"sigprocmask(SIG_BLOCK, [CHLD TTOU], []) = 0"#).inner,
            Call {
                name: "sigprocmask",
                args: vec![
                    Expr(vec![Ident("SIG_BLOCK")]),
                    BitSet(false, vec![Ident("CHLD"), Ident("TTOU")]),
                    Array(vec![])
                ],
                result: Some(0),
                info: None
            }
        );
    }

    #[test]
    fn call_args_bit_set_not() {
        assert_eq!(
            p(r#"sigprocmask(SIG_UNBLOCK, ~[], NULL) = 0"#).inner,
            Call {
                name: "sigprocmask",
                args: vec![Expr(vec![Ident("SIG_UNBLOCK")]), BitSet(true, vec![]), Null],
                result: Some(0),
                info: None
            }
        );
    }

    #[test]
    fn call_args_list() {
        assert_eq!(
            p(r#"ioctl(2, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig icanon echo ...}) = 0"#)
                .inner,
            Call {
                name: "ioctl",
                args: vec![
                    Expr(vec![Number(2)]),
                    Expr(vec![Ident("SNDCTL_TMR_STOP"), Op("or"), Ident("TCSETSW")]),
                    List(vec![
                        Expr(vec![Ident("B38400")]),
                        Expr(vec![Ident("opost")]),
                        Expr(vec![Ident("isig")]),
                        Expr(vec![Ident("icanon")]),
                        Expr(vec![Ident("echo")])
                    ])
                ],
                result: Some(0),
                info: None
            }
        );
    }
}
