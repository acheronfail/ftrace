use std::fmt::{self, Display};
use std::time::Duration;

use anyhow::Result;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::*;
use which::which;

pub fn decode_hex(s: &str) -> String {
    String::from_utf8(hex::decode(s.replace(r"\x", "")).unwrap()).unwrap()
}

#[derive(Debug, Eq, PartialEq)]
pub struct StraceLine<'a> {
    pub pid: Option<i32>,
    pub time: Option<Duration>,
    pub inner: StraceToken<'a>,
}

impl<'a> StraceLine<'a> {
    pub fn serialize(&self) -> String {
        let pid = match self.pid {
            Some(pid) => format!("[pid {}] ", pid),
            None => format!(""),
        };
        let time = match self.time {
            Some(time) => format!("{}.{} ", time.as_secs(), time.subsec_micros()),
            None => format!(""),
        };
        let inner = self.inner.serialize();
        format!("{}{}{}", pid, time, inner)
    }

    pub fn walk(&self, f: &impl Fn(&StraceToken<'a>) -> bool) {
        self.inner.walk(f);
    }
}

impl<'a> Display for StraceLine<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::serialize(self))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StraceToken<'a> {
    Signal(&'a str, Vec<StraceToken<'a>>),
    PermissionDenied(i32),
    ProcessAttach(i32),
    ProcessDetach(i32),
    Kill(&'a str),
    Exit(i32),

    Call {
        name: &'a str,
        args: Vec<StraceToken<'a>>,
        result: Option<i32>,
        info: Option<&'a str>,
    },
    Expr(Vec<StraceToken<'a>>),
    Hash(Vec<(&'a str, StraceToken<'a>)>),
    Array(Vec<StraceToken<'a>>),
    List(Vec<StraceToken<'a>>),
    BitSet(bool, Vec<StraceToken<'a>>),
    String(&'a str),
    Number(i64),
    Ident(&'a str),
    Op(&'a str),
    Truncated,
    Null,
}

impl<'a> StraceToken<'a> {
    pub fn serialize(&self) -> String {
        match self {
            StraceToken::Expr(items) => {
                let items = items.iter().map(Self::serialize).collect::<Vec<_>>();
                format!("{}", items.join(""))
            }
            StraceToken::Array(items) => {
                let items = items.iter().map(Self::serialize).collect::<Vec<_>>();
                format!("[{}]", items.join(", "))
            }
            StraceToken::List(items) => {
                let items = items.iter().map(Self::serialize).collect::<Vec<_>>();
                format!("{{{}}}", items.join(" "))
            }
            StraceToken::BitSet(not, bits) => {
                let bits = bits.iter().map(Self::serialize).collect::<Vec<_>>();
                format!("{}[{}]", if *not { "~" } else { "" }, bits.join(" "))
            }
            StraceToken::Hash(contents) => {
                let contents = contents
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, Self::serialize(v)))
                    .collect::<Vec<_>>();
                format!("{{{}}}", contents.join(", "))
            }
            StraceToken::Call {
                name,
                args,
                result,
                info,
            } => {
                let args = args.iter().map(Self::serialize).collect::<Vec<_>>();
                let result = match result {
                    Some(n) => format!(" = {}", n),
                    None => format!(""),
                };
                match info {
                    Some(info) => format!("{}({}){} {}", name, args.join(", "), result, info),
                    None => format!("{}({}){}", name, args.join(", "), result),
                }
            }
            StraceToken::String(s) => format!("\"{}\"", decode_hex(s)),
            StraceToken::Number(n) => format!("{:#x}", n),
            StraceToken::Ident(inner) | StraceToken::Op(inner) => {
                format!("{}", inner)
            }
            StraceToken::Signal(name, vars) => format!(
                "--- {}{} ---",
                name,
                vars.iter()
                    .map(Self::serialize)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            StraceToken::PermissionDenied(pid) => {
                format!(
                    "{}: attach: ptrace(PTRACE_SEIZE, {}): Operation not permitted",
                    which("strace").unwrap().display(),
                    pid
                )
            }
            StraceToken::ProcessAttach(pid) => {
                format!(
                    "{}: Process {} attached",
                    which("strace").unwrap().display(),
                    pid
                )
            }
            StraceToken::ProcessDetach(pid) => {
                format!("strace: Process {} detached", pid)
            }
            StraceToken::Exit(code) => format!("+++ exited with {} +++", code),
            StraceToken::Kill(sig) => format!("+++ killed by {} +++", sig),
            StraceToken::Truncated => format!("..."),
            StraceToken::Null => format!("NULL"),
        }
    }

    pub fn walk(&self, f: &impl Fn(&StraceToken<'a>) -> bool) {
        if !f(self) {
            return;
        }

        match self {
            StraceToken::Call { args, .. } => args.iter().for_each(|arg| arg.walk(f)),
            StraceToken::Expr(items) => items.iter().for_each(|item| item.walk(f)),
            StraceToken::Hash(items) => items.iter().for_each(|(_, item)| item.walk(f)),
            StraceToken::Array(items) => items.iter().for_each(|item| item.walk(f)),
            _ => {}
        }
    }

    pub fn walk_mut(&self, f: &mut impl FnMut(&StraceToken<'a>) -> bool) {
        if !f(self) {
            return;
        }

        match self {
            StraceToken::Call { args, .. } => args.iter().for_each(|arg| arg.walk_mut(f)),
            StraceToken::Expr(items) => items.iter().for_each(|item| item.walk_mut(f)),
            StraceToken::Hash(items) => items.iter().for_each(|(_, item)| item.walk_mut(f)),
            StraceToken::Array(items) => items.iter().for_each(|item| item.walk_mut(f)),
            _ => {}
        }
    }

    pub fn strs(&self) -> Vec<&'a str> {
        let mut strs = vec![];
        self.walk_mut(&mut |token| {
            if let StraceToken::String(s) = token {
                strs.push(*s);
            }

            true
        });

        strs
    }
}

impl<'a> Display for StraceToken<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::serialize(self))
    }
}

fn strace_time(input: &str) -> Duration {
    Duration::from_micros(input.replace(".", "").parse().unwrap())
}

pub fn strace_line(line: &str) -> Result<StraceLine> {
    // the "strace" rule contains a line
    let mut inner_line = StraceParser::parse(Rule::strace, line)?
        .next()
        .unwrap()
        .into_inner();

    // TODO: clean this up
    // line may be:
    // may be an optional "pid"
    // may be an optional "timestamp"
    // then there's a call
    let first = inner_line.next().unwrap();
    match first.as_rule() {
        // Special lines
        Rule::signal => {
            let mut inner = first.into_inner();
            let name = inner.next().unwrap().as_str();
            let vars = match inner.next() {
                Some(pair) => vec![parse_from_pest(pair)],
                None => vec![],
            };
            Ok(StraceLine {
                pid: None,
                time: None,
                inner: StraceToken::Signal(name, vars),
            })
        }
        Rule::permission_denied => Ok(StraceLine {
            pid: None,
            time: None,
            inner: StraceToken::PermissionDenied(first.into_inner().as_str().parse().unwrap()),
        }),
        Rule::process_attach => Ok(StraceLine {
            pid: None,
            time: None,
            inner: StraceToken::ProcessAttach(first.into_inner().as_str().parse().unwrap()),
        }),
        Rule::process_detach => Ok(StraceLine {
            pid: None,
            time: None,
            inner: StraceToken::ProcessDetach(first.into_inner().as_str().parse().unwrap()),
        }),

        // Standard strace call
        Rule::pid => {
            let pid = Some(first.into_inner().as_str().parse().unwrap());
            let second = inner_line.next().unwrap();
            match second.as_rule() {
                Rule::timestamp => Ok(StraceLine {
                    pid,
                    time: Some(strace_time(second.as_str())),
                    inner: parse_from_pest(inner_line.next().unwrap()),
                }),
                _ => Ok(StraceLine {
                    pid,
                    time: None,
                    inner: parse_from_pest(second),
                }),
            }
        }
        Rule::timestamp => Ok(StraceLine {
            pid: None,
            time: Some(strace_time(first.as_str())),
            inner: parse_from_pest(inner_line.next().unwrap()),
        }),
        _ => Ok(StraceLine {
            pid: None,
            time: None,
            inner: parse_from_pest(first),
        }),
    }
}

#[derive(Parser)]
#[grammar = "strace.pest"]
struct StraceParser;

fn parse_from_pest(pair: Pair<Rule>) -> StraceToken {
    match pair.as_rule() {
        Rule::line => unreachable!(),
        Rule::hash => StraceToken::Hash(
            pair.into_inner()
                .map(|key_value| {
                    let mut inner_rules = key_value.into_inner();
                    let name = inner_rules.next().unwrap().as_str();
                    let value = match inner_rules.next() {
                        Some(pair) => parse_from_pest(pair),
                        None => StraceToken::Truncated,
                    };
                    (name, value)
                })
                .collect(),
        ),
        Rule::array => StraceToken::Array(pair.into_inner().map(parse_from_pest).collect()),
        Rule::list => StraceToken::List(pair.into_inner().map(parse_from_pest).collect()),
        Rule::bit_set => {
            let not = &pair.as_str()[0..1] == "~";
            let bits = pair.into_inner().map(parse_from_pest).collect();
            StraceToken::BitSet(not, bits)
        }
        Rule::call => {
            let mut inner_pairs = pair.into_inner().collect::<Vec<_>>();
            let name = inner_pairs.remove(0).as_str();
            let (result, info): (Option<i32>, Option<&str>) =
                match inner_pairs[inner_pairs.len() - 1].as_rule() {
                    Rule::call_result => {
                        let mut inner = inner_pairs.pop().unwrap().into_inner();
                        let result = inner
                            .next()
                            .unwrap()
                            .as_str()
                            .trim()
                            .parse::<i32>()
                            .unwrap();

                        (Some(result), inner.next().map(|p| p.as_str()))
                    }
                    _ => (None, None),
                };

            let args = inner_pairs.into_iter().map(parse_from_pest).collect();
            StraceToken::Call {
                name,
                args,
                result,
                info,
            }
        }
        Rule::expr => StraceToken::Expr(pair.into_inner().map(parse_from_pest).collect()),
        Rule::exit => StraceToken::Exit(pair.into_inner().as_str().parse().unwrap()),
        Rule::kill => StraceToken::Kill(pair.into_inner().as_str()),
        Rule::string => StraceToken::String(pair.into_inner().next().unwrap().as_str()),
        Rule::constant | Rule::ident => StraceToken::Ident(pair.as_str()),
        Rule::op => StraceToken::Op(pair.as_str()),
        Rule::number => {
            let s = pair.as_str();
            StraceToken::Number(if s.starts_with("0x") {
                i64::from_str_radix(&s[2..], 16).unwrap()
            } else if s.len() > 1 && s.starts_with("0") {
                i64::from_str_radix(&s[1..], 8).unwrap()
            } else {
                s.parse().unwrap()
            })
        }
        Rule::null => StraceToken::Null,

        // Hidden rules from grammar
        Rule::EOI
        | Rule::WHITESPACE
        | Rule::COMMENT
        | Rule::number_hex
        | Rule::number_oct
        | Rule::value
        | Rule::trace
        | Rule::strace => unreachable!("{:?}", pair.as_rule()),

        // Rules consumed by other rules
        Rule::key_value
        | Rule::call_info
        | Rule::call_result
        | Rule::comment_inner
        | Rule::string_inner
        | Rule::char => unreachable!("{:?}", dbg!(pair).as_rule()),

        // Root-level rules handled in `strace_line`
        Rule::timestamp
        | Rule::pid
        | Rule::signal
        | Rule::permission_denied
        | Rule::process_attach
        | Rule::process_detach => {
            unreachable!("{:?}", pair.as_rule())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{strace_line, StraceLine, StraceToken::*};

    fn p(line: &str) -> StraceLine {
        strace_line(line).unwrap()
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
