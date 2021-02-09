use std::fmt::{self, Display};

use pest::iterators::Pair;
use which::which;

use crate::parse::string::decode_hex;
use crate::parse::Rule;

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

    pub fn from_pest(pair: Pair<Rule>) -> StraceToken {
        match pair.as_rule() {
            Rule::line => unreachable!(),
            Rule::hash => StraceToken::Hash(
                pair.into_inner()
                    .map(|key_value| {
                        let mut inner_rules = key_value.into_inner();
                        let name = inner_rules.next().unwrap().as_str();
                        let value = match inner_rules.next() {
                            Some(pair) => Self::from_pest(pair),
                            None => StraceToken::Truncated,
                        };
                        (name, value)
                    })
                    .collect(),
            ),
            Rule::array => StraceToken::Array(pair.into_inner().map(Self::from_pest).collect()),
            Rule::list => StraceToken::List(pair.into_inner().map(Self::from_pest).collect()),
            Rule::bit_set => {
                let not = &pair.as_str()[0..1] == "~";
                let bits = pair.into_inner().map(Self::from_pest).collect();
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

                let args = inner_pairs.into_iter().map(Self::from_pest).collect();
                StraceToken::Call {
                    name,
                    args,
                    result,
                    info,
                }
            }
            Rule::expr => StraceToken::Expr(pair.into_inner().map(Self::from_pest).collect()),
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

            // Root-level rules handled in `StraceLine::from_str`
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
}

impl<'a> Display for StraceToken<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::serialize(self))
    }
}
