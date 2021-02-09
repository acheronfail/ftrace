use std::fmt::{self, Display};
use std::time::Duration;

use anyhow::Result;
use pest::Parser;

use crate::parse::strace_token::StraceToken;
use crate::parse::timestamp::decode_timestamp;
use crate::parse::{Rule, StraceParser};

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

    pub fn from_str(line: &str) -> Result<StraceLine> {
        // the "strace" rule contains a line
        let mut root_pairs = StraceParser::parse(Rule::strace, line)?
            .next()
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>();

        match root_pairs.len() {
            // Top level rules with only one pair
            1 => {
                let pair = root_pairs.pop().unwrap();
                match pair.as_rule() {
                    Rule::signal => {
                        let mut inner = pair.into_inner();
                        let name = inner.next().unwrap().as_str();
                        let vars = match inner.next() {
                            Some(pair) => vec![StraceToken::from_pest(pair)],
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
                        inner: StraceToken::PermissionDenied(
                            pair.into_inner().as_str().parse().unwrap(),
                        ),
                    }),
                    Rule::process_attach => Ok(StraceLine {
                        pid: None,
                        time: None,
                        inner: StraceToken::ProcessAttach(
                            pair.into_inner().as_str().parse().unwrap(),
                        ),
                    }),
                    Rule::process_detach => Ok(StraceLine {
                        pid: None,
                        time: None,
                        inner: StraceToken::ProcessDetach(
                            pair.into_inner().as_str().parse().unwrap(),
                        ),
                    }),

                    // Might just be an `StraceToken::Call` without a pid or timestamp
                    _ => Ok(StraceLine {
                        pid: None,
                        time: None,
                        inner: StraceToken::from_pest(pair),
                    }),
                }
            }

            // Top level rules with two pairs
            2 => {
                let call_pair = root_pairs.pop().unwrap();
                let next_pair = root_pairs.pop().unwrap();
                match next_pair.as_rule() {
                    Rule::timestamp => Ok(StraceLine {
                        pid: None,
                        time: Some(decode_timestamp(next_pair.as_str())),
                        inner: StraceToken::from_pest(call_pair),
                    }),
                    Rule::pid => Ok(StraceLine {
                        pid: Some(next_pair.into_inner().as_str().parse().unwrap()),
                        time: None,
                        inner: StraceToken::from_pest(call_pair),
                    }),
                    _ => unreachable!(),
                }
            }

            // Top level rules with three pairs
            3 => {
                let call_pair = root_pairs.pop().unwrap();
                let time_pair = root_pairs.pop().unwrap();
                let pid_pair = root_pairs.pop().unwrap();
                Ok(StraceLine {
                    pid: Some(pid_pair.into_inner().as_str().parse().unwrap()),
                    time: Some(decode_timestamp(time_pair.as_str())),
                    inner: StraceToken::from_pest(call_pair),
                })
            }

            _ => unreachable!(),
        }
    }
}

impl<'a> Display for StraceLine<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::serialize(self))
    }
}
