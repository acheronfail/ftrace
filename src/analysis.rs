use easy_collections::{map, EasyMap};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref FN_MAP: EasyMap<&'static str, FnInfo> = map! {
        ("access", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("acct", FnInfo::new(AccessMode::Unknown, ErrorReturnCode::NEGATIVE)),
        ("chdir", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("chmod", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("chown", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("chown16", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("chroot", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("creat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("execv", FnInfo::new(AccessMode::Read, ErrorReturnCode::Unknown)),
        ("execve", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("execveat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("faccessat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("fanotify_mark", FnInfo::new(AccessMode::Unknown, ErrorReturnCode::NEGATIVE)),
        ("fchmodat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("fchownat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("fstat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("fstat64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("fstatat64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("fstatfs", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("fstatfs64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("futimesat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        // NOTE: `man 2 getcwd` says it returns `NULL` on error, but `strace` interprets this as `-1`
        ("getcwd", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("getxattr", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("inotify_add_watch", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("link", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("linkat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("listxattr", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("lstat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("lstat64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("mkdir", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("mkdirat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("mknod", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("mknodat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("mount", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("name_to_handle_at", FnInfo::new(AccessMode::Unknown, ErrorReturnCode::NEGATIVE)),
        ("newfstatat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("oldfstat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("oldlstat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("oldstat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("open", FnInfo::new(AccessMode::ReadWrite, ErrorReturnCode::NEGATIVE)),
        ("openat", FnInfo::new(AccessMode::ReadWrite, ErrorReturnCode::NEGATIVE)),
        ("osf_fstatfs", FnInfo::new(AccessMode::Read, ErrorReturnCode::Unknown)),
        ("osf_statfs", FnInfo::new(AccessMode::Read, ErrorReturnCode::Unknown)),
        ("osf_utimes", FnInfo::new(AccessMode::Read, ErrorReturnCode::Unknown)),
        ("perror", FnInfo::new(AccessMode::Ignore, ErrorReturnCode::Unknown)),
        ("pivotroot", FnInfo::new(AccessMode::Read, ErrorReturnCode::Unknown)),
        ("printargs", FnInfo::new(AccessMode::Unknown, ErrorReturnCode::Unknown)),
        ("printf", FnInfo::new(AccessMode::Ignore, ErrorReturnCode::Unknown)),
        ("quotactl", FnInfo::new(AccessMode::Unknown, ErrorReturnCode::NEGATIVE)),
        ("readlink", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("readlinkat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("removexattr", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("rename", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("renameat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("renameat2", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("rmdir", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("setxattr", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("stat", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("stat64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("statfs", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("statfs64", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("statx", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("swapoff", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("swapon", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("symlink", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("symlinkat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("truncate", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("truncate64", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("umount", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("umount2", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("unlink", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("unlinkat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("uselib", FnInfo::new(AccessMode::Read, ErrorReturnCode::NEGATIVE)),
        ("utime", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("utimensat", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
        ("utimes", FnInfo::new(AccessMode::Write, ErrorReturnCode::NEGATIVE)),
    };
}

#[derive(Debug, Clone, Copy)]
pub enum AccessMode {
    Read,
    Write,
    ReadWrite,
    Ignore,
    Unknown,
}
#[derive(Debug, Clone)]
pub enum ErrorReturnCode {
    Single(i32),
    Unknown,
}

impl ErrorReturnCode {
    pub const NEGATIVE: ErrorReturnCode = ErrorReturnCode::Single(-1);
}

#[derive(Debug, Clone)]
pub struct FnInfo {
    pub mode: AccessMode,
    pub err_code: ErrorReturnCode,
}

impl FnInfo {
    pub fn new(mode: AccessMode, err_code: ErrorReturnCode) -> FnInfo {
        FnInfo { mode, err_code }
    }

    pub fn did_succeed(&self, code: i32) -> Option<bool> {
        match self.err_code {
            ErrorReturnCode::Single(n) => Some(code != n),
            ErrorReturnCode::Unknown => None
        }
    }
}

impl Default for FnInfo {
    fn default() -> Self {
        FnInfo {
            mode: AccessMode::Unknown,
            err_code: ErrorReturnCode::Unknown,
        }
    }
}
