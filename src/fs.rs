use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

pub fn is_file(path: &Path) -> bool {
    path.is_file()
}

// Path::is_dir() is not guaranteed to be intuitively correct for "." and ".."
// See: https://github.com/rust-lang/rust/issues/45302
pub fn is_dir(path: &Path) -> bool {
    path.is_dir() && (path.file_name().is_some() || path.canonicalize().is_ok())
}

pub fn is_executable(m: &fs::Metadata) -> bool {
    m.permissions().mode() & 0o111 != 0
}

pub fn is_socket(ft: &fs::FileType) -> bool {
    ft.is_socket()
}

pub fn is_pipe(ft: &fs::FileType) -> bool {
    ft.is_fifo()
}

pub fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

pub fn is_empty(path: &Path) -> bool {
    if is_dir(path) {
        if let Ok(mut entries) = fs::read_dir(path) {
            entries.next().is_none()
        } else {
            false
        }
    } else if is_file(path) {
        path.metadata().map(|m| m.len() == 0).unwrap_or(false)
    } else {
        false
    }
}
