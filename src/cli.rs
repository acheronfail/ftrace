use clap::AppSettings::ColoredHelp;
use clap::ArgSettings::{AllowHyphenValues, Last};
use clap::{crate_authors, crate_description, crate_name, crate_version, Clap};

#[derive(Debug, Default)]
pub struct FileTypes {
    pub files: bool,
    pub directories: bool,
    pub symlinks: bool,
    pub sockets: bool,
    pub pipes: bool,
    pub executables: bool,
    pub empty: bool,
}

pub const POSSIBLE_TYPES: &[&str] = &[
    "f",
    "file",
    "d",
    "directory",
    "l",
    "symlink",
    "x",
    "executable",
    "e",
    "empty",
    "s",
    "socket",
    "p",
    "pipe",
];

const AFTER_HELP: &str = concat!(
    "Note: `",
    crate_name!(),
    " -h` prints a short and concise overview while `",
    crate_name!(),
    " --help` gives all details."
);

#[derive(Debug, Clap)]
#[clap(
    version = crate_version!(),
    about = crate_description!(),
    author = crate_authors!(),
    after_help = AFTER_HELP,
    global_setting(ColoredHelp)
)]
pub struct Args {
    /// Command to trace
    ///
    /// The specified command is executed directly and does not employ a shell, so scripts without shebang that usually
    /// run just fine when invoked by shell fail to execute. It is advisable to manually supply a shell as a command
    /// with the script as its argument
    #[clap(setting = AllowHyphenValues, setting = Last, min_values = 1, required_unless_present = "pid")]
    pub cmd: Vec<String>,
    /// Optional PID to of running process to trace (note requires elevated privileges)
    #[clap(short = 'p', long = "pid")]
    pub pid: Option<usize>,
    /// Print output with terminal colors
    #[clap(short = 'c', long = "color")]
    pub color: bool,
    /// Print lines that the program failed to parse (see --help for more)
    ///
    /// This program uses `strace` in order to trace system calls. One of the caveats is that `strace` outputs over
    /// `STDERR`: this can be a problem if the program to be traced also outputs data on `STDERR` as the output may
    /// confuse the parser.
    /// This option will log all lines that are send over `STDERR` that failed to be correctly parsed.
    #[clap(short = 'i', long = "invalid")]
    pub invalid_lines: bool,
    /// Print paths that the program attempted to access but didn't exist
    ///
    /// This will commonly output heaps of directories as many programs attempt to search for linked libraries, etc.
    #[clap(short = 'e', long = "non-existent")]
    pub non_existent: bool,
    /// Filter the search by type (multiple allowable filetypes can be specified)
    ///
    /// Possible types are:
    ///     'f' or 'file':         regular files
    ///     'd' or 'directory':    directories
    ///     'l' or 'symlink':      symbolic links
    ///     'x' or 'executable':   executables
    ///     'e' or 'empty':        empty files or directories
    ///     's' or 'socket':       socket
    ///     'p' or 'pipe':         named pipe (FIFO)
    #[clap(short = 't', long = "type", verbatim_doc_comment, hide_possible_values = true, multiple = true, possible_values = POSSIBLE_TYPES)]
    file_types: Vec<String>,
    #[clap(skip)]
    _file_types: Option<FileTypes>,
    // TODO: filter by access pattern: r,w,rw,?,all
}

impl Args {
    pub fn parse() -> Args {
        let mut args = <Args as Clap>::parse();
        args._file_types = Args::parse_file_types(&args.file_types);

        args
    }

    pub fn file_types(&self) -> Option<&FileTypes> {
        self._file_types.as_ref()
    }

    fn parse_file_types(input: &Vec<String>) -> Option<FileTypes> {
        if input.is_empty() {
            None
        } else {
            let mut file_types = FileTypes::default();
            for t in input {
                match t.as_str() {
                    "f" | "file" => file_types.files = true,
                    "d" | "directory" => file_types.directories = true,
                    "l" | "symlink" => file_types.symlinks = true,
                    "x" | "executable" => file_types.executables = true,
                    "e" | "empty" => file_types.empty = true,
                    "s" | "socket" => file_types.sockets = true,
                    "p" | "pipe" => file_types.pipes = true,
                    _ => unreachable!(),
                }
            }

            Some(file_types)
        }
    }
}
