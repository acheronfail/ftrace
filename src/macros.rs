// A simpler and more terse way to change terminal colors.

#[macro_export]
macro_rules! choice {
    ($bool:expr) => {
        if $bool {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        }
    };
}

#[macro_export]
macro_rules! p {
    // Single value: just changes the color.
    ($color_choice:expr, None) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(None)).unwrap();
    }};
    ($color_choice:expr, $color:expr) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(Some($color))).unwrap();
    }};

    // Two values: change the color and print string.
    ($color_choice:expr, None, $fmt:expr) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(None)).unwrap();
        writeln!(&mut stdout, $fmt).unwrap();
    }};
    ($color_choice:expr, $color:expr, $fmt:expr) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(Some($color))).unwrap();
        writeln!(&mut stdout, $fmt).unwrap();
    }};

    // Three or more values: change the color and format a string.
    ($color_choice:expr, None, $fmt:expr, $( $fmt_arg:expr ),*) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(None)).unwrap();
        writeln!(&mut stdout, $fmt, $($fmt_arg),*).unwrap();
    }};
    ($color_choice:expr, $color:expr, $fmt:expr, $( $fmt_arg:expr ),*) => {{
        let mut stdout = termcolor::StandardStream::stdout(choice!($color_choice));
        stdout.set_color(termcolor::ColorSpec::new().set_fg(Some($color))).unwrap();
        writeln!(&mut stdout, $fmt, $($fmt_arg),*).unwrap();
    }};
}
