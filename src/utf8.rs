use std::fmt::Write;

// A big thanks to https://github.com/sharkdp/bat/blob/5e77ca37e89c873e4490b42ff556370dc5c6ba4f/src/preprocessor.rs#L52

pub fn replace_nonprintable(input: &[u8]) -> String {
    let mut output = String::new();

    let mut idx = 0;
    let len = input.len();
    while idx < len {
        if let Some((chr, skip_ahead)) = try_parse_utf8_char(&input[idx..]) {
            idx += skip_ahead;

            match chr {
                // space
                ' ' => output.push(' '),
                // tab
                '\t' => output.push('↹'),
                // line feed
                '\x0A' => output.push('␊'),
                // carriage return
                '\x0D' => output.push('␍'),
                // null
                '\x00' => output.push('␀'),
                // bell
                '\x07' => output.push('␇'),
                // backspace
                '\x08' => output.push('␈'),
                // escape
                '\x1B' => output.push('␛'),
                // printable ASCII
                c if c.is_ascii_alphanumeric()
                    || c.is_ascii_punctuation()
                    || c.is_ascii_graphic() =>
                {
                    output.push(c)
                }
                // everything else
                c => output.push_str(&c.escape_unicode().collect::<String>()),
            }
        } else {
            write!(output, "\\x{:02X}", input[idx]).ok();
            idx += 1;
        }
    }

    output
}

fn try_parse_utf8_char(input: &[u8]) -> Option<(char, usize)> {
    let str_from_utf8 = |seq| std::str::from_utf8(seq).ok();

    let decoded = input
        .get(0..1)
        .and_then(str_from_utf8)
        .map(|c| (c, 1))
        .or_else(|| input.get(0..2).and_then(str_from_utf8).map(|c| (c, 2)))
        .or_else(|| input.get(0..3).and_then(str_from_utf8).map(|c| (c, 3)))
        .or_else(|| input.get(0..4).and_then(str_from_utf8).map(|c| (c, 4)));

    decoded.map(|(seq, n)| (seq.chars().next().unwrap(), n))
}
