/// Attempts to decode a hexadecimally escaped string.
/// Returns an owned version of the original string if decoding failed.
pub fn decode_hex(s: &str) -> String {
    match hex::decode(s.replace(r"\x", "")) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(decoded_string) => decoded_string,
            Err(_) => s.to_string(),
        },
        Err(_) => s.to_string(),
    }
}
