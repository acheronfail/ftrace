use std::time::Duration;

pub fn decode_timestamp(input: &str) -> Duration {
    Duration::from_micros(input.replace(".", "").parse().unwrap())
}
