/// The current time in Unix seconds.
pub fn now() -> u64 {
    let now = time::UtcDateTime::now();
    now.unix_timestamp() as u64
}
