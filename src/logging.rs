use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Log a timestamped message to stderr (thread-safe, no line buffering).
pub fn dolog(args: std::fmt::Arguments<'_>) {
    if is_quiet() {
        return;
    }
    let now = chrono_timestamp();
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "{now} ");
    let _ = stderr.write_fmt(args);
}

/// Format a log message with arguments then log it.
#[macro_export]
macro_rules! log_msg {
    ($($arg:tt)*) => {{
        $crate::logging::dolog(format_args!($($arg)*));
    }};
}

fn chrono_timestamp() -> String {
    // Use std time since we want no dependencies.
    // We'll use a simple approach with SystemTime.
    use std::time::SystemTime;

    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC timestamp formatting
    let (year, month, day, hour, min, sec) = unix_to_datetime(secs);
    format!("[{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}]")
}

fn unix_to_datetime(timestamp: u64) -> (u64, u64, u64, u64, u64, u64) {
    let secs_per_day: u64 = 86400;
    let days = timestamp / secs_per_day;
    let remaining_secs = timestamp % secs_per_day;

    let hour = remaining_secs / 3600;
    let min = (remaining_secs % 3600) / 60;
    let sec = remaining_secs % 60;

    // Calculate date from days since epoch (1970-01-01)
    let mut y = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut m = 0u64;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        m += 1;
    }

    (y, m + 1, remaining_days + 1, hour, min, sec)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_quiet() {
        set_quiet(false);
        assert!(!is_quiet());
        set_quiet(true);
        assert!(is_quiet());
        set_quiet(false);
    }

    #[test]
    fn test_unix_to_datetime_epoch() {
        let (y, m, d, h, min, s) = unix_to_datetime(0);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn test_unix_to_datetime_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let (y, m, d, h, min, s) = unix_to_datetime(1704067200);
        assert_eq!((y, m, d, h, min, s), (2024, 1, 1, 0, 0, 0));
    }

    #[test]
    fn test_unix_to_datetime_with_time() {
        // 1970-01-01 01:01:01 = 3661
        let (y, m, d, h, min, s) = unix_to_datetime(3661);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 1, 1, 1));
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(2400));
    }

    #[test]
    fn test_unix_to_datetime_leap_day() {
        // 2024-02-29 00:00:00 UTC = 1709164800
        let (y, m, d, _h, _min, _s) = unix_to_datetime(1709164800);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn test_chrono_timestamp_format() {
        let ts = chrono_timestamp();
        // Should match [YYYY-MM-DD HH:MM:SS] pattern
        assert!(ts.starts_with('['));
        assert!(ts.ends_with(']'));
        assert_eq!(ts.len(), 21);
    }

    #[test]
    fn test_dolog_quiet_mode() {
        // This just verifies it doesn't panic in quiet mode
        set_quiet(true);
        dolog(format_args!("test message\n"));
        set_quiet(false);
    }

    #[test]
    fn test_dolog_normal_mode() {
        // This just verifies it doesn't panic
        set_quiet(false);
        dolog(format_args!("test message\n"));
    }
}
