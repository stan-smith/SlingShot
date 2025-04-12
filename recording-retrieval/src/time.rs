//! Time parsing for recording retrieval
//!
//! Supports:
//! - Relative: "5 mins ago", "2 hours ago", "1 day ago"
//! - Natural: "since yesterday", "since midnight", "last hour", "last 2 hours"
//! - Absolute: ISO8601 timestamps

use chrono::{DateTime, Duration, Local, NaiveDateTime, NaiveTime, TimeZone};

use crate::RetrievalError;

/// Represents a time range for recording retrieval
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub from: DateTime<Local>,
    pub to: DateTime<Local>,
}

/// Parse relative time like "5 mins ago", "2 hours ago", "1 day ago"
fn parse_relative_ago(parts: &[&str]) -> Result<DateTime<Local>, RetrievalError> {
    // Pattern: "<number> <unit> ago"
    if parts.len() != 3 || parts[2] != "ago" {
        return Err(RetrievalError::InvalidTimeFormat(parts.join(" ")));
    }

    let amount: i64 = parts[0]
        .parse()
        .map_err(|_| RetrievalError::InvalidTimeFormat(parts.join(" ")))?;

    let duration = match parts[1].to_lowercase().as_str() {
        "sec" | "secs" | "second" | "seconds" => Duration::seconds(amount),
        "min" | "mins" | "minute" | "minutes" => Duration::minutes(amount),
        "hour" | "hours" => Duration::hours(amount),
        "day" | "days" => Duration::days(amount),
        _ => return Err(RetrievalError::InvalidTimeFormat(parts.join(" "))),
    };

    Ok(Local::now() - duration)
}

/// Parse "since yesterday" or "since midnight"
fn parse_since(parts: &[&str]) -> Result<DateTime<Local>, RetrievalError> {
    if parts.len() != 2 || parts[0] != "since" {
        return Err(RetrievalError::InvalidTimeFormat(parts.join(" ")));
    }

    let now = Local::now();
    let midnight = NaiveTime::from_hms_opt(0, 0, 0).unwrap();

    match parts[1].to_lowercase().as_str() {
        "yesterday" => {
            let yesterday = now.date_naive() - Duration::days(1);
            Ok(Local
                .from_local_datetime(&yesterday.and_time(midnight))
                .single()
                .ok_or_else(|| RetrievalError::InvalidTimeFormat(parts.join(" ")))?)
        }
        "midnight" => {
            let today = now.date_naive();
            Ok(Local
                .from_local_datetime(&today.and_time(midnight))
                .single()
                .ok_or_else(|| RetrievalError::InvalidTimeFormat(parts.join(" ")))?)
        }
        _ => Err(RetrievalError::InvalidTimeFormat(parts.join(" "))),
    }
}

/// Parse "last hour" or "last N hours"
fn parse_last(parts: &[&str]) -> Result<DateTime<Local>, RetrievalError> {
    if parts.is_empty() || parts[0] != "last" {
        return Err(RetrievalError::InvalidTimeFormat(parts.join(" ")));
    }

    let now = Local::now();

    // "last hour" - exactly 1 hour
    if parts.len() == 2 && parts[1] == "hour" {
        return Ok(now - Duration::hours(1));
    }

    // "last N hours" or "last N minutes"
    if parts.len() == 3 {
        let amount: i64 = parts[1]
            .parse()
            .map_err(|_| RetrievalError::InvalidTimeFormat(parts.join(" ")))?;

        let duration = match parts[2].to_lowercase().as_str() {
            "hour" | "hours" => Duration::hours(amount),
            "min" | "mins" | "minute" | "minutes" => Duration::minutes(amount),
            "day" | "days" => Duration::days(amount),
            _ => return Err(RetrievalError::InvalidTimeFormat(parts.join(" "))),
        };

        return Ok(now - duration);
    }

    Err(RetrievalError::InvalidTimeFormat(parts.join(" ")))
}

/// Parse ISO8601 datetime like "2024-12-01T15:30:00"
fn parse_iso8601(input: &str) -> Result<DateTime<Local>, RetrievalError> {
    // Try parsing with timezone (RFC3339)
    if let Ok(dt) = DateTime::parse_from_rfc3339(input) {
        return Ok(dt.with_timezone(&Local));
    }

    // Try parsing without timezone (assume local)
    if let Ok(naive) = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Local
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(|| RetrievalError::InvalidTimeFormat(input.to_string()))?);
    }

    // Try without seconds
    if let Ok(naive) = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M") {
        return Ok(Local
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(|| RetrievalError::InvalidTimeFormat(input.to_string()))?);
    }

    Err(RetrievalError::InvalidTimeFormat(input.to_string()))
}

/// Parse a time range command
///
/// # Formats
///
/// Relative:
/// - `5 mins ago` -> (5 mins ago, now)
/// - `2 hours ago` -> (2 hours ago, now)
///
/// Natural:
/// - `since yesterday` -> (midnight yesterday, now)
/// - `since midnight` -> (midnight today, now)
/// - `last hour` -> (1 hour ago, now)
/// - `last 2 hours` -> (2 hours ago, now)
///
/// Absolute:
/// - `2024-12-01T15:30:00 2024-12-01T16:00:00` -> (from, to)
pub fn parse_time_range(args: &[&str]) -> Result<TimeRange, RetrievalError> {
    if args.is_empty() {
        return Err(RetrievalError::MissingTimeRange);
    }

    let now = Local::now();

    // Check for "since yesterday" or "since midnight"
    if args.len() >= 2 && args[0] == "since" {
        let from = parse_since(args)?;
        return Ok(TimeRange { from, to: now });
    }

    // Check for "last hour" or "last N hours/minutes"
    if args[0] == "last" {
        let from = parse_last(args)?;
        return Ok(TimeRange { from, to: now });
    }

    // Check for relative format: "5 mins ago"
    if args.len() >= 3 && args[args.len() - 1] == "ago" {
        let from = parse_relative_ago(args)?;
        return Ok(TimeRange { from, to: now });
    }

    // Absolute format: two ISO8601 timestamps
    if args.len() == 2 {
        let from = parse_iso8601(args[0])?;
        let to = parse_iso8601(args[1])?;

        if from >= to {
            return Err(RetrievalError::InvalidTimeRange { from, to });
        }

        return Ok(TimeRange { from, to });
    }

    Err(RetrievalError::InvalidTimeFormat(args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relative_ago() {
        let args = vec!["5", "mins", "ago"];
        let range = parse_time_range(&args).unwrap();
        let now = Local::now();

        // Should be approximately 5 mins ago (within a few seconds)
        let diff = now - range.from;
        assert!(diff.num_minutes() >= 4 && diff.num_minutes() <= 6);
        assert!((now - range.to).num_seconds().abs() < 2);
    }

    #[test]
    fn test_parse_since_midnight() {
        let args = vec!["since", "midnight"];
        let range = parse_time_range(&args).unwrap();

        assert_eq!(range.from.time().hour(), 0);
        assert_eq!(range.from.time().minute(), 0);
        assert_eq!(range.from.date_naive(), Local::now().date_naive());
    }

    #[test]
    fn test_parse_last_hour() {
        let args = vec!["last", "hour"];
        let range = parse_time_range(&args).unwrap();
        let now = Local::now();

        let diff = now - range.from;
        assert!(diff.num_minutes() >= 59 && diff.num_minutes() <= 61);
    }

    #[test]
    fn test_parse_iso8601() {
        let args = vec!["2024-12-01T15:30:00", "2024-12-01T16:00:00"];
        let range = parse_time_range(&args).unwrap();

        assert_eq!(range.from.hour(), 15);
        assert_eq!(range.from.minute(), 30);
        assert_eq!(range.to.hour(), 16);
        assert_eq!(range.to.minute(), 0);
    }

    #[test]
    fn test_invalid_range() {
        let args = vec!["2024-12-01T16:00:00", "2024-12-01T15:00:00"];
        let result = parse_time_range(&args);
        assert!(matches!(result, Err(RetrievalError::InvalidTimeRange { .. })));
    }
}
