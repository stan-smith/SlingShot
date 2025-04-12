//! File discovery for recording retrieval
//!
//! Finds recording files that overlap a given time range.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone};

use crate::{RetrievalError, TimeRange};

/// Default segment duration in seconds (matches ffmpeg-recorder default)
pub const DEFAULT_SEGMENT_DURATION: i64 = 30;

/// Represents a recording file with parsed timing
#[derive(Debug, Clone)]
pub struct RecordingFile {
    pub path: PathBuf,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    pub size_bytes: u64,
}

/// Parse filename like "2024-12-01_15-30-00.mp4" to DateTime
fn parse_filename_timestamp(filename: &str) -> Option<DateTime<Local>> {
    // Extract stem (remove extension)
    let stem = filename
        .strip_suffix(".mp4")
        .or_else(|| filename.strip_suffix(".mkv"))?;

    // Parse "YYYY-MM-DD_HH-MM-SS"
    let naive = NaiveDateTime::parse_from_str(stem, "%Y-%m-%d_%H-%M-%S").ok()?;
    Local.from_local_datetime(&naive).single()
}

/// Find all recordings that overlap the given time range ("round up" logic)
///
/// A recording overlaps if:
/// - recording.start_time < range.to AND recording.end_time > range.from
///
/// This ensures any partial overlap is included.
pub fn find_recordings_in_range(
    recordings_dir: &Path,
    range: &TimeRange,
    segment_duration_secs: i64,
) -> Result<Vec<RecordingFile>, RetrievalError> {
    let mut recordings = Vec::new();

    // List all files in recordings directory
    let entries =
        std::fs::read_dir(recordings_dir).map_err(|e| RetrievalError::IoError(e.to_string()))?;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Only process .mp4 and .mkv files
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("mp4") && ext != Some("mkv") {
            continue;
        }

        // Parse timestamp from filename
        let filename = path.file_name().and_then(|f| f.to_str());
        let Some(start_time) = filename.and_then(parse_filename_timestamp) else {
            continue;
        };

        // Estimate end time (start + segment duration)
        let end_time = start_time + Duration::seconds(segment_duration_secs);

        // Check overlap: recording overlaps range if
        // recording_start < range_end AND recording_end > range_start
        if start_time < range.to && end_time > range.from {
            let metadata = entry.metadata().ok();
            let size_bytes = metadata.map(|m| m.len()).unwrap_or(0);

            recordings.push(RecordingFile {
                path,
                start_time,
                end_time,
                size_bytes,
            });
        }
    }

    // Sort by start time (oldest first)
    recordings.sort_by_key(|r| r.start_time);

    Ok(recordings)
}

/// List all recording files in a directory
pub fn list_all_recordings(recordings_dir: &Path) -> Result<Vec<RecordingFile>, RetrievalError> {
    // Use a very wide range to get all files
    let range = TimeRange {
        from: Local.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap(),
        to: Local::now() + Duration::days(1),
    };
    find_recordings_in_range(recordings_dir, &range, DEFAULT_SEGMENT_DURATION)
}

/// Get total size of recordings
pub fn total_size(recordings: &[RecordingFile]) -> u64 {
    recordings.iter().map(|r| r.size_bytes).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_filename() {
        let dt = parse_filename_timestamp("2024-12-01_15-30-00.mp4").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 15);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_parse_filename_mkv() {
        let dt = parse_filename_timestamp("2024-12-01_15-30-00.mkv").unwrap();
        assert_eq!(dt.hour(), 15);
    }

    #[test]
    fn test_overlap_detection() {
        // Recording: 15:30:00 - 15:30:30
        // Query:     15:30:15 - 15:30:45
        // Should overlap

        let recording_start = Local.with_ymd_and_hms(2024, 12, 1, 15, 30, 0).unwrap();
        let recording_end = recording_start + Duration::seconds(30);

        let range = TimeRange {
            from: Local.with_ymd_and_hms(2024, 12, 1, 15, 30, 15).unwrap(),
            to: Local.with_ymd_and_hms(2024, 12, 1, 15, 30, 45).unwrap(),
        };

        // recording_start < range.to AND recording_end > range.from
        let overlaps = recording_start < range.to && recording_end > range.from;
        assert!(overlaps);
    }

    #[test]
    fn test_no_overlap() {
        // Recording: 15:30:00 - 15:30:30
        // Query:     15:31:00 - 15:31:30
        // Should NOT overlap

        let recording_start = Local.with_ymd_and_hms(2024, 12, 1, 15, 30, 0).unwrap();
        let recording_end = recording_start + Duration::seconds(30);

        let range = TimeRange {
            from: Local.with_ymd_and_hms(2024, 12, 1, 15, 31, 0).unwrap(),
            to: Local.with_ymd_and_hms(2024, 12, 1, 15, 31, 30).unwrap(),
        };

        let overlaps = recording_start < range.to && recording_end > range.from;
        assert!(!overlaps);
    }
}
