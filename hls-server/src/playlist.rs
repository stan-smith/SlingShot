use recording_retrieval::RecordingFile;

/// Information about a live HLS segment
pub struct SegmentInfo {
    pub sequence: u64,
    pub filename: String,
    pub duration: f32,
}

/// Generate a live HLS playlist (EVENT type for live streaming)
///
/// This creates a playlist that updates as new segments are added.
/// Clients will poll this endpoint to get updated segment lists.
pub fn live_playlist(segments: &[SegmentInfo], media_sequence: u64) -> String {
    let target_duration = segments
        .iter()
        .map(|s| s.duration.ceil() as u32)
        .max()
        .unwrap_or(3);

    let mut playlist = format!(
        "#EXTM3U\n\
         #EXT-X-VERSION:3\n\
         #EXT-X-TARGETDURATION:{}\n\
         #EXT-X-MEDIA-SEQUENCE:{}\n",
        target_duration, media_sequence
    );

    for seg in segments {
        playlist.push_str(&format!("#EXTINF:{:.3},\n{}\n", seg.duration, seg.filename));
    }

    playlist
}

/// Generate a VOD playlist for recordings
///
/// This creates a complete playlist with all segments and an ENDLIST marker.
/// The browser will play through all segments in order.
pub fn recording_playlist(node: &str, recordings: &[RecordingFile]) -> String {
    // Calculate max segment duration (should be ~30s for recordings)
    let target_duration = 30;

    let mut playlist = format!(
        "#EXTM3U\n\
         #EXT-X-VERSION:3\n\
         #EXT-X-TARGETDURATION:{}\n\
         #EXT-X-PLAYLIST-TYPE:VOD\n\
         #EXT-X-MEDIA-SEQUENCE:0\n",
        target_duration
    );

    for rec in recordings {
        // Extract timestamp from filename, stripping extensions
        let filename = rec.path.file_stem().unwrap_or_default().to_string_lossy();
        // Handle both .mp4 and .mp4.enc files - stem already strips one extension
        let timestamp = filename.strip_suffix(".mp4").unwrap_or(&filename);

        // Calculate actual duration from recording times
        let duration = (rec.end_time - rec.start_time).num_seconds() as f32;
        let duration = if duration > 0.0 { duration } else { 30.0 };

        playlist.push_str(&format!(
            "#EXTINF:{:.1},\n/hls/{}/recording/{}.ts\n",
            duration, node, timestamp
        ));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;
    use std::path::PathBuf;

    #[test]
    fn test_live_playlist_generation() {
        let segments = vec![
            SegmentInfo {
                sequence: 0,
                filename: "segment_000.ts".to_string(),
                duration: 2.0,
            },
            SegmentInfo {
                sequence: 1,
                filename: "segment_001.ts".to_string(),
                duration: 2.0,
            },
            SegmentInfo {
                sequence: 2,
                filename: "segment_002.ts".to_string(),
                duration: 2.0,
            },
        ];

        let playlist = live_playlist(&segments, 0);

        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("#EXT-X-TARGETDURATION:2"));
        assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:0"));
        assert!(playlist.contains("segment_000.ts"));
        assert!(playlist.contains("segment_001.ts"));
        assert!(playlist.contains("segment_002.ts"));
        // Live playlists should NOT have ENDLIST
        assert!(!playlist.contains("#EXT-X-ENDLIST"));
    }

    #[test]
    fn test_recording_playlist_generation() {
        let now = Local::now();
        let recordings = vec![
            RecordingFile {
                path: PathBuf::from("/recordings/2024-12-01_15-30-00.mp4"),
                start_time: now,
                end_time: now + chrono::Duration::seconds(30),
                size_bytes: 1000,
            },
            RecordingFile {
                path: PathBuf::from("/recordings/2024-12-01_15-30-30.mp4.enc"),
                start_time: now + chrono::Duration::seconds(30),
                end_time: now + chrono::Duration::seconds(60),
                size_bytes: 1000,
            },
        ];

        let playlist = recording_playlist("cam1", &recordings);

        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("#EXT-X-PLAYLIST-TYPE:VOD"));
        assert!(playlist.contains("#EXT-X-TARGETDURATION:30"));
        assert!(playlist.contains("/hls/cam1/recording/2024-12-01_15-30-00.ts"));
        assert!(playlist.contains("/hls/cam1/recording/2024-12-01_15-30-30.ts"));
        assert!(playlist.contains("#EXT-X-ENDLIST"));
    }
}
