/// Information about a live HLS segment
pub struct SegmentInfo {
    pub sequence: u64,
    pub filename: String,
    pub duration: f32,
}

/// Generate a live HLS playlist
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
