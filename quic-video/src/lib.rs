//! Video frame protocol for QUIC transport
//!
//! Provides serialization/deserialization of H.264 video frames for transmission over QUIC.
//! Includes integrity checking via CRC32 and sequence numbers to detect corruption.
//! Uses sync markers to allow recovery from framing desync.

use crc32fast::Hasher;

/// Magic sync marker at the start of each frame (chosen to be unlikely in H.264 data)
/// 0xCAFEBABE is a classic magic number, easy to spot in hex dumps
pub const SYNC_MARKER: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// Video frame message sent over QUIC
///
/// Each frame contains one or more H.264 NALUs with timing metadata.
/// Includes sequence number and CRC32 for integrity verification.
#[derive(Debug, Clone, PartialEq)]
pub struct VideoFrame {
    /// Monotonically increasing sequence number (for detecting framing desync)
    pub sequence: u32,
    /// Presentation timestamp (90kHz clock, matches RTP convention)
    pub pts: u64,
    /// Decode timestamp (optional, usually same as PTS for H.264)
    pub dts: Option<u64>,
    /// Whether this frame contains a keyframe (SPS/PPS/IDR)
    pub is_keyframe: bool,
    /// H.264 NALU data (may contain multiple NALUs with start codes)
    pub data: Vec<u8>,
}

impl VideoFrame {
    /// Create a new video frame
    pub fn new(sequence: u32, pts: u64, is_keyframe: bool, data: Vec<u8>) -> Self {
        Self {
            sequence,
            pts,
            dts: None,
            is_keyframe,
            data,
        }
    }

    /// Serialize the frame for QUIC transmission
    ///
    /// Wire format (v2 with integrity):
    /// - 4 bytes: sequence number (big-endian u32)
    /// - 4 bytes: CRC32 checksum of remaining header + data
    /// - 8 bytes: PTS (big-endian u64)
    /// - 8 bytes: DTS (big-endian u64, 0 if None)
    /// - 1 byte: flags (bit 0 = is_keyframe, bit 1 = has_dts)
    /// - 4 bytes: data length (big-endian u32)
    /// - N bytes: data
    pub fn encode(&self) -> Vec<u8> {
        let flags = (self.is_keyframe as u8) | ((self.dts.is_some() as u8) << 1);
        let dts = self.dts.unwrap_or(0);
        let data_len = self.data.len() as u32;

        // Build the payload that will be checksummed (everything after CRC field)
        let mut payload = Vec::with_capacity(21 + self.data.len());
        payload.extend_from_slice(&self.pts.to_be_bytes());
        payload.extend_from_slice(&dts.to_be_bytes());
        payload.push(flags);
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(&self.data);

        // Compute CRC32 of payload
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let crc = hasher.finalize();

        // Build final buffer: sequence + crc + payload
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&crc.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    /// Deserialize a frame from QUIC data
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        // Minimum: 4 (seq) + 4 (crc) + 8 (pts) + 8 (dts) + 1 (flags) + 4 (len) = 29 bytes
        if data.len() < 29 {
            return Err(DecodeError::TooShort);
        }

        let sequence = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let expected_crc = u32::from_be_bytes(data[4..8].try_into().unwrap());

        // Verify CRC32 of payload (everything after CRC field)
        let payload = &data[8..];
        let mut hasher = Hasher::new();
        hasher.update(payload);
        let actual_crc = hasher.finalize();

        if actual_crc != expected_crc {
            return Err(DecodeError::ChecksumMismatch {
                expected: expected_crc,
                actual: actual_crc,
                sequence,
            });
        }

        let pts = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let dts_raw = u64::from_be_bytes(data[16..24].try_into().unwrap());
        let flags = data[24];
        let data_len = u32::from_be_bytes(data[25..29].try_into().unwrap()) as usize;

        let is_keyframe = (flags & 1) != 0;
        let has_dts = (flags & 2) != 0;
        let dts = if has_dts { Some(dts_raw) } else { None };

        if data.len() < 29 + data_len {
            return Err(DecodeError::TooShort);
        }

        let frame_data = data[29..29 + data_len].to_vec();

        Ok(Self {
            sequence,
            pts,
            dts,
            is_keyframe,
            data: frame_data,
        })
    }

    /// Header size in bytes (fixed overhead per frame)
    pub const HEADER_SIZE: usize = 29;
}

/// Error decoding a video frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough data for header or payload
    TooShort,
    /// CRC32 checksum mismatch (data corruption detected)
    ChecksumMismatch {
        expected: u32,
        actual: u32,
        sequence: u32,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "insufficient data for video frame"),
            DecodeError::ChecksumMismatch {
                expected,
                actual,
                sequence,
            } => write!(
                f,
                "CRC32 mismatch on frame {}: expected 0x{:08X}, got 0x{:08X}",
                sequence, expected, actual
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Sequence tracker for detecting gaps in frame delivery
pub struct SequenceTracker {
    expected_next: Option<u32>,
    gaps_detected: u64,
    total_frames: u64,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self {
            expected_next: None,
            gaps_detected: 0,
            total_frames: 0,
        }
    }

    /// Check a frame's sequence number, returns gap size if any
    pub fn check(&mut self, sequence: u32) -> Option<u32> {
        self.total_frames += 1;

        let gap = if let Some(expected) = self.expected_next {
            if sequence != expected {
                let gap = sequence.wrapping_sub(expected);
                self.gaps_detected += 1;
                Some(gap)
            } else {
                None
            }
        } else {
            None
        };

        self.expected_next = Some(sequence.wrapping_add(1));
        gap
    }

    pub fn gaps_detected(&self) -> u64 {
        self.gaps_detected
    }

    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let frame = VideoFrame {
            sequence: 42,
            pts: 12345678,
            dts: Some(12345670),
            is_keyframe: true,
            data: vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e], // fake SPS
        };

        let encoded = frame.encode();
        let decoded = VideoFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.pts, frame.pts);
        assert_eq!(decoded.dts, frame.dts);
        assert_eq!(decoded.is_keyframe, frame.is_keyframe);
        assert_eq!(decoded.data, frame.data);
    }

    #[test]
    fn test_encode_decode_no_dts() {
        let frame = VideoFrame::new(1, 999, false, vec![1, 2, 3, 4]);

        let encoded = frame.encode();
        let decoded = VideoFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.pts, 999);
        assert_eq!(decoded.dts, None);
        assert!(!decoded.is_keyframe);
        assert_eq!(decoded.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_decode_too_short() {
        let result = VideoFrame::decode(&[0; 10]);
        assert!(matches!(result, Err(DecodeError::TooShort)));
    }

    #[test]
    fn test_crc_detects_corruption() {
        let frame = VideoFrame::new(1, 1000, true, vec![1, 2, 3, 4]);
        let mut encoded = frame.encode();

        // Corrupt a byte in the data portion
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let result = VideoFrame::decode(&encoded);
        assert!(matches!(result, Err(DecodeError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_sequence_tracker() {
        let mut tracker = SequenceTracker::new();

        // First frame establishes baseline
        assert!(tracker.check(0).is_none());

        // Sequential frames
        assert!(tracker.check(1).is_none());
        assert!(tracker.check(2).is_none());

        // Gap of 2 frames (3, 4 missing)
        let gap = tracker.check(5);
        assert_eq!(gap, Some(2));

        assert_eq!(tracker.gaps_detected(), 1);
    }
}
