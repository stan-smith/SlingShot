use crate::config::RecorderConfig;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// FFmpeg-based RTSP recorder
pub struct Recorder {
    config: RecorderConfig,
    ffmpeg_process: Option<Child>,
    restart_count: u32,
    stopped: bool,
}

impl Recorder {
    /// Create a new recorder with the given configuration
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            config,
            ffmpeg_process: None,
            restart_count: 0,
            stopped: false,
        }
    }

    /// Start recording (spawns ffmpeg in background)
    pub fn start(&mut self) -> Result<(), RecorderError> {
        if self.ffmpeg_process.is_some() {
            return Ok(()); // Already running
        }

        self.stopped = false;

        // Ensure output directory exists
        std::fs::create_dir_all(&self.config.output_dir)
            .map_err(RecorderError::Io)?;

        // Build ffmpeg command
        let child = Command::new("ffmpeg")
            // Input options
            .arg("-rtsp_transport")
            .arg("tcp")
            .arg("-i")
            .arg(&self.config.rtsp_url)
            // Output options - copy without re-encoding
            .arg("-c")
            .arg("copy")
            // Segmentation
            .arg("-f")
            .arg("segment")
            .arg("-segment_time")
            .arg(self.config.segment_duration.to_string())
            .arg("-segment_format")
            .arg(&self.config.file_format)
            .arg("-strftime")
            .arg("1")
            .arg("-reset_timestamps")
            .arg("1")
            // Output pattern
            .arg(self.config.output_pattern())
            // Suppress interactive prompts and reduce output
            .arg("-y")
            .arg("-loglevel")
            .arg("warning")
            // Redirect stderr to null to avoid blocking
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    RecorderError::FfmpegNotFound
                } else {
                    RecorderError::Io(e)
                }
            })?;

        self.ffmpeg_process = Some(child);
        self.restart_count = 0;

        Ok(())
    }

    /// Stop recording (kills ffmpeg process)
    pub fn stop(&mut self) -> Result<(), RecorderError> {
        self.stopped = true;

        if let Some(mut child) = self.ffmpeg_process.take() {
            // Send SIGTERM for graceful shutdown
            #[cfg(unix)]
            {
                unsafe {
                    nix::libc::kill(child.id() as i32, nix::libc::SIGTERM);
                }
            }

            // Wait a bit for graceful shutdown
            std::thread::sleep(Duration::from_millis(500));

            // Force kill if still running
            match child.try_wait() {
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Ok(Some(_)) => {}
                Err(e) => return Err(RecorderError::Io(e)),
            }
        }

        Ok(())
    }

    /// Check if recording is currently active
    pub fn is_recording(&mut self) -> bool {
        if let Some(ref mut child) = self.ffmpeg_process {
            match child.try_wait() {
                Ok(None) => true, // Still running
                Ok(Some(_)) => {
                    self.ffmpeg_process = None;
                    false
                }
                Err(_) => {
                    self.ffmpeg_process = None;
                    false
                }
            }
        } else {
            false
        }
    }

    /// Monitor ffmpeg and restart if it crashed
    /// Returns true if a restart occurred
    pub fn check_and_restart(&mut self) -> Result<bool, RecorderError> {
        if self.stopped {
            return Ok(false); // Don't restart if intentionally stopped
        }

        if let Some(ref mut child) = self.ffmpeg_process {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited
                    eprintln!("ffmpeg exited with status: {}", status);

                    // Capture stderr if available
                    if let Some(stderr) = child.stderr.take() {
                        use std::io::Read;
                        let mut buf = Vec::new();
                        if let Ok(mut stderr) = std::io::BufReader::new(stderr).take(4096).bytes().collect::<Result<Vec<_>, _>>() {
                            buf.append(&mut stderr);
                        }
                        if !buf.is_empty() {
                            let msg = String::from_utf8_lossy(&buf);
                            eprintln!("ffmpeg stderr: {}", msg);
                        }
                    }

                    self.ffmpeg_process = None;

                    // Exponential backoff: 1s, 2s, 4s, 8s, max 60s
                    let delay_secs = std::cmp::min(60, 1u64 << self.restart_count);
                    eprintln!("Restarting ffmpeg in {}s (attempt {})", delay_secs, self.restart_count + 1);
                    std::thread::sleep(Duration::from_secs(delay_secs));

                    self.restart_count += 1;
                    self.start()?;
                    return Ok(true);
                }
                Ok(None) => {
                    // Still running, reset restart count after sustained success
                    if self.restart_count > 0 {
                        self.restart_count = 0;
                    }
                }
                Err(e) => return Err(RecorderError::Io(e)),
            }
        } else if !self.stopped {
            // Not running and not intentionally stopped - restart
            self.start()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Get the current restart count
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Get a reference to the config
    pub fn config(&self) -> &RecorderConfig {
        &self.config
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    #[error("ffmpeg not found - is it installed?")]
    FfmpegNotFound,
    #[error("ffmpeg failed: {0}")]
    FfmpegFailed(String),
    #[error("Disk full")]
    DiskFull,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
