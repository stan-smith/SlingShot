use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::obfuscate;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceConfig {
    Rtsp(RtspConfig),
    Onvif(OnvifConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtspConfig {
    /// Base64-encoded RTSP URL (may contain credentials)
    pub url_b64: String,
}

impl RtspConfig {
    /// Create from plain URL (will be base64 encoded)
    pub fn new(url: &str) -> Self {
        Self {
            url_b64: obfuscate::encode(url),
        }
    }

    /// Get decoded URL
    pub fn url(&self) -> Result<String, ConfigError> {
        obfuscate::decode(&self.url_b64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnvifConfig {
    pub ip: String,
    pub username: String,
    /// Base64-encoded password
    pub password_b64: String,
    /// Selected profile token (optional - if None, will be prompted at runtime)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_token: Option<String>,
}

impl OnvifConfig {
    /// Create new with plain password (will be base64 encoded)
    pub fn new(ip: String, username: String, password: &str) -> Self {
        Self {
            ip,
            username,
            password_b64: obfuscate::encode(password),
            profile_token: None,
        }
    }

    /// Create new with profile token
    pub fn with_profile(ip: String, username: String, password: &str, profile_token: String) -> Self {
        Self {
            ip,
            username,
            password_b64: obfuscate::encode(password),
            profile_token: Some(profile_token),
        }
    }

    /// Get decoded password
    pub fn password(&self) -> Result<String, ConfigError> {
        obfuscate::decode(&self.password_b64)
    }
}
