use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub device: String,
    pub uuid: String,
    pub mountpoint: PathBuf,
}

impl StorageConfig {
    pub fn new(device: String, uuid: String, mountpoint: PathBuf) -> Self {
        Self {
            device,
            uuid,
            mountpoint,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            device: String::new(),
            uuid: String::new(),
            mountpoint: PathBuf::from("/media/recordings"),
        }
    }
}
