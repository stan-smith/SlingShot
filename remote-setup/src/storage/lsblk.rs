//! Block device enumeration via lsblk.

use serde::Deserialize;
use std::io::{Error, ErrorKind};
use std::process::Command;

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

/// Block device information from lsblk.
#[derive(Debug, Deserialize, Clone)]
pub struct BlockDevice {
    pub name: String,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(rename = "type")]
    pub device_type: String,
    #[serde(default)]
    pub mountpoint: Option<String>,
    #[serde(default)]
    pub mountpoints: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub children: Option<Vec<BlockDevice>>,
}

impl BlockDevice {
    pub fn device_path(&self) -> String {
        format!("/dev/{}", self.name)
    }

    pub fn mount_point_str(&self) -> String {
        if let Some(mp) = &self.mountpoint {
            if !mp.is_empty() {
                return mp.clone();
            }
        }
        if let Some(mps) = &self.mountpoints {
            if let Some(m) = mps.iter().flatten().next() {
                return m.clone();
            }
        }
        "-".to_string()
    }

    pub fn size_str(&self) -> String {
        self.size.clone().unwrap_or_else(|| "-".to_string())
    }

    pub fn model_str(&self) -> String {
        self.model.clone().unwrap_or_else(|| "-".to_string())
    }

    pub fn is_disk(&self) -> bool {
        self.device_type == "disk"
    }

    pub fn is_partition(&self) -> bool {
        self.device_type == "part"
    }

    /// Check if this device or any of its children contain critical system mounts
    pub fn has_system_mount(&self) -> bool {
        let critical_mounts = ["/", "/boot", "/home", "/usr", "/var"];

        // Check this device
        let mp = self.mount_point_str();
        if critical_mounts.contains(&mp.as_str()) {
            return true;
        }

        // Check children
        if let Some(children) = &self.children {
            for child in children {
                let child_mp = child.mount_point_str();
                if critical_mounts.contains(&child_mp.as_str()) {
                    return true;
                }
            }
        }

        false
    }
}

/// List all block devices using lsblk
pub fn list_block_devices() -> Result<Vec<BlockDevice>, Error> {
    let output = Command::new("lsblk")
        .args([
            "--json",
            "-o",
            "NAME,SIZE,TYPE,MOUNTPOINT,MOUNTPOINTS,MODEL",
        ])
        .output()?;

    if !output.status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            "lsblk returned non-zero exit code",
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let lsblk: LsblkOutput = serde_json::from_str(&json_str)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse lsblk: {}", e)))?;

    if lsblk.blockdevices.is_empty() {
        return Err(Error::new(ErrorKind::NotFound, "No block devices found"));
    }

    Ok(lsblk.blockdevices)
}

/// Filter devices to those suitable for storage selection.
/// Excludes system disks with critical mounts.
pub fn filter_selectable_devices(devices: &[BlockDevice]) -> Vec<SelectableDevice> {
    let mut selectable = Vec::new();

    for device in devices {
        // Skip devices with system mounts
        if device.has_system_mount() {
            continue;
        }

        if device.is_disk() {
            selectable.push(SelectableDevice {
                device: device.clone(),
                indent_level: 0,
            });

            if let Some(children) = &device.children {
                for child in children {
                    if child.is_partition() {
                        selectable.push(SelectableDevice {
                            device: child.clone(),
                            indent_level: 1,
                        });
                    }
                }
            }
        }
    }

    selectable
}

#[derive(Debug, Clone)]
pub struct SelectableDevice {
    pub device: BlockDevice,
    pub indent_level: u8,
}

impl SelectableDevice {
    pub fn display_line(&self) -> String {
        let indent = if self.indent_level > 0 { "  " } else { "" };
        let name = &self.device.name;
        let dtype = &self.device.device_type;
        let size = self.device.size_str();
        let model = self.device.model_str();
        let mount = self.device.mount_point_str();

        format!(
            "{}{:<13} {:>4}   {:>10}   {:<24} {}",
            indent, name, dtype, size, model, mount
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsblk_json() {
        let json = r#"{
            "blockdevices": [
                {
                    "name": "sda",
                    "size": "500G",
                    "type": "disk",
                    "mountpoint": null,
                    "model": "Samsung SSD 860",
                    "children": [
                        {
                            "name": "sda1",
                            "size": "100G",
                            "type": "part",
                            "mountpoint": "/data",
                            "model": null
                        }
                    ]
                }
            ]
        }"#;

        let lsblk: LsblkOutput = serde_json::from_str(json).unwrap();
        assert_eq!(lsblk.blockdevices.len(), 1);
        assert_eq!(lsblk.blockdevices[0].name, "sda");
        assert!(lsblk.blockdevices[0].is_disk());
        assert_eq!(lsblk.blockdevices[0].mount_point_str(), "-");

        let children = lsblk.blockdevices[0].children.as_ref().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "sda1");
        assert!(children[0].is_partition());
        assert_eq!(children[0].mount_point_str(), "/data");
    }

    #[test]
    fn test_system_mount_detection() {
        let root_device = BlockDevice {
            name: "nvme0n1p1".to_string(),
            size: Some("500G".to_string()),
            device_type: "part".to_string(),
            mountpoint: Some("/".to_string()),
            mountpoints: None,
            model: None,
            children: None,
        };

        assert!(root_device.has_system_mount());

        let data_device = BlockDevice {
            name: "sdb1".to_string(),
            size: Some("1T".to_string()),
            device_type: "part".to_string(),
            mountpoint: Some("/data".to_string()),
            mountpoints: None,
            model: None,
            children: None,
        };

        assert!(!data_device.has_system_mount());
    }
}
