use serde::Deserialize;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LsblkError {
    #[error("Failed to execute lsblk: {0}")]
    ExecutionFailed(#[from] std::io::Error),
    #[error("lsblk returned non-zero exit code")]
    NonZeroExit,
    #[error("Failed to parse lsblk JSON: {0}")]
    ParseFailed(#[from] serde_json::Error),
    #[error("No suitable devices found")]
    NoDevices,
}

#[derive(Debug, Deserialize)]
pub struct LsblkOutput {
    pub blockdevices: Vec<BlockDevice>,
}

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
    #[serde(default)]
    pub fstype: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

impl BlockDevice {
    pub fn device_path(&self) -> String {
        format!("/dev/{}", self.name)
    }

    pub fn is_mounted(&self) -> bool {
        if let Some(mp) = &self.mountpoint {
            return !mp.is_empty();
        }
        if let Some(mps) = &self.mountpoints {
            return mps.iter().any(|mp| mp.is_some());
        }
        false
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
}

pub fn list_block_devices() -> Result<Vec<BlockDevice>, LsblkError> {
    let output = Command::new("lsblk")
        .args(["--json", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MOUNTPOINTS,MODEL,FSTYPE,LABEL"])
        .output()?;

    if !output.status.success() {
        return Err(LsblkError::NonZeroExit);
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let lsblk: LsblkOutput = serde_json::from_str(&json_str)?;

    if lsblk.blockdevices.is_empty() {
        return Err(LsblkError::NoDevices);
    }

    Ok(lsblk.blockdevices)
}

pub fn filter_selectable_devices(devices: &[BlockDevice]) -> Vec<SelectableDevice> {
    let mut selectable = Vec::new();

    for device in devices {
        if device.is_disk() {
            selectable.push(SelectableDevice {
                device: device.clone(),
                parent: None,
                indent_level: 0,
            });

            if let Some(children) = &device.children {
                for child in children {
                    if child.is_partition() {
                        selectable.push(SelectableDevice {
                            device: child.clone(),
                            parent: Some(device.name.clone()),
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
    pub parent: Option<String>,
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
            "{}{:<15} {:>4}   {:>10}   {:<24} {}",
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
        assert!(!lsblk.blockdevices[0].is_mounted());

        let children = lsblk.blockdevices[0].children.as_ref().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "sda1");
        assert!(children[0].is_partition());
        assert!(children[0].is_mounted());
    }
}
