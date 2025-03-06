use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FstabError {
    #[error("Failed to read fstab: {0}")]
    ReadFailed(#[from] std::io::Error),
    #[error("Failed to write fstab: {0}")]
    WriteFailed(String),
    #[error("Entry already exists for UUID {0}")]
    EntryExists(String),
}

const FSTAB_PATH: &str = "/etc/fstab";

#[derive(Debug, Clone)]
pub struct FstabEntry {
    pub uuid: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: String,
    pub dump: u8,
    pub pass: u8,
}

impl FstabEntry {
    pub fn new(uuid: &str, mountpoint: &str) -> Self {
        Self {
            uuid: uuid.to_string(),
            mountpoint: mountpoint.to_string(),
            fstype: "ext4".to_string(),
            options: "defaults,nofail".to_string(),
            dump: 0,
            pass: 2,
        }
    }

    pub fn to_line(&self) -> String {
        format!(
            "UUID={}  {}  {}  {}  {}  {}",
            self.uuid, self.mountpoint, self.fstype, self.options, self.dump, self.pass
        )
    }
}

pub fn entry_exists(uuid: &str) -> Result<bool, FstabError> {
    let content = std::fs::read_to_string(FSTAB_PATH)?;
    let search = format!("UUID={}", uuid);
    Ok(content.contains(&search))
}

pub fn add_entry(entry: &FstabEntry, dry_run: bool) -> Result<(), FstabError> {
    let line = entry.to_line();

    if dry_run {
        println!("[DRY-RUN] Would add to {}:", FSTAB_PATH);
        println!("  {}", line);
        return Ok(());
    }

    // Check if entry already exists
    if entry_exists(&entry.uuid)? {
        return Err(FstabError::EntryExists(entry.uuid.clone()));
    }

    // Read existing content
    let mut content = std::fs::read_to_string(FSTAB_PATH)?;

    // Add newline if needed
    if !content.ends_with('\n') {
        content.push('\n');
    }

    // Add comment and entry
    content.push_str(&format!(
        "\n# Storage for recordings (added by storage-mount)\n{}\n",
        line
    ));

    std::fs::write(FSTAB_PATH, content).map_err(|e| FstabError::WriteFailed(e.to_string()))
}

pub fn remove_entry(uuid: &str, dry_run: bool) -> Result<bool, FstabError> {
    if dry_run {
        println!("[DRY-RUN] Would remove UUID={} from {}", uuid, FSTAB_PATH);
        return Ok(true);
    }

    let content = std::fs::read_to_string(FSTAB_PATH)?;
    let search = format!("UUID={}", uuid);

    if !content.contains(&search) {
        return Ok(false);
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<&str> = Vec::new();
    let mut skip_next_comment = false;

    for line in &lines {
        if line.contains("# Storage for recordings") {
            skip_next_comment = true;
            continue;
        }
        if skip_next_comment && line.contains(&search) {
            skip_next_comment = false;
            continue;
        }
        if line.contains(&search) {
            continue;
        }
        skip_next_comment = false;
        new_lines.push(line);
    }

    let new_content = new_lines.join("\n") + "\n";
    std::fs::write(FSTAB_PATH, new_content).map_err(|e| FstabError::WriteFailed(e.to_string()))?;

    Ok(true)
}

pub fn get_fstab_path() -> &'static Path {
    Path::new(FSTAB_PATH)
}
