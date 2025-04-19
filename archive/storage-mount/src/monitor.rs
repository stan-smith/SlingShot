use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("Failed to create watcher: {0}")]
    WatcherFailed(#[from] notify::Error),
    #[error("Failed to watch path: {0}")]
    WatchFailed(String),
    #[error("UUID not found")]
    UuidNotFound,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageEvent {
    Available,
    Unavailable,
}

pub struct DeviceMonitor {
    uuid: String,
    rx: Receiver<StorageEvent>,
    _watcher: RecommendedWatcher,
}

impl DeviceMonitor {
    pub fn new(uuid: &str) -> Result<Self, MonitorError> {
        let uuid_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid));
        let uuid_string = uuid.to_string();

        let (tx, rx) = channel();

        // Check initial state
        let initial_available = uuid_path.exists();
        if initial_available {
            let _ = tx.send(StorageEvent::Available);
        }

        // Set up watcher on /dev/disk/by-uuid directory
        let watch_dir = Path::new("/dev/disk/by-uuid");
        let uuid_clone = uuid_string.clone();
        let tx_clone = tx.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let target_path = format!("/dev/disk/by-uuid/{}", uuid_clone);
                    let target = Path::new(&target_path);

                    for path in &event.paths {
                        if path.to_string_lossy().contains(&uuid_clone) {
                            match event.kind {
                                notify::EventKind::Create(_) => {
                                    let _ = tx_clone.send(StorageEvent::Available);
                                }
                                notify::EventKind::Remove(_) => {
                                    let _ = tx_clone.send(StorageEvent::Unavailable);
                                }
                                _ => {
                                    // Check if device exists now
                                    if target.exists() {
                                        let _ = tx_clone.send(StorageEvent::Available);
                                    } else {
                                        let _ = tx_clone.send(StorageEvent::Unavailable);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            },
            Config::default(),
        )?;

        watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;

        Ok(Self {
            uuid: uuid_string,
            rx,
            _watcher: watcher,
        })
    }

    pub fn recv(&self) -> Option<StorageEvent> {
        self.rx.recv().ok()
    }

    pub fn try_recv(&self) -> Option<StorageEvent> {
        self.rx.try_recv().ok()
    }

    pub fn is_available(&self) -> bool {
        let uuid_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", self.uuid));
        uuid_path.exists()
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }
}

pub fn watch_device(uuid: &str) -> Result<Receiver<StorageEvent>, MonitorError> {
    let (tx, rx) = channel();
    let uuid_string = uuid.to_string();

    thread::spawn(move || {
        let uuid_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid_string));

        // Send initial state
        if uuid_path.exists() {
            let _ = tx.send(StorageEvent::Available);
        } else {
            let _ = tx.send(StorageEvent::Unavailable);
        }

        // Watch for changes
        let (notify_tx, notify_rx) = channel();

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                let _ = notify_tx.send(res);
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(_) => return,
        };

        let watch_dir = Path::new("/dev/disk/by-uuid");
        if watcher.watch(watch_dir, RecursiveMode::NonRecursive).is_err() {
            return;
        }

        let mut last_state = uuid_path.exists();

        for event_result in notify_rx {
            if event_result.is_ok() {
                let current_state = uuid_path.exists();
                if current_state != last_state {
                    let event = if current_state {
                        StorageEvent::Available
                    } else {
                        StorageEvent::Unavailable
                    };
                    if tx.send(event).is_err() {
                        break;
                    }
                    last_state = current_state;
                }
            }
        }
    });

    Ok(rx)
}

pub fn check_device_available(uuid: &str) -> bool {
    let uuid_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid));
    uuid_path.exists()
}
