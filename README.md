# Slingshot

Distributed RTSP streaming system with central control and remote edge nodes.

## Architecture

```
┌─────────────────────────────────────┐
│           Central Node              │
│  QUIC Control (5001)                │
│  RTSP Relay (8554)                  │
│  ONVIF Emulation (8080)             │
│  Admin Web UI (8081)                │
└──────────────┬──────────────────────┘
               │ QUIC (encrypted)
               ▼
┌─────────────────────────────────────┐
│          Remote Node(s)             │
│  RTSP Server (8554)                 │
│  ONVIF Client → IP Camera           │
└─────────────────────────────────────┘
```

## Prerequisites

- Rust 1.70+
- GStreamer 1.20+ with plugins: base, good, ugly, libav
- For ARM devices: cross-compilation toolchain

### Install GStreamer (Ubuntu/Debian)

```bash
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-ugly gstreamer1.0-libav
```

## Build

```bash
# Build all crates
cargo build --release

# Build specific binaries
cargo build --release -p rtsp-server --bin central
cargo build --release -p rtsp-server-remote
```

## Deploy

### Central Node

```bash
# Interactive mode
./target/release/central

# Headless mode (admin via web UI only)
./target/release/central --headless

# Custom admin port
./target/release/central --headless --admin-port 9000
```

**Ports:**
- 5001: QUIC control (remote nodes connect here)
- 8554: RTSP relay (view streams here)
- 8080: ONVIF emulation (for VMS integration)
- 8081: Admin web UI

### Remote Node

```bash
# Connect to central node
./target/release/rtsp-server-remote <node-name> <central-ip>:5001 <camera-ip> <user> <pass>

# Example
./target/release/rtsp-server-remote cam1 192.168.1.100:5001 192.168.1.50 admin password
```

### Approve Nodes

1. Open http://localhost:8081 in browser
2. When remote connects, you'll see: `[PENDING] cam1 (fingerprint) from ...`
3. Type: `approve cam1`

### View Streams

```bash
# Via central relay
ffplay rtsp://localhost:8554/cam1/stream

# Or use any RTSP client / VMS
```

## Crates

| Crate | Description |
|-------|-------------|
| `rtsp-server` | Central node binaries |
| `rtsp-server-remote` | Remote edge node |
| `quic-common` | Shared QUIC/TLS (Ed25519 only) |
| `quic-auth` | Device fingerprinting |
| `onvif-server` | ONVIF protocol for VMS |
| `onvif-client` | ONVIF camera control |
| `admin-web` | WebSocket admin interface |
| `storage-mount` | Storage device mounting |
| `storage-selector` | Storage device selection |
| `ffmpeg-recorder` | Video recording |

## Commands (via Admin UI)

```
# Node management
nodes                    - List connected nodes
pending                  - List pending approvals
approve <name>           - Approve node
reject <name>            - Reject node

# Stream control
<node> params            - Show stream parameters
<node> res <w> <h>       - Set resolution
<node> bitrate <kbps>    - Set bitrate
<node> fps <rate>        - Set framerate

# PTZ control
<node> left/right/up/down [speed] [ms]
<node> zoomin/zoomout [speed] [ms]
<node> home              - Go to home position
<node> stop              - Stop movement
```
