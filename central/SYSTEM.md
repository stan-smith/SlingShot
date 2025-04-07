# RTSP Stream Controller System

A distributed RTSP streaming system with central control, PTZ camera support, and dynamic stream parameter adjustment.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CENTRAL NODE                                    │
│                         (Your local machine)                                 │
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐        │
│  │   QUIC Server   │     │   RTSP Server   │     │  Command CLI    │        │
│  │   (port 5001)   │     │   (port 8554)   │     │                 │        │
│  └────────┬────────┘     └────────┬────────┘     └────────┬────────┘        │
│           │                       │                       │                  │
│           │  Accepts connections  │  Serves relayed       │  User input      │
│           │  from remote nodes    │  streams to clients   │  for commands    │
│           │                       │                       │                  │
└───────────┼───────────────────────┼───────────────────────┼──────────────────┘
            │                       │                       │
            │ QUIC (encrypted)      │ RTSP                  │
            │                       │                       │
            ▼                       ▼                       │
┌───────────────────────────────────────────────────────────┼──────────────────┐
│                           NETWORK                         │                  │
└───────────────────────────────────────────────────────────┼──────────────────┘
            │                       ▲                       │
            │                       │                       │
            ▼                       │                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              REMOTE NODE                                     │
│                      (ARM device, e.g., Khadas)                              │
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐        │
│  │   QUIC Client   │     │   RTSP Server   │     │  ONVIF Client   │        │
│  │                 │     │   (port 8554)   │     │                 │        │
│  └────────┬────────┘     └────────┬────────┘     └────────┬────────┘        │
│           │                       │                       │                  │
│           │  Connects to central  │  Relays camera        │  Controls PTZ    │
│           │  for auth & commands  │  stream               │  via SOAP/HTTP   │
│           │                       │                       │                  │
└───────────┼───────────────────────┼───────────────────────┼──────────────────┘
            │                       │                       │
            │                       │                       │ ONVIF (HTTP)
            │                       │                       │
            │                       │                       ▼
            │                       │              ┌─────────────────┐
            │                       │              │   ONVIF Camera  │
            │                       │              │   (IP Camera)   │
            │                       └──────────────┤   RTSP Stream   │
            │                          pulls from  └─────────────────┘
            │
            │
            ▼
    Central pulls RTSP from
    Remote's relay server
```

## Component Details

### 1. Central Node (`src/bin/central.rs`)

The central node is the control hub that:
- Accepts QUIC connections from remote nodes
- Authenticates remote nodes via fingerprint verification
- Relays RTSP streams from remote nodes to local clients
- Sends commands to remote nodes for PTZ and stream control

#### QUIC Server Setup

```rust
// Generate self-signed certificate for QUIC
let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec![
    "localhost".to_string(),
    "0.0.0.0".to_string(),
])?;

// Configure transport with keepalive to prevent timeout
let mut transport_config = quinn::TransportConfig::default();
transport_config.max_idle_timeout(None);  // Disable idle timeout
transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
```

The QUIC server listens on port 5001 and uses self-signed certificates. Key configuration:
- **No idle timeout**: Connections stay open indefinitely
- **5-second keepalive**: Prevents NAT/firewall from dropping the connection
- **100 concurrent streams**: Allows many simultaneous command/response exchanges

#### Authentication Flow

```
Remote Node                          Central Node
    │                                     │
    │──── AUTH|name|fingerprint|url ────▶│
    │                                     │
    │                            [User prompted to approve]
    │                                     │
    │◀─── APPROVED|Welcome, name! ────────│
    │                                     │
    │──── CONFIRM|name|Ready ───────────▶│
    │                                     │
    │         [Connection established]    │
```

The fingerprint is derived from an Ed25519 public key, providing a unique identifier for each remote node.

#### RTSP Relay Factory

When a remote node connects, the central creates an RTSP relay:

```rust
fn create_relay_factory(
    mounts: &RTSPMountPoints,
    mount_path: &str,      // e.g., "/khadas/stream"
    source_rtsp_url: &str, // Remote's RTSP URL
) -> Result<()> {
    let factory = RTSPMediaFactory::new();

    // Pipeline: pull from remote, parse H.264, repacketize
    let pipeline = format!(
        "( rtspsrc location={} latency=100 \
           ! rtph264depay \
           ! h264parse \
           ! rtph264pay name=pay0 pt=96 )",
        source_rtsp_url
    );

    factory.set_launch(&pipeline);
    factory.set_shared(true);  // Multiple clients can connect
    mounts.add_factory(mount_path, factory);
}
```

This creates a passthrough relay - minimal processing, just repacketizing the H.264 stream.

### 2. Remote Node (`src/main.rs`)

The remote node runs on edge devices and:
- Connects to ONVIF cameras
- Serves the camera stream via RTSP
- Connects to central for control
- Executes PTZ and stream commands

#### ONVIF Camera Connection

```rust
// Create ONVIF client
let onvif = OnvifClient::new(&camera.host, &camera.user, &camera.pass);

// Fetch available profiles
let profiles = onvif.get_profiles()?;

// Let user select if multiple profiles exist
if profiles.len() > 1 {
    println!("Available profiles:");
    for (i, profile) in profiles.iter().enumerate() {
        println!("  [{}] {}", i + 1, profile);
    }
    // User selects...
}

// Get RTSP URL for selected profile
let camera_rtsp_url = onvif.get_stream_uri_for_profile(&selected_token)?;
```

#### Dynamic Pipeline

The remote node uses a dynamic pipeline that allows runtime parameter changes:

```rust
let pipeline = format!(
    "( rtspsrc location=\"{}\" latency=100 \
       ! rtph264depay \
       ! avdec_h264 \
       ! videoconvert \
       ! videoscale \
       ! videorate \
       ! capsfilter name=caps caps=video/x-raw,width={},height={},framerate={}/1 \
       ! x264enc name=encoder bitrate={} tune=zerolatency speed-preset=ultrafast \
       ! rtph264pay name=pay0 pt=96 )",
    camera_rtsp_url, width, height, framerate, bitrate
);
```

**Pipeline breakdown:**

| Element | Purpose |
|---------|---------|
| `rtspsrc` | Pulls RTSP stream from camera |
| `rtph264depay` | Removes RTP packaging from H.264 |
| `avdec_h264` | Decodes H.264 to raw video |
| `videoconvert` | Converts pixel formats if needed |
| `videoscale` | Scales video to target resolution |
| `videorate` | Adjusts framerate |
| `capsfilter` | Enforces output format (resolution, fps) |
| `x264enc` | Re-encodes to H.264 with specified bitrate |
| `rtph264pay` | Packages H.264 into RTP for RTSP |

#### Element Capture for Dynamic Control

```rust
// Capture element references when media is configured
factory.connect_media_configure(move |_factory, media| {
    let element = media.element();
    if let Some(bin) = element.downcast_ref::<gstreamer::Bin>() {
        let mut state = pipeline_state.lock().unwrap();
        state.capsfilter = bin.by_name("caps");
        state.encoder = bin.by_name("encoder");
    }
});
```

The `media-configure` signal fires when a client connects and the pipeline is created. We capture references to:
- **capsfilter**: For resolution and framerate changes
- **encoder**: For bitrate changes

#### Runtime Parameter Changes

**Resolution change:**
```rust
let new_caps = gstreamer::Caps::builder("video/x-raw")
    .field("width", width)
    .field("height", height)
    .field("framerate", gstreamer::Fraction::new(framerate, 1))
    .build();
capsfilter.set_property("caps", &new_caps);
```

**Bitrate change:**
```rust
encoder.set_property("bitrate", bitrate);
```

These changes take effect immediately without disconnecting clients.

### 3. ONVIF Client (`src/onvif.rs`)

The ONVIF client communicates with IP cameras using SOAP over HTTP with Digest authentication.

#### Digest Authentication Flow

```
Client                                    Camera
   │                                        │
   │──── POST /onvif/services ─────────────▶│
   │     (no auth)                          │
   │                                        │
   │◀─── 401 Unauthorized ──────────────────│
   │     WWW-Authenticate: Digest           │
   │       realm="...", nonce="...", qop=...│
   │                                        │
   │──── POST /onvif/services ─────────────▶│
   │     Authorization: Digest              │
   │       username="...", response="...",  │
   │       nonce="...", cnonce="..."        │
   │                                        │
   │◀─── 200 OK (SOAP Response) ────────────│
```

```rust
fn soap_request(&self, url: &str, body: &str) -> Result<String> {
    // First request - expect 401
    let resp = self.client.post(url)
        .header(CONTENT_TYPE, "application/soap+xml")
        .body(body.to_string())
        .send()?;

    if resp.status().is_success() {
        return Ok(resp.text()?);
    }

    // Extract WWW-Authenticate header
    let www_auth = resp.headers().get(WWW_AUTHENTICATE)?;

    // Compute digest response
    let context = AuthContext::new_post(&self.user, &self.pass, uri_path, Some(body));
    let mut prompt = digest_auth::parse(www_auth)?;
    let auth_header = prompt.respond(&context)?.to_header_string();

    // Retry with authentication
    let resp = self.client.post(url)
        .header("Authorization", auth_header)
        .body(body.to_string())
        .send()?;

    Ok(resp.text()?)
}
```

#### SOAP Message Structure

**GetDeviceInformation:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

**GetStreamUri:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
      <StreamSetup>
        <Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
        <Transport xmlns="http://www.onvif.org/ver10/schema">
          <Protocol>RTSP</Protocol>
        </Transport>
      </StreamSetup>
      <ProfileToken>profile_1_h264</ProfileToken>
    </GetStreamUri>
  </s:Body>
</s:Envelope>
```

**PTZ ContinuousMove:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>profile_1_h264</ProfileToken>
      <Velocity>
        <PanTilt xmlns="http://www.onvif.org/ver10/schema" x="0.5" y="0.0"/>
        <Zoom xmlns="http://www.onvif.org/ver10/schema" x="0.0"/>
      </Velocity>
    </ContinuousMove>
  </s:Body>
</s:Envelope>
```

#### XML Parsing

Response parsing uses `quick-xml` with streaming events:

```rust
fn extract_profiles(xml: &str) -> Vec<MediaProfile> {
    let mut profiles = Vec::new();
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref());

                if name == "Profiles" {
                    // Extract token attribute
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.local_name().as_ref());
                        if key == "token" {
                            current_token = Some(attr.unescape_value()?.to_string());
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if in_name {
                    current_name = Some(e.unescape()?.to_string());
                }
            }
            Ok(Event::End(e)) => {
                if name == "Profiles" {
                    profiles.push(MediaProfile { token, name });
                }
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
    }
    profiles
}
```

### 4. Command Protocol

Commands flow from central to remote via QUIC unidirectional streams:

```
Central                                   Remote
   │                                        │
   │──── CMD|left 0.5 500 ─────────────────▶│
   │                                        │
   │                               [Execute PTZ move]
   │                                        │
   │◀─── RESULT|ok|Panned left... ──────────│
```

#### Message Types

| Prefix | Direction | Purpose |
|--------|-----------|---------|
| `AUTH\|` | Remote→Central | Authentication request |
| `APPROVED\|` | Central→Remote | Authentication approved |
| `DENIED\|` | Central→Remote | Authentication denied |
| `CONFIRM\|` | Remote→Central | Connection confirmed |
| `CMD\|` | Central→Remote | Command to execute |
| `RESULT\|` | Remote→Central | Command result |
| `STATUS\|` | Remote→Central | Status update |

#### Available Commands

**Stream Control:**
| Command | Description | Example |
|---------|-------------|---------|
| `res <w> <h>` | Set resolution | `res 1280 720` |
| `bitrate <kbps>` | Set bitrate | `bitrate 2000` |
| `fps <rate>` | Set framerate | `fps 15` |
| `params` | Show current params | `params` |

**PTZ Control:**
| Command | Description | Example |
|---------|-------------|---------|
| `left [speed] [ms]` | Pan left | `left 0.5 500` |
| `right [speed] [ms]` | Pan right | `right 0.5 500` |
| `up [speed] [ms]` | Tilt up | `up 0.5 500` |
| `down [speed] [ms]` | Tilt down | `down 0.5 500` |
| `zoomin [speed] [ms]` | Zoom in | `zi 0.3 1000` |
| `zoomout [speed] [ms]` | Zoom out | `zo 0.3 1000` |
| `ptz <p> <t> [z] [ms]` | Custom move | `ptz 0.5 -0.3 0 500` |
| `goto <p> <t> <z>` | Absolute position | `goto 0 0 0.5` |
| `home` | Return to home | `home` |
| `stop` | Stop movement | `stop` |
| `status` | Get position | `status` |
| `info` | Camera info | `info` |

### 5. GStreamer Pipeline Techniques

#### Why Decode and Re-encode?

The dynamic pipeline decodes and re-encodes because:
1. **Resolution scaling** requires decoded frames
2. **Framerate adjustment** needs raw video
3. **Bitrate control** happens at encoding

A passthrough pipeline (central's relay) cannot change these parameters.

#### Shared Media Factory

```rust
factory.set_shared(true);
```

This allows multiple clients to connect to the same stream. Without this, each client would create a new pipeline and pull separately from the camera.

#### Low-Latency Encoding

```rust
x264enc ... tune=zerolatency speed-preset=ultrafast
```

- **tune=zerolatency**: Disables features that add latency (B-frames, lookahead)
- **speed-preset=ultrafast**: Fastest encoding, lower quality but minimal CPU usage

### 6. Security Considerations

#### Current Implementation

- **QUIC encryption**: All control traffic is encrypted
- **Self-signed certificates**: No CA verification (development mode)
- **Fingerprint verification**: Manual approval based on Ed25519 public key
- **RTSP credentials**: Embedded in URL (passed to GStreamer)

#### Production Recommendations

1. **Certificate management**: Use proper CA-signed certificates
2. **Fingerprint storage**: Save approved fingerprints to disk
3. **RTSP authentication**: Configure GStreamer with proper auth
4. **Network isolation**: Keep camera network separate from control network

### 7. Deployment

#### Central Node

```bash
cd rtsp-server
cargo build --release
./target/release/central
```

#### Remote Node

```bash
# On ARM device
cd rtsp-server-remote
cargo build --release
./target/release/rtsp-server-remote \
    khadas \                    # Node name
    192.168.1.100:5001 \       # Central address
    192.168.2.90 \             # Camera IP
    admin \                     # Camera username
    password                    # Camera password
```

#### Viewing Streams

```bash
# From central's relay (recommended)
ffplay rtsp://127.0.0.1:8554/khadas/stream

# Direct from remote (if accessible)
ffplay rtsp://192.168.1.50:8554/stream
```

### 8. Troubleshooting

#### QUIC Connection Timeout

**Symptom:** "Disconnected from central: timed out"

**Solution:** Ensure both sides have keepalive configured:
```rust
transport_config.max_idle_timeout(None);
transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
```

#### Pipeline Not Ready

**Symptom:** "Pipeline not ready (no clients connected?)"

**Cause:** Element references are captured when a client connects. Without clients, the pipeline doesn't exist.

**Solution:** Connect a viewer before sending stream control commands.

#### ONVIF Authentication Failed

**Symptom:** "No WWW-Authenticate header"

**Cause:** Camera may not require auth, or URL is wrong.

**Solution:** Verify camera URL and check if auth is actually required.

#### No Profiles Found

**Symptom:** "No profiles found, using default"

**Cause:** GetProfiles response parsing failed or camera uses non-standard format.

**Solution:** Check XML response format, may need to adjust parsing for specific camera vendor.

## Dependencies

### Central Node
- `gstreamer`, `gstreamer-rtsp-server`: RTSP server functionality
- `quinn`: QUIC implementation
- `rustls`: TLS for QUIC
- `rcgen`: Certificate generation
- `ed25519-dalek`: Fingerprint generation
- `tokio`: Async runtime

### Remote Node
All of the above, plus:
- `reqwest`: HTTP client for ONVIF
- `digest_auth`: HTTP Digest authentication
- `quick-xml`: XML parsing for SOAP

## Future Enhancements

1. **Hardware encoding**: Use VA-API or NVENC on capable devices
2. **Recording**: Add DVR functionality to central
3. **Motion detection**: Trigger events on movement
4. **Web interface**: Browser-based control panel
5. **Multi-camera switching**: Combine streams from multiple remotes
6. **Audio support**: Add audio track handling
