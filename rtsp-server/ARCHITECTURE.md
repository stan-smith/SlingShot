# Dynamic RTSP Server Architecture

This document explains the techniques used to create an RTSP server with runtime-configurable stream parameters that apply to connected clients without requiring reconnection.

## Overview

The server uses GStreamer's RTSP server library (`gstreamer-rtsp-server`) with a carefully designed pipeline that supports dynamic property changes. The key challenge is modifying stream parameters (resolution, framerate, bitrate) on active pipelines without breaking the stream.

## Pipeline Design

```
videotestsrc -> videoscale -> videorate -> capsfilter -> x264enc -> rtph264pay
     |              |             |            |            |
   pattern      scaling       frame         caps        bitrate
   (dynamic)    (dynamic)    dropping     (dynamic)    (dynamic)
```

### Why This Structure Works

1. **videotestsrc**: Generates raw video at its native rate. The `pattern` property can be changed at any time.

2. **videoscale**: Converts input resolution to output resolution. When downstream caps change, it automatically rescales.

3. **videorate**: Converts input framerate to output framerate by duplicating or dropping frames. Handles framerate changes dynamically.

4. **capsfilter**: Acts as the control point for resolution and framerate. Changing its `caps` property triggers renegotiation upstream through videoscale and videorate.

5. **x264enc**: H.264 encoder. The `bitrate` property can be changed at runtime (with `tune=zerolatency`).

6. **rtph264pay**: Packetizes H.264 for RTP transport. No dynamic configuration needed.

## Key Techniques

### 1. Named Elements in Launch String

Elements are given names so they can be retrieved later:

```rust
"( videotestsrc name=src is-live=true pattern=smpte \
   ! videoscale \
   ! videorate \
   ! capsfilter name=caps caps=video/x-raw,width=1280,height=720,framerate=30/1 \
   ! x264enc name=enc tune=zerolatency bitrate=2000 speed-preset=superfast \
   ! rtph264pay name=pay0 pt=96 )"
```

The `name=xxx` syntax allows retrieval via `bin.by_name("xxx")`.

### 2. Media Configure Signal

The `RTSPMediaFactory` emits a `media-configure` signal when a new client connects and a pipeline is created. This is the hook point to capture element references:

```rust
factory.connect_media_configure(move |_factory, media| {
    let element = media.element();
    let bin = element.downcast_ref::<gstreamer::Bin>()
        .expect("Element is not a Bin");

    // Retrieve named elements
    let capsfilter = bin.by_name("caps").expect("No capsfilter");
    let encoder = bin.by_name("enc").expect("No encoder");
    let videosrc = bin.by_name("src").expect("No videosrc");

    // Store references for later modification
    // ...
});
```

### 3. Dynamic Property Changes

#### Bitrate (Encoder Property)

The x264enc `bitrate` property can be changed at any time:

```rust
encoder.set_property("bitrate", new_bitrate_kbps);
```

This takes effect on subsequent frames. The encoder adjusts its output rate accordingly.

#### Resolution and Framerate (Caps Renegotiation)

Changing resolution or framerate requires caps renegotiation. The capsfilter's `caps` property defines the desired output format:

```rust
let caps = gstreamer::Caps::builder("video/x-raw")
    .field("width", new_width as i32)
    .field("height", new_height as i32)
    .field("framerate", gstreamer::Fraction::new(new_fps as i32, 1))
    .build();

capsfilter.set_property("caps", &caps);
```

When caps change:
1. The capsfilter requests new caps from upstream
2. videorate adjusts frame timing to match new framerate
3. videoscale rescales frames to match new resolution
4. The encoder receives frames in the new format and adapts

#### Test Pattern (Source Property)

The videotestsrc `pattern` property is an enum that can be changed at runtime:

```rust
videosrc.set_property("pattern", pattern_id);  // 0=smpte, 1=snow, 2=black, etc.
```

### 4. Shared Factory Mode

```rust
factory.set_shared(true);
```

This allows multiple clients to share the same pipeline instance. All clients receive the same stream, and parameter changes affect all viewers simultaneously.

Without shared mode, each client would get an independent pipeline, and you'd need to track and update each one separately.

### 5. Thread Safety with Arc<Mutex<>>

Element references must be shared between the GLib main loop (RTSP server) and the input handling thread:

```rust
let elements: Arc<Mutex<Vec<PipelineElements>>> = Arc::new(Mutex::new(Vec::new()));

// In media-configure callback (GLib thread)
elements_clone.lock().unwrap().push(pe);

// In input thread
let elements = elements_input.lock().unwrap();
for pe in elements.iter() {
    pe.encoder.set_property("bitrate", br);
}
```

## Limitations and Considerations

### Resolution Changes

- Large resolution changes may cause a brief visual glitch as the encoder adapts
- Some players may not handle mid-stream resolution changes gracefully
- The H.264 SPS/PPS (Sequence/Picture Parameter Sets) need to be updated

### Framerate Changes

- videorate handles this by duplicating or dropping frames
- Very large framerate changes (e.g., 60fps to 5fps) work but may look choppy during transition

### Bitrate Changes

- x264enc handles this smoothly with `tune=zerolatency`
- Without zerolatency, the encoder's lookahead buffer may delay changes

### Element Lifecycle

The current implementation doesn't handle client disconnections - element references accumulate in the vector. A production implementation should:
- Connect to media unprepare/teardown signals
- Remove stale element references
- Use weak references if needed

## GStreamer Concepts Used

| Concept | Purpose |
|---------|---------|
| RTSPServer | Handles RTSP protocol, client connections |
| RTSPMediaFactory | Creates pipelines for each mount point |
| RTSPMedia | Represents an active streaming session |
| Bin | Container for multiple elements (pipeline is a Bin) |
| Caps | Describes media format (resolution, framerate, codec) |
| Caps Negotiation | Process of agreeing on formats between elements |
| Properties | Element configuration (can be static or dynamic) |

## Dependencies

```toml
[dependencies]
gstreamer = "0.23"
gstreamer-rtsp-server = "0.23"
glib = "0.20"
```

System requirements:
- GStreamer 1.x development libraries
- gst-rtsp-server development libraries
- x264 encoder plugin (`gst-plugins-ugly` or `gst-plugins-bad`)

## References

- [GStreamer RTSP Server Documentation](https://gstreamer.freedesktop.org/documentation/gst-rtsp-server/)
- [gstreamer-rs Rust Bindings](https://gitlab.freedesktop.org/gstreamer/gstreamer-rs)
- [GStreamer Dynamic Pipelines](https://gstreamer.freedesktop.org/documentation/application-development/advanced/pipeline-manipulation.html)
