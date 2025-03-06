use gstreamer::prelude::*;
use gstreamer_rtsp_server::prelude::*;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

struct StreamParams {
    width: u32,
    height: u32,
    framerate: u32,
    bitrate: u32,
}

impl Default for StreamParams {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            framerate: 30,
            bitrate: 2000,
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  resolution <width> <height>  - Set resolution (e.g., resolution 1920 1080)");
    println!("  bitrate <kbps>               - Set bitrate in kbps (e.g., bitrate 300)");
    println!("  fr <fps>                     - Set framerate (e.g., fr 20)");
    println!("  pattern <name>               - Set test pattern (smpte, snow, black, white, red, etc.)");
    println!("  status                       - Show current settings");
    println!("  help                         - Show this help");
    println!("  quit                         - Exit the server");
}

fn print_status(params: &StreamParams) {
    println!("Current settings:");
    println!("  Resolution: {}x{}", params.width, params.height);
    println!("  Framerate:  {} fps", params.framerate);
    println!("  Bitrate:    {} kbps", params.bitrate);
}

// Store references to pipeline elements for dynamic updates
struct PipelineElements {
    capsfilter: gstreamer::Element,
    encoder: gstreamer::Element,
    videosrc: gstreamer::Element,
}

fn main() {
    gstreamer::init().expect("Failed to initialize GStreamer");

    let server = gstreamer_rtsp_server::RTSPServer::new();
    server.set_service("8554");

    let mounts = server.mount_points().expect("Failed to get mount points");
    let params = Arc::new(Mutex::new(StreamParams::default()));
    let elements: Arc<Mutex<Vec<PipelineElements>>> = Arc::new(Mutex::new(Vec::new()));

    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();

    // Pipeline with named elements for dynamic control
    // videoscale and videorate allow dynamic resolution/framerate changes
    {
        let p = params.lock().unwrap();
        let launch = format!(
            "( videotestsrc name=src is-live=true pattern=smpte \
               ! videoscale \
               ! videorate \
               ! capsfilter name=caps caps=video/x-raw,width={},height={},framerate={}/1 \
               ! x264enc name=enc tune=zerolatency bitrate={} speed-preset=superfast \
               ! rtph264pay name=pay0 pt=96 )",
            p.width, p.height, p.framerate, p.bitrate
        );
        factory.set_launch(&launch);
    }
    factory.set_shared(true);

    // Connect to media-configure to get pipeline elements
    let elements_clone = Arc::clone(&elements);
    let params_clone = Arc::clone(&params);
    factory.connect_media_configure(move |_factory, media| {
        let element = media.element();
        let bin = element.downcast_ref::<gstreamer::Bin>().expect("Element is not a Bin");

        // Get named elements from pipeline
        let capsfilter = bin.by_name("caps").expect("No capsfilter found");
        let encoder = bin.by_name("enc").expect("No encoder found");
        let videosrc = bin.by_name("src").expect("No videosrc found");

        // Apply current params in case they changed before this client connected
        let p = params_clone.lock().unwrap();
        let caps = gstreamer::Caps::builder("video/x-raw")
            .field("width", p.width as i32)
            .field("height", p.height as i32)
            .field("framerate", gstreamer::Fraction::new(p.framerate as i32, 1))
            .build();
        capsfilter.set_property("caps", &caps);
        encoder.set_property("bitrate", p.bitrate);

        let pe = PipelineElements {
            capsfilter,
            encoder,
            videosrc,
        };

        elements_clone.lock().unwrap().push(pe);
    });

    mounts.add_factory("/test", factory);

    let _id = server.attach(None).expect("Failed to attach server");

    println!("RTSP server started");
    println!("Stream available at: rtsp://127.0.0.1:8554/test");
    println!();
    print_help();
    println!();

    let params_input = Arc::clone(&params);
    let elements_input = Arc::clone(&elements);

    // Input handling thread
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            print!("> ");
            stdout.flush().unwrap();

            let mut line = String::new();
            if stdin.lock().read_line(&mut line).unwrap() == 0 {
                break;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let mut params = params_input.lock().unwrap();
            let elements = elements_input.lock().unwrap();

            match parts[0].to_lowercase().as_str() {
                "resolution" | "res" => {
                    if parts.len() == 3 {
                        if let (Ok(w), Ok(h)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
                            params.width = w;
                            params.height = h;

                            let caps = gstreamer::Caps::builder("video/x-raw")
                                .field("width", w as i32)
                                .field("height", h as i32)
                                .field("framerate", gstreamer::Fraction::new(params.framerate as i32, 1))
                                .build();

                            for pe in elements.iter() {
                                pe.capsfilter.set_property("caps", &caps);
                            }
                            println!("Resolution set to {}x{} ({} active streams)", w, h, elements.len());
                        } else {
                            println!("Invalid resolution values");
                        }
                    } else {
                        println!("Usage: resolution <width> <height>");
                    }
                }
                "bitrate" | "br" => {
                    if parts.len() == 2 {
                        if let Ok(br) = parts[1].parse::<u32>() {
                            params.bitrate = br;
                            for pe in elements.iter() {
                                pe.encoder.set_property("bitrate", br);
                            }
                            println!("Bitrate set to {} kbps ({} active streams)", br, elements.len());
                        } else {
                            println!("Invalid bitrate value");
                        }
                    } else {
                        println!("Usage: bitrate <kbps>");
                    }
                }
                "fr" | "framerate" | "fps" => {
                    if parts.len() == 2 {
                        if let Ok(fr) = parts[1].parse::<u32>() {
                            params.framerate = fr;

                            let caps = gstreamer::Caps::builder("video/x-raw")
                                .field("width", params.width as i32)
                                .field("height", params.height as i32)
                                .field("framerate", gstreamer::Fraction::new(fr as i32, 1))
                                .build();

                            for pe in elements.iter() {
                                pe.capsfilter.set_property("caps", &caps);
                            }
                            println!("Framerate set to {} fps ({} active streams)", fr, elements.len());
                        } else {
                            println!("Invalid framerate value");
                        }
                    } else {
                        println!("Usage: fr <fps>");
                    }
                }
                "pattern" | "pat" => {
                    if parts.len() == 2 {
                        let pattern = match parts[1].to_lowercase().as_str() {
                            "smpte" => 0,
                            "snow" => 1,
                            "black" => 2,
                            "white" => 3,
                            "red" => 4,
                            "green" => 5,
                            "blue" => 6,
                            "checkers1" | "checkers-1" => 7,
                            "checkers2" | "checkers-2" => 8,
                            "checkers4" | "checkers-4" => 9,
                            "checkers8" | "checkers-8" => 10,
                            "circular" => 11,
                            "blink" => 12,
                            "smpte75" => 13,
                            "ball" => 18,
                            other => {
                                if let Ok(n) = other.parse::<i32>() {
                                    n
                                } else {
                                    println!("Unknown pattern: {}", other);
                                    println!("Try: smpte, snow, black, white, red, green, blue, ball, circular");
                                    continue;
                                }
                            }
                        };
                        for pe in elements.iter() {
                            pe.videosrc.set_property("pattern", pattern);
                        }
                        println!("Pattern set to {} ({} active streams)", parts[1], elements.len());
                    } else {
                        println!("Usage: pattern <name>");
                        println!("Patterns: smpte, snow, black, white, red, green, blue, ball, circular");
                    }
                }
                "status" | "s" => {
                    print_status(&params);
                    println!("  Active streams: {}", elements.len());
                }
                "help" | "h" | "?" => {
                    print_help();
                }
                "quit" | "exit" | "q" => {
                    println!("Shutting down...");
                    std::process::exit(0);
                }
                _ => {
                    println!("Unknown command: {}", parts[0]);
                    println!("Type 'help' for available commands");
                }
            }
        }
    });

    let main_loop = glib::MainLoop::new(None, false);
    main_loop.run();
}
