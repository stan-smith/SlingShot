//! ONVIF Server Library
//!
//! Presents connected remote nodes as virtual ONVIF cameras to VMS systems.
//! Translates ONVIF PTZ commands to an internal command protocol.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Handle to a connected remote node for sending commands
#[derive(Clone)]
pub struct NodeHandle {
    pub name: String,
    pub cmd_tx: mpsc::Sender<String>,
}

/// ONVIF server state
pub struct OnvifServerState {
    pub nodes: Arc<Mutex<HashMap<String, NodeHandle>>>,
    pub local_ip: String,
}

/// Start the ONVIF HTTP server
pub async fn run_onvif_server(
    addr: SocketAddr,
    nodes: Arc<Mutex<HashMap<String, NodeHandle>>>,
    local_ip: String,
) -> anyhow::Result<()> {
    let state = Arc::new(OnvifServerState { nodes, local_ip });

    let app = Router::new()
        // Per-node endpoints
        .route("/onvif/{node}/device_service", post(handle_device_service))
        .route("/onvif/{node}/media_service", post(handle_media_service))
        .route("/onvif/{node}/ptz_service", post(handle_ptz_service))
        // Generic discovery endpoint
        .route("/onvif/device_service", post(handle_discovery))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ONVIF server listening on port {}", addr.port());

    axum::serve(listener, app).await?;

    Ok(())
}

/// Handle discovery requests (list all nodes)
async fn handle_discovery(
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] Discovery: {}", action);

    let response = match action.as_str() {
        "GetServices" => {
            let nodes = state.nodes.lock().await;
            let mut services = String::new();

            for name in nodes.keys() {
                services.push_str(&format!(
                    r#"
      <tds:Service>
        <tds:Namespace>http://www.onvif.org/ver20/ptz/wsdl</tds:Namespace>
        <tds:XAddr>http://{}:8080/onvif/{}/ptz_service</tds:XAddr>
        <tds:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tds:Version>
      </tds:Service>"#,
                    state.local_ip, name
                ));
            }

            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tds:GetServicesResponse>{}</tds:GetServicesResponse>
  </s:Body>
</s:Envelope>"#,
                services
            )
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF Device Service requests for a specific node
async fn handle_device_service(
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] Device service for '{}': {}", node, action);

    // Check if node exists
    let nodes = state.nodes.lock().await;
    if !nodes.contains_key(&node) {
        return (
            StatusCode::NOT_FOUND,
            [("Content-Type", "application/soap+xml")],
            soap_fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
        );
    }
    drop(nodes);

    let response = match action.as_str() {
        "GetDeviceInformation" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>RTSP-Proxy</tds:Manufacturer>
      <tds:Model>Virtual-{}</tds:Model>
      <tds:FirmwareVersion>1.0.0</tds:FirmwareVersion>
      <tds:SerialNumber>{}</tds:SerialNumber>
      <tds:HardwareId>Central-Proxy</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>"#,
                node, node
            )
        }

        "GetCapabilities" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tds:GetCapabilitiesResponse>
      <tds:Capabilities>
        <tt:Media>
          <tt:XAddr>http://{}:8080/onvif/{}/media_service</tt:XAddr>
        </tt:Media>
        <tt:PTZ>
          <tt:XAddr>http://{}:8080/onvif/{}/ptz_service</tt:XAddr>
        </tt:PTZ>
      </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
  </s:Body>
</s:Envelope>"#,
                state.local_ip, node, state.local_ip, node
            )
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF Media Service requests for a specific node
async fn handle_media_service(
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] Media service for '{}': {}", node, action);

    // Check if node exists
    let nodes = state.nodes.lock().await;
    if !nodes.contains_key(&node) {
        return (
            StatusCode::NOT_FOUND,
            [("Content-Type", "application/soap+xml")],
            soap_fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
        );
    }
    drop(nodes);

    let response = match action.as_str() {
        "GetProfiles" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <trt:GetProfilesResponse>
      <trt:Profiles token="profile_{}" fixed="true">
        <tt:Name>{}</tt:Name>
        <tt:VideoSourceConfiguration token="vsrc_{}">
          <tt:Name>VideoSource</tt:Name>
        </tt:VideoSourceConfiguration>
        <tt:VideoEncoderConfiguration token="venc_{}">
          <tt:Name>H264</tt:Name>
          <tt:Encoding>H264</tt:Encoding>
        </tt:VideoEncoderConfiguration>
        <tt:PTZConfiguration token="ptz_{}">
          <tt:Name>PTZ</tt:Name>
        </tt:PTZConfiguration>
      </trt:Profiles>
    </trt:GetProfilesResponse>
  </s:Body>
</s:Envelope>"#,
                node, node, node, node, node
            )
        }

        "GetStreamUri" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>rtsp://{}:8554/{}/stream</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
  </s:Body>
</s:Envelope>"#,
                state.local_ip, node
            )
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF PTZ Service requests - translates to internal protocol
async fn handle_ptz_service(
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] PTZ service for '{}': {}", node, action);

    // Get node handle
    let nodes = state.nodes.lock().await;
    let node_handle = match nodes.get(&node) {
        Some(h) => h.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                [("Content-Type", "application/soap+xml")],
                soap_fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
            );
        }
    };
    drop(nodes);

    let response = match action.as_str() {
        "ContinuousMove" => {
            let (pan, tilt, zoom) = extract_velocity(&body);
            println!(
                "[ONVIF->{}] ContinuousMove: pan={}, tilt={}, zoom={}",
                node, pan, tilt, zoom
            );

            // Translate to our command format
            let cmd = format!("CMD|ptz {} {} {}", pan, tilt, zoom);
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    soap_fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:ContinuousMoveResponse/>
  </s:Body>
</s:Envelope>"#
                .to_string()
        }

        "Stop" => {
            println!("[ONVIF->{}] Stop", node);

            let cmd = "CMD|stop".to_string();
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    soap_fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:StopResponse/>
  </s:Body>
</s:Envelope>"#
                .to_string()
        }

        "AbsoluteMove" => {
            let (pan, tilt, zoom) = extract_position(&body);
            println!(
                "[ONVIF->{}] AbsoluteMove: pan={}, tilt={}, zoom={}",
                node, pan, tilt, zoom
            );

            let cmd = format!("CMD|goto {} {} {}", pan, tilt, zoom);
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    soap_fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:AbsoluteMoveResponse/>
  </s:Body>
</s:Envelope>"#
                .to_string()
        }

        "GotoHomePosition" => {
            println!("[ONVIF->{}] GotoHomePosition", node);

            let cmd = "CMD|home".to_string();
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    soap_fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:GotoHomePositionResponse/>
  </s:Body>
</s:Envelope>"#
                .to_string()
        }

        "GetStatus" => {
            // For status, we'd need to wait for response from remote
            // For now, return a default position
            // TODO: Implement request-response pattern for status queries
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tptz:GetStatusResponse>
      <tptz:PTZStatus>
        <tt:Position>
          <tt:PanTilt x="0.00" y="0.00"/>
          <tt:Zoom x="0.00"/>
        </tt:Position>
        <tt:MoveStatus>
          <tt:PanTilt>IDLE</tt:PanTilt>
          <tt:Zoom>IDLE</tt:Zoom>
        </tt:MoveStatus>
      </tptz:PTZStatus>
    </tptz:GetStatusResponse>
  </s:Body>
</s:Envelope>"#
                .to_string()
        }

        "GetConfigurations" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tptz:GetConfigurationsResponse>
      <tptz:PTZConfiguration token="ptz_{}">
        <tt:Name>PTZ Configuration</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:NodeToken>ptz_node_{}</tt:NodeToken>
        <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
        <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
      </tptz:PTZConfiguration>
    </tptz:GetConfigurationsResponse>
  </s:Body>
</s:Envelope>"#,
                node, node
            )
        }

        "GetNodes" => {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tptz:GetNodesResponse>
      <tptz:PTZNode token="ptz_node_{}">
        <tt:Name>{} PTZ</tt:Name>
        <tt:SupportedPTZSpaces>
          <tt:ContinuousPanTiltVelocitySpace>
            <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:URI>
            <tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange>
            <tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange>
          </tt:ContinuousPanTiltVelocitySpace>
          <tt:ContinuousZoomVelocitySpace>
            <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:URI>
            <tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange>
          </tt:ContinuousZoomVelocitySpace>
        </tt:SupportedPTZSpaces>
        <tt:HomeSupported>true</tt:HomeSupported>
      </tptz:PTZNode>
    </tptz:GetNodesResponse>
  </s:Body>
</s:Envelope>"#,
                node, node
            )
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

// ============================================================================
// Helper functions for SOAP/XML parsing
// ============================================================================

/// Extract SOAP action from ONVIF request body
pub fn extract_soap_action(xml: &str) -> String {
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref()).to_string();

                // Skip envelope and body tags
                if name != "Envelope" && name != "Body" && name != "Header" && name != "Security" {
                    return name;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    "Unknown".to_string()
}

/// Extract velocity (pan, tilt, zoom) from ONVIF ContinuousMove request
pub fn extract_velocity(xml: &str) -> (f32, f32, f32) {
    let mut pan = 0.0f32;
    let mut tilt = 0.0f32;
    let mut zoom = 0.0f32;

    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref());

                if name == "PanTilt" {
                    for attr in e.attributes().flatten() {
                        let key_local = attr.key.local_name();
                        let key = String::from_utf8_lossy(key_local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                pan = v.parse().unwrap_or(0.0);
                            }
                        } else if key == "y" {
                            if let Ok(v) = attr.unescape_value() {
                                tilt = v.parse().unwrap_or(0.0);
                            }
                        }
                    }
                } else if name == "Zoom" {
                    for attr in e.attributes().flatten() {
                        let key_local = attr.key.local_name();
                        let key = String::from_utf8_lossy(key_local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                zoom = v.parse().unwrap_or(0.0);
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    (pan, tilt, zoom)
}

/// Extract position from ONVIF AbsoluteMove request (same format as velocity)
pub fn extract_position(xml: &str) -> (f32, f32, f32) {
    extract_velocity(xml)
}

/// Generate SOAP fault response
pub fn soap_fault(code: &str, reason: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>{}</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en">{}</s:Text>
      </s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>"#,
        code, reason
    )
}

/// Get the local IP address by connecting to an external address
pub fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}
