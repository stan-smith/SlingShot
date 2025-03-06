//! ONVIF Client Library
//!
//! Provides ONVIF camera control via SOAP/HTTP with Digest authentication.
//! Supports device info, stream URIs, and PTZ commands.

use anyhow::{Context, Result};
use digest_auth::AuthContext;
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, WWW_AUTHENTICATE};

/// ONVIF camera client
pub struct OnvifClient {
    client: Client,
    host: String,
    user: String,
    pass: String,
    profile: String,
}

impl OnvifClient {
    pub fn new(host: &str, user: &str, pass: &str) -> Self {
        Self {
            client: Client::new(),
            host: host.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            profile: "profile_1_h264".to_string(),
        }
    }

    pub fn set_profile(&mut self, profile: &str) {
        self.profile = profile.to_string();
    }

    fn device_url(&self) -> String {
        format!("http://{}/onvif/device_service", self.host)
    }

    fn services_url(&self) -> String {
        format!("http://{}/onvif/services", self.host)
    }

    /// Send SOAP request with digest authentication
    fn soap_request(&self, url: &str, body: &str) -> Result<String> {
        // First request to get WWW-Authenticate header
        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .body(body.to_string())
            .send()
            .context("Failed to send initial request")?;

        if resp.status().is_success() {
            return Ok(resp.text()?);
        }

        // Get the WWW-Authenticate header for digest auth
        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("No WWW-Authenticate header")?
            .to_str()?;

        // Parse and compute digest response
        let uri_path = url
            .find("://")
            .and_then(|i| url[i + 3..].find('/'))
            .map(|i| &url[url.find("://").unwrap() + 3 + i..])
            .unwrap_or("/");
        let context = AuthContext::new_post(
            &self.user,
            &self.pass,
            uri_path,
            Some(body.as_bytes().to_vec()),
        );
        let mut prompt = digest_auth::parse(www_auth)?;
        let auth_header = prompt.respond(&context)?.to_header_string();

        // Retry with authentication
        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .header("Authorization", auth_header)
            .body(body.to_string())
            .send()
            .context("Failed to send authenticated request")?;

        if !resp.status().is_success() {
            anyhow::bail!("Request failed with status: {}", resp.status());
        }

        Ok(resp.text()?)
    }

    /// Get device information (manufacturer, model, firmware)
    pub fn get_device_info(&self) -> Result<DeviceInfo> {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"#;

        let response = self.soap_request(&self.device_url(), body)?;

        Ok(DeviceInfo {
            manufacturer: extract_xml_value(&response, "Manufacturer").unwrap_or_default(),
            model: extract_xml_value(&response, "Model").unwrap_or_default(),
            firmware: extract_xml_value(&response, "FirmwareVersion").unwrap_or_default(),
        })
    }

    /// Get available media profiles
    pub fn get_profiles(&self) -> Result<Vec<MediaProfile>> {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
  </s:Body>
</s:Envelope>"#;

        let response = self.soap_request(&self.services_url(), body)?;
        Ok(extract_profiles(&response))
    }

    /// Get RTSP stream URI for a specific profile
    pub fn get_stream_uri_for_profile(&self, profile: &str) -> Result<String> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
      <StreamSetup>
        <Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
        <Transport xmlns="http://www.onvif.org/ver10/schema">
          <Protocol>RTSP</Protocol>
        </Transport>
      </StreamSetup>
      <ProfileToken>{}</ProfileToken>
    </GetStreamUri>
  </s:Body>
</s:Envelope>"#,
            profile
        );

        let response = self.soap_request(&self.services_url(), &body)?;

        let uri = extract_xml_value(&response, "Uri").context("No Uri in response")?;
        let uri = uri.replace("&amp;", "&");
        let uri_with_creds = if uri.starts_with("rtsp://") {
            format!(
                "rtsp://{}:{}@{}",
                self.user,
                self.pass,
                uri.trim_start_matches("rtsp://")
            )
        } else {
            uri
        };

        Ok(uri_with_creds)
    }

    /// Get RTSP stream URI for the configured profile
    pub fn get_stream_uri(&self) -> Result<String> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
      <StreamSetup>
        <Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
        <Transport xmlns="http://www.onvif.org/ver10/schema">
          <Protocol>RTSP</Protocol>
        </Transport>
      </StreamSetup>
      <ProfileToken>{}</ProfileToken>
    </GetStreamUri>
  </s:Body>
</s:Envelope>"#,
            self.profile
        );

        let response = self.soap_request(&self.services_url(), &body)?;

        let uri = extract_xml_value(&response, "Uri").context("No Uri in response")?;
        // Decode HTML entities and add credentials
        let uri = uri.replace("&amp;", "&");
        let uri_with_creds = if uri.starts_with("rtsp://") {
            format!(
                "rtsp://{}:{}@{}",
                self.user,
                self.pass,
                uri.trim_start_matches("rtsp://")
            )
        } else {
            uri
        };

        Ok(uri_with_creds)
    }

    /// PTZ continuous move (pan/tilt/zoom speeds from -1.0 to 1.0)
    pub fn ptz_move(&self, pan: f32, tilt: f32, zoom: f32) -> Result<()> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <Velocity>
        <PanTilt xmlns="http://www.onvif.org/ver10/schema" x="{}" y="{}"/>
        <Zoom xmlns="http://www.onvif.org/ver10/schema" x="{}"/>
      </Velocity>
    </ContinuousMove>
  </s:Body>
</s:Envelope>"#,
            self.profile, pan, tilt, zoom
        );

        self.soap_request(&self.services_url(), &body)?;
        Ok(())
    }

    /// PTZ stop all movement
    pub fn ptz_stop(&self) -> Result<()> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <PanTilt>true</PanTilt>
      <Zoom>true</Zoom>
    </Stop>
  </s:Body>
</s:Envelope>"#,
            self.profile
        );

        self.soap_request(&self.services_url(), &body)?;
        Ok(())
    }

    /// PTZ absolute move (positions from -1.0 to 1.0 for pan/tilt, 0.0 to 1.0 for zoom)
    pub fn ptz_goto(&self, pan: f32, tilt: f32, zoom: f32) -> Result<()> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <Position>
        <PanTilt xmlns="http://www.onvif.org/ver10/schema" x="{}" y="{}"/>
        <Zoom xmlns="http://www.onvif.org/ver10/schema" x="{}"/>
      </Position>
    </AbsoluteMove>
  </s:Body>
</s:Envelope>"#,
            self.profile, pan, tilt, zoom
        );

        self.soap_request(&self.services_url(), &body)?;
        Ok(())
    }

    /// Get current PTZ position
    pub fn ptz_status(&self) -> Result<PtzPosition> {
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetStatus xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
    </GetStatus>
  </s:Body>
</s:Envelope>"#,
            self.profile
        );

        let response = self.soap_request(&self.services_url(), &body)?;
        extract_ptz_position(&response).context("Could not parse PTZ position")
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub manufacturer: String,
    pub model: String,
    pub firmware: String,
}

impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({})", self.manufacturer, self.model, self.firmware)
    }
}

#[derive(Debug, Clone)]
pub struct MediaProfile {
    pub token: String,
    pub name: String,
}

impl std::fmt::Display for MediaProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.token)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PtzPosition {
    pub pan: f32,
    pub tilt: f32,
    pub zoom: f32,
}

impl std::fmt::Display for PtzPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pan={:.2}, tilt={:.2}, zoom={:.2}", self.pan, self.tilt, self.zoom)
    }
}

/// Extract a simple XML element value by tag name
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    // Try various namespace prefixes
    for prefix in &["tds:", "tt:", ""] {
        let open_tag = format!("<{}{}>", prefix, tag);
        let close_tag = format!("</{}{}>", prefix, tag);

        if let Some(start) = xml.find(&open_tag) {
            let start = start + open_tag.len();
            if let Some(end) = xml[start..].find(&close_tag) {
                return Some(xml[start..start + end].to_string());
            }
        }
    }
    None
}

/// Extract PTZ position from GetStatus response
fn extract_ptz_position(xml: &str) -> Option<PtzPosition> {
    let mut pos = PtzPosition::default();
    let mut found = false;

    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref());

                if name == "PanTilt" {
                    for attr in e.attributes().flatten() {
                        let local = attr.key.local_name();
                        let key = String::from_utf8_lossy(local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                pos.pan = v.parse().unwrap_or(0.0);
                                found = true;
                            }
                        } else if key == "y" {
                            if let Ok(v) = attr.unescape_value() {
                                pos.tilt = v.parse().unwrap_or(0.0);
                            }
                        }
                    }
                } else if name == "Zoom" {
                    for attr in e.attributes().flatten() {
                        let local = attr.key.local_name();
                        let key = String::from_utf8_lossy(local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                pos.zoom = v.parse().unwrap_or(0.0);
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

    if found { Some(pos) } else { None }
}

/// Extract media profiles from GetProfiles response
fn extract_profiles(xml: &str) -> Vec<MediaProfile> {
    let mut profiles = Vec::new();
    let mut reader = Reader::from_str(xml);

    let mut current_token: Option<String> = None;
    let mut current_name: Option<String> = None;
    let mut in_profile = false;
    let mut in_name = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref());

                if name == "Profiles" {
                    in_profile = true;
                    // Get token attribute
                    for attr in e.attributes().flatten() {
                        let local = attr.key.local_name();
                        let key = String::from_utf8_lossy(local.as_ref());
                        if key == "token" {
                            if let Ok(v) = attr.unescape_value() {
                                current_token = Some(v.to_string());
                            }
                        }
                    }
                } else if in_profile && name == "Name" {
                    in_name = true;
                }
            }
            Ok(Event::Text(e)) => {
                if in_name {
                    if let Ok(text) = e.unescape() {
                        current_name = Some(text.to_string());
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref());

                if name == "Profiles" {
                    if let (Some(token), Some(profile_name)) = (current_token.take(), current_name.take()) {
                        profiles.push(MediaProfile {
                            token,
                            name: profile_name,
                        });
                    }
                    in_profile = false;
                } else if name == "Name" {
                    in_name = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    profiles
}
