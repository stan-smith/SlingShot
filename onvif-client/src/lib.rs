//! ONVIF Client Library
//!
//! Provides ONVIF camera control via SOAP/HTTP with automatic authentication.
//! Supports both HTTP Digest and WS-Security (UsernameToken) authentication.
//! Supports device info, stream URIs, and PTZ commands.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use digest_auth::AuthContext;
use quick_xml::events::Event;
use quick_xml::Reader;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use sha1::{Digest, Sha1};

/// Authentication method for ONVIF requests
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum AuthMethod {
    /// Auto-detect based on server response (default)
    #[default]
    Auto,
    /// HTTP Digest authentication (RFC 2617)
    HttpDigest,
    /// WS-Security UsernameToken (OASIS WSS 1.1)
    WsSecurity,
}

/// Service endpoint paths (different cameras use different paths)
#[derive(Debug, Clone)]
pub struct ServiceEndpoints {
    pub device: String,
    pub media: String,
    pub ptz: String,
}

impl Default for ServiceEndpoints {
    fn default() -> Self {
        Self {
            device: "/onvif/device_service".to_string(),
            media: "/onvif/services".to_string(),
            ptz: "/onvif/services".to_string(),
        }
    }
}

impl ServiceEndpoints {
    /// Separate service endpoints (used by Wisenet and some other cameras)
    pub fn separate() -> Self {
        Self {
            device: "/onvif/device_service".to_string(),
            media: "/onvif/media_service".to_string(),
            ptz: "/onvif/ptz_service".to_string(),
        }
    }
}

/// Internal: Detected authentication state after probing
#[derive(Debug, Clone)]
struct DetectedAuth {
    /// The endpoint this auth was detected for
    endpoint: String,
    /// The auth method
    method: AuthType,
}

#[derive(Debug, Clone)]
enum AuthType {
    /// No authentication required
    None,
    /// HTTP Digest with cached WWW-Authenticate header
    HttpDigest(String),
    /// WS-Security (camera time offset stored separately)
    WsSecurity,
}

/// ONVIF camera client
pub struct OnvifClient {
    client: Client,
    host: String,
    user: String,
    pass: String,
    profile: String,
    auth_method: AuthMethod,
    detected_auth: Option<DetectedAuth>,
    camera_time_offset: Option<Duration>,
    endpoints: ServiceEndpoints,
}

impl OnvifClient {
    pub fn new(host: &str, user: &str, pass: &str) -> Self {
        Self {
            client: Client::new(),
            host: host.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            profile: "profile_1_h264".to_string(),
            auth_method: AuthMethod::Auto,
            detected_auth: None,
            camera_time_offset: None,
            endpoints: ServiceEndpoints::default(),
        }
    }

    /// Create client with custom endpoints
    pub fn with_endpoints(host: &str, user: &str, pass: &str, endpoints: ServiceEndpoints) -> Self {
        Self {
            client: Client::new(),
            host: host.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            profile: "profile_1_h264".to_string(),
            auth_method: AuthMethod::Auto,
            detected_auth: None,
            camera_time_offset: None,
            endpoints,
        }
    }

    pub fn set_profile(&mut self, profile: &str) {
        self.profile = profile.to_string();
    }

    /// Set authentication method explicitly (default is Auto)
    pub fn set_auth_method(&mut self, method: AuthMethod) {
        self.auth_method = method;
        self.detected_auth = None; // Reset detection when method changes
    }

    /// Set custom service endpoints
    pub fn set_endpoints(&mut self, endpoints: ServiceEndpoints) {
        self.endpoints = endpoints;
    }

    /// Force camera time resync (useful if camera time changes)
    pub fn resync_camera_time(&mut self) -> Result<()> {
        self.camera_time_offset = Some(self.fetch_camera_time_offset()?);
        Ok(())
    }

    fn device_url(&self) -> String {
        format!("http://{}{}", self.host, self.endpoints.device)
    }

    fn media_url(&self) -> String {
        format!("http://{}{}", self.host, self.endpoints.media)
    }

    fn ptz_url(&self) -> String {
        format!("http://{}{}", self.host, self.endpoints.ptz)
    }

    /// Fetch camera time from HTTP Date header and compute offset from local time
    fn fetch_camera_time_offset(&self) -> Result<Duration> {
        let url = format!("http://{}/", self.host);
        let resp = self
            .client
            .head(&url)
            .send()
            .context("Failed to fetch camera time")?;

        if let Some(date_header) = resp.headers().get("date") {
            let date_str = date_header.to_str().context("Invalid date header")?;
            // Parse RFC 2822 date format (e.g., "Sat, 01 Jan 2000 00:00:00 GMT")
            let camera_time = DateTime::parse_from_rfc2822(date_str)
                .context("Failed to parse camera Date header")?;
            let local_now = Utc::now();
            let camera_utc = camera_time.with_timezone(&Utc);
            let offset = camera_utc.signed_duration_since(local_now);
            Ok(offset)
        } else {
            // No Date header, assume camera time matches our time
            Ok(Duration::zero())
        }
    }

    /// Generate WS-Security UsernameToken header
    fn generate_ws_security_header(&self) -> String {
        // Generate 16-byte random nonce
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_b64 = BASE64.encode(nonce_bytes);

        // Calculate created timestamp using camera time offset
        let offset = self.camera_time_offset.unwrap_or_else(Duration::zero);
        let created = (Utc::now() + offset).format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Compute password digest: Base64(SHA1(nonce + created + password))
        let mut hasher = Sha1::new();
        hasher.update(&nonce_bytes);
        hasher.update(created.as_bytes());
        hasher.update(self.pass.as_bytes());
        let digest = BASE64.encode(hasher.finalize());

        format!(
            r#"<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <wsse:UsernameToken>
            <wsse:Username>{}</wsse:Username>
            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
            <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
            <wsu:Created>{}</wsu:Created>
        </wsse:UsernameToken>
    </wsse:Security>"#,
            self.user, digest, nonce_b64, created
        )
    }

    /// Build SOAP envelope with optional WS-Security header
    fn build_soap_envelope(&self, body: &str, include_ws_security: bool) -> String {
        let security = if include_ws_security {
            self.generate_ws_security_header()
        } else {
            String::new()
        };

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Header>{}</soap:Header>
    <soap:Body>{}</soap:Body>
</soap:Envelope>"#,
            security, body
        )
    }

    /// Build simple SOAP envelope without WS-Security (for HTTP Digest auth)
    fn build_simple_envelope(&self, body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>{}</s:Body>
</s:Envelope>"#,
            body
        )
    }

    /// Send SOAP request with automatic authentication detection
    fn soap_request(&mut self, url: &str, body: &str) -> Result<String> {
        match self.auth_method {
            AuthMethod::Auto => self.soap_request_auto(url, body),
            AuthMethod::HttpDigest => self.soap_request_digest(url, body),
            AuthMethod::WsSecurity => self.soap_request_ws_security(url, body),
        }
    }

    /// Auto-detect authentication method based on server response
    fn soap_request_auto(&mut self, url: &str, body: &str) -> Result<String> {
        // Extract endpoint path from URL for cache matching
        let endpoint = url.find("://")
            .and_then(|i| url[i + 3..].find('/'))
            .map(|i| &url[url.find("://").unwrap() + 3 + i..])
            .unwrap_or("/")
            .to_string();

        // If we've already detected the auth method for this endpoint, use it
        if let Some(ref detected) = self.detected_auth.clone() {
            if detected.endpoint == endpoint {
                return match &detected.method {
                    AuthType::None => self.soap_request_no_auth(url, body),
                    AuthType::HttpDigest(www_auth) => {
                        self.soap_request_digest_with_header(url, body, www_auth)
                    }
                    AuthType::WsSecurity => self.soap_request_ws_security(url, body),
                };
            }
        }

        // First request: try without authentication (with simple envelope)
        let envelope = self.build_simple_envelope(body);
        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .body(envelope.clone())
            .send()
            .context("Failed to send initial request")?;

        if resp.status().is_success() {
            self.detected_auth = Some(DetectedAuth { endpoint: endpoint.clone(), method: AuthType::None });
            return Ok(resp.text()?);
        }

        // Check for WWW-Authenticate header (HTTP Digest)
        if let Some(www_auth) = resp.headers().get(WWW_AUTHENTICATE) {
            let www_auth_str = www_auth.to_str()?.to_string();
            self.detected_auth = Some(DetectedAuth { endpoint: endpoint.clone(), method: AuthType::HttpDigest(www_auth_str.clone()) });
            return self.soap_request_digest_with_header(url, body, &www_auth_str);
        }

        // Check response body for SOAP Fault indicating auth required
        let resp_text = resp.text().unwrap_or_default();
        if resp_text.contains("NotAuthorized")
            || resp_text.contains("Sender not authorized")
            || resp_text.contains("security token could not be authenticated")
        {
            // No WWW-Authenticate header but auth is required: try WS-Security
            if self.camera_time_offset.is_none() {
                self.camera_time_offset = Some(self.fetch_camera_time_offset()?);
            }
            self.detected_auth = Some(DetectedAuth { endpoint: endpoint.clone(), method: AuthType::WsSecurity });
            return self.soap_request_ws_security(url, body);
        }

        // If we got a 401 without WWW-Authenticate, try WS-Security
        if self.camera_time_offset.is_none() {
            self.camera_time_offset = Some(self.fetch_camera_time_offset()?);
        }
        self.detected_auth = Some(DetectedAuth { endpoint: endpoint.clone(), method: AuthType::WsSecurity });
        self.soap_request_ws_security(url, body)
    }

    /// Send request without authentication
    fn soap_request_no_auth(&self, url: &str, body: &str) -> Result<String> {
        let envelope = self.build_simple_envelope(body);
        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .body(envelope)
            .send()
            .context("Failed to send request")?;

        if !resp.status().is_success() {
            anyhow::bail!("Request failed with status: {}", resp.status());
        }

        Ok(resp.text()?)
    }

    /// Send request with HTTP Digest authentication
    fn soap_request_digest(&mut self, url: &str, body: &str) -> Result<String> {
        // First request to get WWW-Authenticate header
        let envelope = self.build_simple_envelope(body);
        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .body(envelope.clone())
            .send()
            .context("Failed to send initial request")?;

        if resp.status().is_success() {
            return Ok(resp.text()?);
        }

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("No WWW-Authenticate header for digest auth")?
            .to_str()?;

        self.soap_request_digest_with_header(url, body, www_auth)
    }

    /// Send request with HTTP Digest authentication using cached WWW-Authenticate header
    fn soap_request_digest_with_header(
        &self,
        url: &str,
        body: &str,
        www_auth: &str,
    ) -> Result<String> {
        let envelope = self.build_simple_envelope(body);
        let uri_path = url
            .find("://")
            .and_then(|i| url[i + 3..].find('/'))
            .map(|i| &url[url.find("://").unwrap() + 3 + i..])
            .unwrap_or("/");

        let context = AuthContext::new_post(
            &self.user,
            &self.pass,
            uri_path,
            Some(envelope.as_bytes().to_vec()),
        );
        let mut prompt = digest_auth::parse(www_auth)?;
        let auth_header = prompt.respond(&context)?.to_header_string();

        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .header("Authorization", auth_header)
            .body(envelope)
            .send()
            .context("Failed to send authenticated request")?;

        if !resp.status().is_success() {
            anyhow::bail!("Request failed with status: {}", resp.status());
        }

        Ok(resp.text()?)
    }

    /// Send request with WS-Security authentication
    fn soap_request_ws_security(&mut self, url: &str, body: &str) -> Result<String> {
        // Ensure we have camera time offset
        if self.camera_time_offset.is_none() {
            self.camera_time_offset = Some(self.fetch_camera_time_offset()?);
        }

        let envelope = self.build_soap_envelope(body, true);

        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml")
            .body(envelope)
            .send()
            .context("Failed to send WS-Security request")?;

        let status = resp.status();
        let resp_text = resp.text()?;

        // Check HTTP status first
        if status == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Request failed with status: 404 Not Found");
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            anyhow::bail!("Request failed with status: 401 Unauthorized");
        }

        // Check for auth failure in SOAP response
        if resp_text.contains("security token could not be authenticated")
            || resp_text.contains("NotAuthorized")
        {
            anyhow::bail!("WS-Security authentication failed");
        }

        Ok(resp_text)
    }

    /// Get device information (manufacturer, model, firmware)
    pub fn get_device_info(&mut self) -> Result<DeviceInfo> {
        let body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
        let url = self.device_url();
        let response = self.soap_request(&url, body)?;

        Ok(DeviceInfo {
            manufacturer: extract_xml_value(&response, "Manufacturer").unwrap_or_default(),
            model: extract_xml_value(&response, "Model").unwrap_or_default(),
            firmware: extract_xml_value(&response, "FirmwareVersion").unwrap_or_default(),
        })
    }

    /// Get available media profiles
    pub fn get_profiles(&mut self) -> Result<Vec<MediaProfile>> {
        let body = "<trt:GetProfiles/>";
        let url = self.media_url();

        // Try primary endpoint first
        match self.soap_request(&url, body) {
            Ok(response) => return Ok(extract_profiles(&response)),
            Err(e) => {
                let err_str = e.to_string();
                // If 404 or 401 and using default endpoints, try separate media endpoint
                // Some cameras return 401 for non-existent endpoints instead of 404
                if (err_str.contains("404") || err_str.contains("401"))
                    && self.endpoints.media == "/onvif/services"
                {
                    // Update endpoints and retry (keep detected auth)
                    self.endpoints.media = "/onvif/media_service".to_string();
                    self.endpoints.ptz = "/onvif/ptz_service".to_string();

                    let alt_url = self.media_url();
                    let response = self.soap_request(&alt_url, body)?;
                    return Ok(extract_profiles(&response));
                }
                return Err(e);
            }
        }
    }

    /// Get RTSP stream URI for a specific profile
    pub fn get_stream_uri_for_profile(&mut self, profile: &str) -> Result<String> {
        let body = format!(
            r#"<trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>{}</trt:ProfileToken>
    </trt:GetStreamUri>"#,
            profile
        );

        let url = self.media_url();
        let response = self.soap_request(&url, &body)?;

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
    pub fn get_stream_uri(&mut self) -> Result<String> {
        let profile = self.profile.clone();
        self.get_stream_uri_for_profile(&profile)
    }

    /// PTZ continuous move (pan/tilt/zoom speeds from -1.0 to 1.0)
    pub fn ptz_move(&mut self, pan: f32, tilt: f32, zoom: f32) -> Result<()> {
        let body = format!(
            r#"<ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <Velocity>
        <PanTilt xmlns="http://www.onvif.org/ver10/schema" x="{}" y="{}"/>
        <Zoom xmlns="http://www.onvif.org/ver10/schema" x="{}"/>
      </Velocity>
    </ContinuousMove>"#,
            self.profile, pan, tilt, zoom
        );

        let url = self.ptz_url();
        self.soap_request(&url, &body)?;
        Ok(())
    }

    /// PTZ stop all movement
    pub fn ptz_stop(&mut self) -> Result<()> {
        let body = format!(
            r#"<Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <PanTilt>true</PanTilt>
      <Zoom>true</Zoom>
    </Stop>"#,
            self.profile
        );

        let url = self.ptz_url();
        self.soap_request(&url, &body)?;
        Ok(())
    }

    /// PTZ absolute move (positions from -1.0 to 1.0 for pan/tilt, 0.0 to 1.0 for zoom)
    pub fn ptz_goto(&mut self, pan: f32, tilt: f32, zoom: f32) -> Result<()> {
        let body = format!(
            r#"<AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
      <Position>
        <PanTilt xmlns="http://www.onvif.org/ver10/schema" x="{}" y="{}"/>
        <Zoom xmlns="http://www.onvif.org/ver10/schema" x="{}"/>
      </Position>
    </AbsoluteMove>"#,
            self.profile, pan, tilt, zoom
        );

        let url = self.ptz_url();
        self.soap_request(&url, &body)?;
        Ok(())
    }

    /// Get current PTZ position
    pub fn ptz_status(&mut self) -> Result<PtzPosition> {
        let body = format!(
            r#"<GetStatus xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{}</ProfileToken>
    </GetStatus>"#,
            self.profile
        );

        let url = self.ptz_url();
        let response = self.soap_request(&url, &body)?;
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
    /// Video encoding (e.g., "H264", "JPEG", "H265")
    pub encoding: Option<String>,
    /// Video width in pixels
    pub width: Option<u32>,
    /// Video height in pixels
    pub height: Option<u32>,
    /// Frame rate limit
    pub framerate: Option<u32>,
}

impl std::fmt::Display for MediaProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![self.name.clone()];

        // Build video info string
        let mut video_info = Vec::new();
        if let Some(enc) = &self.encoding {
            video_info.push(enc.to_lowercase());
        }
        if let (Some(w), Some(h)) = (self.width, self.height) {
            video_info.push(format!("{}x{}", w, h));
        }
        if let Some(fps) = self.framerate {
            video_info.push(format!("{}fps", fps));
        }

        if !video_info.is_empty() {
            parts.push(video_info.join(" "));
        }

        write!(f, "{}", parts.join(" - "))
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
    let mut current_encoding: Option<String> = None;
    let mut current_width: Option<u32> = None;
    let mut current_height: Option<u32> = None;
    let mut current_framerate: Option<u32> = None;

    let mut in_profile = false;
    let mut in_video_encoder = false;
    let mut in_resolution = false;
    let mut in_rate_control = false;
    let mut reading_element: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let tag = String::from_utf8_lossy(local_name.as_ref()).to_string();

                if tag == "Profiles" {
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
                } else if in_profile {
                    match tag.as_str() {
                        "Name" if !in_video_encoder => reading_element = Some("name".to_string()),
                        "VideoEncoderConfiguration" => in_video_encoder = true,
                        "Encoding" if in_video_encoder => reading_element = Some("encoding".to_string()),
                        "Resolution" if in_video_encoder => in_resolution = true,
                        "Width" if in_resolution => reading_element = Some("width".to_string()),
                        "Height" if in_resolution => reading_element = Some("height".to_string()),
                        "RateControl" if in_video_encoder => in_rate_control = true,
                        "FrameRateLimit" if in_rate_control => reading_element = Some("framerate".to_string()),
                        _ => {}
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(ref element) = reading_element {
                    if let Ok(text) = e.unescape() {
                        let text = text.trim().to_string();
                        match element.as_str() {
                            "name" => current_name = Some(text),
                            "encoding" => current_encoding = Some(text),
                            "width" => current_width = text.parse().ok(),
                            "height" => current_height = text.parse().ok(),
                            "framerate" => current_framerate = text.parse().ok(),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let tag = String::from_utf8_lossy(local_name.as_ref());

                match tag.as_ref() {
                    "Profiles" => {
                        if let (Some(token), Some(profile_name)) = (current_token.take(), current_name.take()) {
                            profiles.push(MediaProfile {
                                token,
                                name: profile_name,
                                encoding: current_encoding.take(),
                                width: current_width.take(),
                                height: current_height.take(),
                                framerate: current_framerate.take(),
                            });
                        }
                        in_profile = false;
                        in_video_encoder = false;
                        in_resolution = false;
                        in_rate_control = false;
                    }
                    "VideoEncoderConfiguration" => in_video_encoder = false,
                    "Resolution" => in_resolution = false,
                    "RateControl" => in_rate_control = false,
                    "Name" | "Encoding" | "Width" | "Height" | "FrameRateLimit" => {
                        reading_element = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    profiles
}
