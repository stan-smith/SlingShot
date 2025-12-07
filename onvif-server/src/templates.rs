//! ONVIF SOAP XML response templates
//!
//! All XML templates are centralized here to keep the main library clean.

use quick_xml::escape::escape;

/// Escape a string for safe inclusion in XML content/attributes.
/// Converts &, <, >, ", ' to their XML entity equivalents.
fn xml_escape(s: &str) -> String {
    escape(s).to_string()
}

/// SOAP authentication fault response
pub fn auth_fault(reason: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>wsse:FailedAuthentication</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en">{}</s:Text>
      </s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>"#,
        xml_escape(reason)
    )
}

/// Generic SOAP fault response
pub fn fault(code: &str, reason: &str) -> String {
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
        xml_escape(code),
        xml_escape(reason)
    )
}

/// Service entry for discovery GetServices response
pub fn service_entry(local_ip: &str, node_name: &str) -> String {
    format!(
        r#"
      <tds:Service>
        <tds:Namespace>http://www.onvif.org/ver20/ptz/wsdl</tds:Namespace>
        <tds:XAddr>http://{}:8080/onvif/{}/ptz_service</tds:XAddr>
        <tds:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tds:Version>
      </tds:Service>"#,
        xml_escape(local_ip),
        xml_escape(node_name)
    )
}

/// GetServices response wrapper
pub fn get_services_response(services: &str) -> String {
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

/// GetDeviceInformation response
pub fn get_device_information(node: &str) -> String {
    let escaped = xml_escape(node);
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
        escaped, escaped
    )
}

/// GetCapabilities response
pub fn get_capabilities(local_ip: &str, node: &str) -> String {
    let escaped_ip = xml_escape(local_ip);
    let escaped_node = xml_escape(node);
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
        escaped_ip, escaped_node, escaped_ip, escaped_node
    )
}

/// GetProfiles response
pub fn get_profiles(node: &str) -> String {
    let escaped = xml_escape(node);
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
        escaped, escaped, escaped, escaped, escaped
    )
}

/// GetStreamUri response
pub fn get_stream_uri(local_ip: &str, node: &str) -> String {
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
        xml_escape(local_ip),
        xml_escape(node)
    )
}

/// ContinuousMove response
pub fn continuous_move_response() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:ContinuousMoveResponse/>
  </s:Body>
</s:Envelope>"#
}

/// Stop response
pub fn stop_response() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:StopResponse/>
  </s:Body>
</s:Envelope>"#
}

/// AbsoluteMove response
pub fn absolute_move_response() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:AbsoluteMoveResponse/>
  </s:Body>
</s:Envelope>"#
}

/// GotoHomePosition response
pub fn goto_home_response() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:GotoHomePositionResponse/>
  </s:Body>
</s:Envelope>"#
}

/// GetStatus response (default idle position)
pub fn get_status_response() -> &'static str {
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
}

/// GetConfigurations response
pub fn get_configurations(node: &str) -> String {
    let escaped = xml_escape(node);
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
        escaped, escaped
    )
}

/// GetNodes response
pub fn get_nodes(node: &str) -> String {
    let escaped = xml_escape(node);
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
        escaped, escaped
    )
}
