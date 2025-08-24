//! XML parsing for WS-Security UsernameToken
//!
//! Extracts authentication credentials from SOAP Security headers.

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::WsSecurityError;

/// Parsed UsernameToken from SOAP Security header
#[derive(Debug, Clone)]
pub struct UsernameToken {
    /// The username
    pub username: String,
    /// Base64-encoded password digest
    pub password_digest: String,
    /// Base64-encoded nonce
    pub nonce: String,
    /// ISO 8601 timestamp
    pub created: String,
}

/// Parse UsernameToken from a SOAP envelope
///
/// Looks for the structure:
/// ```xml
/// <Envelope>
///   <Header>
///     <Security>
///       <UsernameToken>
///         <Username>...</Username>
///         <Password Type="...#PasswordDigest">...</Password>
///         <Nonce EncodingType="...#Base64Binary">...</Nonce>
///         <Created>...</Created>
///       </UsernameToken>
///     </Security>
///   </Header>
///   <Body>...</Body>
/// </Envelope>
/// ```
pub fn parse_username_token(xml: &str) -> Result<UsernameToken, WsSecurityError> {
    let mut reader = Reader::from_str(xml);

    let mut in_security = false;
    let mut in_username_token = false;
    let mut current_element: Option<String> = None;

    let mut username: Option<String> = None;
    let mut password_digest: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut created: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref()).to_string();

                match name.as_str() {
                    "Security" => in_security = true,
                    "UsernameToken" if in_security => in_username_token = true,
                    "Username" | "Password" | "Nonce" | "Created" if in_username_token => {
                        current_element = Some(name);
                    }
                    _ => {}
                }
            }

            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref()).to_string();

                match name.as_str() {
                    "Security" => in_security = false,
                    "UsernameToken" => in_username_token = false,
                    "Username" | "Password" | "Nonce" | "Created" => {
                        current_element = None;
                    }
                    _ => {}
                }
            }

            Ok(Event::Text(e)) => {
                if let Some(ref elem) = current_element {
                    let text = e
                        .unescape()
                        .map_err(|e| WsSecurityError::XmlError(e.to_string()))?
                        .trim()
                        .to_string();

                    match elem.as_str() {
                        "Username" => username = Some(text),
                        "Password" => password_digest = Some(text),
                        "Nonce" => nonce = Some(text),
                        "Created" => created = Some(text),
                        _ => {}
                    }
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => return Err(WsSecurityError::XmlError(e.to_string())),
            _ => {}
        }
    }

    // Check if we found Security header at all
    if username.is_none() && password_digest.is_none() && nonce.is_none() && created.is_none() {
        // No token found - check if Security header existed
        return Err(WsSecurityError::MissingSecurityHeader);
    }

    // Validate all required fields are present
    let username = username.ok_or_else(|| WsSecurityError::MissingElement("Username".into()))?;
    let password_digest =
        password_digest.ok_or_else(|| WsSecurityError::MissingElement("Password".into()))?;
    let nonce = nonce.ok_or_else(|| WsSecurityError::MissingElement("Nonce".into()))?;
    let created = created.ok_or_else(|| WsSecurityError::MissingElement("Created".into()))?;

    Ok(UsernameToken {
        username,
        password_digest,
        nonce,
        created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SOAP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>onvif_user</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">tuOSpGlFlIXsozq4HFNeeGeFLEI=</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">LKqI6G/AikKCQrN0zqZFlg==</wsse:Nonce>
        <wsu:Created>2010-09-16T07:50:45.000Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <GetDeviceInformation/>
  </s:Body>
</s:Envelope>"#;

    #[test]
    fn test_parse_username_token() {
        let token = parse_username_token(SAMPLE_SOAP).unwrap();

        assert_eq!(token.username, "onvif_user");
        assert_eq!(token.password_digest, "tuOSpGlFlIXsozq4HFNeeGeFLEI=");
        assert_eq!(token.nonce, "LKqI6G/AikKCQrN0zqZFlg==");
        assert_eq!(token.created, "2010-09-16T07:50:45.000Z");
    }

    #[test]
    fn test_missing_security_header() {
        let xml = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body><GetDeviceInformation/></s:Body>
</s:Envelope>"#;

        let result = parse_username_token(xml);
        assert!(matches!(result, Err(WsSecurityError::MissingSecurityHeader)));
    }

    #[test]
    fn test_missing_username() {
        let xml = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security>
      <UsernameToken>
        <Password>digest</Password>
        <Nonce>nonce</Nonce>
        <Created>2024-01-01T00:00:00Z</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body/>
</s:Envelope>"#;

        let result = parse_username_token(xml);
        assert!(matches!(
            result,
            Err(WsSecurityError::MissingElement(ref s)) if s == "Username"
        ));
    }
}
