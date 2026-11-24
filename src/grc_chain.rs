//! Parser and comparison logic for GRC's HTTPS certificate-chain page.
//!
//! GRC fingerprints are external corroboration only. They never become trust
//! anchors and never override wolfSSL's local certificate verification.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::document::parse_html;
use crate::url::Url;

const GRC_BASE_URL: &str = "https://www.grc.com/fingerprints.htm";
const MAX_GRC_CERTIFICATES: usize = 16;
const SHA1_TEXT_LEN: usize = 59;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateRole {
    Root,
    Intermediate,
    Server,
    Unknown,
}

impl CertificateRole {
    fn from_heading(line: &str) -> Option<Self> {
        match line.trim().to_ascii_lowercase().as_str() {
            "root" => Some(Self::Root),
            "intermediate" => Some(Self::Intermediate),
            "server" => Some(Self::Server),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "Root",
            Self::Intermediate => "Intermediate",
            Self::Server => "Server",
            Self::Unknown => "Unknown role",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCertificate {
    pub role: CertificateRole,
    pub name: String,
    pub sha1: [u8; 20],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceChain {
    pub hostname: String,
    /// GRC presents the path from root toward the server leaf.
    pub certificates: Vec<ReferenceCertificate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidBaseUrl,
    MissingChainHeading,
    HostnameMismatch,
    NoFingerprints,
    TooManyCertificates,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainComparison {
    pub matched: Vec<ReferenceCertificate>,
    pub missing: Vec<ReferenceCertificate>,
    pub unexpected_local: Vec<[u8; 20]>,
    pub server_leaf_matches: bool,
    pub local_chain_empty: bool,
}

impl ChainComparison {
    /// The root may legitimately be omitted from the certificates sent by a
    /// TLS server, so it is not counted as missing when comparing peer data.
    pub fn is_consistent(&self) -> bool {
        !self.local_chain_empty
            && self.server_leaf_matches
            && self.missing.is_empty()
            && self.unexpected_local.is_empty()
    }

    pub fn has_divergence(&self) -> bool {
        !self.local_chain_empty
            && (!self.server_leaf_matches
                || !self.missing.is_empty()
                || !self.unexpected_local.is_empty())
    }
}

/// Parse GRC's visible HTML output for
/// `https://www.grc.com/fingerprints.htm?chain=<hostname>`.
///
/// The parser is deliberately tolerant of whitespace and table layout changes,
/// but requires the exact requested hostname and at least one valid SHA-1
/// fingerprint before returning data.
pub fn parse_grc_chain_html(
    html: &str,
    expected_hostname: &str,
) -> Result<ReferenceChain, ParseError> {
    let base = Url::parse(GRC_BASE_URL).map_err(|_| ParseError::InvalidBaseUrl)?;
    let visible = parse_html(html, &base).text;
    parse_grc_chain_text(&visible, expected_hostname)
}

/// Parse the text-only representation emitted by the browser's HTML parser.
/// This is public to make the format parser independently testable.
pub fn parse_grc_chain_text(
    visible_text: &str,
    expected_hostname: &str,
) -> Result<ReferenceChain, ParseError> {
    let lower = visible_text.to_ascii_lowercase();
    let heading = lower
        .find("chain of trust for")
        .ok_or(ParseError::MissingChainHeading)?;
    let heading_tail = &visible_text[heading + "chain of trust for".len()..];
    let hostname_found = heading_tail
        .split_whitespace()
        .take(12)
        .map(|token| token.trim_matches(|ch: char| {
            matches!(ch, ':' | ',' | ';' | '(' | ')' | '[' | ']')
        }))
        .any(|token| token.eq_ignore_ascii_case(expected_hostname));

    if !hostname_found {
        return Err(ParseError::HostnameMismatch);
    }

    let mut role = CertificateRole::Unknown;
    let mut previous_text = "";
    let mut certificates = Vec::new();

    for line in visible_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(found_role) = CertificateRole::from_heading(line) {
            role = found_role;
            previous_text = "";
            continue;
        }

        if let Some((start, fingerprint)) = find_sha1_fingerprint(line) {
            if certificates.len() >= MAX_GRC_CERTIFICATES {
                return Err(ParseError::TooManyCertificates);
            }

            let name_in_line = line[..start].trim();
            let name = if name_in_line.is_empty()
                || name_in_line.eq_ignore_ascii_case("certificate identification")
                || name_in_line.to_ascii_lowercase().contains("sha1 fingerprint")
            {
                previous_text.trim()
            } else {
                name_in_line
            };
            let name = if name.is_empty() {
                String::from("Unlabelled certificate")
            } else {
                name.to_string()
            };

            certificates.push(ReferenceCertificate {
                role,
                name,
                sha1: fingerprint,
            });
        } else if !line.to_ascii_lowercase().contains("certificate identification")
            && !line.to_ascii_lowercase().contains("sha1 fingerprint")
            && !line.to_ascii_lowercase().contains("chain of trust for")
            && !line.eq_ignore_ascii_case(expected_hostname)
        {
            previous_text = line;
        }
    }

    if certificates.is_empty() {
        return Err(ParseError::NoFingerprints);
    }

    Ok(ReferenceChain {
        hostname: expected_hostname.to_ascii_lowercase(),
        certificates,
    })
}

/// Compare the SHA-1 fingerprints observed by wolfSSL's verify callback with
/// the independently retrieved GRC reference. SHA-1 is used only because that
/// is the fingerprint format GRC publishes; it is not used to validate TLS.
pub fn compare_chains(
    reference: &ReferenceChain,
    local_depth_order: &[[u8; 20]],
) -> ChainComparison {
    let mut matched = Vec::new();
    let mut missing = Vec::new();
    let mut unexpected_local = Vec::new();

    for certificate in &reference.certificates {
        let found = local_depth_order.iter().any(|local| local == &certificate.sha1);
        if found {
            matched.push(certificate.clone());
        } else if certificate.role != CertificateRole::Root {
            // Servers frequently omit the root trust anchor from the TLS
            // Certificate message. The root is therefore informational only.
            missing.push(certificate.clone());
        }
    }

    for local in local_depth_order {
        if !reference
            .certificates
            .iter()
            .any(|certificate| &certificate.sha1 == local)
        {
            unexpected_local.push(*local);
        }
    }

    let server_fingerprint = reference
        .certificates
        .iter()
        .find(|certificate| certificate.role == CertificateRole::Server)
        .map(|certificate| certificate.sha1);
    let server_leaf_matches = match (server_fingerprint, local_depth_order.first()) {
        (Some(expected), Some(observed)) => expected == *observed,
        (None, _) => false,
        (_, None) => false,
    };

    ChainComparison {
        matched,
        missing,
        unexpected_local,
        server_leaf_matches,
        local_chain_empty: local_depth_order.is_empty(),
    }
}

pub fn format_sha1(fingerprint: &[u8; 20]) -> String {
    let mut output = String::with_capacity(SHA1_TEXT_LEN);
    for (index, byte) in fingerprint.iter().enumerate() {
        if index != 0 {
            output.push(':');
        }
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn find_sha1_fingerprint(line: &str) -> Option<(usize, [u8; 20])> {
    let bytes = line.as_bytes();
    if bytes.len() < SHA1_TEXT_LEN {
        return None;
    }

    for start in 0..=bytes.len() - SHA1_TEXT_LEN {
        let mut fingerprint = [0u8; 20];
        let mut valid = true;
        for index in 0..20 {
            let offset = start + index * 3;
            if index != 0 && bytes[offset - 1] != b':' {
                valid = false;
                break;
            }
            let high = hex_value(bytes[offset]);
            let low = hex_value(bytes[offset + 1]);
            match (high, low) {
                (Some(high), Some(low)) => fingerprint[index] = (high << 4) | low,
                _ => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Some((start, fingerprint));
        }
    }

    None
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        <main>
          <h2>Chain of Trust for:</h2>
          <div>www.google.com</div>
          <h3>Root</h3>
          <table>
            <tr><th>Certificate Identification</th><th>Certificate's SHA1 Fingerprint Hash</th></tr>
            <tr><td>GlobalSign Root CA</td><td>B1:BC:96:8B:D4:F4:9D:62:2A:A8:9A:81:F2:15:01:52:A4:1D:82:9C</td></tr>
          </table>
          <h3>Intermediate</h3>
          <table>
            <tr><td>WR2</td><td>66:E4:16:12:60:B1:00:FE:E0:DE:28:7A:9A:52:93:B4:C2:22:4A:E6</td></tr>
          </table>
          <h3>Server</h3>
          <table>
            <tr><td>www.google.com</td><td>18:B1:F1:CC:EC:F4:C8:DB:35:13:D2:80:D3:9E:8C:5A:FA:54:50:2C</td></tr>
          </table>
        </main>
    "#;

    fn sample_reference() -> ReferenceChain {
        parse_grc_chain_html(SAMPLE, "www.google.com").unwrap()
    }

    #[test]
    fn parses_root_intermediate_and_server_fingerprints() {
        let parsed = sample_reference();
        assert_eq!(parsed.hostname, "www.google.com");
        assert_eq!(parsed.certificates.len(), 3);
        assert_eq!(parsed.certificates[0].role, CertificateRole::Root);
        assert_eq!(parsed.certificates[0].name, "GlobalSign Root CA");
        assert_eq!(parsed.certificates[1].role, CertificateRole::Intermediate);
        assert_eq!(parsed.certificates[1].name, "WR2");
        assert_eq!(parsed.certificates[2].role, CertificateRole::Server);
        assert_eq!(parsed.certificates[2].name, "www.google.com");
    }

    #[test]
    fn rejects_reference_for_a_different_hostname() {
        assert_eq!(
            parse_grc_chain_html(SAMPLE, "example.com").unwrap_err(),
            ParseError::HostnameMismatch
        );
    }

    #[test]
    fn compares_leaf_and_intermediate_fingerprints() {
        let reference = sample_reference();
        let local = [
            reference.certificates[2].sha1,
            reference.certificates[1].sha1,
        ];
        let comparison = compare_chains(&reference, &local);
        assert!(comparison.is_consistent());
        assert!(comparison.server_leaf_matches);
        assert_eq!(comparison.matched.len(), 2);
        assert!(comparison.missing.is_empty());
    }

    #[test]
    fn reports_leaf_and_intermediate_divergence() {
        let reference = sample_reference();
        let local = [[0xAA; 20], [0xBB; 20]];
        let comparison = compare_chains(&reference, &local);
        assert!(comparison.has_divergence());
        assert!(!comparison.server_leaf_matches);
        assert_eq!(comparison.missing.len(), 2);
        assert_eq!(comparison.unexpected_local.len(), 2);
    }
}
