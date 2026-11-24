//! Bounded, allocation-conscious extraction of human-readable X.509 fields.
//!
//! This parser is diagnostic only. wolfSSL remains the sole authority for
//! certificate-path and hostname verification. The input is the exact DER
//! certificate copied from wolfSSL's verification callback.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSummary {
    pub version: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub subject: String,
    pub public_key_algorithm: String,
    pub public_key_parameters: String,
    pub public_key_bits: usize,
    pub basic_constraints: String,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
    pub subject_key_identifier: String,
    pub authority_key_identifier: String,
    pub authority_certificate_issuer: String,
    pub authority_certificate_serial_number: String,
    pub issuer_unique_id: String,
    pub subject_unique_id: String,
    pub certificate_policies: Vec<String>,
    pub authority_info_access: Vec<String>,
    pub crl_distribution_points: Vec<String>,
    pub extensions: Vec<String>,
    pub signature_value_bytes: usize,
    pub der_bytes: usize,
}

impl CertificateSummary {
    /// Render every field extracted from the certificate in a console-safe form.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("X.509 CERTIFICATE FIELD SUMMARY\n");
        out.push_str(&format!("  Version: {}\n", self.version));
        out.push_str(&format!("  Serial number: {}\n", self.serial_number));
        out.push_str(&format!(
            "  Signature algorithm: {}\n",
            self.signature_algorithm
        ));
        out.push_str(&format!("  Issuer: {}\n", self.issuer));
        out.push_str(&format!("  Not before: {}\n", self.not_before));
        out.push_str(&format!("  Not after: {}\n", self.not_after));
        out.push_str(&format!("  Subject: {}\n", self.subject));
        out.push_str(&format!(
            "  Subject public-key algorithm: {}\n",
            self.public_key_algorithm
        ));
        out.push_str(&format!(
            "  Subject public-key parameters: {}\n",
            self.public_key_parameters
        ));
        out.push_str(&format!(
            "  Subject public-key size: {} bits\n",
            self.public_key_bits
        ));
        out.push_str(&format!(
            "  Basic constraints: {}\n",
            self.basic_constraints
        ));
        out.push_str(&format!(
            "  Key usage: {}\n",
            join_or_unavailable(&self.key_usage)
        ));
        out.push_str(&format!(
            "  Extended key usage: {}\n",
            join_or_unavailable(&self.extended_key_usage)
        ));
        out.push_str(&format!(
            "  Subject alternative names: {}\n",
            join_or_unavailable(&self.subject_alt_names)
        ));
        out.push_str(&format!(
            "  Subject key identifier: {}\n",
            self.subject_key_identifier
        ));
        out.push_str(&format!(
            "  Authority key identifier: {}\n",
            self.authority_key_identifier
        ));
        out.push_str(&format!(
            "  Authority certificate issuer: {}\n",
            self.authority_certificate_issuer
        ));
        out.push_str(&format!(
            "  Authority certificate serial number: {}\n",
            self.authority_certificate_serial_number
        ));
        out.push_str(&format!("  Issuer unique ID: {}\n", self.issuer_unique_id));
        out.push_str(&format!(
            "  Subject unique ID: {}\n",
            self.subject_unique_id
        ));
        out.push_str(&format!(
            "  Certificate policies: {}\n",
            join_or_unavailable(&self.certificate_policies)
        ));
        out.push_str(&format!(
            "  Authority information access: {}\n",
            join_or_unavailable(&self.authority_info_access)
        ));
        out.push_str(&format!(
            "  CRL distribution points: {}\n",
            join_or_unavailable(&self.crl_distribution_points)
        ));
        out.push_str("  Extensions (OID and critical flag):\n");
        if self.extensions.is_empty() {
            out.push_str("    unavailable / none present\n");
        } else {
            for extension in &self.extensions {
                out.push_str(&format!("    - {}\n", extension));
            }
        }
        out.push_str(&format!(
            "  Signature value: {} bytes\n",
            self.signature_value_bytes
        ));
        out.push_str(&format!(
            "  Encoded certificate size: {} bytes\n",
            self.der_bytes
        ));
        out
    }
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one bounded DER TLV. Indefinite lengths and high-tag-number forms are
/// rejected because they are not valid in the certificate structures parsed here.
fn read_tlv<'a>(input: &'a [u8], offset: &mut usize) -> Option<Tlv<'a>> {
    let tag = *input.get(*offset)?;
    *offset = (*offset).checked_add(1)?;
    if tag & 0x1f == 0x1f {
        return None;
    }

    let first_length = *input.get(*offset)?;
    *offset = (*offset).checked_add(1)?;
    let length = if first_length & 0x80 == 0 {
        first_length as usize
    } else {
        let octets = (first_length & 0x7f) as usize;
        if octets == 0 || octets > 4 {
            return None;
        }
        let end = (*offset).checked_add(octets)?;
        if end > input.len() {
            return None;
        }
        let mut parsed = 0usize;
        while *offset < end {
            parsed = parsed.checked_mul(256)?;
            parsed = parsed.checked_add(input[*offset] as usize)?;
            *offset += 1;
        }
        parsed
    };

    let end = (*offset).checked_add(length)?;
    if end > input.len() {
        return None;
    }
    let value = &input[*offset..end];
    *offset = end;
    Some(Tlv { tag, value })
}

fn children(input: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < input.len() {
        result.push(read_tlv(input, &mut offset)?);
    }
    Some(result)
}

fn oid_text(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("invalid OID");
    }
    let mut subidentifiers = Vec::new();
    let mut value = 0u64;
    for byte in bytes {
        value = value
            .saturating_mul(128)
            .saturating_add((byte & 0x7f) as u64);
        if byte & 0x80 == 0 {
            subidentifiers.push(value);
            value = 0;
        }
    }
    if subidentifiers.is_empty() || bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        return String::from("invalid OID");
    }
    let first = subidentifiers.remove(0);
    let first_arc = core::cmp::min(first / 40, 2);
    let second_arc = first.saturating_sub(first_arc * 40);
    let mut arcs = Vec::new();
    arcs.push(first_arc);
    arcs.push(second_arc);
    arcs.extend(subidentifiers);

    let mut output = String::new();
    for (index, arc) in arcs.iter().enumerate() {
        if index != 0 {
            output.push('.');
        }
        output.push_str(&arc.to_string());
    }
    output
}

fn safe_text(bytes: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(bytes);
    let mut output = String::new();
    for character in decoded.chars() {
        if character.is_control() {
            output.push_str(&format!("\\u{:04X}", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push(':');
        }
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn oid_label(oid: &str) -> &'static str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.5" => "serialNumber",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        _ => "OID",
    }
}

fn parse_name(input: &[u8]) -> String {
    // Certificate issuer/subject fields arrive as the contents of a Name
    // SEQUENCE, while GeneralName.directoryName carries the SEQUENCE wrapper.
    // Accept both representations without relaxing DER bounds checking.
    let mut outer_offset = 0usize;
    let name_content = match read_tlv(input, &mut outer_offset) {
        Some(sequence) if sequence.tag == 0x30 && outer_offset == input.len() => {
            sequence.value
        }
        _ => input,
    };

    let mut parts = Vec::new();
    let mut set_offset = 0usize;
    while set_offset < name_content.len() {
        let Some(set) = read_tlv(name_content, &mut set_offset) else {
            return String::from("malformed distinguished name");
        };
        if set.tag != 0x31 {
            continue;
        }
        let Some(attributes) = children(set.value) else {
            return String::from("malformed distinguished name");
        };
        for attribute in attributes {
            if attribute.tag != 0x30 {
                continue;
            }
            let Some(fields) = children(attribute.value) else {
                continue;
            };
            if fields.len() < 2 || fields[0].tag != 0x06 {
                continue;
            }
            let oid = oid_text(fields[0].value);
            let value = safe_text(fields[1].value);
            let label = oid_label(&oid);
            if label == "OID" {
                parts.push(format!("OID {oid}={value}"));
            } else {
                parts.push(format!("{label}={value}"));
            }
        }
    }

    if parts.is_empty() {
        String::from("empty distinguished name")
    } else {
        let mut output = String::new();
        for (index, part) in parts.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            output.push_str(part);
        }
        output
    }
}

fn algorithm(input: &[u8]) -> (String, String) {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return (String::from("unavailable"), String::from("unavailable"));
    };
    if sequence.tag != 0x30 {
        return (String::from("unavailable"), String::from("unavailable"));
    }
    let Some(fields) = children(sequence.value) else {
        return (
            String::from("malformed algorithm identifier"),
            String::from("unavailable"),
        );
    };
    let Some(oid) = fields.first().filter(|field| field.tag == 0x06) else {
        return (
            String::from("unknown algorithm"),
            String::from("unavailable"),
        );
    };
    let oid = oid_text(oid.value);
    let name = match oid.as_str() {
        "1.2.840.113549.1.1.1" => "RSA encryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.2.1" => "EC public key",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.2.840.10040.4.1" => "DSA",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-SHA256",
        _ => "unrecognized algorithm",
    };

    let parameters = fields
        .get(1)
        .map(|parameter| {
            if parameter.tag == 0x06 {
                let curve = oid_text(parameter.value);
                match curve.as_str() {
                    "1.2.840.10045.3.1.7" => String::from("prime256v1 / secp256r1"),
                    "1.3.132.0.34" => String::from("secp384r1"),
                    "1.3.132.0.35" => String::from("secp521r1"),
                    _ => format!("OID {curve}"),
                }
            } else if parameter.tag == 0x05 {
                String::from("NULL")
            } else {
                format!("ASN.1 tag 0x{:02X}", parameter.tag)
            }
        })
        .unwrap_or_else(|| String::from("none"));

    (format!("{name} (OID {oid})"), parameters)
}

fn time_text(field: Option<Tlv<'_>>) -> String {
    match field {
        Some(value) if value.tag == 0x17 => format!("UTCTime {}", safe_text(value.value)),
        Some(value) if value.tag == 0x18 => format!("GeneralizedTime {}", safe_text(value.value)),
        Some(_) => String::from("unsupported ASN.1 time"),
        None => String::from("unavailable"),
    }
}

fn join_or_unavailable(values: &[String]) -> String {
    if values.is_empty() {
        return String::from("unavailable / not present");
    }
    let mut output = String::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push_str("; ");
        }
        output.push_str(value);
    }
    output
}

fn parse_san(input: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return names;
    };
    if sequence.tag != 0x30 {
        return names;
    }
    let Some(entries) = children(sequence.value) else {
        return names;
    };

    for entry in entries.into_iter().take(24) {
        let value = match entry.tag {
            0x82 => format!("DNS: {}", safe_text(entry.value)),
            0x81 => format!("email: {}", safe_text(entry.value)),
            0x86 => format!("URI: {}", safe_text(entry.value)),
            0x87 if entry.value.len() == 4 => format!(
                "IP: {}.{}.{}.{}",
                entry.value[0], entry.value[1], entry.value[2], entry.value[3]
            ),
            0x87 if entry.value.len() == 16 => {
                let mut ip = String::new();
                for (index, pair) in entry.value.chunks_exact(2).enumerate() {
                    if index != 0 {
                        ip.push(':');
                    }
                    ip.push_str(&format!("{:02x}{:02x}", pair[0], pair[1]));
                }
                format!("IP: {ip}")
            }
            0xa4 => format!("directoryName: {}", parse_name(entry.value)),
            _ => continue,
        };
        names.push(value);
    }
    names
}

fn decimal_integer(bytes: &[u8]) -> String {
    let value = bytes.iter().fold(0u64, |acc, byte| {
        acc.saturating_mul(256).saturating_add(*byte as u64)
    });
    value.to_string()
}

fn parse_basic_constraints(input: &[u8]) -> String {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return String::from("malformed");
    };
    if sequence.tag != 0x30 {
        return String::from("malformed");
    }
    let Some(fields) = children(sequence.value) else {
        return String::from("malformed");
    };
    let mut is_ca = false;
    let mut path_len = None;
    for field in fields {
        if field.tag == 0x01 && !field.value.is_empty() {
            is_ca = field.value[0] != 0;
        } else if field.tag == 0x02 {
            path_len = Some(decimal_integer(field.value));
        }
    }
    match (is_ca, path_len) {
        (true, Some(length)) => format!("CA:TRUE, pathLenConstraint: {length}"),
        (true, None) => String::from("CA:TRUE"),
        (false, _) => String::from("CA:FALSE"),
    }
}

fn parse_bit_names(input: &[u8], names: &[&str]) -> Vec<String> {
    let mut offset = 0usize;
    let Some(bit_string) = read_tlv(input, &mut offset) else {
        return Vec::new();
    };
    if bit_string.tag != 0x03 || bit_string.value.is_empty() {
        return Vec::new();
    }
    let bits = &bit_string.value[1..];
    let mut output = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let byte_index = index / 8;
        let bit_index = index % 8;
        if bits
            .get(byte_index)
            .is_some_and(|byte| byte & (0x80 >> bit_index) != 0)
        {
            output.push((*name).to_string());
        }
    }
    output
}

fn parse_eku(input: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return Vec::new();
    };
    if sequence.tag != 0x30 {
        return Vec::new();
    }
    let Some(items) = children(sequence.value) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter(|item| item.tag == 0x06)
        .map(|item| {
            let oid = oid_text(item.value);
            let label = match oid.as_str() {
                "1.3.6.1.5.5.7.3.1" => "serverAuth",
                "1.3.6.1.5.5.7.3.2" => "clientAuth",
                "1.3.6.1.5.5.7.3.3" => "codeSigning",
                "1.3.6.1.5.5.7.3.4" => "emailProtection",
                "1.3.6.1.5.5.7.3.8" => "timeStamping",
                "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
                _ => "unknown EKU",
            };
            format!("{label} (OID {oid})")
        })
        .collect()
}

fn parse_ski(input: &[u8]) -> String {
    let mut offset = 0usize;
    match read_tlv(input, &mut offset) {
        Some(value) if value.tag == 0x04 => hex(value.value),
        _ => String::from("malformed"),
    }
}

fn parse_aki(input: &[u8]) -> (String, String, String) {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return (
            String::from("malformed"),
            String::from("unavailable"),
            String::from("unavailable"),
        );
    };
    if sequence.tag != 0x30 {
        return (
            String::from("malformed"),
            String::from("unavailable"),
            String::from("unavailable"),
        );
    }
    let Some(fields) = children(sequence.value) else {
        return (
            String::from("malformed"),
            String::from("unavailable"),
            String::from("unavailable"),
        );
    };
    let mut key_id = String::from("keyIdentifier not present");
    let mut issuer = String::from("not present");
    let mut serial = String::from("not present");
    for field in fields {
        match field.tag {
            0x80 => key_id = hex(field.value),
            0xa1 => issuer = format!("present (DER: {})", hex(field.value)),
            0x82 => serial = hex(field.value),
            _ => {}
        }
    }
    (key_id, issuer, serial)
}

fn parse_policies(input: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return Vec::new();
    };
    if sequence.tag != 0x30 {
        return Vec::new();
    }
    let Some(items) = children(sequence.value) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let fields = children(item.value)?;
            fields
                .first()
                .filter(|field| field.tag == 0x06)
                .map(|oid| oid_text(oid.value))
        })
        .take(24)
        .collect()
}

fn parse_aia(input: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let Some(sequence) = read_tlv(input, &mut offset) else {
        return Vec::new();
    };
    if sequence.tag != 0x30 {
        return Vec::new();
    }
    let Some(items) = children(sequence.value) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for item in items.into_iter().take(16) {
        let Some(fields) = children(item.value) else {
            continue;
        };
        if fields.len() < 2 || fields[0].tag != 0x06 {
            continue;
        }
        let method = oid_text(fields[0].value);
        let method_name = match method.as_str() {
            "1.3.6.1.5.5.7.48.1" => "OCSP",
            "1.3.6.1.5.5.7.48.2" => "CA Issuers",
            _ => "AIA",
        };
        if fields[1].tag == 0x86 {
            output.push(format!("{method_name}: {}", safe_text(fields[1].value)));
        } else {
            output.push(format!(
                "{method_name}: location tag 0x{:02X}",
                fields[1].tag
            ));
        }
    }
    output
}

fn parse_crl_uris(input: &[u8]) -> Vec<String> {
    // DistributionPoint nesting is variable; recursively collect GeneralName
    // URI values (tag 0x86) without interpreting untrusted text as control codes.
    fn visit(input: &[u8], output: &mut Vec<String>, depth: usize) {
        if depth > 8 || output.len() >= 16 {
            return;
        }
        let mut offset = 0usize;
        while offset < input.len() {
            let Some(item) = read_tlv(input, &mut offset) else {
                return;
            };
            if item.tag == 0x86 {
                output.push(safe_text(item.value));
            } else if item.tag & 0x20 != 0 || item.tag == 0xa0 || item.tag == 0xa1 {
                visit(item.value, output, depth + 1);
            }
        }
    }
    let mut output = Vec::new();
    visit(input, &mut output, 0);
    output
}

/// Parse the identifying fields and standard extensions of one X.509 DER
/// certificate. Any malformed outer/TBS structure returns an error; absent
/// optional extension fields are explicitly rendered as unavailable.
pub fn summarize_certificate(der: &[u8]) -> Result<CertificateSummary, &'static str> {
    let mut outer_offset = 0usize;
    let outer = read_tlv(der, &mut outer_offset).ok_or("invalid certificate DER")?;
    if outer.tag != 0x30 || outer_offset != der.len() {
        return Err("certificate is not one complete DER SEQUENCE");
    }
    let outer_fields = children(outer.value).ok_or("malformed Certificate sequence")?;
    if outer_fields.len() < 3
        || outer_fields[0].tag != 0x30
        || outer_fields[1].tag != 0x30
        || outer_fields[2].tag != 0x03
        || outer_fields[2].value.is_empty()
    {
        return Err("Certificate is missing required fields or has an invalid signature field");
    }

    let tbs = outer_fields[0];
    let (outer_signature_algorithm, _) = algorithm_from_tlv(outer_fields[1]);
    let signature_bytes = if outer_fields[2].tag == 0x03 {
        outer_fields[2].value.len().saturating_sub(1)
    } else {
        0
    };

    let tbs_fields = children(tbs.value).ok_or("malformed TBSCertificate sequence")?;
    let mut index = 0usize;
    let mut version = String::from("v1 (default)");
    if tbs_fields.get(index).is_some_and(|field| field.tag == 0xa0) {
        let version_field = tbs_fields[index];
        let mut inner_offset = 0usize;
        let inner = read_tlv(version_field.value, &mut inner_offset).ok_or("malformed version")?;
        if inner.tag != 0x02 || inner.value.is_empty() {
            return Err("malformed certificate version");
        }
        version = match inner.value.last().copied().unwrap_or(0) {
            0 => String::from("v1"),
            1 => String::from("v2"),
            2 => String::from("v3"),
            number => format!("unknown version {number}"),
        };
        index += 1;
    }

    let serial = *tbs_fields.get(index).ok_or("missing serial number")?;
    if serial.tag != 0x02 {
        return Err("invalid serial number field");
    }
    index += 1;
    let tbs_signature = *tbs_fields.get(index).ok_or("missing signature algorithm")?;
    index += 1;
    let issuer = *tbs_fields.get(index).ok_or("missing issuer")?;
    index += 1;
    let validity = *tbs_fields.get(index).ok_or("missing validity")?;
    index += 1;
    let subject = *tbs_fields.get(index).ok_or("missing subject")?;
    index += 1;
    let spki = *tbs_fields
        .get(index)
        .ok_or("missing SubjectPublicKeyInfo")?;

    if issuer.tag != 0x30 || subject.tag != 0x30 || validity.tag != 0x30 || spki.tag != 0x30 {
        return Err("invalid X.509 field structure");
    }

    let (tbs_sig_name, _) = algorithm_from_tlv(tbs_signature);
    let signature_algorithm = if outer_signature_algorithm == "unavailable" {
        tbs_sig_name
    } else {
        outer_signature_algorithm
    };

    let validity_fields = children(validity.value).ok_or("malformed validity sequence")?;
    if validity_fields.len() != 2 {
        return Err("Validity must contain exactly notBefore and notAfter");
    }
    let not_before = time_text(validity_fields.first().copied());
    let not_after = time_text(validity_fields.get(1).copied());

    let spki_fields = children(spki.value).ok_or("malformed SubjectPublicKeyInfo")?;
    if spki_fields.len() < 2 || spki_fields[1].tag != 0x03 || spki_fields[1].value.is_empty() {
        return Err("SubjectPublicKeyInfo is missing its BIT STRING");
    }
    let public_key_algorithm_field = *spki_fields.first().ok_or("missing public key algorithm")?;
    let (public_key_algorithm, public_key_parameters) =
        algorithm_from_tlv(public_key_algorithm_field);
    let public_key_bits = spki_fields
        .get(1)
        .filter(|field| field.tag == 0x03)
        .map(|bits| {
            let encoded_bits = bits.value.len().saturating_sub(1).saturating_mul(8);
            encoded_bits.saturating_sub(bits.value.first().copied().unwrap_or(0) as usize)
        })
        .unwrap_or(0);

    let mut summary = CertificateSummary {
        version,
        serial_number: hex(serial.value),
        signature_algorithm,
        issuer: parse_name(issuer.value),
        not_before,
        not_after,
        subject: parse_name(subject.value),
        public_key_algorithm,
        public_key_parameters,
        public_key_bits,
        basic_constraints: String::from("not present"),
        key_usage: Vec::new(),
        extended_key_usage: Vec::new(),
        subject_alt_names: Vec::new(),
        subject_key_identifier: String::from("not present"),
        authority_key_identifier: String::from("not present"),
        authority_certificate_issuer: String::from("not present"),
        authority_certificate_serial_number: String::from("not present"),
        issuer_unique_id: String::from("not present"),
        subject_unique_id: String::from("not present"),
        certificate_policies: Vec::new(),
        authority_info_access: Vec::new(),
        crl_distribution_points: Vec::new(),
        extensions: Vec::new(),
        signature_value_bytes: signature_bytes,
        der_bytes: der.len(),
    };

    for field in tbs_fields.iter().skip(index + 1) {
        match field.tag {
            0x81 => {
                summary.issuer_unique_id = hex(field.value);
                continue;
            }
            0x82 => {
                summary.subject_unique_id = hex(field.value);
                continue;
            }
            0xa3 => {}
            _ => continue,
        }
        let mut explicit_offset = 0usize;
        let extension_sequence =
            read_tlv(field.value, &mut explicit_offset).ok_or("malformed extensions wrapper")?;
        if extension_sequence.tag != 0x30 {
            return Err("extensions are not a SEQUENCE");
        }
        let extension_fields = children(extension_sequence.value).ok_or("malformed extensions")?;
        for extension in extension_fields.into_iter().take(48) {
            if extension.tag != 0x30 {
                continue;
            }
            let Some(parts) = children(extension.value) else {
                continue;
            };
            if parts.len() < 2 || parts[0].tag != 0x06 {
                continue;
            }
            let oid = oid_text(parts[0].value);
            let mut critical = false;
            let mut value_index = 1usize;
            if parts.get(value_index).is_some_and(|part| part.tag == 0x01) {
                critical = parts[value_index].value.first().copied().unwrap_or(0) != 0;
                value_index += 1;
            }
            let Some(value) = parts.get(value_index).filter(|part| part.tag == 0x04) else {
                summary
                    .extensions
                    .push(format!("{oid}, critical={critical}, value unavailable"));
                continue;
            };
            summary
                .extensions
                .push(format!("{oid}, critical={critical}"));
            match oid.as_str() {
                "2.5.29.17" => summary.subject_alt_names = parse_san(value.value),
                "2.5.29.19" => summary.basic_constraints = parse_basic_constraints(value.value),
                "2.5.29.15" => {
                    summary.key_usage = parse_bit_names(
                        value.value,
                        &[
                            "digitalSignature",
                            "contentCommitment",
                            "keyEncipherment",
                            "dataEncipherment",
                            "keyAgreement",
                            "keyCertSign",
                            "cRLSign",
                            "encipherOnly",
                            "decipherOnly",
                        ],
                    )
                }
                "2.5.29.37" => summary.extended_key_usage = parse_eku(value.value),
                "2.5.29.14" => summary.subject_key_identifier = parse_ski(value.value),
                "2.5.29.35" => {
                    let (key_id, issuer, serial) = parse_aki(value.value);
                    summary.authority_key_identifier = key_id;
                    summary.authority_certificate_issuer = issuer;
                    summary.authority_certificate_serial_number = serial;
                }
                "2.5.29.32" => summary.certificate_policies = parse_policies(value.value),
                "1.3.6.1.5.5.7.1.1" => summary.authority_info_access = parse_aia(value.value),
                "2.5.29.31" => summary.crl_distribution_points = parse_crl_uris(value.value),
                _ => {}
            }
        }
    }

    Ok(summary)
}

fn algorithm_from_tlv(field: Tlv<'_>) -> (String, String) {
    let mut encoded = Vec::new();
    encoded.push(field.tag);
    // This helper is only used for already parsed AlgorithmIdentifier values.
    // Reconstruct a minimal TLV to share the same safe OID/parameter parser.
    let length = field.value.len();
    if length < 128 {
        encoded.push(length as u8);
    } else if length <= 255 {
        encoded.push(0x81);
        encoded.push(length as u8);
    } else {
        return (
            String::from("oversized algorithm identifier"),
            String::from("unavailable"),
        );
    }
    encoded.extend_from_slice(field.value);
    algorithm(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(tag);
        if value.len() < 128 {
            output.push(value.len() as u8);
        } else {
            output.push(0x81);
            output.push(value.len() as u8);
        }
        output.extend_from_slice(value);
        output
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
        tlv(0x30, &content)
    }

    #[test]
    fn parses_core_certificate_fields_and_san() {
        let oid_cn = tlv(0x06, &[0x55, 0x04, 0x03]);
        let cn = tlv(0x0c, b"example.test");
        let attribute = sequence(&[oid_cn, cn]);
        let issuer = sequence(&[tlv(0x31, &attribute)]);
        let subject = issuer.clone();

        let algorithm = sequence(&[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            ),
            tlv(0x05, &[]),
        ]);
        let validity = sequence(&[tlv(0x17, b"260101000000Z"), tlv(0x17, b"270101000000Z")]);
        let spki = sequence(&[algorithm.clone(), tlv(0x03, &[0, 0xaa, 0xbb, 0xcc])]);

        let san_value = sequence(&[tlv(0x82, b"example.test")]);
        let san_ext = sequence(&[tlv(0x06, &[0x55, 0x1d, 0x11]), tlv(0x04, &san_value)]);
        let extensions = tlv(0xa3, &sequence(&[san_ext]));
        let tbs = sequence(&[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[0x01, 0x23]),
            algorithm.clone(),
            issuer,
            validity,
            subject,
            spki,
            extensions,
        ]);
        let certificate = sequence(&[tbs, algorithm, tlv(0x03, &[0, 0xde, 0xad])]);

        let summary = summarize_certificate(&certificate).unwrap();
        assert_eq!(summary.version, "v3");
        assert_eq!(summary.serial_number, "01:23");
        assert!(summary.subject.contains("CN=example.test"));
        assert!(summary.issuer.contains("CN=example.test"));
        assert_eq!(summary.public_key_bits, 24);
        assert_eq!(summary.subject_alt_names, vec!["DNS: example.test"]);
        assert_eq!(summary.signature_value_bytes, 2);
    }

    #[test]
    fn rejects_truncated_certificate_der() {
        assert!(summarize_certificate(&[0x30, 0x82, 0x01]).is_err());
    }

    #[test]
    fn oid_decoder_reports_invalid_continuation() {
        assert_eq!(oid_text(&[0x2a, 0x81]), "invalid OID");
    }
}
