//! Hickory-backed DNS stub client for UEFI.
//!
//! Hickory handles DNS wire-format construction and parsing. Packet I/O is
//! supplied by a UEFI UDP4 adapter; no host socket or std networking is used.
//! The adapter must only return a datagram received from the exact configured
//! resolver address and UDP source port.

use alloc::format;
use alloc::string::String;
use core::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

use crate::entropy::SecureRandom;

pub const DNS_PORT: u16 = 53;
pub const DNS_UDP_MAX_PACKET: usize = 512;
const DNS_ATTEMPTS: usize = 2;
const DEFAULT_TIMEOUT_MS: u64 = 2500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsIoError {
    Timeout,
    Network,
    InvalidDatagram,
}

pub trait UdpDnsTransport {
    /// Send one UDP DNS query and copy its matching response into output.
    ///
    /// Implementations must bind an ephemeral local UDP port, send to
    /// resolver:port, reject packets from every other source address or port,
    /// reject datagrams larger than output, and enforce timeout_ms.
    fn exchange(
        &mut self,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    InvalidName,
    EntropyUnavailable,
    EncodeFailed,
    DecodeFailed,
    TransactionMismatch,
    NotAResponse,
    QuestionMismatch,
    Truncated,
    NameDoesNotExist,
    ServerFailure,
    Refused,
    ResponseError,
    NoAddress,
    Timeout,
    Network,
    InvalidDatagram,
}

/// Resolve a hostname to its IPv4 A record using a recursive resolver.
///
/// Transaction IDs are generated from the caller's cryptographically secure
/// random source. The query is retried once after a timeout with a fresh ID.
/// Truncated UDP responses fail closed; DNS-over-TCP retry is a later addition.
pub fn resolve_a<T: UdpDnsTransport, R: SecureRandom>(
    transport: &mut T,
    random: &mut R,
    resolver: Ipv4Addr,
    hostname: &str,
    timeout_ms: u64,
) -> Result<Ipv4Addr, DnsError> {
    let mut response = [0u8; DNS_UDP_MAX_PACKET];

    for attempt in 0..DNS_ATTEMPTS {
        let mut id_bytes = [0u8; 2];
        random
            .fill_bytes(&mut id_bytes)
            .map_err(|_| DnsError::EntropyUnavailable)?;
        let transaction_id = u16::from_be_bytes(id_bytes);

        let query = build_a_query(hostname, transaction_id)?;
        match transport.exchange(
            resolver,
            DNS_PORT,
            &query,
            &mut response,
            if timeout_ms == 0 {
                DEFAULT_TIMEOUT_MS
            } else {
                timeout_ms
            },
        ) {
            Ok(length) => {
                if length > response.len() {
                    return Err(DnsError::InvalidDatagram);
                }
                return parse_a_response(&response[..length], transaction_id, hostname);
            }
            Err(DnsIoError::Timeout) if attempt + 1 < DNS_ATTEMPTS => continue,
            Err(DnsIoError::Timeout) => return Err(DnsError::Timeout),
            Err(DnsIoError::Network) => return Err(DnsError::Network),
            Err(DnsIoError::InvalidDatagram) => return Err(DnsError::InvalidDatagram),
        }
    }

    Err(DnsError::Timeout)
}

/// Encode a DNS A/IN recursive query using Hickory's DNS protocol types.
pub fn build_a_query(hostname: &str, transaction_id: u16) -> Result<alloc::vec::Vec<u8>, DnsError> {
    let fqdn = absolute_name(hostname)?;
    let name = Name::from_ascii(fqdn.as_str()).map_err(|_| DnsError::InvalidName)?;

    let mut message = Message::new(transaction_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::A));

    message.to_vec().map_err(|_| DnsError::EncodeFailed)
}

/// Validate a DNS response and return an A record owned by the queried name.
pub fn parse_a_response(
    packet: &[u8],
    expected_id: u16,
    hostname: &str,
) -> Result<Ipv4Addr, DnsError> {
    let fqdn = absolute_name(hostname)?;
    let expected_name = Name::from_ascii(fqdn.as_str()).map_err(|_| DnsError::InvalidName)?;
    let message = Message::from_vec(packet).map_err(|_| DnsError::DecodeFailed)?;
    let metadata = message.metadata;

    if metadata.id != expected_id {
        return Err(DnsError::TransactionMismatch);
    }
    if metadata.message_type != MessageType::Response || metadata.op_code != OpCode::Query {
        return Err(DnsError::NotAResponse);
    }
    if metadata.truncation {
        return Err(DnsError::Truncated);
    }

    match metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Err(DnsError::NameDoesNotExist),
        ResponseCode::ServFail => return Err(DnsError::ServerFailure),
        ResponseCode::Refused => return Err(DnsError::Refused),
        _ => return Err(DnsError::ResponseError),
    }

    let question = message.queries.first().ok_or(DnsError::QuestionMismatch)?;
    if question.query_type != RecordType::A
        || question.query_class != DNSClass::IN
        || question.name != expected_name
    {
        return Err(DnsError::QuestionMismatch);
    }

    for record in &message.answers {
        if record.name == expected_name && record.dns_class == DNSClass::IN {
            if let RData::A(address) = &record.data {
                return Ok(address.0);
            }
        }
    }

    Err(DnsError::NoAddress)
}

fn absolute_name(hostname: &str) -> Result<String, DnsError> {
    let hostname = hostname.trim().trim_end_matches('.');
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'/' || byte == b'\\' || byte == 0)
    {
        return Err(DnsError::InvalidName);
    }

    let mut label_len = 0usize;
    for byte in hostname.bytes() {
        if byte == b'.' {
            if label_len == 0 || label_len > 63 {
                return Err(DnsError::InvalidName);
            }
            label_len = 0;
        } else {
            label_len += 1;
        }
    }
    if label_len == 0 || label_len > 63 {
        return Err(DnsError::InvalidName);
    }

    Ok(format!("{hostname}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use hickory_proto::rr::{Record, rdata::A};

    struct FixedRandom(u16);

    impl SecureRandom for FixedRandom {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), ()> {
            if output.len() != 2 {
                return Err(());
            }
            output.copy_from_slice(&self.0.to_be_bytes());
            Ok(())
        }
    }

    struct FakeUdp {
        packet: Vec<u8>,
        calls: usize,
        last_port: u16,
    }

    impl UdpDnsTransport for FakeUdp {
        fn exchange(
            &mut self,
            _resolver: Ipv4Addr,
            port: u16,
            query: &[u8],
            output: &mut [u8],
            _timeout_ms: u64,
        ) -> Result<usize, DnsIoError> {
            self.calls += 1;
            self.last_port = port;
            let request = Message::from_vec(query).map_err(|_| DnsIoError::InvalidDatagram)?;
            let reply = Message::from_vec(&self.packet).map_err(|_| DnsIoError::InvalidDatagram)?;
            if request.id != reply.id || self.packet.len() > output.len() {
                return Err(DnsIoError::InvalidDatagram);
            }
            output[..self.packet.len()].copy_from_slice(&self.packet);
            Ok(self.packet.len())
        }
    }

    fn response(id: u16) -> Vec<u8> {
        let name = Name::from_ascii("example.org.").unwrap();
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        message.to_vec().unwrap()
    }

    #[test]
    fn builds_recursive_dns_query_with_supplied_random_id() {
        let wire = build_a_query("example.org", 0x7A31).unwrap();
        let message = Message::from_vec(&wire).unwrap();
        assert_eq!(message.metadata.id, 0x7A31);
        assert_eq!(message.metadata.message_type, MessageType::Query);
        assert!(message.metadata.recursion_desired);
        assert_eq!(message.queries[0].query_type, RecordType::A);
    }

    #[test]
    fn validates_dns_response_and_extracts_ipv4() {
        assert_eq!(
            parse_a_response(&response(0x7A31), 0x7A31, "example.org").unwrap(),
            Ipv4Addr::new(93, 184, 216, 34)
        );
        assert_eq!(
            parse_a_response(&response(0x7A31), 0x7A32, "example.org"),
            Err(DnsError::TransactionMismatch)
        );
    }

    #[test]
    fn resolver_uses_hickory_and_firmware_rng_on_port_53() {
        let mut udp = FakeUdp {
            packet: response(0x7A31),
            calls: 0,
            last_port: 0,
        };
        let mut random = FixedRandom(0x7A31);
        let address = resolve_a(
            &mut udp,
            &mut random,
            Ipv4Addr::new(192, 0, 2, 53),
            "example.org",
            1000,
        )
        .unwrap();

        assert_eq!(address, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(udp.calls, 1);
        assert_eq!(udp.last_port, 53);
    }

    #[test]
    fn rejects_invalid_hostnames_and_truncated_packets() {
        assert_eq!(build_a_query("", 1), Err(DnsError::InvalidName));
        assert_eq!(
            build_a_query("invalid..example", 1),
            Err(DnsError::InvalidName)
        );

        let mut truncated = Message::new(7, MessageType::Response, OpCode::Query);
        truncated.metadata.truncation = true;
        truncated.add_query(Query::query(
            Name::from_ascii("example.org.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            parse_a_response(&truncated.to_vec().unwrap(), 7, "example.org"),
            Err(DnsError::Truncated)
        );
    }
}
