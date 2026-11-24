//! Small bounded HTTP/1.1 client codec for the UEFI browser.
//!
//! Transport-agnostic: callers send request bytes over a TCP or Mbed TLS stream
//! and pass response bytes to parse_response. Supports close-delimited,
//! Content-Length, and chunked response bodies without depending on std.

use crate::tls::TlsStreamIo;
use crate::url::{Scheme, Url};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const HEADER_LIMIT: usize = 32 * 1024;
const HEADER_COUNT_LIMIT: usize = 128;
const RESPONSE_WIRE_OVERHEAD_LIMIT: usize = 64 * 1024;
const STREAM_BUFFER_SIZE: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.header("location").is_some()
    }
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    HeaderTooLarge,
    MissingHeaderTerminator,
    InvalidStatusLine,
    InvalidStatusCode,
    InvalidHeader,
    TooManyHeaders,
    InvalidContentLength,
    ConflictingContentLength,
    UnsupportedTransferEncoding,
    InvalidChunkSize,
    InvalidChunkTerminator,
    IncompleteBody,
    BodyTooLarge,
    SendError,
    ReceiveError,
    NoFinalResponse,
}

/// Construct a minimal HTTP/1.1 GET request.
pub fn build_get_request(url: &Url) -> Vec<u8> {
    build_request(url, "GET", &[])
}

/// Construct a bounded form POST request. The caller supplies an already
/// URL-encoded body; no remote content controls request headers.
pub fn build_post_request(url: &Url, body: &[u8]) -> Vec<u8> {
    build_request(url, "POST", body)
}

fn build_request(url: &Url, method: &str, body: &[u8]) -> Vec<u8> {
    build_request_with_validators(url, method, body, None, None)
}

/// Build a cache-revalidation GET. Validator values are bounded and checked
/// before they are copied into HTTP header lines.
pub fn build_conditional_get_request(
    url: &Url,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Vec<u8> {
    build_request_with_validators(url, "GET", &[], etag, last_modified)
}

fn valid_validator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn build_request_with_validators(
    url: &Url,
    method: &str,
    body: &[u8],
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Vec<u8> {
    let host = host_header(url);
    let mut request = String::new();
    request.push_str(method);
    request.push(' ');
    request.push_str(&url.path_and_query);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(&host);
    request.push_str("\r\nUser-Agent: UEFI-Browser/0.1\r\n");
    request.push_str("Accept: text/html, text/plain;q=0.9, */*;q=0.1\r\n");
    request.push_str("Accept-Encoding: identity\r\n");
    if method == "GET" {
        if let Some(etag) = etag.filter(|value| valid_validator(value)) {
            request.push_str("If-None-Match: ");
            request.push_str(etag);
            request.push_str("\r\n");
        }
        if let Some(modified) = last_modified.filter(|value| valid_validator(value)) {
            request.push_str("If-Modified-Since: ");
            request.push_str(modified);
            request.push_str("\r\n");
        }
    }
    if method == "POST" {
        request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");
    let mut bytes = request.into_bytes();
    if method == "POST" {
        bytes.extend_from_slice(body);
    }
    bytes
}

/// Send an HTTP GET over any byte stream and read the response until EOF.
pub fn exchange_get<S: TlsStreamIo>(
    stream: &mut S,
    url: &Url,
    max_body: usize,
) -> Result<HttpResponse, HttpError> {
    exchange_request(stream, url, "GET", &[], max_body)
}

/// Send an application/x-www-form-urlencoded POST over any byte stream.
pub fn exchange_post<S: TlsStreamIo>(
    stream: &mut S,
    url: &Url,
    body: &[u8],
    max_body: usize,
) -> Result<HttpResponse, HttpError> {
    exchange_request(stream, url, "POST", body, max_body)
}

/// Shared bounded request exchange used by GET navigation and HTML forms.
pub fn exchange_request<S: TlsStreamIo>(
    stream: &mut S,
    url: &Url,
    method: &str,
    body: &[u8],
    max_body: usize,
) -> Result<HttpResponse, HttpError> {
    exchange_request_with_validators(stream, url, method, body, max_body, None, None)
}

/// Send GET/POST with optional GET cache validators.
pub fn exchange_request_with_validators<S: TlsStreamIo>(
    stream: &mut S,
    url: &Url,
    method: &str,
    body: &[u8],
    max_body: usize,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<HttpResponse, HttpError> {
    if !matches!(method, "GET" | "POST") || (method == "GET" && !body.is_empty()) {
        return Err(HttpError::SendError);
    }
    let request = build_request_with_validators(url, method, body, etag, last_modified);
    let mut sent = 0usize;
    while sent < request.len() {
        let count = stream
            .send(&request[sent..])
            .map_err(|_| HttpError::SendError)?;
        if count == 0 || count > request.len() - sent {
            return Err(HttpError::SendError);
        }
        sent += count;
    }

    let wire_limit = HEADER_LIMIT
        .checked_add(max_body)
        .and_then(|length| length.checked_add(RESPONSE_WIRE_OVERHEAD_LIMIT))
        .ok_or(HttpError::BodyTooLarge)?;
    let mut response = Vec::new();
    let mut buffer = [0u8; STREAM_BUFFER_SIZE];

    loop {
        let count = stream
            .receive(&mut buffer)
            .map_err(|_| HttpError::ReceiveError)?;
        if count == 0 {
            break;
        }
        if count > buffer.len()
            || response
                .len()
                .checked_add(count)
                .is_none_or(|total| total > wire_limit)
        {
            return Err(HttpError::BodyTooLarge);
        }
        response.extend_from_slice(&buffer[..count]);
        if response_is_complete(&response, max_body)? {
            break;
        }
    }

    parse_response(&response, max_body)
}

/// Return true once a length-delimited or chunked HTTP response is complete.
/// Close-delimited responses still require transport EOF.
fn response_is_complete(input: &[u8], max_body: usize) -> Result<bool, HttpError> {
    let Some(header_end) = find_bytes(input, b"\r\n\r\n") else {
        if input.len() > HEADER_LIMIT {
            return Err(HttpError::HeaderTooLarge);
        }
        return Ok(false);
    };
    if header_end > HEADER_LIMIT {
        return Err(HttpError::HeaderTooLarge);
    }

    let headers =
        core::str::from_utf8(&input[..header_end]).map_err(|_| HttpError::InvalidHeader)?;
    let status_line = headers
        .split("\r\n")
        .next()
        .ok_or(HttpError::InvalidStatusLine)?;
    let (_, status, _) = parse_status_line(status_line)?;
    if (100..200).contains(&status) && status != 101 {
        let next = header_end
            .checked_add(4)
            .ok_or(HttpError::NoFinalResponse)?;
        if next >= input.len() {
            return Ok(false);
        }
        return response_is_complete(&input[next..], max_body);
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in headers.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':').ok_or(HttpError::InvalidHeader)?;
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| HttpError::InvalidContentLength)?;
            if content_length.is_some_and(|previous| previous != length) {
                return Err(HttpError::ConflictingContentLength);
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        }
    }

    if chunked || content_length.is_some() {
        match parse_response(input, max_body) {
            Ok(_) => Ok(true),
            Err(
                HttpError::IncompleteBody
                | HttpError::InvalidChunkSize
                | HttpError::InvalidChunkTerminator,
            ) => Ok(false),
            Err(error) => Err(error),
        }
    } else {
        Ok(false)
    }
}

fn host_header(url: &Url) -> String {
    let default_port = match url.scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    if url.port == default_port {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

/// Parse a complete HTTP response held in memory.
///
/// max_body bounds the decoded body. For close-delimited responses, input must
/// represent all bytes read up to EOF. Bytes after Content-Length are ignored.
pub fn parse_response(input: &[u8], max_body: usize) -> Result<HttpResponse, HttpError> {
    let input = skip_informational_responses(input)?;
    let header_end = find_bytes(input, b"\r\n\r\n").ok_or_else(|| {
        if input.len() > HEADER_LIMIT {
            HttpError::HeaderTooLarge
        } else {
            HttpError::MissingHeaderTerminator
        }
    })?;
    if header_end > HEADER_LIMIT {
        return Err(HttpError::HeaderTooLarge);
    }

    let header_text =
        core::str::from_utf8(&input[..header_end]).map_err(|_| HttpError::InvalidHeader)?;
    let mut lines = header_text.split("\r\n");
    let (version, status, reason) =
        parse_status_line(lines.next().ok_or(HttpError::InvalidStatusLine)?)?;

    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= HEADER_COUNT_LIMIT {
            return Err(HttpError::TooManyHeaders);
        }
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError::InvalidHeader);
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::InvalidHeader)?;
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&byte) || byte == 0x60
            })
        {
            return Err(HttpError::InvalidHeader);
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(HttpError::InvalidHeader);
        }
        headers.push(Header {
            name: name.to_ascii_lowercase(),
            value: value.to_string(),
        });
    }

    let body_start = header_end + 4;
    let encoded_body = &input[body_start..];
    let no_body = (100..200).contains(&status) || matches!(status, 204 | 304);
    let body = if no_body {
        Vec::new()
    } else {
        decode_body(encoded_body, &headers, max_body)?
    };

    Ok(HttpResponse {
        version,
        status,
        reason,
        headers,
        body,
    })
}

/// Skip informational responses (for example 100 Continue and 103 Early Hints)
/// so the parser returns the final response to the original request.
fn skip_informational_responses(mut input: &[u8]) -> Result<&[u8], HttpError> {
    loop {
        let header_end =
            find_bytes(input, b"\r\n\r\n").ok_or(HttpError::MissingHeaderTerminator)?;
        if header_end > HEADER_LIMIT {
            return Err(HttpError::HeaderTooLarge);
        }
        let headers =
            core::str::from_utf8(&input[..header_end]).map_err(|_| HttpError::InvalidHeader)?;
        let status_line = headers
            .split("\r\n")
            .next()
            .ok_or(HttpError::InvalidStatusLine)?;
        let (_, status, _) = parse_status_line(status_line)?;
        if !(100..200).contains(&status) || status == 101 {
            return Ok(input);
        }
        let next = header_end
            .checked_add(4)
            .ok_or(HttpError::NoFinalResponse)?;
        if next >= input.len() {
            return Err(HttpError::NoFinalResponse);
        }
        input = &input[next..];
    }
}

fn parse_status_line(line: &str) -> Result<(String, u16, String), HttpError> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(HttpError::InvalidStatusLine)?;
    let status = parts.next().ok_or(HttpError::InvalidStatusLine)?;
    let reason = parts.next().unwrap_or("").to_string();
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(HttpError::InvalidStatusLine);
    }
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::InvalidStatusCode);
    }
    let code = status
        .parse::<u16>()
        .map_err(|_| HttpError::InvalidStatusCode)?;
    Ok((version.to_string(), code, reason))
}

fn decode_body(body: &[u8], headers: &[Header], max_body: usize) -> Result<Vec<u8>, HttpError> {
    let mut content_length: Option<usize> = None;
    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        let value = header
            .value
            .trim()
            .parse::<usize>()
            .map_err(|_| HttpError::InvalidContentLength)?;
        if content_length.is_some_and(|previous| previous != value) {
            return Err(HttpError::ConflictingContentLength);
        }
        content_length = Some(value);
    }

    let transfer_encoding = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|h| h.value.as_str())
        .collect::<Vec<_>>();

    if !transfer_encoding.is_empty() {
        let joined = transfer_encoding.join(",");
        let codings = joined
            .split(',')
            .map(|coding| coding.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        if codings.last().map(String::as_str) != Some("chunked")
            || codings
                .iter()
                .any(|coding| coding != "identity" && coding != "chunked")
        {
            return Err(HttpError::UnsupportedTransferEncoding);
        }
        if content_length.is_some() {
            return Err(HttpError::ConflictingContentLength);
        }
        return decode_chunked(body, max_body);
    }

    if let Some(length) = content_length {
        if length > max_body {
            return Err(HttpError::BodyTooLarge);
        }
        if body.len() < length {
            return Err(HttpError::IncompleteBody);
        }
        return Ok(body[..length].to_vec());
    }
    if body.len() > max_body {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(body.to_vec())
}

fn decode_chunked(input: &[u8], max_body: usize) -> Result<Vec<u8>, HttpError> {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    loop {
        let line_end = find_bytes(&input[cursor..], b"\r\n")
            .map(|offset| cursor + offset)
            .ok_or(HttpError::InvalidChunkSize)?;
        let line = core::str::from_utf8(&input[cursor..line_end])
            .map_err(|_| HttpError::InvalidChunkSize)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || !size_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HttpError::InvalidChunkSize);
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpError::InvalidChunkSize)?;
        cursor = line_end + 2;

        if size == 0 {
            if input.get(cursor..cursor + 2) == Some(b"\r\n") {
                return Ok(output);
            }
            let trailers_end = find_bytes(&input[cursor..], b"\r\n\r\n")
                .map(|offset| cursor + offset)
                .ok_or(HttpError::InvalidChunkTerminator)?;
            let trailers = core::str::from_utf8(&input[cursor..trailers_end])
                .map_err(|_| HttpError::InvalidHeader)?;
            if trailers.lines().any(|line| !line.contains(':')) {
                return Err(HttpError::InvalidHeader);
            }
            return Ok(output);
        }

        if output
            .len()
            .checked_add(size)
            .is_none_or(|total| total > max_body)
        {
            return Err(HttpError::BodyTooLarge);
        }
        let chunk_end = cursor
            .checked_add(size)
            .ok_or(HttpError::InvalidChunkSize)?;
        let chunk = input
            .get(cursor..chunk_end)
            .ok_or(HttpError::IncompleteBody)?;
        output.extend_from_slice(chunk);
        if input.get(chunk_end..chunk_end + 2) != Some(b"\r\n") {
            return Err(HttpError::InvalidChunkTerminator);
        }
        cursor = chunk_end + 2;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::Url;

    #[test]
    fn detects_complete_content_length_response_without_waiting_for_eof() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(response_is_complete(response, 1024).unwrap());
        assert!(
            !response_is_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhell", 1024)
                .unwrap()
        );
    }

    #[test]
    fn detects_complete_chunked_response_without_waiting_for_eof() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(response_is_complete(response, 1024).unwrap());
    }

    #[test]
    fn skips_early_hints_and_returns_the_final_http_response() {
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
        assert!(response_is_complete(response, 1024).unwrap());
        let parsed = parse_response(response, 1024).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hello");
    }

    #[test]
    fn an_interim_response_alone_is_not_a_complete_page() {
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n";
        assert!(!response_is_complete(response, 1024).unwrap());
    }

    #[test]
    fn close_delimited_response_waits_for_transport_eof() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        assert!(!response_is_complete(response, 1024).unwrap());
    }

    #[test]
    fn builds_conditional_get_with_safe_cache_validators() {
        let url = Url::parse("https://example.org/docs?q=rust").unwrap();
        let request = String::from_utf8(build_conditional_get_request(
            &url,
            Some("\"v1\""),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
        )).unwrap();
        assert!(request.contains("If-None-Match: \"v1\"\r\n"));
        assert!(request.contains("If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n"));
        assert!(!request.contains("If-None-Match: bad\\r\\nInjected"));
        let unsafe_request = String::from_utf8(build_conditional_get_request(
            &url,
            Some("bad\\r\\nInjected: yes"),
            None,
        )).unwrap();
        assert!(!unsafe_request.contains("Injected: yes"));
    }

    #[test]
    fn builds_http11_request_with_correct_host_and_target() {
        let url = Url::parse("https://example.org:8443/docs?q=uefi").unwrap();
        let request = String::from_utf8(build_get_request(&url)).unwrap();
        assert!(request.starts_with("GET /docs?q=uefi HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.org:8443\r\n"));
        assert!(request.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn builds_urlencoded_post_request_with_exact_content_length() {
        let url = Url::parse("https://example.org/search").unwrap();
        let body = b"q=UEFI+browser&safe=yes";
        let request = String::from_utf8(build_post_request(&url, body)).unwrap();
        assert!(request.starts_with("POST /search HTTP/1.1\r\n"));
        assert!(request.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(request.contains("Content-Length: 23\r\n"));
        assert!(request.ends_with("\r\n\r\nq=UEFI+browser&safe=yes"));
    }

    #[test]
    fn parses_content_length_response() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let response = parse_response(wire, 1024).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type(), Some("text/plain"));
        assert_eq!(response.body, b"hello");
    }

    #[test]
    fn decodes_chunked_response_with_extensions_and_trailers() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Foo: bar\r\n\r\n";
        let response = parse_response(wire, 1024).unwrap();
        assert_eq!(response.body, b"Wikipedia");
    }

    #[test]
    fn exposes_redirect_metadata() {
        let wire = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
        let response = parse_response(wire, 1024).unwrap();
        assert!(response.is_redirect());
        assert_eq!(response.location(), Some("/next"));
    }

    struct FakeStream {
        request: Vec<u8>,
        response: Vec<u8>,
        response_at: usize,
    }

    impl TlsStreamIo for FakeStream {
        fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            let count = core::cmp::min(7, bytes.len());
            self.request.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> {
            if self.response_at == self.response.len() {
                return Ok(0);
            }
            let count = core::cmp::min(
                core::cmp::min(11, output.len()),
                self.response.len() - self.response_at,
            );
            output[..count]
                .copy_from_slice(&self.response[self.response_at..self.response_at + count]);
            self.response_at += count;
            Ok(count)
        }
    }

    #[test]
    fn exchange_get_handles_partial_writes_and_short_reads() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npage".to_vec();
        let mut stream = FakeStream {
            request: Vec::new(),
            response,
            response_at: 0,
        };
        let url = Url::parse("https://example.org/").unwrap();

        let page = exchange_get(&mut stream, &url, 4096).unwrap();

        assert_eq!(page.status, 200);
        assert_eq!(page.body, b"page");
        let request = core::str::from_utf8(&stream.request).unwrap();
        assert!(request.starts_with("GET / HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.org\r\n"));
    }

    #[test]
    fn rejects_conflicting_lengths_and_oversized_body() {
        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(
            parse_response(conflicting, 1024),
            Err(HttpError::ConflictingContentLength)
        );
        let too_large = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        assert_eq!(parse_response(too_large, 4), Err(HttpError::BodyTooLarge));
    }
}
