use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub fragment: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlError {
    Empty,
    UnsupportedScheme,
    InvalidAuthority,
    InvalidPort,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("URL is empty"),
            Self::UnsupportedScheme => f.write_str("only HTTP and HTTPS are supported"),
            Self::InvalidAuthority => f.write_str("invalid URL authority"),
            Self::InvalidPort => f.write_str("invalid TCP port"),
        }
    }
}

impl Url {
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(UrlError::Empty);
        }

        let (without_fragment, fragment) = input
            .split_once('#')
            .map(|(before, after)| (before, Some(after.to_string())))
            .unwrap_or((input, None));
        let (scheme, rest) = if let Some(value) = without_fragment.strip_prefix("https://") {
            (Scheme::Https, value)
        } else if let Some(value) = without_fragment.strip_prefix("http://") {
            (Scheme::Http, value)
        } else if without_fragment.contains("://") {
            return Err(UrlError::UnsupportedScheme);
        } else {
            (Scheme::Https, without_fragment)
        };

        if rest.is_empty() {
            return Err(UrlError::InvalidAuthority);
        }

        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let suffix = &rest[authority_end..];

        if authority.is_empty()
            || authority.contains('@')
            || authority.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(UrlError::InvalidAuthority);
        }

        let (host, port) = parse_authority(authority, scheme)?;
        let path_and_query = if suffix.is_empty() {
            String::from("/")
        } else if suffix.starts_with('?') {
            format!("/{suffix}")
        } else {
            suffix.to_string()
        };

        Ok(Self {
            scheme,
            host,
            port,
            path_and_query,
            fragment,
        })
    }

    pub fn origin(&self) -> String {
        let default = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default {
            format!("{}://{}", self.scheme_text(), self.host)
        } else {
            format!("{}://{}:{}", self.scheme_text(), self.host, self.port)
        }
    }

    pub fn as_string(&self) -> String {
        let mut output = format!("{}{}", self.origin(), self.path_and_query);
        if let Some(fragment) = &self.fragment {
            output.push('#');
            output.push_str(fragment);
        }
        output
    }

    pub fn scheme_text(&self) -> &'static str {
        match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    pub fn resolve(&self, reference: &str) -> Result<Self, UrlError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Ok(self.clone());
        }
        if let Some(fragment) = reference.strip_prefix('#') {
            let mut target = self.clone();
            target.fragment = Some(fragment.to_string());
            return Ok(target);
        }

        let (reference, fragment) = reference
            .split_once('#')
            .map(|(before, after)| (before, Some(after)))
            .unwrap_or((reference, None));

        if reference.starts_with("http://") || reference.starts_with("https://") {
            let mut target = Self::parse(reference)?;
            target.fragment = fragment.map(ToString::to_string);
            return Ok(target);
        }
        if reference.contains("://") {
            return Err(UrlError::UnsupportedScheme);
        }

        let absolute = if reference.starts_with("//") {
            format!("{}:{reference}", self.scheme_text())
        } else if reference.starts_with('/') {
            format!("{}{}", self.origin(), normalize_path(reference))
        } else if reference.starts_with('?') {
            let path = self.path_and_query.split('?').next().unwrap_or("/");
            format!("{}{}{}", self.origin(), path, reference)
        } else {
            let path = self.path_and_query.split('?').next().unwrap_or("/");
            let directory = path
                .rsplit_once('/')
                .map(|(head, _)| if head.is_empty() { "/" } else { head })
                .unwrap_or("/");
            let joined = if directory.ends_with('/') {
                format!("{directory}{reference}")
            } else {
                format!("{directory}/{reference}")
            };
            format!("{}{}", self.origin(), normalize_path(&joined))
        };

        let mut absolute = absolute;
        if let Some(fragment) = fragment {
            absolute.push('#');
            absolute.push_str(fragment);
        }
        Self::parse(&absolute)
    }
}

fn parse_authority(authority: &str, scheme: Scheme) -> Result<(String, u16), UrlError> {
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };

    if authority.starts_with('[') {
        return Err(UrlError::InvalidAuthority);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse::<u16>().map_err(|_| UrlError::InvalidPort)?;
            if port == 0 {
                return Err(UrlError::InvalidPort);
            }
            (host, port)
        }
        _ => (authority, default_port),
    };

    if host.is_empty() || host.starts_with('.') || host.ends_with('.') || host.contains('/') {
        return Err(UrlError::InvalidAuthority);
    }

    Ok((host.to_ascii_lowercase(), port))
}

fn normalize_path(input: &str) -> String {
    let (path, query) = input
        .split_once('?')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((input, None));
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }

    let mut output = String::from("/");
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            output.push('/');
        }
        output.push_str(part);
    }
    if trailing && !output.ends_with('/') {
        output.push('/');
    }
    if let Some(query) = query {
        output.push('?');
        output.push_str(query);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_unqualified_names_to_https() {
        let url = Url::parse("example.org/docs").unwrap();
        assert_eq!(url.scheme, Scheme::Https);
        assert_eq!(url.port, 443);
        assert_eq!(url.as_string(), "https://example.org/docs");
        assert_eq!(url.fragment, None);
    }

    #[test]
    fn preserves_explicit_http_and_custom_port() {
        let url = Url::parse("http://example.org:8080/path").unwrap();
        assert_eq!(url.scheme, Scheme::Http);
        assert_eq!(url.port, 8080);
        assert_eq!(url.as_string(), "http://example.org:8080/path");
    }

    #[test]
    fn resolves_relative_and_root_relative_references() {
        let base = Url::parse("https://example.org/a/b/page.html").unwrap();
        assert_eq!(
            base.resolve("../next").unwrap().as_string(),
            "https://example.org/a/next"
        );
        assert_eq!(
            base.resolve("/index.html").unwrap().as_string(),
            "https://example.org/index.html"
        );
        assert_eq!(
            base.resolve("//cdn.example.org/x").unwrap().as_string(),
            "https://cdn.example.org/x"
        );
    }

    #[test]
    fn preserves_and_resolves_fragments_without_sending_them_in_the_request_target() {
        let base = Url::parse("https://example.org/docs/page.html?mode=1#old").unwrap();
        assert_eq!(base.as_string(), "https://example.org/docs/page.html?mode=1#old");
        assert_eq!(base.path_and_query, "/docs/page.html?mode=1");
        assert_eq!(
            base.resolve("#section-2").unwrap().as_string(),
            "https://example.org/docs/page.html?mode=1#section-2"
        );
        assert_eq!(
            base.resolve("../guide#install").unwrap().as_string(),
            "https://example.org/guide#install"
        );
    }

    #[test]
    fn rejects_unsupported_schemes_and_userinfo() {
        assert_eq!(
            Url::parse("ftp://example.org").unwrap_err(),
            UrlError::UnsupportedScheme
        );
        assert_eq!(
            Url::parse("https://user@example.org").unwrap_err(),
            UrlError::InvalidAuthority
        );
    }
}
