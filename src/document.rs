use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::url::Url;

mod elinks_entities {
    include!(concat!(env!("OUT_DIR"), "/elinks_entities.rs"));
}

const MAX_LINKS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub label: String,
    pub target: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Document {
    pub title: String,
    pub text: String,
    pub links: Vec<Link>,
}

struct PendingLink {
    href: String,
    label: String,
}

pub fn parse_html(source: &str, base: &Url) -> Document {
    let mut document = Document::default();
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut in_head = false;
    let mut in_title = false;
    let mut skipped: Option<String> = None;
    let mut pending_link: Option<PendingLink> = None;

    while cursor < bytes.len() {
        if bytes[cursor] == b'<' {
            if source[cursor..].starts_with("<!--") {
                if let Some(end) = source[cursor + 4..].find("-->") {
                    cursor += 4 + end + 3;
                } else {
                    break;
                }
                continue;
            }

            let Some(relative_end) = source[cursor..].find('>') else {
                break;
            };
            let end = cursor + relative_end;
            let tag = source[cursor + 1..end].trim();
            cursor = end + 1;

            if tag.is_empty() || tag.starts_with('!') || tag.starts_with('?') {
                continue;
            }

            let closing = tag.starts_with('/');
            let content = tag.trim_start_matches('/').trim_start();
            let name_end = content
                .find(|c: char| c.is_ascii_whitespace() || c == '/')
                .unwrap_or(content.len());
            let name = content[..name_end].to_ascii_lowercase();

            if let Some(hidden) = skipped.as_ref() {
                if closing && *hidden == name {
                    skipped = None;
                }
                continue;
            }

            if !closing
                && matches!(
                    name.as_str(),
                    "script" | "style" | "template" | "noscript" | "svg"
                )
            {
                skipped = Some(name);
                continue;
            }

            if closing {
                match name.as_str() {
                    "title" => in_title = false,
                    "head" => in_head = false,
                    "a" => complete_link(&mut document, &mut pending_link, base),
                    _ => {}
                }
                if !in_head && is_block(&name) {
                    newline(&mut document.text);
                }
            } else {
                match name.as_str() {
                    "head" => in_head = true,
                    "title" => in_title = true,
                    _ => {}
                }

                if !in_head {
                    if name == "a" {
                        if let Some(href) = attribute(content, "href") {
                            let href = href.trim();
                            if !href.is_empty()
                                && !href.starts_with('#')
                                && !href.starts_with("mailto:")
                                && !href.starts_with("javascript:")
                                && !href.starts_with("data:")
                            {
                                pending_link = Some(PendingLink {
                                    href: href.to_string(),
                                    label: String::new(),
                                });
                            }
                        }
                    }
                    if is_block(&name) {
                        newline(&mut document.text);
                    }
                }
            }
            continue;
        }

        let end = source[cursor..]
            .find('<')
            .map(|n| cursor + n)
            .unwrap_or(bytes.len());
        let raw = &source[cursor..end];
        cursor = end;
        if raw.is_empty() {
            continue;
        }

        let decoded = decode_entities(raw);
        if in_title {
            append_text(&mut document.title, &decoded);
        } else if !in_head && skipped.is_none() {
            append_text(&mut document.text, &decoded);
            if let Some(link) = pending_link.as_mut() {
                append_text(&mut link.label, &decoded);
            }
        }
    }

    document.title = if document.title.trim().is_empty() {
        String::from("(untitled document)")
    } else {
        document.title.trim().to_string()
    };
    document.text = document.text.trim().to_string();
    document
}

fn complete_link(document: &mut Document, pending: &mut Option<PendingLink>, base: &Url) {
    let Some(link) = pending.take() else {
        return;
    };
    if document.links.len() >= MAX_LINKS {
        return;
    }

    let Ok(target) = base.resolve(&link.href) else {
        return;
    };
    let label = if link.label.trim().is_empty() {
        target.as_string()
    } else {
        link.label.trim().to_string()
    };
    document.links.push(Link {
        label,
        target: target.as_string(),
    });
    document
        .text
        .push_str(&format!(" [{}]", document.links.len()));
}

fn append_text(output: &mut String, input: &str) {
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !output.is_empty() && !output.ends_with('\n') && !output.ends_with(' ') {
                output.push(' ');
            }
        } else {
            output.push(ch);
        }
    }
}

fn newline(output: &mut String) {
    while output.ends_with(' ') {
        output.pop();
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
}

fn is_block(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "blockquote"
            | "br"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tr"
            | "ul"
    )
}

fn attribute(tag: &str, wanted: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut at = tag
        .find(|c: char| c.is_ascii_whitespace() || c == '/')
        .unwrap_or(tag.len());

    while at < bytes.len() {
        while at < bytes.len() && (bytes[at].is_ascii_whitespace() || bytes[at] == b'/') {
            at += 1;
        }
        if at >= bytes.len() {
            break;
        }

        let start = at;
        while at < bytes.len()
            && !bytes[at].is_ascii_whitespace()
            && bytes[at] != b'='
            && bytes[at] != b'/'
        {
            at += 1;
        }
        let key = &tag[start..at];
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }

        let mut value = String::new();
        if at < bytes.len() && bytes[at] == b'=' {
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if at < bytes.len() && (bytes[at] == b'"' || bytes[at] == b'\'') {
                let quote = bytes[at];
                at += 1;
                let value_start = at;
                while at < bytes.len() && bytes[at] != quote {
                    at += 1;
                }
                value = tag[value_start..at].to_string();
                if at < bytes.len() {
                    at += 1;
                }
            } else {
                let value_start = at;
                while at < bytes.len() && !bytes[at].is_ascii_whitespace() && bytes[at] != b'/' {
                    at += 1;
                }
                value = tag[value_start..at].to_string();
            }
        }

        if key.eq_ignore_ascii_case(wanted) {
            return Some(value);
        }
        if at == start {
            at += 1;
        }
    }
    None
}

fn decode_entities(input: &str) -> String {
    let mut output = String::new();
    let mut rest = input;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        let entity_text = &rest[start..];
        let Some(end) = entity_text.find(';') else {
            output.push_str(entity_text);
            return output;
        };
        let entity = &entity_text[1..end];
        if let Some(ch) = decode_entity(entity) {
            output.push(ch);
        } else {
            output.push_str(&entity_text[..=end]);
        }
        rest = &entity_text[end + 1..];
    }
    output.push_str(rest);
    output
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "nbsp" => Some(' '),
        "copy" => Some('©'),
        "reg" => Some('®'),
        "mdash" => Some('—'),
        "ndash" => Some('–'),
        "hellip" => Some('…'),
        _ if entity.starts_with("#x") || entity.starts_with("#X") => {
            u32::from_str_radix(&entity[2..], 16)
                .ok()
                .and_then(char::from_u32)
        }
        _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
        _ => elinks_entities::decode_named_entity(entity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_visible_text_and_resolves_links() {
        let base = Url::parse("https://example.org/docs/start.html").unwrap();
        let html = "<head><title>Boot &amp; Browse</title></head><body><h1>Welcome</h1><p>Read the <a href='../guide'>guide</a>.</p></body>";
        let page = parse_html(html, &base);
        assert_eq!(page.title, "Boot & Browse");
        assert!(page.text.contains("Welcome"));
        assert!(page.text.contains("guide [1]"));
        assert_eq!(page.links[0].target, "https://example.org/guide");
    }

    #[test]
    fn decodes_public_domain_elinks_named_entities() {
        assert_eq!(
            decode_entities("&AElig; &alpha; &euro; &trade; &rarr;"),
            "Æ α € ™ →"
        );
        // Entity names remain case-sensitive, as they are in HTML.
        assert_eq!(decode_entities("&Alpha; &alpha;"), "Α α");
        assert_eq!(decode_entities("&NotAnEntity;"), "&NotAnEntity;");
    }
    #[test]
    fn removes_script_style_and_comments() {
        let base = Url::parse("https://example.org/").unwrap();
        let page = parse_html(
            "<!-- ignore --><style>hidden</style><script>evil()</script><p>Visible</p>",
            &base,
        );
        assert!(page.text.contains("Visible"));
        assert!(!page.text.contains("evil"));
        assert!(!page.text.contains("hidden"));
    }
}
