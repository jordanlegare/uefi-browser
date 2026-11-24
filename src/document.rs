use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::url::Url;

mod elinks_entities {
    include!(concat!(env!("OUT_DIR"), "/elinks_entities.rs"));
}

const MAX_LINKS: usize = 128;
const MAX_BLOCKS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub label: String,
    pub target: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InlineStyle {
    pub strong: bool,
    pub emphasis: bool,
    pub code: bool,
    pub underline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineRun {
    pub text: String,
    pub style: InlineStyle,
    pub link: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockKind {
    Paragraph,
    Heading(u8),
    Preformatted,
    Quote,
    ListItem {
        depth: u8,
        ordered: bool,
        ordinal: u16,
    },
    TableRow {
        header: bool,
    },
    DefinitionTerm,
    DefinitionDescription,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub kind: BlockKind,
    pub runs: Vec<InlineRun>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Document {
    pub title: String,
    pub text: String,
    pub links: Vec<Link>,
    pub blocks: Vec<Block>,
}

impl Document {
    pub fn from_plain(title: &str, text: &str) -> Self {
        let mut document = Self {
            title: title.to_string(),
            text: text.to_string(),
            ..Self::default()
        };
        if !text.is_empty() {
            document.blocks.push(Block {
                // Plain-text responses have no HTML whitespace-collapsing rules.
                // Keep their original line breaks and indentation.
                kind: BlockKind::Preformatted,
                runs: alloc::vec![InlineRun {
                    text: text.to_string(),
                    style: InlineStyle::default(),
                    link: None,
                }],
            });
        }
        document
    }
}

struct LinkState {
    index: usize,
    label: String,
}

pub fn parse_html(source: &str, base: &Url) -> Document {
    let mut document = Document::default();
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut in_head = false;
    let mut in_title = false;
    let mut in_pre = false;
    let mut skipped: Option<String> = None;
    let mut style = InlineStyle::default();
    let mut style_stack: Vec<(String, InlineStyle)> = Vec::new();
    let mut active_link: Option<LinkState> = None;
    let mut current_kind = BlockKind::Paragraph;
    let mut current_runs: Vec<InlineRun> = Vec::new();
    let mut list_stack: Vec<(bool, u16)> = Vec::new();
    let mut in_table_row = false;
    let mut table_cells = 0usize;

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

            let Some(end) = find_tag_end(source, cursor) else {
                break;
            };
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
                    "a" => {
                        if let Some(link) = active_link.take() {
                            let label = if link.label.trim().is_empty() {
                                document.links[link.index].target.clone()
                            } else {
                                link.label.trim().to_string()
                            };
                            document.links[link.index].label = label;
                            let marker = format!(" [{}]", link.index + 1);
                            push_run(&mut current_runs, &marker, InlineStyle::default(), None);
                            append_plain(&mut document.text, &marker, false);
                        }
                    }
                    "b" | "strong" | "i" | "em" | "u" | "code" | "tt" => {
                        if let Some(position) =
                            style_stack.iter().rposition(|(tag, _)| tag == &name)
                        {
                            let (_, previous) = style_stack.remove(position);
                            style = previous;
                        }
                    }
                    "pre" => in_pre = false,
                    "ul" | "ol" => {
                        list_stack.pop();
                    }
                    "td" | "th" => {
                        table_cells = table_cells.saturating_add(1);
                    }
                    "tr" => {
                        flush_block(
                            &mut document.blocks,
                            &mut current_runs,
                            current_kind.clone(),
                        );
                        current_kind = BlockKind::Paragraph;
                        in_table_row = false;
                        table_cells = 0;
                        append_newline(&mut document.text);
                    }
                    _ => {}
                }

                if is_block_tag(&name) && !matches!(name.as_str(), "tr") {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::Paragraph;
                    append_newline(&mut document.text);
                }
                continue;
            }

            if in_head {
                if name == "title" {
                    in_title = true;
                }
                continue;
            }

            match name.as_str() {
                "head" => in_head = true,
                "title" => in_title = true,
                "br" => {
                    push_run(
                        &mut current_runs,
                        "\n",
                        style,
                        active_link.as_ref().map(|link| link.index),
                    );
                    append_newline(&mut document.text);
                }
                "hr" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    if document.blocks.len() < MAX_BLOCKS {
                        document.blocks.push(Block {
                            kind: BlockKind::Paragraph,
                            runs: alloc::vec![InlineRun {
                                text: "────────────────────────────────────────────────────────────────".to_string(),
                                style: InlineStyle::default(),
                                link: None,
                            }],
                        });
                    }
                    append_newline(&mut document.text);
                }
                "ul" => list_stack.push((false, 0)),
                "ol" => list_stack.push((true, 0)),
                "li" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    let depth = list_stack.len().min(u8::MAX as usize) as u8;
                    let (ordered, ordinal) = if let Some((ordered, count)) = list_stack.last_mut() {
                        *count = count.saturating_add(1);
                        (*ordered, *count)
                    } else {
                        (false, 1)
                    };
                    current_kind = BlockKind::ListItem {
                        depth,
                        ordered,
                        ordinal,
                    };
                }
                "blockquote" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::Quote;
                }
                "pre" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::Preformatted;
                    in_pre = true;
                }
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::Heading(name.as_bytes()[1] - b'0');
                }
                "dt" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::DefinitionTerm;
                }
                "dd" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::DefinitionDescription;
                }
                "tr" => {
                    flush_block(
                        &mut document.blocks,
                        &mut current_runs,
                        current_kind.clone(),
                    );
                    current_kind = BlockKind::TableRow { header: false };
                    in_table_row = true;
                    table_cells = 0;
                }
                "th" => {
                    if in_table_row {
                        current_kind = BlockKind::TableRow { header: true };
                        if table_cells > 0 {
                            push_run(&mut current_runs, "  │  ", style, None);
                            append_plain(&mut document.text, " | ", false);
                        }
                    }
                }
                "td" => {
                    if in_table_row && table_cells > 0 {
                        push_run(&mut current_runs, "  │  ", style, None);
                        append_plain(&mut document.text, " | ", false);
                    }
                }
                "a" => {
                    if let Some(href) = attribute(content, "href") {
                        let href = href.trim();
                        if !href.is_empty()
                            && !href.starts_with('#')
                            && !href.starts_with("mailto:")
                            && !href.starts_with("javascript:")
                            && !href.starts_with("data:")
                            && document.links.len() < MAX_LINKS
                        {
                            if let Ok(target) = base.resolve(href) {
                                let index = document.links.len();
                                document.links.push(Link {
                                    label: String::new(),
                                    target: target.as_string(),
                                });
                                active_link = Some(LinkState {
                                    index,
                                    label: String::new(),
                                });
                            }
                        }
                    }
                }
                "b" | "strong" | "i" | "em" | "u" | "code" | "tt" => {
                    style_stack.push((name.clone(), style));
                    match name.as_str() {
                        "b" | "strong" => style.strong = true,
                        "i" | "em" => style.emphasis = true,
                        "u" => style.underline = true,
                        "code" | "tt" => style.code = true,
                        _ => {}
                    }
                }
                "img" => {
                    if let Some(alt) = attribute(content, "alt") {
                        let label = format!("[image: {}]", alt);
                        push_run(
                            &mut current_runs,
                            &label,
                            style,
                            active_link.as_ref().map(|link| link.index),
                        );
                        append_plain(&mut document.text, &label, false);
                    }
                }
                _ => {
                    if is_block_tag(&name) {
                        flush_block(
                            &mut document.blocks,
                            &mut current_runs,
                            current_kind.clone(),
                        );
                        current_kind = BlockKind::Paragraph;
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
            append_plain(&mut document.title, &decoded, false);
        } else if !in_head && skipped.is_none() {
            let link_index = active_link.as_ref().map(|link| link.index);
            push_run(&mut current_runs, &decoded, style, link_index);
            append_plain(&mut document.text, &decoded, in_pre);
            if let Some(link) = active_link.as_mut() {
                append_plain(&mut link.label, &decoded, in_pre);
            }
        }
    }

    flush_block(&mut document.blocks, &mut current_runs, current_kind);
    document.title = if document.title.trim().is_empty() {
        String::from("(untitled document)")
    } else {
        document.title.trim().to_string()
    };
    document.text = document.text.trim().to_string();
    document
}

fn flush_block(blocks: &mut Vec<Block>, runs: &mut Vec<InlineRun>, kind: BlockKind) {
    if runs.is_empty() || blocks.len() >= MAX_BLOCKS {
        runs.clear();
        return;
    }
    blocks.push(Block {
        kind,
        runs: core::mem::take(runs),
    });
}

fn push_run(runs: &mut Vec<InlineRun>, text: &str, style: InlineStyle, link: Option<usize>) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = runs.last_mut() {
        if last.style == style && last.link == link {
            last.text.push_str(text);
            return;
        }
    }
    runs.push(InlineRun {
        text: text.to_string(),
        style,
        link,
    });
}

fn append_plain(output: &mut String, input: &str, preserve_whitespace: bool) {
    if preserve_whitespace {
        output.push_str(input);
        return;
    }
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

fn append_newline(output: &mut String) {
    while output.ends_with(' ') {
        output.pop();
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
}

fn is_block_tag(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "blockquote"
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
            | "li"
            | "main"
            | "nav"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "ul"
            | "ol"
    )
}

fn find_tag_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quote = None;

    for (index, byte) in bytes.iter().enumerate().skip(start) {
        match quote {
            Some(delimiter) if *byte == delimiter => quote = None,
            Some(_) => {}
            None if *byte == b'\'' || *byte == b'"' => quote = Some(*byte),
            None if *byte == b'>' => return Some(index),
            None => {}
        }
    }
    None
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
                while at < bytes.len() && !bytes[at].is_ascii_whitespace() {
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
    fn parses_structured_blocks_and_resolves_links() {
        let base = Url::parse("https://example.org/docs/start.html").unwrap();
        let html = "<head><title>Boot &amp; Browse</title></head><body><h1>Welcome</h1><p>Read the <a href='../guide'><strong>guide</strong></a>.</p><ul><li>One</li><li>Two</li></ul><pre>  x = 1;\n  y = 2;</pre></body>";
        let page = parse_html(html, &base);
        assert_eq!(page.title, "Boot & Browse");
        assert!(page.text.contains("Welcome"));
        assert!(page.text.contains("guide [1]"));
        assert_eq!(page.links[0].target, "https://example.org/guide");
        assert!(
            page.blocks
                .iter()
                .any(|block| matches!(&block.kind, BlockKind::Heading(1)))
        );
        assert!(
            page.blocks
                .iter()
                .any(|block| matches!(&block.kind, BlockKind::ListItem { .. }))
        );
        assert!(
            page.blocks
                .iter()
                .flat_map(|block| &block.runs)
                .any(|run| run.style.strong)
        );
        assert!(
            page.blocks
                .iter()
                .any(|block| matches!(&block.kind, BlockKind::Preformatted))
        );
    }

    #[test]
    fn preserves_slashes_in_unquoted_link_targets_and_quoted_tag_delimiters() {
        let base = Url::parse("https://example.org/docs/").unwrap();
        let page = parse_html(
            "<p title=\"left > right\">Go to <a href=https://www.example.net/a/b?q=one>the page</a>.</p>",
            &base,
        );
        assert_eq!(page.links[0].target, "https://www.example.net/a/b?q=one");
        assert!(page.text.contains("the page [1]"));
    }

    #[test]
    fn decodes_public_domain_elinks_named_entities() {
        assert_eq!(
            decode_entities("&AElig; &alpha; &euro; &trade; &rarr;"),
            "Æ α € ™ →"
        );
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
