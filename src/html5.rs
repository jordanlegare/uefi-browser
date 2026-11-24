use alloc::string::{String, ToString};
use alloc::vec::Vec;

const MAX_NODES: usize = 16_384;
const MAX_ATTRIBUTES: usize = 64;
const MAX_DEPTH: usize = 128;
const MAX_TOKEN_BYTES: usize = 32 * 1024;

pub type NodeId = usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Document,
    Element { tag: String, attributes: Vec<Attribute> },
    Text(String),
    Comment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dom {
    pub nodes: Vec<Node>,
    pub root: NodeId,
}

impl Dom {
    fn new() -> Self {
        Self {
            nodes: alloc::vec![Node {
                kind: NodeKind::Document,
                parent: None,
                children: Vec::new(),
            }],
            root: 0,
        }
    }

    fn append(&mut self, parent: NodeId, kind: NodeKind) -> Option<NodeId> {
        if self.nodes.len() >= MAX_NODES || parent >= self.nodes.len() {
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            kind,
            parent: Some(parent),
            children: Vec::new(),
        });
        self.nodes[parent].children.push(id);
        Some(id)
    }

    fn element(&self, id: NodeId) -> Option<(&str, &[Attribute])> {
        match &self.nodes.get(id)?.kind {
            NodeKind::Element { tag, attributes } => Some((tag, attributes)),
            _ => None,
        }
    }

    pub fn tag(&self, id: NodeId) -> Option<&str> {
        self.element(id).map(|(tag, _)| tag)
    }

    pub fn attr(&self, id: NodeId, name: &str) -> Option<&str> {
        self.element(id)?.1.iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
            .map(|attribute| attribute.value.as_str())
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        self.nodes.get(id).map(|node| node.children.as_slice()).unwrap_or(&[])
    }

    pub fn text_content(&self, id: NodeId) -> String {
        let mut output = String::new();
        self.append_text(id, &mut output);
        output
    }

    fn append_text(&self, id: NodeId, output: &mut String) {
        let Some(node) = self.nodes.get(id) else { return; };
        if let NodeKind::Text(value) = &node.kind {
            output.push_str(value);
            return;
        }
        for child in &node.children {
            self.append_text(*child, output);
        }
    }

    pub fn ancestors(&self, id: NodeId) -> Vec<NodeId> {
        let mut result = Vec::new();
        let mut current = self.nodes.get(id).and_then(|node| node.parent);
        while let Some(parent) = current {
            result.push(parent);
            current = self.nodes.get(parent).and_then(|node| node.parent);
            if result.len() >= MAX_DEPTH {
                break;
            }
        }
        result
    }

    pub fn find_by_tag(&self, root: NodeId, tag: &str) -> Vec<NodeId> {
        let mut found = Vec::new();
        self.collect_by_tag(root, tag, &mut found);
        found
    }

    fn collect_by_tag(&self, root: NodeId, tag: &str, found: &mut Vec<NodeId>) {
        if self.tag(root).is_some_and(|name| name.eq_ignore_ascii_case(tag)) {
            found.push(root);
        }
        for child in self.children(root) {
            self.collect_by_tag(*child, tag, found);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    StartTag {
        name: String,
        attributes: Vec<Attribute>,
        self_closing: bool,
    },
    EndTag(String),
    Text(String),
    Comment,
    Doctype,
}

struct Tokenizer<'a> {
    source: &'a str,
    cursor: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(source: &'a str) -> Self {
        Self { source, cursor: 0 }
    }

    fn next(&mut self) -> Option<Token> {
        if self.cursor >= self.source.len() {
            return None;
        }
        let rest = &self.source[self.cursor..];
        if rest.starts_with("<!--") {
            let content = &rest[4..];
            if let Some(end) = content.find("-->") {
                self.cursor += 4 + end + 3;
            } else {
                self.cursor = self.source.len();
            }
            return Some(Token::Comment);
        }

        if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case("<!") {
            let end = find_markup_end(self.source, self.cursor).unwrap_or(self.source.len() - 1);
            self.cursor = (end + 1).min(self.source.len());
            return Some(Token::Doctype);
        }

        if rest.starts_with("</") {
            if let Some(end) = find_tag_end(self.source, self.cursor) {
                let inner = self.source[self.cursor + 2..end].trim();
                let name = parse_name(inner);
                self.cursor = end + 1;
                if !name.is_empty() {
                    return Some(Token::EndTag(name));
                }
            }
            self.cursor = (self.cursor + 1).min(self.source.len());
            return Some(Token::Text("<".to_string()));
        }

        if rest.starts_with('<')
            && rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
        {
            if let Some(end) = find_tag_end(self.source, self.cursor) {
                let inner = &self.source[self.cursor + 1..end];
                self.cursor = end + 1;
                let (name, attributes, self_closing) = parse_start_tag(inner);
                if !name.is_empty() {
                    return Some(Token::StartTag { name, attributes, self_closing });
                }
            }
        }

        let end = rest.find('<').unwrap_or(rest.len());
        if end == 0 {
            self.cursor += 1;
            return Some(Token::Text("<".to_string()));
        }
        let mut consumed = end.min(MAX_TOKEN_BYTES);
        while consumed > 0 && !rest.is_char_boundary(consumed) {
            consumed -= 1;
        }
        if consumed == 0 {
            return None;
        }
        let text = &rest[..consumed];
        self.cursor += consumed;
        Some(Token::Text(crate::document::decode_html_entities(text)))
    }

    fn consume_raw_text(&mut self, tag: &str, decode_references: bool) -> Option<String> {
        let rest = &self.source[self.cursor..];
        let lower = rest.to_ascii_lowercase();
        let needle = alloc::format!("</{tag}");
        let end = lower.find(&needle).unwrap_or(rest.len());
        let raw = &rest[..end];
        self.cursor += end;
        let mut boundary = raw.len().min(MAX_TOKEN_BYTES);
        while !raw.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let bounded = &raw[..boundary];
        Some(if decode_references {
            crate::document::decode_html_entities(bounded)
        } else {
            bounded.to_string()
        })
    }
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

fn find_markup_end(source: &str, start: usize) -> Option<usize> {
    source[start..].find('>').map(|offset| start + offset)
}

fn parse_name(source: &str) -> String {
    let end = source.find(|ch: char| ch.is_ascii_whitespace() || ch == '/' || ch == '>').unwrap_or(source.len());
    source[..end].to_ascii_lowercase()
}

fn parse_start_tag(source: &str) -> (String, Vec<Attribute>, bool) {
    let name = parse_name(source);
    if name.is_empty() {
        return (name, Vec::new(), false);
    }
    let mut attributes = Vec::new();
    let bytes = source.as_bytes();
    let mut cursor = name.len();
    let mut self_closing = false;

    while cursor < bytes.len() && attributes.len() < MAX_ATTRIBUTES {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        if bytes[cursor] == b'/' {
            self_closing = true;
            cursor += 1;
            continue;
        }

        let name_start = cursor;
        while cursor < bytes.len()
            && !bytes[cursor].is_ascii_whitespace()
            && !matches!(bytes[cursor], b'=' | b'/' | b'>')
        {
            cursor += 1;
        }
        if cursor == name_start {
            cursor += 1;
            continue;
        }
        let attribute_name = source[name_start..cursor].to_ascii_lowercase();

        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }

        let mut value = String::new();
        if cursor < bytes.len() && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < bytes.len() && (bytes[cursor] == b'\'' || bytes[cursor] == b'"') {
                let quote = bytes[cursor];
                cursor += 1;
                let value_start = cursor;
                while cursor < bytes.len() && bytes[cursor] != quote {
                    cursor += 1;
                }
                value = crate::document::decode_html_entities(&source[value_start..cursor]);
                if cursor < bytes.len() {
                    cursor += 1;
                }
            } else {
                let value_start = cursor;
                while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'>' {
                    cursor += 1;
                }
                value = crate::document::decode_html_entities(&source[value_start..cursor]);
            }
        }

        if !attributes.iter().any(|attribute: &Attribute| attribute.name == attribute_name) {
            attributes.push(Attribute { name: attribute_name, value });
        }
    }
    (name, attributes, self_closing)
}

fn is_void(name: &str) -> bool {
    matches!(name, "area" | "base" | "br" | "col" | "embed" | "hr" | "img" | "input" | "link" | "meta" | "param" | "source" | "track" | "wbr")
}

fn is_head_tag(name: &str) -> bool {
    matches!(name, "base" | "link" | "meta" | "title" | "style" | "script" | "noscript")
}

fn is_block_start(name: &str) -> bool {
    matches!(name, "address" | "article" | "aside" | "blockquote" | "div" | "dl" | "fieldset" | "footer" | "form" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "header" | "hr" | "main" | "nav" | "ol" | "p" | "pre" | "section" | "table" | "ul")
}

fn close_open(stack: &mut Vec<NodeId>, dom: &Dom, target: &str) {
    if let Some(position) = stack.iter().rposition(|id| dom.tag(*id) == Some(target)) {
        stack.truncate(position);
    }
}

fn current_tag(stack: &[NodeId], dom: &Dom) -> Option<&str> {
    stack.last().and_then(|id| dom.tag(*id))
}

fn ensure_table_section(stack: &mut Vec<NodeId>, dom: &mut Dom) {
    let table_position = stack.iter().rposition(|id| dom.tag(*id) == Some("table"));
    if let Some(position) = table_position {
        let has_section = stack[position + 1..].iter().any(|id| {
            matches!(dom.tag(*id), Some("tbody" | "thead" | "tfoot"))
        });
        if !has_section {
            stack.truncate(position + 1);
            if let Some(table) = stack.last().copied() {
                if let Some(section) = dom.append(table, NodeKind::Element {
                    tag: "tbody".to_string(),
                    attributes: Vec::new(),
                }) {
                    stack.push(section);
                }
            }
        }
    }
}

pub fn build_tree(source: &str) -> Dom {
    let mut dom = Dom::new();
    let html = dom.append(0, NodeKind::Element { tag: "html".to_string(), attributes: Vec::new() }).unwrap_or(0);
    let head = dom.append(html, NodeKind::Element { tag: "head".to_string(), attributes: Vec::new() }).unwrap_or(html);
    let body = dom.append(html, NodeKind::Element { tag: "body".to_string(), attributes: Vec::new() }).unwrap_or(html);

    let mut stack = alloc::vec![html, head];
    let mut body_started = false;
    let mut tokenizer = Tokenizer::new(source);

    while let Some(token) = tokenizer.next() {
        match token {
            Token::Comment => {
                if let Some(parent) = stack.last().copied() {
                    let _ = dom.append(parent, NodeKind::Comment);
                }
            }
            Token::Doctype => {}
            Token::Text(text) => {
                if !body_started && text.trim().is_empty() {
                    continue;
                }
                if !body_started {
                    body_started = true;
                    stack.clear();
                    stack.push(html);
                    stack.push(body);
                }
                if let Some(parent) = stack.last().copied() {
                    if let Some(Node { kind: NodeKind::Text(previous), .. }) = stack.last().and_then(|parent| dom.nodes.get(*parent)).and_then(|node| node.children.last()).and_then(|child| dom.nodes.get(*child)) {
                        let mut combined = previous.clone();
                        combined.push_str(&text);
                        if let Some(child) = dom.nodes[parent].children.last().copied() {
                            dom.nodes[child].kind = NodeKind::Text(combined);
                        }
                    } else {
                        let _ = dom.append(parent, NodeKind::Text(text));
                    }
                }
            }
            Token::StartTag { name, attributes, self_closing } => {
                if name == "html" || name == "head" || name == "body" {
                    if name == "body" {
                        body_started = true;
                        stack.clear();
                        stack.push(html);
                        stack.push(body);
                        if let Some(NodeKind::Element { attributes: existing, .. }) = dom.nodes.get_mut(body).map(|node| &mut node.kind) {
                            existing.extend(attributes);
                        }
                    }
                    continue;
                }

                if !body_started && is_head_tag(&name) {
                    stack.clear();
                    stack.push(html);
                    stack.push(head);
                } else if !body_started {
                    body_started = true;
                    stack.clear();
                    stack.push(html);
                    stack.push(body);
                }

                if name == "p" && stack.iter().any(|id| dom.tag(*id) == Some("p")) {
                    close_open(&mut stack, &dom, "p");
                }
                if name == "li" { close_open(&mut stack, &dom, "li"); }
                if name == "dt" || name == "dd" {
                    close_open(&mut stack, &dom, "dt");
                    close_open(&mut stack, &dom, "dd");
                }
                if matches!(name.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
                    for heading in ["h1", "h2", "h3", "h4", "h5", "h6"] {
                        close_open(&mut stack, &dom, heading);
                    }
                }
                if name == "option" { close_open(&mut stack, &dom, "option"); }
                if name == "optgroup" { close_open(&mut stack, &dom, "option"); close_open(&mut stack, &dom, "optgroup"); }
                if name == "td" || name == "th" {
                    close_open(&mut stack, &dom, "td");
                    close_open(&mut stack, &dom, "th");
                    if !stack.iter().any(|id| dom.tag(*id) == Some("tr")) {
                        ensure_table_section(&mut stack, &mut dom);
                        let parent = stack.last().copied().unwrap_or(body);
                        if let Some(row) = dom.append(parent, NodeKind::Element { tag: "tr".to_string(), attributes: Vec::new() }) {
                            stack.push(row);
                        }
                    }
                }
                if name == "tr" {
                    close_open(&mut stack, &dom, "td");
                    close_open(&mut stack, &dom, "th");
                    close_open(&mut stack, &dom, "tr");
                    ensure_table_section(&mut stack, &mut dom);
                }
                if name == "p" || is_block_start(&name) {
                    if name != "p" { close_open(&mut stack, &dom, "p"); }
                }

                let parent = stack.last().copied().unwrap_or(body);
                let Some(id) = dom.append(parent, NodeKind::Element { tag: name.clone(), attributes }) else {
                    break;
                };

                if !self_closing && matches!(name.as_str(), "script" | "style" | "title" | "textarea") {
                    let decode = matches!(name.as_str(), "title" | "textarea");
                    if let Some(raw) = tokenizer.consume_raw_text(&name, decode) {
                        if !raw.is_empty() {
                            let _ = dom.append(id, NodeKind::Text(raw));
                        }
                    }
                }

                if !self_closing && !is_void(&name) && stack.len() < MAX_DEPTH {
                    stack.push(id);
                }
            }
            Token::EndTag(name) => {
                if name == "head" && !body_started {
                    body_started = true;
                    stack.clear();
                    stack.push(html);
                    stack.push(body);
                    continue;
                }
                if name == "body" || name == "html" {
                    stack.clear();
                    stack.push(html);
                    stack.push(body);
                    continue;
                }
                close_open(&mut stack, &dom, &name);
            }
        }
    }

    dom
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_implied_document_and_table_elements() {
        let dom = build_tree("<h1 id=top>Title</h1><table><tr><td>A<td>B</table>");
        let html = dom.find_by_tag(dom.root, "html");
        let body = dom.find_by_tag(dom.root, "body");
        let tbody = dom.find_by_tag(dom.root, "tbody");
        let cells = dom.find_by_tag(dom.root, "td");
        assert_eq!(html.len(), 1);
        assert_eq!(body.len(), 1);
        assert_eq!(tbody.len(), 1);
        assert_eq!(cells.len(), 2);
        assert_eq!(dom.attr(dom.find_by_tag(dom.root, "h1")[0], "id"), Some("top"));
    }

    #[test]
    fn tokenizes_quoted_greater_than_and_unquoted_urls() {
        let dom = build_tree("<a title='left > right' href=https://example.org/a/b>x</a>");
        let anchor = dom.find_by_tag(dom.root, "a")[0];
        assert_eq!(dom.attr(anchor, "title"), Some("left > right"));
        assert_eq!(dom.attr(anchor, "href"), Some("https://example.org/a/b"));
    }

    #[test]
    fn respects_void_elements_and_raw_stylesheets() {
        let dom = build_tree("<style>p { color: red }</style><p>A<br>B<img alt=x>");
        assert_eq!(dom.find_by_tag(dom.root, "style").len(), 1);
        assert_eq!(dom.find_by_tag(dom.root, "br").len(), 1);
        assert_eq!(dom.find_by_tag(dom.root, "img").len(), 1);
        let style = dom.find_by_tag(dom.root, "style")[0];
        assert_eq!(dom.text_content(style), "p { color: red }");
    }
}
