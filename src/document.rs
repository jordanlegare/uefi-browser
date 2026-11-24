use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::css::{ComputedStyle, DisplayMode, StyleSheet};
use crate::html5::{Dom, NodeId, NodeKind};
use crate::url::Url;

mod elinks_entities {
    include!(concat!(env!("OUT_DIR"), "/elinks_entities.rs"));
}

const MAX_LINKS: usize = 256;
const MAX_BLOCKS: usize = 4096;
const MAX_FORMS: usize = 32;
const MAX_FORM_CONTROLS: usize = 64;
const MAX_TABLES: usize = 128;

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
    pub foreground: Option<TermColor>,
    pub background: Option<TermColor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TermColor {
    Black,
    DarkRed,
    DarkGreen,
    Brown,
    DarkBlue,
    DarkMagenta,
    DarkCyan,
    LightGray,
    DarkGray,
    LightRed,
    LightGreen,
    Yellow,
    LightBlue,
    LightMagenta,
    LightCyan,
    White,
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
    ListItem { depth: u8, ordered: bool, ordinal: u16 },
    TableRow { header: bool },
    Table { table_index: usize },
    DefinitionTerm,
    DefinitionDescription,
    HorizontalRule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub kind: BlockKind,
    pub runs: Vec<InlineRun>,
    pub style: ComputedStyle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    pub name: String,
    pub block_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableCell {
    pub runs: Vec<InlineRun>,
    pub colspan: u8,
    pub rowspan: u8,
    pub style: ComputedStyle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableRow {
    pub header: bool,
    pub cells: Vec<TableCell>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub rows: Vec<TableRow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormControlKind {
    Text,
    Password,
    Email,
    Search,
    Number,
    Hidden,
    File,
    Checkbox,
    Radio,
    Select,
    TextArea,
    Submit,
    Reset,
    Button,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormOption {
    pub label: String,
    pub value: String,
    pub selected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormControl {
    pub name: String,
    pub label: String,
    pub value: String,
    pub kind: FormControlKind,
    pub required: bool,
    pub disabled: bool,
    pub checked: bool,
    pub options: Vec<FormOption>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Form {
    pub action: String,
    pub method: FormMethod,
    pub controls: Vec<FormControl>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Document {
    pub title: String,
    pub text: String,
    pub links: Vec<Link>,
    pub blocks: Vec<Block>,
    pub anchors: Vec<Anchor>,
    pub forms: Vec<Form>,
    pub tables: Vec<Table>,
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
                kind: BlockKind::Preformatted,
                runs: alloc::vec![InlineRun {
                    text: text.to_string(),
                    style: InlineStyle::default(),
                    link: None,
                }],
                style: ComputedStyle::default(),
            });
        }
        document
    }

    pub fn anchor_block(&self, name: &str) -> Option<usize> {
        self.anchors
            .iter()
            .find(|anchor| anchor.name == name)
            .map(|anchor| anchor.block_index)
    }
}

pub fn parse_html(source: &str, base: &Url) -> Document {
    let dom = crate::html5::build_tree(source);
    parse_dom_with_styles(dom, base, &[])
}

pub fn parse_html_with_styles(source: &str, base: &Url, external_css: &[String]) -> Document {
    let dom = crate::html5::build_tree(source);
    parse_dom_with_styles(dom, base, external_css)
}

pub fn external_stylesheet_urls(source: &str, base: &Url) -> Vec<Url> {
    let dom = crate::html5::build_tree(source);
    let mut urls = Vec::new();
    for node in dom.find_by_tag(dom.root, "link") {
        let rel = dom.attr(node, "rel").unwrap_or("");
        if !rel.split_ascii_whitespace().any(|token| token.eq_ignore_ascii_case("stylesheet")) {
            continue;
        }
        let Some(href) = dom.attr(node, "href") else { continue; };
        let Ok(url) = base.resolve(href) else { continue; };
        if base.scheme == crate::url::Scheme::Https && url.scheme == crate::url::Scheme::Http {
            continue;
        }
        if !urls.iter().any(|existing: &Url| existing.as_string() == url.as_string()) {
            urls.push(url);
        }
        if urls.len() >= 4 {
            break;
        }
    }
    urls
}

fn parse_dom_with_styles(dom: crate::html5::Dom, base: &Url, external_css: &[String]) -> Document {
    let style_sheet = StyleSheet::from_dom_with_external(&dom, external_css);
    let mut builder = DocumentBuilder {
        dom: &dom,
        base,
        style_sheet,
        document: Document::default(),
    };

    if let Some(title) = dom.find_by_tag(dom.root, "title").first().copied() {
        builder.document.title = collapse_whitespace(&dom.text_content(title));
    }
    let body = dom.find_by_tag(dom.root, "body").first().copied();
    if let Some(body) = body {
        let body_style = builder.computed(body, &ComputedStyle::default());
        if body_style.display != DisplayMode::None {
            builder.walk_flow(body, body_style, 0);
        }
    }

    if builder.document.title.is_empty() {
        builder.document.title = String::from("(untitled document)");
    }
    while builder.document.text.ends_with('\n') {
        builder.document.text.pop();
    }
    builder.document
}

struct DocumentBuilder<'a> {
    dom: &'a Dom,
    base: &'a Url,
    style_sheet: StyleSheet,
    document: Document,
}

impl DocumentBuilder<'_> {
    fn computed(&self, node: NodeId, parent: &ComputedStyle) -> ComputedStyle {
        self.style_sheet.compute(self.dom, node, parent)
    }

    fn walk_flow(&mut self, parent: NodeId, parent_style: ComputedStyle, list_depth: u8) {
        let mut inline = Vec::new();
        for child in self.dom.children(parent).iter().copied() {
            match &self.dom.nodes[child].kind {
                NodeKind::Text(text) => push_run(
                    &mut inline,
                    text,
                    inline_style(&parent_style),
                    None,
                ),
                NodeKind::Comment | NodeKind::Document => {}
                NodeKind::Element { .. } => {
                    let style = self.computed(child, &parent_style);
                    if style.display == DisplayMode::None {
                        continue;
                    }
                    let tag = self.dom.tag(child).unwrap_or("");
                    if (style.display == DisplayMode::Inline || is_inline_tag(tag))
                        && style.display != DisplayMode::Block
                    {
                        self.collect_inline(child, style, None, &mut inline);
                    } else {
                        self.flush_paragraph(&mut inline, parent_style);
                        self.emit_block(child, style, list_depth);
                    }
                }
            }
        }
        self.flush_paragraph(&mut inline, parent_style);
    }

    fn emit_block(&mut self, node: NodeId, style: ComputedStyle, list_depth: u8) {
        let tag = self.dom.tag(node).unwrap_or("");
        if matches!(tag, "script" | "style" | "noscript" | "template" | "svg" | "head") {
            return;
        }

        self.add_anchor(node, self.document.blocks.len());

        match tag {
            "p" => self.emit_inline_block(node, BlockKind::Paragraph, style, false),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = tag.as_bytes()[1] - b'0';
                self.emit_inline_block(node, BlockKind::Heading(level), style, false);
            }
            "pre" => self.emit_inline_block(node, BlockKind::Preformatted, style, true),
            "blockquote" => self.emit_inline_block(node, BlockKind::Quote, style, true),
            "dt" => self.emit_inline_block(node, BlockKind::DefinitionTerm, style, false),
            "dd" => self.emit_inline_block(node, BlockKind::DefinitionDescription, style, false),
            "li" => {
                let (ordered, ordinal) = self.list_metadata(node);
                self.emit_inline_block(
                    node,
                    BlockKind::ListItem {
                        depth: list_depth,
                        ordered,
                        ordinal,
                    },
                    style,
                    false,
                );
                for child in self.dom.children(node).iter().copied() {
                    if matches!(self.dom.tag(child), Some("ul" | "ol")) {
                        self.emit_block(child, self.computed(child, &style), list_depth.saturating_add(1));
                    }
                }
            }
            "ul" | "ol" => {
                for child in self.dom.children(node).iter().copied() {
                    if self.dom.tag(child) == Some("li") {
                        let item_style = self.computed(child, &style);
                        self.emit_block(child, item_style, list_depth);
                    }
                }
            }
            "table" => self.emit_table(node, style),
            "form" => self.emit_form(node, style),
            "hr" => {
                self.document.blocks.push(Block {
                    kind: BlockKind::HorizontalRule,
                    runs: Vec::new(),
                    style,
                });
                self.document.text.push('\n');
            }
            "br" => {
                self.document.blocks.push(Block {
                    kind: BlockKind::Paragraph,
                    runs: alloc::vec![InlineRun {
                        text: String::from("\n"),
                        style: inline_style(&style),
                        link: None,
                    }],
                    style,
                });
                self.document.text.push('\n');
            }
            _ => self.walk_flow(node, style, list_depth),
        }
    }

    fn emit_inline_block(
        &mut self,
        node: NodeId,
        kind: BlockKind,
        style: ComputedStyle,
        preserve_whitespace: bool,
    ) {
        let mut runs = Vec::new();
        self.collect_inline_children(node, style, None, &mut runs, preserve_whitespace);
        if !runs.is_empty() {
            self.push_block(kind, runs, style);
        }
    }

    fn flush_paragraph(&mut self, runs: &mut Vec<InlineRun>, style: ComputedStyle) {
        if runs.is_empty() {
            return;
        }
        let collected = core::mem::take(runs);
        self.push_block(BlockKind::Paragraph, collected, style);
    }

    fn push_block(&mut self, kind: BlockKind, runs: Vec<InlineRun>, style: ComputedStyle) {
        if self.document.blocks.len() >= MAX_BLOCKS {
            return;
        }
        for run in &runs {
            self.document.text.push_str(&run.text);
        }
        self.document.text.push('\n');
        self.document.blocks.push(Block { kind, runs, style });
    }

    fn collect_inline(
        &mut self,
        node: NodeId,
        style: ComputedStyle,
        active_link: Option<usize>,
        output: &mut Vec<InlineRun>,
    ) {
        let tag = self.dom.tag(node).unwrap_or("");
        if matches!(tag, "script" | "style" | "noscript" | "template" | "svg") {
            return;
        }

        if let Some(id) = self.dom.attr(node, "id") {
            self.add_anchor_name(id, self.document.blocks.len());
        }
        if tag == "a" {
            if let Some(name) = self.dom.attr(node, "name") {
                self.add_anchor_name(name, self.document.blocks.len());
            }
        }

        let mut link = active_link;
        let mut created_link = None;
        if tag == "a" {
            if let Some(href) = self.dom.attr(node, "href") {
                if !href.is_empty()
                    && !href.starts_with("javascript:")
                    && !href.starts_with("data:")
                    && self.document.links.len() < MAX_LINKS
                {
                    if let Ok(target) = self.base.resolve(href) {
                        let index = self.document.links.len();
                        self.document.links.push(Link {
                            label: String::new(),
                            target: target.as_string(),
                        });
                        link = Some(index);
                        created_link = Some(index);
                    }
                }
            }
        }

        if tag == "br" {
            push_run(output, "\n", inline_style(&style), link);
            return;
        }
        if tag == "img" {
            let alt = self.dom.attr(node, "alt").unwrap_or("image");
            push_run(output, &format!("[image: {alt}]"), inline_style(&style), link);
            return;
        }

        for child in self.dom.children(node).iter().copied() {
            match &self.dom.nodes[child].kind {
                NodeKind::Text(text) => push_run(output, text, inline_style(&style), link),
                NodeKind::Comment | NodeKind::Document => {}
                NodeKind::Element { .. } => {
                    let child_style = self.computed(child, &style);
                    if child_style.display != DisplayMode::None {
                        self.collect_inline(child, child_style, link, output);
                    }
                }
            }
        }

        if let Some(index) = created_link {
            let label = runs_text_for_link(output, index);
            if let Some(item) = self.document.links.get_mut(index) {
                item.label = label;
            }
            push_run(output, &format!(" [{}]", index + 1), InlineStyle::default(), None);
        }
    }

    fn collect_inline_children(
        &mut self,
        parent: NodeId,
        style: ComputedStyle,
        active_link: Option<usize>,
        output: &mut Vec<InlineRun>,
        preserve_whitespace: bool,
    ) {
        for child in self.dom.children(parent).iter().copied() {
            match &self.dom.nodes[child].kind {
                NodeKind::Text(text) => {
                    push_run(output, text, inline_style(&style), active_link);
                }
                NodeKind::Comment | NodeKind::Document => {}
                NodeKind::Element { .. } => {
                    let child_style = self.computed(child, &style);
                    if child_style.display == DisplayMode::None {
                        continue;
                    }
                    let tag = self.dom.tag(child).unwrap_or("");
                    if is_inline_tag(tag) || !is_block_tag(tag) {
                        self.collect_inline(child, child_style, active_link, output);
                    } else if preserve_whitespace {
                        let text = self.dom.text_content(child);
                        push_run(output, &text, inline_style(&child_style), active_link);
                    }
                }
            }
        }
    }

    fn emit_table(&mut self, node: NodeId, style: ComputedStyle) {
        if self.document.tables.len() >= MAX_TABLES {
            return;
        }
        let mut rows = Vec::new();
        self.collect_table_rows(node, style, &mut rows);
        if rows.is_empty() {
            return;
        }
        let index = self.document.tables.len();
        self.document.tables.push(Table { rows });
        self.document.blocks.push(Block {
            kind: BlockKind::Table { table_index: index },
            runs: Vec::new(),
            style,
        });
        self.document.text.push('\n');
    }

    fn collect_table_rows(&mut self, node: NodeId, style: ComputedStyle, rows: &mut Vec<TableRow>) {
        for child in self.dom.children(node).iter().copied() {
            let tag = self.dom.tag(child).unwrap_or("");
            if tag == "tr" {
                let mut cells = Vec::new();
                for cell in self.dom.children(child).iter().copied() {
                    let cell_tag = self.dom.tag(cell).unwrap_or("");
                    if cell_tag != "td" && cell_tag != "th" {
                        continue;
                    }
                    let cell_style = self.computed(cell, &style);
                    let mut runs = Vec::new();
                    self.collect_inline_children(cell, cell_style, None, &mut runs, false);
                    let colspan = self.dom.attr(cell, "colspan").and_then(|v| v.parse::<u8>().ok()).filter(|v| *v > 0).unwrap_or(1).min(8);
                    let rowspan = self.dom.attr(cell, "rowspan").and_then(|v| v.parse::<u8>().ok()).filter(|v| *v > 0).unwrap_or(1).min(8);
                    for run in &runs {
                        self.document.text.push_str(&run.text);
                    }
                    cells.push(TableCell {
                        runs,
                        colspan,
                        rowspan,
                        style: cell_style,
                    });
                }
                if !cells.is_empty() {
                    rows.push(TableRow {
                        header: self.dom.children(child).iter().any(|id| self.dom.tag(*id) == Some("th")),
                        cells,
                    });
                    self.document.text.push('\n');
                }
            } else if matches!(tag, "thead" | "tbody" | "tfoot") {
                self.collect_table_rows(child, style, rows);
            }
        }
    }

    fn emit_form(&mut self, node: NodeId, style: ComputedStyle) {
        if self.document.forms.len() >= MAX_FORMS {
            return;
        }
        let action = self.dom.attr(node, "action")
            .and_then(|value| self.base.resolve(value).ok())
            .map(|url| url.as_string())
            .unwrap_or_else(|| self.base.as_string());
        let method = match self.dom.attr(node, "method").unwrap_or("get").to_ascii_lowercase().as_str() {
            "post" => FormMethod::Post,
            _ => FormMethod::Get,
        };
        let mut controls = Vec::new();
        self.collect_form_controls(node, &mut controls);
        let index = self.document.forms.len();
        self.document.forms.push(Form { action, method, controls });
        let mut runs = Vec::new();
        push_run(
            &mut runs,
            &format!("[Form {} — use 'form {}' to fill and submit]", index + 1, index + 1),
            InlineStyle::default(),
            None,
        );
        self.push_block(BlockKind::Paragraph, runs, style);
    }

    fn collect_form_controls(&self, node: NodeId, controls: &mut Vec<FormControl>) {
        for child in self.dom.children(node).iter().copied() {
            if controls.len() >= MAX_FORM_CONTROLS {
                return;
            }
            let tag = self.dom.tag(child).unwrap_or("");
            if tag == "input" {
                let input_type = self.dom.attr(child, "type").unwrap_or("text").to_ascii_lowercase();
                let kind = match input_type.as_str() {
                    "password" => FormControlKind::Password,
                    "email" => FormControlKind::Email,
                    "search" => FormControlKind::Search,
                    "number" => FormControlKind::Number,
                    "hidden" => FormControlKind::Hidden,
                    "file" => FormControlKind::File,
                    "checkbox" => FormControlKind::Checkbox,
                    "radio" => FormControlKind::Radio,
                    "submit" | "image" => FormControlKind::Submit,
                    "reset" => FormControlKind::Reset,
                    "button" => FormControlKind::Button,
                    _ => FormControlKind::Text,
                };
                controls.push(FormControl {
                    name: self.dom.attr(child, "name").unwrap_or("").to_string(),
                    label: self.dom.attr(child, "aria-label")
                        .or_else(|| self.dom.attr(child, "placeholder"))
                        .or_else(|| self.dom.attr(child, "title"))
                        .or_else(|| self.dom.attr(child, "name"))
                        .unwrap_or("field")
                        .to_string(),
                    value: self.dom.attr(child, "value").unwrap_or("").to_string(),
                    kind,
                    required: self.dom.attr(child, "required").is_some(),
                    disabled: self.dom.attr(child, "disabled").is_some(),
                    checked: self.dom.attr(child, "checked").is_some(),
                    options: Vec::new(),
                });
            } else if tag == "textarea" {
                controls.push(FormControl {
                    name: self.dom.attr(child, "name").unwrap_or("").to_string(),
                    label: self.dom.attr(child, "aria-label")
                        .or_else(|| self.dom.attr(child, "placeholder"))
                        .or_else(|| self.dom.attr(child, "name"))
                        .unwrap_or("text")
                        .to_string(),
                    value: self.dom.text_content(child),
                    kind: FormControlKind::TextArea,
                    required: self.dom.attr(child, "required").is_some(),
                    disabled: self.dom.attr(child, "disabled").is_some(),
                    checked: false,
                    options: Vec::new(),
                });
            } else if tag == "select" {
                let mut options = Vec::new();
                self.collect_options(child, &mut options);
                let selected = options.iter().find(|option| option.selected).map(|option| option.value.clone())
                    .or_else(|| options.first().map(|option| option.value.clone())).unwrap_or_default();
                controls.push(FormControl {
                    name: self.dom.attr(child, "name").unwrap_or("").to_string(),
                    label: self.dom.attr(child, "aria-label")
                        .or_else(|| self.dom.attr(child, "name"))
                        .unwrap_or("choice")
                        .to_string(),
                    value: selected,
                    kind: FormControlKind::Select,
                    required: self.dom.attr(child, "required").is_some(),
                    disabled: self.dom.attr(child, "disabled").is_some(),
                    checked: false,
                    options,
                });
            } else if tag == "button" {
                let kind = match self.dom.attr(child, "type").unwrap_or("submit") {
                    "reset" => FormControlKind::Reset,
                    "button" => FormControlKind::Button,
                    _ => FormControlKind::Submit,
                };
                controls.push(FormControl {
                    name: self.dom.attr(child, "name").unwrap_or("").to_string(),
                    label: collapse_whitespace(&self.dom.text_content(child)),
                    value: self.dom.attr(child, "value").unwrap_or("").to_string(),
                    kind,
                    required: false,
                    disabled: self.dom.attr(child, "disabled").is_some(),
                    checked: false,
                    options: Vec::new(),
                });
            } else {
                self.collect_form_controls(child, controls);
            }
        }
    }

    fn collect_options(&self, node: NodeId, options: &mut Vec<FormOption>) {
        for child in self.dom.children(node).iter().copied() {
            if self.dom.tag(child) == Some("option") {
                let label = collapse_whitespace(&self.dom.text_content(child));
                let value = self.dom.attr(child, "value").unwrap_or(&label).to_string();
                options.push(FormOption {
                    label,
                    value,
                    selected: self.dom.attr(child, "selected").is_some(),
                });
            } else {
                self.collect_options(child, options);
            }
        }
    }

    fn list_metadata(&self, node: NodeId) -> (bool, u16) {
        let mut current = self.dom.nodes.get(node).and_then(|item| item.parent);
        while let Some(parent) = current {
            match self.dom.tag(parent) {
                Some("ol") => {
                    let ordinal = self.dom.children(parent).iter()
                        .filter(|child| self.dom.tag(**child) == Some("li"))
                        .position(|child| **child == node)
                        .unwrap_or(0) as u16 + 1;
                    return (true, ordinal);
                }
                Some("ul") => {
                    let ordinal = self.dom.children(parent).iter()
                        .filter(|child| self.dom.tag(**child) == Some("li"))
                        .position(|child| **child == node)
                        .unwrap_or(0) as u16 + 1;
                    return (false, ordinal);
                }
                _ => current = self.dom.nodes.get(parent).and_then(|item| item.parent),
            }
        }
        (false, 1)
    }

    fn add_anchor(&mut self, node: NodeId, block_index: usize) {
        if let Some(id) = self.dom.attr(node, "id") {
            self.add_anchor_name(id, block_index);
        }
        if self.dom.tag(node) == Some("a") {
            if let Some(name) = self.dom.attr(node, "name") {
                self.add_anchor_name(name, block_index);
            }
        }
    }

    fn add_anchor_name(&mut self, name: &str, block_index: usize) {
        if !name.is_empty()
            && name.len() <= 256
            && !self.document.anchors.iter().any(|anchor| anchor.name == name)
        {
            self.document.anchors.push(Anchor {
                name: name.to_string(),
                block_index,
            });
        }
    }
}

fn inline_style(style: &ComputedStyle) -> InlineStyle {
    InlineStyle {
        strong: style.bold,
        emphasis: style.italic,
        code: false,
        underline: style.underline,
        foreground: style.foreground,
        background: style.background,
    }
}

fn is_inline_tag(tag: &str) -> bool {
    matches!(
        tag,
        "a" | "abbr" | "b" | "bdi" | "bdo" | "cite" | "code" | "data" | "del"
            | "dfn" | "em" | "i" | "ins" | "kbd" | "mark" | "q" | "s" | "samp"
            | "small" | "span" | "strong" | "sub" | "sup" | "time" | "u" | "var"
            | "img" | "br" | "input" | "label" | "select" | "textarea"
    )
}

fn is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "address" | "article" | "aside" | "blockquote" | "div" | "dl" | "fieldset"
            | "footer" | "form" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
            | "header" | "hr" | "main" | "nav" | "ol" | "p" | "pre" | "section"
            | "table" | "ul" | "li" | "dt" | "dd"
    )
}

fn push_run(output: &mut Vec<InlineRun>, input: &str, style: InlineStyle, link: Option<usize>) {
    if input.is_empty() {
        return;
    }
    if let Some(last) = output.last_mut() {
        if last.style == style && last.link == link {
            last.text.push_str(input);
            return;
        }
    }
    output.push(InlineRun {
        text: input.to_string(),
        style,
        link,
    });
}

fn runs_text_for_link(runs: &[InlineRun], index: usize) -> String {
    let mut output = String::new();
    for run in runs {
        if run.link == Some(index) {
            output.push_str(&run.text);
        }
    }
    collapse_whitespace(&output)
}

pub fn collapse_whitespace(input: &str) -> String {
    let mut output = String::new();
    let mut pending_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            pending_space = !output.is_empty();
        } else {
            if pending_space {
                output.push(' ');
            }
            pending_space = false;
            output.push(ch);
        }
    }
    output
}

pub fn decode_html_entities(input: &str) -> String {
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
            let digits = entity.get(2..)?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            u32::from_str_radix(digits, 16).ok().and_then(char::from_u32)
        }
        _ if entity.starts_with('#') => {
            let digits = entity.get(1..)?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            digits.parse::<u32>().ok().and_then(char::from_u32)
        }
        _ => elinks_entities::decode_named_entity(entity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_public_domain_elinks_named_entities() {
        assert_eq!(
            decode_html_entities("&AElig; &alpha; &euro; &trade; &rarr;"),
            "Æ α € ™ →"
        );
        assert_eq!(decode_html_entities("&Alpha; &alpha;"), "Α α");
        assert_eq!(decode_html_entities("&NotAnEntity;"), "&NotAnEntity;");
    }

    #[test]
    fn parses_structured_blocks_resolves_links_and_collects_anchors() {
        let base = Url::parse("https://example.org/docs/start.html").unwrap();
        let page = parse_html(
            "<!doctype html><title>Boot &amp; Browse</title><h1 id=top>Welcome</h1><p>Read the <a href='../guide'><strong>guide</strong></a>.</p><ul><li>One<li>Two</ul><pre>  x = 1;\n  y = 2;</pre>",
            &base,
        );
        assert_eq!(page.title, "Boot & Browse");
        assert!(page.text.contains("Welcome"));
        assert_eq!(page.links[0].target, "https://example.org/guide");
        assert_eq!(page.anchor_block("top"), Some(0));
        assert!(page.blocks.iter().any(|block| matches!(&block.kind, BlockKind::Heading(1))));
        assert!(page.blocks.iter().any(|block| matches!(&block.kind, BlockKind::ListItem { .. })));
        assert!(page.blocks.iter().flat_map(|block| &block.runs).any(|run| run.style.strong));
        assert!(page.blocks.iter().any(|block| matches!(&block.kind, BlockKind::Preformatted)));
    }

    #[test]
    fn discovers_bounded_external_stylesheets_and_rejects_https_mixed_content() {
        let base = Url::parse("https://example.org/docs/").unwrap();
        let urls = external_stylesheet_urls(
            "<link rel=icon href=/favicon.ico><link rel='alternate stylesheet' href=/a.css><link rel=stylesheet href=http://bad.example/x.css><link rel=stylesheet href=theme.css>",
            &base,
        );
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].as_string(), "https://example.org/a.css");
        assert_eq!(urls[1].as_string(), "https://example.org/docs/theme.css");
    }

    #[test]
    fn extracts_tables_and_forms() {
        let base = Url::parse("https://example.org/").unwrap();
        let page = parse_html(
            "<table><tr><th>Name<th>Value<tbody><tr><td>port<td>443</table><form action=/search><input name=q placeholder=Search><input type=submit value=Go></form>",
            &base,
        );
        assert_eq!(page.tables.len(), 1);
        assert_eq!(page.tables[0].rows.len(), 2);
        assert_eq!(page.forms.len(), 1);
        assert_eq!(page.forms[0].controls.len(), 2);
    }
}
