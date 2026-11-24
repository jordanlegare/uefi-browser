use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::document::TermColor;
use crate::html5::{Dom, NodeId};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DisplayMode {
    #[default]
    Inline,
    Block,
    Table,
    TableRow,
    TableCell,
    None,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TextAlign {
    #[default]
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComputedStyle {
    pub display: DisplayMode,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub foreground: Option<TermColor>,
    pub background: Option<TermColor>,
    pub white_space_pre: bool,
    pub margin_top: u8,
    pub margin_bottom: u8,
    pub padding_left: u8,
    pub text_align: TextAlign,
    pub width_percent: Option<u8>,
    pub list_ordered: bool,
    pub list_ordinal: u16,
}

#[derive(Clone, Debug, Default)]
pub struct StyleSheet {
    rules: Vec<Rule>,
}

#[derive(Clone, Debug)]
struct Rule {
    selectors: Vec<Selector>,
    declarations: Vec<Declaration>,
    order: usize,
}

#[derive(Clone, Debug)]
struct Selector {
    compounds: Vec<CompoundSelector>,
    specificity: u16,
}

#[derive(Clone, Debug, Default)]
struct CompoundSelector {
    tag: Option<String>,
    id: Option<String>,
    classes: Vec<String>,
    attributes: Vec<(String, Option<String>)>,
    pseudo_classes: Vec<PseudoClass>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PseudoClass {
    FirstChild,
    LastChild,
    OnlyChild,
    Empty,
    NthChild(usize),
}

#[derive(Clone, Debug)]
struct Declaration {
    property: String,
    value: String,
    important: bool,
}

impl StyleSheet {
    pub fn from_dom(dom: &Dom) -> Self {
        Self::from_dom_with_external(dom, &[])
    }

    pub fn from_dom_with_external(dom: &Dom, external_css: &[String]) -> Self {
        let mut sheet = Self::default();
        for node in dom.find_by_tag(dom.root, "style") {
            let css = dom.text_content(node);
            sheet.parse_into(&css);
        }
        for css in external_css.iter().take(4) {
            sheet.parse_into(&css[..css.len().min(32 * 1024)]);
        }
        sheet
    }

    pub fn parse(css: &str) -> Self {
        let mut sheet = Self::default();
        sheet.parse_into(css);
        sheet
    }

    fn parse_into(&mut self, css: &str) {
        let css = strip_comments(css);
        let mut cursor = 0usize;
        while cursor < css.len() {
            let Some(open_rel) = css[cursor..].find('{') else {
                break;
            };
            let open = cursor + open_rel;
            let Some(close_rel) = css[open + 1..].find('}') else {
                break;
            };
            let close = open + 1 + close_rel;
            let selector_text = css[cursor..open].trim();
            let declarations = parse_declarations(&css[open + 1..close]);
            if !selector_text.is_empty() && !declarations.is_empty() {
                let selectors = selector_text
                    .split(',')
                    .filter_map(parse_selector)
                    .collect::<Vec<_>>();
                if !selectors.is_empty() {
                    let order = self.rules.len();
                    self.rules.push(Rule {
                        selectors,
                        declarations,
                        order,
                    });
                }
            }
            cursor = close + 1;
        }
    }

    pub fn compute(&self, dom: &Dom, node: NodeId, parent: &ComputedStyle) -> ComputedStyle {
        let tag = dom.tag(node).unwrap_or("");
        let mut result = default_style(tag, parent);
        let mut matched: Vec<(u16, usize, Vec<Declaration>)> = Vec::new();

        for rule in &self.rules {
            let specificity = rule
                .selectors
                .iter()
                .filter(|selector| matches_selector(dom, node, selector))
                .map(|selector| selector.specificity)
                .max();
            if let Some(specificity) = specificity {
                matched.push((specificity, rule.order, rule.declarations.clone()));
            }
        }

        matched.sort_by_key(|(specificity, order, _)| (*specificity, *order));
        let inline = dom.attr(node, "style").map(parse_declarations).unwrap_or_default();

        // Normal declarations cascade first; important declarations cascade
        // in a second pass so a lower-specificity !important rule still wins
        // over a normal inline declaration.
        for important in [false, true] {
            for (_, _, declarations) in &matched {
                for declaration in declarations.iter().filter(|item| item.important == important) {
                    apply_declaration(&mut result, &declaration.property, &declaration.value);
                }
            }
            for declaration in inline.iter().filter(|item| item.important == important) {
                apply_declaration(&mut result, &declaration.property, &declaration.value);
            }
        }
        result
    }
}

fn default_style(tag: &str, parent: &ComputedStyle) -> ComputedStyle {
    let block = matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "div"
            | "dl"
            | "dt"
            | "dd"
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
            | "html"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "ul"
            | "li"
    );
    let mut style = ComputedStyle {
        display: if block {
            DisplayMode::Block
        } else {
            DisplayMode::Inline
        },
        bold: parent.bold,
        italic: parent.italic,
        underline: parent.underline,
        foreground: parent.foreground,
        background: None,
        white_space_pre: parent.white_space_pre,
        margin_top: 0,
        margin_bottom: 0,
        padding_left: parent.padding_left,
        text_align: parent.text_align,
        width_percent: None,
        list_ordered: parent.list_ordered,
        list_ordinal: parent.list_ordinal,
    };
    match tag {
        "h1" => {
            style.bold = true;
            style.margin_top = 1;
            style.margin_bottom = 1;
        }
        "h2" | "h3" | "h4" | "h5" | "h6" => {
            style.bold = true;
            style.margin_top = 1;
        }
        "b" | "strong" => style.bold = true,
        "th" => {
            style.bold = true;
            style.display = DisplayMode::TableCell;
        }
        "i" | "em" | "cite" | "dfn" | "var" => style.italic = true,
        "u" | "ins" => style.underline = true,
        "pre" | "textarea" => style.white_space_pre = true,
        "table" => style.display = DisplayMode::Table,
        "tr" => style.display = DisplayMode::TableRow,
        "td" => style.display = DisplayMode::TableCell,
        "script" | "style" | "head" | "meta" | "link" | "template" => {
            style.display = DisplayMode::None
        }
        _ => {}
    }
    style
}

fn apply_declaration(style: &mut ComputedStyle, property: &str, value: &str) {
    let value = value.trim().to_ascii_lowercase();
    match property.trim().to_ascii_lowercase().as_str() {
        "display" => {
            style.display = match value.as_str() {
                "none" => DisplayMode::None,
                "block" | "list-item" | "flex" | "grid" | "inline-block" => DisplayMode::Block,
                "table" | "inline-table" => DisplayMode::Table,
                "table-row" => DisplayMode::TableRow,
                "table-cell" => DisplayMode::TableCell,
                "inline" => DisplayMode::Inline,
                _ => style.display,
            };
        }
        "font-weight" => {
            if matches!(
                value.as_str(),
                "bold" | "bolder" | "600" | "700" | "800" | "900"
            ) {
                style.bold = true;
            } else if matches!(value.as_str(), "normal" | "400") {
                style.bold = false;
            }
        }
        "font-style" => {
            if value == "italic" || value == "oblique" {
                style.italic = true;
            } else if value == "normal" {
                style.italic = false;
            }
        }
        "text-decoration" | "text-decoration-line" => {
            if value.contains("underline") {
                style.underline = true;
            } else if value == "none" {
                style.underline = false;
            }
        }
        "white-space" => {
            style.white_space_pre = matches!(value.as_str(), "pre" | "pre-wrap" | "break-spaces");
        }
        "color" => style.foreground = parse_color(&value).or(style.foreground),
        "background" | "background-color" => {
            style.background = if value == "transparent" || value == "none" {
                None
            } else {
                parse_color(&value).or(style.background)
            };
        }
        "margin" => {
            let first = value.split_whitespace().next().unwrap_or("0");
            let amount = parse_cells(first);
            style.margin_top = amount;
            style.margin_bottom = amount;
        }
        "margin-top" => style.margin_top = parse_cells(&value),
        "margin-bottom" => style.margin_bottom = parse_cells(&value),
        "padding-left" | "margin-left" | "text-indent" => style.padding_left = parse_cells(&value),
        "text-align" => {
            style.text_align = match value.as_str() {
                "center" => TextAlign::Center,
                "right" | "end" => TextAlign::Right,
                _ => TextAlign::Left,
            };
        }
        "width" => {
            if let Some(percent) = value.strip_suffix('%').and_then(|v| v.parse::<u8>().ok()) {
                style.width_percent = Some(percent.min(100));
            }
        }
        _ => {}
    }
}

fn parse_cells(value: &str) -> u8 {
    let numeric = value
        .trim_end_matches("px")
        .trim_end_matches("rem")
        .trim_end_matches("em");
    numeric.parse::<u16>().unwrap_or(0).div_ceil(8).min(12) as u8
}

fn parse_color(value: &str) -> Option<TermColor> {
    if let Some(hex) = value.strip_prefix('#') {
        let bytes = hex.as_bytes();
        let rgb = match bytes.len() {
            3 if bytes.iter().all(u8::is_ascii_hexdigit) => {
                let expand = |byte: u8| -> Option<u8> {
                    let digit = (byte as char).to_digit(16)? as u8;
                    Some(digit * 17)
                };
                let r = expand(bytes[0])?;
                let g = expand(bytes[1])?;
                let b = expand(bytes[2])?;
                (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b)
            }
            6 if bytes.iter().all(u8::is_ascii_hexdigit) => u32::from_str_radix(hex, 16).ok()?,
            _ => return None,
        };
        let r = ((rgb >> 16) & 0xff) as u8;
        let g = ((rgb >> 8) & 0xff) as u8;
        let b = (rgb & 0xff) as u8;
        return Some(nearest_terminal_color(r, g, b));
    }

    match value {
        "black" => Some(TermColor::Black),
        "silver" => Some(TermColor::LightGray),
        "gray" => Some(TermColor::DarkGray),
        "white" => Some(TermColor::White),
        "maroon" | "darkred" => Some(TermColor::DarkRed),
        "red" => Some(TermColor::LightRed),
        "olive" => Some(TermColor::Brown),
        "yellow" => Some(TermColor::Yellow),
        "green" | "darkgreen" => Some(TermColor::DarkGreen),
        "lime" => Some(TermColor::LightGreen),
        "teal" => Some(TermColor::DarkCyan),
        "aqua" | "cyan" => Some(TermColor::LightCyan),
        "navy" => Some(TermColor::DarkBlue),
        "blue" => Some(TermColor::LightBlue),
        "purple" => Some(TermColor::DarkMagenta),
        "fuchsia" | "magenta" => Some(TermColor::LightMagenta),
        _ => None,
    }
}

fn nearest_terminal_color(r: u8, g: u8, b: u8) -> TermColor {
    let palette = [
        (0u8, 0u8, 0u8, TermColor::Black),
        (128, 0, 0, TermColor::DarkRed),
        (0, 128, 0, TermColor::DarkGreen),
        (128, 128, 0, TermColor::Brown),
        (0, 0, 128, TermColor::DarkBlue),
        (128, 0, 128, TermColor::DarkMagenta),
        (0, 128, 128, TermColor::DarkCyan),
        (192, 192, 192, TermColor::LightGray),
        (128, 128, 128, TermColor::DarkGray),
        (255, 0, 0, TermColor::LightRed),
        (0, 255, 0, TermColor::LightGreen),
        (255, 255, 0, TermColor::Yellow),
        (0, 0, 255, TermColor::LightBlue),
        (255, 0, 255, TermColor::LightMagenta),
        (0, 255, 255, TermColor::LightCyan),
        (255, 255, 255, TermColor::White),
    ];
    let mut best = (u32::MAX, TermColor::White);
    for (pr, pg, pb, color) in palette {
        let dr = i32::from(r) - i32::from(pr);
        let dg = i32::from(g) - i32::from(pg);
        let db = i32::from(b) - i32::from(pb);
        let distance = (dr * dr + dg * dg + db * db) as u32;
        if distance < best.0 {
            best = (distance, color);
        }
    }
    best.1
}

fn parse_declarations(input: &str) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 0usize;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' => parentheses = parentheses.saturating_add(1),
            ')' => parentheses = parentheses.saturating_sub(1),
            ';' if parentheses == 0 => {
                if let Some(item) = parse_declaration(&input[start..index]) {
                    declarations.push(item);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if let Some(item) = parse_declaration(&input[start..]) {
        declarations.push(item);
    }
    declarations
}

fn parse_declaration(part: &str) -> Option<Declaration> {
    let (property, value) = part.split_once(':')?;
    let property = property.trim();
    let value = value.trim();
    let important = value
        .to_ascii_lowercase()
        .trim_end()
        .ends_with("!important");
    let value = if important {
        value[..value.len().saturating_sub("!important".len())].trim()
    } else {
        value
    };
    if property.is_empty() || value.is_empty() {
        None
    } else {
        Some(Declaration {
            property: property.to_ascii_lowercase(),
            value: value.to_string(),
            important,
        })
    }
}

fn strip_comments(input: &str) -> String {
    let mut output = String::new();
    let mut rest = input;
    while let Some(start) = rest.find("/*") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("*/") else {
            return output;
        };
        rest = &after[end + 2..];
    }
    output.push_str(rest);
    output
}

fn parse_selector(input: &str) -> Option<Selector> {
    let mut compounds = Vec::new();
    let mut specificity = 0u16;
    for token in input.split_whitespace() {
        let mut compound = CompoundSelector::default();
        let bytes = token.as_bytes();
        let mut cursor = 0usize;
        if cursor < bytes.len() && bytes[cursor] != b'#'
            && bytes[cursor] != b'.' && bytes[cursor] != b'[' && bytes[cursor] != b':'
            && bytes[cursor] != b'*'
        {
            let start = cursor;
            while cursor < bytes.len()
                && !matches!(bytes[cursor], b'#' | b'.' | b'[' | b':' | b'*')
            {
                cursor += 1;
            }
            compound.tag = Some(token[start..cursor].to_ascii_lowercase());
            specificity = specificity.saturating_add(1);
        } else if bytes.get(cursor) == Some(&b'*') {
            cursor += 1;
        }
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'#' | b'.' => {
                    let kind = bytes[cursor];
                    cursor += 1;
                    let start = cursor;
                    while cursor < bytes.len()
                        && !matches!(bytes[cursor], b'#' | b'.' | b'[' | b':')
                    {
                        cursor += 1;
                    }
                    if start == cursor {
                        return None;
                    }
                    let value = token[start..cursor].to_string();
                    if kind == b'#' {
                        compound.id = Some(value);
                        specificity = specificity.saturating_add(100);
                    } else {
                        compound.classes.push(value);
                        specificity = specificity.saturating_add(10);
                    }
                }
                b'[' => {
                    let start = cursor + 1;
                    let end = token[start..].find(']')? + start;
                    let expression = token[start..end].trim();
                    if expression.is_empty() {
                        return None;
                    }
                    let (name, value) = if let Some((name, value)) = expression.split_once('=') {
                        let value = value.trim().trim_matches(['\'', '"']).to_string();
                        (name.trim().to_ascii_lowercase(), Some(value))
                    } else {
                        (expression.to_ascii_lowercase(), None)
                    };
                    if name.is_empty() {
                        return None;
                    }
                    compound.attributes.push((name, value));
                    specificity = specificity.saturating_add(10);
                    cursor = end + 1;
                }
                b':' => {
                    cursor += 1;
                    let start = cursor;
                    while cursor < bytes.len()
                        && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'-')
                    {
                        cursor += 1;
                    }
                    let name = token[start..cursor].to_ascii_lowercase();
                    let pseudo = match name.as_str() {
                        "first-child" => PseudoClass::FirstChild,
                        "last-child" => PseudoClass::LastChild,
                        "only-child" => PseudoClass::OnlyChild,
                        "empty" => PseudoClass::Empty,
                        "nth-child" => {
                            if bytes.get(cursor) != Some(&b'(') {
                                return None;
                            }
                            let end = token[cursor + 1..].find(')')? + cursor + 1;
                            let index = token[cursor + 1..end].trim().parse::<usize>().ok()?;
                            if index == 0 {
                                return None;
                            }
                            cursor = end + 1;
                            PseudoClass::NthChild(index)
                        }
                        _ => return None,
                    };
                    compound.pseudo_classes.push(pseudo);
                    specificity = specificity.saturating_add(10);
                }
                _ => return None,
            }
        }
        if compound.tag.is_some()
            || compound.id.is_some()
            || !compound.classes.is_empty()
            || !compound.attributes.is_empty()
            || !compound.pseudo_classes.is_empty()
        {
            compounds.push(compound);
        }
    }
    if compounds.is_empty() {
        None
    } else {
        Some(Selector {
            compounds,
            specificity,
        })
    }
}

fn matches_selector(dom: &Dom, node: NodeId, selector: &Selector) -> bool {
    let Some(last) = selector.compounds.last() else {
        return false;
    };
    if !matches_compound(dom, node, last) {
        return false;
    }
    let mut ancestor = dom.nodes.get(node).and_then(|item| item.parent);
    for compound in selector.compounds.iter().rev().skip(1) {
        let mut matched = None;
        while let Some(id) = ancestor {
            if matches_compound(dom, id, compound) {
                matched = Some(id);
                ancestor = dom.nodes.get(id).and_then(|item| item.parent);
                break;
            }
            ancestor = dom.nodes.get(id).and_then(|item| item.parent);
        }
        if matched.is_none() {
            return false;
        }
    }
    true
}

fn matches_compound(dom: &Dom, node: NodeId, selector: &CompoundSelector) -> bool {
    if let Some(tag) = &selector.tag {
        if !dom
            .tag(node)
            .is_some_and(|name| name.eq_ignore_ascii_case(tag))
        {
            return false;
        }
    }
    if let Some(id) = &selector.id {
        if dom.attr(node, "id") != Some(id.as_str()) {
            return false;
        }
    }
    if !selector.classes.is_empty() {
        let classes = dom.attr(node, "class").unwrap_or("");
        if selector.classes.iter().any(|wanted| {
            !classes
                .split_ascii_whitespace()
                .any(|class| class == wanted)
        }) {
            return false;
        }
    }
    for (name, expected) in &selector.attributes {
        let Some(actual) = dom.attr(node, name) else {
            return false;
        };
        if expected.as_ref().is_some_and(|value| actual != value) {
            return false;
        }
    }
    if !selector.pseudo_classes.is_empty() {
        let Some(parent) = dom.nodes.get(node).and_then(|item| item.parent) else {
            return false;
        };
        let siblings: Vec<NodeId> = dom
            .children(parent)
            .iter()
            .copied()
            .filter(|id| dom.tag(*id).is_some())
            .collect();
        let Some(position) = siblings.iter().position(|id| *id == node) else {
            return false;
        };
        for pseudo in &selector.pseudo_classes {
            let matches = match pseudo {
                PseudoClass::FirstChild => position == 0,
                PseudoClass::LastChild => position + 1 == siblings.len(),
                PseudoClass::OnlyChild => siblings.len() == 1,
                PseudoClass::NthChild(index) => position + 1 == *index,
                PseudoClass::Empty => {
                    dom.children(node).iter().all(|child| {
                        matches!(&dom.nodes[*child].kind, crate::html5::NodeKind::Comment)
                    })
                }
            };
            if !matches {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html5::build_tree;

    #[test]
    fn cascades_element_class_and_inline_rules() {
        let dom = build_tree(
            "<style>p { color: red } .intro { font-weight: bold; margin-bottom: 16px } #first { color: blue }</style><p id=first class=intro style='text-decoration: underline'>Hello</p>",
        );
        let p = dom.find_by_tag(dom.root, "p")[0];
        let sheet = StyleSheet::from_dom(&dom);
        let style = sheet.compute(&dom, p, &ComputedStyle::default());
        assert!(style.bold);
        assert!(style.underline);
        assert_eq!(style.foreground, Some(TermColor::LightBlue));
        assert_eq!(style.margin_bottom, 2);
    }

    #[test]
    fn rejects_malformed_non_ascii_hex_colors_without_panicking() {
        assert_eq!(parse_color("#éa"), None);
        assert_eq!(parse_color("#zzzzzz"), None);
        assert_eq!(parse_color("#abc"), Some(TermColor::LightGray));
    }

    #[test]
    fn important_and_inline_cascade_order_is_respected() {
        let dom = build_tree(
            "<style>.field{color:red!important}.field{font-weight:bold}</style><input class=field style='color:blue;font-weight:normal'>",
        );
        let input = dom.find_by_tag(dom.root, "input")[0];
        let style = StyleSheet::from_dom(&dom).compute(&dom, input, &ComputedStyle::default());
        assert_eq!(style.foreground, Some(TermColor::LightRed));
        assert!(!style.bold);
    }

    #[test]
    fn matches_attribute_and_basic_structural_selectors() {
        let dom = build_tree(
            "<style>form .field[type=search]:first-child{color:green} form input:last-child{font-weight:bold}</style><form><input class=field type=search><input name=submit></form>",
        );
        let inputs = dom.find_by_tag(dom.root, "input");
        let sheet = StyleSheet::from_dom(&dom);
        let first = sheet.compute(&dom, inputs[0], &ComputedStyle::default());
        let last = sheet.compute(&dom, inputs[1], &ComputedStyle::default());
        assert_eq!(first.foreground, Some(TermColor::DarkGreen));
        assert!(last.bold);
    }

    #[test]
    fn supports_table_display_and_hidden_elements() {
        let dom = build_tree(
            "<style>.gone{display:none} table{display:table}</style><div class=gone>x</div><table></table>",
        );
        let div = dom.find_by_tag(dom.root, "div")[0];
        let table = dom.find_by_tag(dom.root, "table")[0];
        let sheet = StyleSheet::from_dom(&dom);
        assert_eq!(
            sheet.compute(&dom, div, &ComputedStyle::default()).display,
            DisplayMode::None
        );
        assert_eq!(
            sheet
                .compute(&dom, table, &ComputedStyle::default())
                .display,
            DisplayMode::Table
        );
    }
}
