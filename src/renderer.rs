use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::css::{ComputedStyle, DisplayMode, TextAlign};
use crate::document::{
    Block, BlockKind, Document, FormControl, FormControlKind, InlineRun, InlineStyle, Table,
    TableCell, TermColor,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderLine {
    pub spans: Vec<RenderSpan>,
    pub width: usize,
    pub block_index: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderSpan {
    pub text: String,
    pub style: InlineStyle,
    pub link: Option<usize>,
}

impl RenderLine {
    pub fn plain_text(&self) -> String {
        let mut text = String::new();
        for span in &self.spans {
            text.push_str(&span.text);
        }
        text
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0
    }
}

pub fn layout_document(document: &Document, width: usize) -> Vec<RenderLine> {
    let width = width.max(8);
    let mut output = Vec::new();

    for (block_index, block) in document.blocks.iter().enumerate() {
        if block.style.display == DisplayMode::None {
            continue;
        }

        let block_width = block
            .style
            .width_percent
            .map(|percent| {
                width
                    .saturating_mul(percent as usize)
                    .saturating_div(100)
                    .max(8)
            })
            .unwrap_or(width)
            .min(width);
        let indent = block.style.padding_left.min(8) as usize;
        let local_width = block_width.saturating_sub(indent).max(1);
        let mut block_lines = match &block.kind {
            BlockKind::Table { table_index } => document
                .tables
                .get(*table_index)
                .map(|table| layout_table(table, local_width))
                .unwrap_or_default(),
            BlockKind::FormControl {
                form_index,
                control_index,
            } => document
                .forms
                .get(*form_index)
                .and_then(|form| form.controls.get(*control_index))
                .map(|control| layout_form_control(control, local_width))
                .unwrap_or_default(),
            _ => layout_block(block, local_width),
        };
        if block_lines.is_empty() {
            continue;
        }

        for line in &mut block_lines {
            line.block_index = Some(block_index);
            apply_alignment(line, local_width, block.style.text_align);
            apply_block_indent(line, indent);
        }

        let margin_top = block.style.margin_top.min(4) as usize;
        let margin_bottom = block.style.margin_bottom.min(4) as usize;
        for _ in 0..margin_top {
            push_empty(&mut output);
        }
        if !output.is_empty() && !output.last().is_some_and(RenderLine::is_empty) {
            push_empty(&mut output);
        }
        output.extend(block_lines);
        for _ in 0..margin_bottom {
            push_empty(&mut output);
        }
    }

    while output.last().is_some_and(RenderLine::is_empty) {
        output.pop();
    }
    output
}

fn layout_form_control(control: &FormControl, width: usize) -> Vec<RenderLine> {
    let style = InlineStyle::default();
    let mut text = String::new();
    match control.kind {
        FormControlKind::Text
        | FormControlKind::Password
        | FormControlKind::Email
        | FormControlKind::Search
        | FormControlKind::Number
        | FormControlKind::TextArea => {
            let label = if control.label.is_empty() {
                "Input"
            } else {
                control.label.as_str()
            };
            text.push_str(label);
            text.push_str(": [");
            let available = width.saturating_sub(character_width('[') + character_width(']') + label.chars().map(character_width).sum::<usize>() + 2).max(1);
            let shown = if control.kind == FormControlKind::Password {
                "*".repeat(control.value.chars().count())
            } else {
                control.value.replace('\n', " ")
            };
            let shown_width = shown.chars().map(character_width).sum::<usize>();
            if shown_width > available {
                let mut suffix = String::new();
                let mut used = 0usize;
                for ch in shown.chars().rev() {
                    let cw = character_width(ch);
                    if used + cw > available.saturating_sub(1) {
                        break;
                    }
                    suffix.insert(0, ch);
                    used += cw;
                }
                text.push('…');
                text.push_str(&suffix);
            } else {
                text.push_str(&shown);
            }
            text.push(']');
        }
        FormControlKind::Checkbox => {
            text.push_str(if control.checked { "[x] " } else { "[ ] " });
            text.push_str(&control.label);
        }
        FormControlKind::Radio => {
            text.push_str(if control.checked { "(*) " } else { "( ) " });
            text.push_str(&control.label);
        }
        FormControlKind::Select => {
            text.push_str(&control.label);
            text.push_str(": [");
            let selected = control
                .options
                .iter()
                .find(|option| option.value == control.value)
                .map(|option| option.label.as_str())
                .unwrap_or("select");
            text.push_str(selected);
            text.push_str(" v]");
        }
        FormControlKind::Submit => {
            text.push_str("[ ");
            text.push_str(if control.label.is_empty() { "Submit" } else { &control.label });
            text.push_str(" ]");
        }
        FormControlKind::Reset => {
            text.push_str("[ ");
            text.push_str(if control.label.is_empty() { "Reset" } else { &control.label });
            text.push_str(" ]");
        }
        FormControlKind::Button => {
            text.push_str("[ ");
            text.push_str(if control.label.is_empty() { "Button" } else { &control.label });
            text.push_str(" ]");
        }
        FormControlKind::File => {
            text.push_str(&control.label);
            text.push_str(": [file input unsupported]");
        }
        FormControlKind::Hidden => return Vec::new(),
    }
    let run = InlineRun {
        text,
        style,
        link: None,
    };
    wrap_runs(&[run], width, false)
}

fn layout_block(block: &Block, width: usize) -> Vec<RenderLine> {
    let mut prefix = String::new();
    let mut style = InlineStyle {
        strong: block.style.bold,
        emphasis: block.style.italic,
        underline: block.style.underline,
        foreground: block.style.foreground,
        background: block.style.background,
        ..InlineStyle::default()
    };
    let preserve_whitespace =
        block.style.white_space_pre || matches!(&block.kind, BlockKind::Preformatted);

    match &block.kind {
        BlockKind::Paragraph => {}
        BlockKind::Heading(level) => {
            style.strong = true;
            if *level <= 2 {
                style.underline = true;
            }
        }
        BlockKind::Preformatted => prefix.push_str("  "),
        BlockKind::Quote => prefix.push_str("| "),
        BlockKind::ListItem {
            depth,
            ordered,
            ordinal,
        } => {
            for _ in 0..(*depth).min(8) {
                prefix.push_str("  ");
            }
            if *ordered {
                prefix.push_str(&ordinal.to_string());
                prefix.push_str(". ");
            } else {
                prefix.push_str("* ");
            }
        }
        BlockKind::TableRow { header } => {
            prefix.push_str("| ");
            style.strong |= *header;
        }
        BlockKind::Table { .. } => {}
        BlockKind::FormControl { .. } => {}
        BlockKind::DefinitionTerm => style.strong = true,
        BlockKind::DefinitionDescription => prefix.push_str("    "),
        BlockKind::HorizontalRule => {
            return alloc::vec![line_from_text(&"─".repeat(width), style)];
        }
    }

    let mut runs = block.runs.clone();
    if !prefix.is_empty() {
        runs.insert(
            0,
            InlineRun {
                text: prefix,
                style: InlineStyle::default(),
                link: None,
            },
        );
    }
    wrap_runs(&runs, width, preserve_whitespace)
}

fn layout_table(table: &Table, width: usize) -> Vec<RenderLine> {
    if table.rows.is_empty() {
        return Vec::new();
    }

    let column_count = table
        .rows
        .iter()
        .map(|row| {
            row.cells
                .iter()
                .map(|cell| cell.colspan.max(1) as usize)
                .sum::<usize>()
        })
        .max()
        .unwrap_or(0)
        .min(16)
        .min(width.saturating_sub(1).div_euclid(4).max(1));
    if column_count == 0 {
        return Vec::new();
    }

    let mut widths = alloc::vec![3usize; column_count];
    for row in &table.rows {
        let mut column = 0usize;
        for cell in &row.cells {
            let span = (cell.colspan.max(1) as usize).min(column_count.saturating_sub(column));
            if span == 0 {
                continue;
            }
            let measured = max_run_width(&cell.runs).min(width);
            let available = span
                .saturating_mul(3)
                .saturating_add(span.saturating_sub(1) * 2);
            if span == 1 {
                widths[column] = widths[column].max(measured.min(width));
            } else if measured > available {
                let extra = measured - available;
                let each = extra.div_ceil(span);
                for index in column..column + span {
                    widths[index] = widths[index].saturating_add(each).min(width);
                }
            }
            column += span;
        }
    }

    let border_overhead = column_count.saturating_mul(3).saturating_add(1);
    let max_content = width.saturating_sub(border_overhead).max(column_count);
    while widths.iter().sum::<usize>() > max_content {
        let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, value)| **value > 1)
            .max_by_key(|(_, value)| **value)
        else {
            break;
        };
        widths[index] -= 1;
    }

    let mut output = Vec::new();
    output.push(table_border(&widths));
    for row in &table.rows {
        let mut cell_lines: Vec<Vec<RenderLine>> = Vec::new();
        let mut cell_widths = Vec::new();
        let mut column = 0usize;
        for cell in &row.cells {
            if column >= column_count {
                break;
            }
            let span = (cell.colspan.max(1) as usize)
                .min(column_count.saturating_sub(column))
                .max(1);
            let inner = widths[column..column + span]
                .iter()
                .sum::<usize>()
                .saturating_add(span.saturating_sub(1) * 2)
                .max(1);
            let mut lines = wrap_runs(&cell.runs, inner, false);
            let cell_style = InlineStyle {
                strong: row.header || cell.style.bold,
                emphasis: cell.style.italic,
                underline: cell.style.underline,
                foreground: cell.style.foreground,
                background: cell.style.background,
                ..InlineStyle::default()
            };
            for line in &mut lines {
                if row.header {
                    for span in &mut line.spans {
                        span.style.strong = true;
                    }
                } else if line.spans.is_empty() && !cell.runs.is_empty() {
                    line.spans.push(RenderSpan {
                        text: String::new(),
                        style: cell_style,
                        link: None,
                    });
                }
            }
            cell_widths.push(inner);
            cell_lines.push(lines);
            column += span;
        }
        let height = cell_lines.iter().map(Vec::len).max().unwrap_or(1).max(1);
        for line_index in 0..height {
            let mut line = RenderLine::default();
            append_text(&mut line, "| ", InlineStyle::default(), None);
            for cell_index in 0..cell_lines.len() {
                let inner = cell_widths[cell_index];
                let source = cell_lines[cell_index].get(line_index);
                let used = source.map_or(0, |item| item.width).min(inner);
                if let Some(source) = source {
                    for span in &source.spans {
                        append_text(&mut line, &span.text, span.style, span.link);
                    }
                }
                let padding = inner.saturating_sub(used);
                if padding > 0 {
                    append_text(
                        &mut line,
                        &" ".repeat(padding),
                        InlineStyle::default(),
                        None,
                    );
                }
                if cell_index + 1 == cell_lines.len() {
                    append_text(&mut line, " |", InlineStyle::default(), None);
                } else {
                    append_text(&mut line, " | ", InlineStyle::default(), None);
                }
            }
            output.push(line);
        }
        output.push(table_border(&widths));
    }
    output
}

fn table_border(widths: &[usize]) -> RenderLine {
    let mut line = RenderLine::default();
    append_text(&mut line, "+", InlineStyle::default(), None);
    for width in widths {
        append_text(
            &mut line,
            &"-".repeat(width.saturating_add(2)),
            InlineStyle::default(),
            None,
        );
        append_text(&mut line, "+", InlineStyle::default(), None);
    }
    line
}

fn max_run_width(runs: &[InlineRun]) -> usize {
    let mut maximum = 0usize;
    let mut current = 0usize;
    for run in runs {
        for ch in run.text.chars() {
            if ch == '\n' {
                maximum = maximum.max(current);
                current = 0;
            } else {
                current = current.saturating_add(character_width(ch));
            }
        }
    }
    maximum.max(current)
}

fn line_from_text(text: &str, style: InlineStyle) -> RenderLine {
    let mut line = RenderLine::default();
    append_text(&mut line, text, style, None);
    line
}

fn push_empty(lines: &mut Vec<RenderLine>) {
    if !lines.last().is_some_and(RenderLine::is_empty) {
        lines.push(RenderLine::default());
    }
}

fn apply_alignment(line: &mut RenderLine, width: usize, alignment: TextAlign) {
    if line.width >= width {
        return;
    }
    let padding = match alignment {
        TextAlign::Left => 0,
        TextAlign::Center => (width - line.width) / 2,
        TextAlign::Right => width - line.width,
    };
    if padding > 0 {
        line.spans.insert(
            0,
            RenderSpan {
                text: " ".repeat(padding),
                style: InlineStyle::default(),
                link: None,
            },
        );
        line.width = line.width.saturating_add(padding);
    }
}

fn apply_block_indent(line: &mut RenderLine, indent: usize) {
    if indent == 0 || line.is_empty() {
        return;
    }
    line.spans.insert(
        0,
        RenderSpan {
            text: " ".repeat(indent),
            style: InlineStyle::default(),
            link: None,
        },
    );
    line.width = line.width.saturating_add(indent);
}

fn wrap_runs(runs: &[InlineRun], width: usize, preserve_whitespace: bool) -> Vec<RenderLine> {
    let width = width.max(1);
    let mut lines = alloc::vec![RenderLine::default()];
    let mut pending_space = false;

    for run in runs {
        write_text(
            &mut lines,
            &run.text,
            run.style,
            run.link,
            width,
            preserve_whitespace,
            &mut pending_space,
        );
    }
    while lines.len() > 1 && lines.last().is_some_and(RenderLine::is_empty) {
        lines.pop();
    }
    lines
}

fn write_text(
    lines: &mut Vec<RenderLine>,
    text: &str,
    style: InlineStyle,
    link: Option<usize>,
    width: usize,
    preserve_whitespace: bool,
    pending_space: &mut bool,
) {
    for ch in text.chars() {
        if ch == '\n' || ch == '\r' {
            if ch == '\n' {
                lines.push(RenderLine::default());
            }
            *pending_space = false;
            continue;
        }

        if !preserve_whitespace && ch.is_whitespace() {
            *pending_space = !lines.last().is_some_and(RenderLine::is_empty);
            continue;
        }

        let char_width = character_width(ch);
        if preserve_whitespace {
            if lines.last().map_or(0, |line| line.width) + char_width > width
                && !lines.last().is_some_and(RenderLine::is_empty)
            {
                lines.push(RenderLine::default());
            }
            append_char(lines, ch, char_width, style, link);
            continue;
        }

        let current_width = lines.last().map_or(0, |line| line.width);
        if *pending_space
            && current_width > 0
            && current_width.saturating_add(1).saturating_add(char_width) > width
        {
            lines.push(RenderLine::default());
        } else if *pending_space && current_width > 0 {
            append_char(lines, ' ', 1, style, link);
        }
        *pending_space = false;

        let current_width = lines.last().map_or(0, |line| line.width);
        if current_width.saturating_add(char_width) > width
            && !lines.last().is_some_and(RenderLine::is_empty)
        {
            lines.push(RenderLine::default());
        }
        append_char(lines, ch, char_width, style, link);
    }
}

fn append_text(line: &mut RenderLine, text: &str, style: InlineStyle, link: Option<usize>) {
    for ch in text.chars() {
        append_char_to_line(line, ch, character_width(ch), style, link);
    }
}

fn append_char(
    lines: &mut Vec<RenderLine>,
    ch: char,
    char_width: usize,
    style: InlineStyle,
    link: Option<usize>,
) {
    if let Some(line) = lines.last_mut() {
        append_char_to_line(line, ch, char_width, style, link);
    }
}

fn append_char_to_line(
    line: &mut RenderLine,
    ch: char,
    char_width: usize,
    style: InlineStyle,
    link: Option<usize>,
) {
    if let Some(span) = line.spans.last_mut() {
        if span.style == style && span.link == link {
            span.text.push(ch);
            line.width = line.width.saturating_add(char_width);
            return;
        }
    }
    let mut text = String::new();
    text.push(ch);
    line.spans.push(RenderSpan { text, style, link });
    line.width = line.width.saturating_add(char_width);
}

pub fn character_width(ch: char) -> usize {
    let code = ch as u32;
    if code == 0
        || matches!(code, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
    {
        return 0;
    }
    if matches!(
        code,
        0x1100..=0x115F
            | 0x2329..=0x232A
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD
    ) {
        2
    } else {
        1
    }
}

pub fn find_line(lines: &[RenderLine], query: &str, start: usize) -> Option<usize> {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return None;
    }
    lines
        .iter()
        .enumerate()
        .skip(start.min(lines.len()))
        .find_map(|(index, line)| {
            line.plain_text()
                .to_ascii_lowercase()
                .contains(&query)
                .then_some(index)
        })
}

pub fn line_for_link(lines: &[RenderLine], link_index: usize) -> Option<usize> {
    lines.iter().enumerate().find_map(|(line_index, line)| {
        line.spans
            .iter()
            .any(|span| span.link == Some(link_index))
            .then_some(line_index)
    })
}

pub fn line_for_anchor(document: &Document, lines: &[RenderLine], name: &str) -> Option<usize> {
    let block = document.anchor_block(name)?;
    lines
        .iter()
        .enumerate()
        .find_map(|(index, line)| (line.block_index == Some(block)).then_some(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{Block, Document, Link, Table, TableCell, TableRow};

    #[test]
    fn wraps_to_terminal_width_without_losing_link_metadata() {
        let document = Document {
            title: "Example".to_string(),
            text: "A useful sentence with a link".to_string(),
            links: alloc::vec![Link {
                label: "link".to_string(),
                target: "https://example.org".to_string(),
            }],
            blocks: alloc::vec![Block {
                kind: BlockKind::Paragraph,
                runs: alloc::vec![
                    InlineRun {
                        text: "A useful sentence with a ".to_string(),
                        style: InlineStyle::default(),
                        link: None,
                    },
                    InlineRun {
                        text: "link".to_string(),
                        style: InlineStyle::default(),
                        link: Some(0),
                    },
                ],
                style: ComputedStyle::default(),
            }],
            ..Document::default()
        };

        let lines = layout_document(&document, 12);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.width <= 12));
        assert!(
            lines
                .iter()
                .any(|line| line.spans.iter().any(|span| span.link == Some(0)))
        );
        assert_eq!(line_for_link(&lines, 0), Some(2));
    }

    #[test]
    fn renders_current_form_values_and_masks_passwords() {
        use crate::document::{Form, FormControl};

        let document = Document {
            forms: alloc::vec![Form {
                action: "https://example.org/login".to_string(),
                method: crate::document::FormMethod::Post,
                controls: alloc::vec![
                    FormControl {
                        name: "user".to_string(),
                        label: "Username".to_string(),
                        value: "alice".to_string(),
                        kind: FormControlKind::Text,
                        required: true,
                        disabled: false,
                        checked: false,
                        options: Vec::new(),
                    },
                    FormControl {
                        name: "password".to_string(),
                        label: "Password".to_string(),
                        value: "secret".to_string(),
                        kind: FormControlKind::Password,
                        required: true,
                        disabled: false,
                        checked: false,
                        options: Vec::new(),
                    },
                ],
            }],
            blocks: alloc::vec![
                Block {
                    kind: BlockKind::FormControl { form_index: 0, control_index: 0 },
                    runs: Vec::new(),
                    style: ComputedStyle::default(),
                },
                Block {
                    kind: BlockKind::FormControl { form_index: 0, control_index: 1 },
                    runs: Vec::new(),
                    style: ComputedStyle::default(),
                },
            ],
            ..Document::default()
        };
        let lines = layout_document(&document, 60);
        let rendered = lines.iter().map(RenderLine::plain_text).collect::<Vec<_>>().join("\n");
        assert!(rendered.contains("Username: [alice]"));
        assert!(rendered.contains("Password: [******]"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn recognizes_double_width_and_combining_characters() {
        assert_eq!(character_width('界'), 2);
        assert_eq!(character_width('e'), 1);
        assert_eq!(character_width('\u{0301}'), 0);
    }

    #[test]
    fn lays_out_tables_using_measured_column_widths() {
        let table = Table {
            rows: alloc::vec![
                TableRow {
                    header: true,
                    cells: alloc::vec![
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "Name".to_string(),
                                style: InlineStyle::default(),
                                link: None
                            }],
                            colspan: 1,
                            rowspan: 1,
                            style: ComputedStyle::default()
                        },
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "Value".to_string(),
                                style: InlineStyle::default(),
                                link: None
                            }],
                            colspan: 1,
                            rowspan: 1,
                            style: ComputedStyle::default()
                        },
                    ],
                },
                TableRow {
                    header: false,
                    cells: alloc::vec![
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "port".to_string(),
                                style: InlineStyle::default(),
                                link: None
                            }],
                            colspan: 1,
                            rowspan: 1,
                            style: ComputedStyle::default()
                        },
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "443".to_string(),
                                style: InlineStyle::default(),
                                link: None
                            }],
                            colspan: 1,
                            rowspan: 1,
                            style: ComputedStyle::default()
                        },
                    ],
                },
            ],
        };
        let lines = layout_table(&table, 32);
        assert!(lines.iter().any(|line| line.plain_text().contains("Name")));
        assert!(lines.iter().any(|line| line.plain_text().contains("443")));
        assert!(lines.iter().all(|line| line.width <= 32));
        let narrow = layout_table(&table, 8);
        assert!(narrow.iter().all(|line| line.width <= 8));
    }

    #[test]
    fn search_returns_matching_rendered_line() {
        let document = Document::from_plain("Example", "first line\nsecond match\nthird line");
        let lines = layout_document(&document, 80);
        assert_eq!(find_line(&lines, "MATCH", 0), Some(1));
        assert_eq!(find_line(&lines, "match", 2), None);
    }
}
