use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::css::{ComputedStyle, DisplayMode, TextAlign};
use crate::document::{
    Block, BlockKind, Document, FormControl, FormControlKind, InlineRun, InlineStyle, Table,
    TableCell,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderLine {
    pub spans: Vec<RenderSpan>,
    pub width: usize,
    pub block_index: Option<usize>,
    /// True on the visual row that represents the interactive face of a control.
    pub focusable_control: bool,
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
    let width = width.max(8);
    let style = InlineStyle::default();
    let mut output = Vec::new();

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
                &control.label
            };
            push_label_lines(&mut output, label, width);

            let box_width = width.min(36).max(8);
            let inner_width = box_width.saturating_sub(4).max(1);
            let border = format!("+{}+", "-".repeat(box_width.saturating_sub(2)));
            output.push(line_from_text(&border, style));

            let mut value = if control.kind == FormControlKind::Password {
                "*".repeat(control.value.chars().count())
            } else {
                control.value.replace(['\r', '\n'], " ")
            };
            let field_chars = inner_width.saturating_sub(1).max(1);
            let field_width = value.chars().map(character_width).sum::<usize>();
            if field_width > field_chars {
                let mut suffix = String::new();
                let mut used = 0usize;
                for ch in value.chars().rev() {
                    let char_width = character_width(ch);
                    if used.saturating_add(char_width) > field_chars.saturating_sub(1) {
                        break;
                    }
                    suffix.insert(0, ch);
                    used += char_width;
                }
                value = format!("<{suffix}");
            }
            let shown_width = value.chars().map(character_width).sum::<usize>();
            let padding = inner_width.saturating_sub(shown_width.saturating_add(1));
            let mut face = String::from("| ");
            face.push_str(&value);
            face.push('_');
            face.push_str(&" ".repeat(padding));
            face.push_str(" |");
            let mut input_line = line_from_text(&face, style);
            input_line.focusable_control = true;
            output.push(input_line);
            output.push(line_from_text(&border, style));
        }
        FormControlKind::Select => {
            push_label_lines(
                &mut output,
                if control.label.is_empty() {
                    "Select"
                } else {
                    &control.label
                },
                width,
            );
            let box_width = width.min(36).max(8);
            let border = format!("+{}+", "-".repeat(box_width.saturating_sub(2)));
            output.push(line_from_text(&border, style));
            let selected = control
                .options
                .iter()
                .find(|option| option.value == control.value)
                .map(|option| option.label.as_str())
                .unwrap_or("select");
            let visible: String = selected.chars().take(box_width.saturating_sub(8)).collect();
            let padding = box_width.saturating_sub(visible.chars().count().saturating_add(8));
            let face = format!("| < {visible} >{} |", " ".repeat(padding));
            let mut input_line = line_from_text(&face, style);
            input_line.focusable_control = true;
            output.push(input_line);
            output.push(line_from_text(&border, style));
        }
        FormControlKind::Checkbox => {
            let checked = if control.checked { "[X] " } else { "[ ] " };
            let mut line = line_from_text(&format!("{checked}{}", control.label), style);
            line.focusable_control = true;
            output.extend(wrap_render_line(line, width));
        }
        FormControlKind::Radio => {
            let checked = if control.checked { "(*) " } else { "( ) " };
            let mut line = line_from_text(&format!("{checked}{}", control.label), style);
            line.focusable_control = true;
            output.extend(wrap_render_line(line, width));
        }
        FormControlKind::Submit | FormControlKind::Reset | FormControlKind::Button => {
            let label = if control.label.is_empty() {
                match control.kind {
                    FormControlKind::Submit => "Submit",
                    FormControlKind::Reset => "Reset",
                    _ => "Button",
                }
            } else {
                &control.label
            };
            let face = format!("[ {label} ]");
            let mut line = line_from_text(&face, style);
            line.focusable_control = true;
            output.extend(wrap_render_line(line, width));
        }
        FormControlKind::File => {
            let mut line = line_from_text(
                &format!("{}: [file input unsupported]", control.label),
                style,
            );
            line.focusable_control = true;
            output.extend(wrap_render_line(line, width));
        }
        FormControlKind::Hidden => {}
    }
    output
}

fn push_label_lines(output: &mut Vec<RenderLine>, label: &str, width: usize) {
    if !label.is_empty() {
        let run = InlineRun {
            text: label.to_string(),
            style: InlineStyle::default(),
            link: None,
        };
        output.extend(wrap_runs(&[run], width, false));
    }
}

fn wrap_render_line(line: RenderLine, width: usize) -> Vec<RenderLine> {
    if line.width <= width {
        return alloc::vec![line];
    }
    let mut wrapped = wrap_runs(
        &[InlineRun {
            text: line.plain_text(),
            style: line
                .spans
                .first()
                .map_or(InlineStyle::default(), |span| span.style),
            link: None,
        }],
        width,
        false,
    );
    if let Some(first) = wrapped.first_mut() {
        first.focusable_control = true;
    }
    wrapped
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

    struct CellPlacement<'a> {
        row: usize,
        column: usize,
        colspan: usize,
        rowspan: usize,
        cell: &'a TableCell,
        lines: Vec<RenderLine>,
        inner_width: usize,
    }

    let max_columns = 16usize.min(width.saturating_sub(1).div_euclid(4).max(1));
    let row_count = table.rows.len();
    let mut remaining = alloc::vec![0usize; max_columns];
    let mut placements = Vec::new();
    let mut column_count = 0usize;

    // Place each cell into the first unoccupied columns. Rowspan reservations
    // are carried forward, so later rows cannot overwrite a cell above them.
    for (row_index, row) in table.rows.iter().enumerate() {
        let mut column = 0usize;
        for cell in &row.cells {
            while column < max_columns && remaining[column] > 0 {
                column += 1;
            }
            if column >= max_columns {
                break;
            }
            let colspan = (cell.colspan.max(1) as usize).min(max_columns.saturating_sub(column));
            let rowspan =
                (cell.rowspan.max(1) as usize).min(row_count.saturating_sub(row_index).max(1));
            for occupied in &mut remaining[column..column + colspan] {
                *occupied = rowspan;
            }
            column_count = column_count.max(column + colspan);
            placements.push(CellPlacement {
                row: row_index,
                column,
                colspan,
                rowspan,
                cell,
                lines: Vec::new(),
                inner_width: 1,
            });
            column += colspan;
        }
        for occupied in &mut remaining {
            *occupied = occupied.saturating_sub(1);
        }
    }
    if column_count == 0 {
        return Vec::new();
    }

    let mut widths = alloc::vec![3usize; column_count];
    for placement in &placements {
        let span = placement.colspan;
        let measured = max_run_width(&placement.cell.runs).min(width);
        let available = span
            .saturating_mul(3)
            .saturating_add(span.saturating_sub(1) * 2);
        if span == 1 {
            widths[placement.column] = widths[placement.column].max(measured);
        } else if measured > available {
            let extra = measured - available;
            let each = extra.div_ceil(span);
            for index in placement.column..placement.column + span {
                widths[index] = widths[index].saturating_add(each).min(width);
            }
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

    for placement in &mut placements {
        placement.inner_width = widths[placement.column..placement.column + placement.colspan]
            .iter()
            .sum::<usize>()
            .saturating_add(placement.colspan.saturating_sub(1) * 2)
            .max(1);
        placement.lines = wrap_runs(&placement.cell.runs, placement.inner_width, false);
        if placement.lines.is_empty() {
            placement.lines.push(RenderLine::default());
        }
        if table.rows[placement.row].header {
            for line in &mut placement.lines {
                for span in &mut line.spans {
                    span.style.strong = true;
                }
            }
        } else if placement.cell.style.bold
            || placement.cell.style.italic
            || placement.cell.style.underline
            || placement.cell.style.foreground.is_some()
            || placement.cell.style.background.is_some()
        {
            let style = InlineStyle {
                strong: placement.cell.style.bold,
                emphasis: placement.cell.style.italic,
                underline: placement.cell.style.underline,
                foreground: placement.cell.style.foreground,
                background: placement.cell.style.background,
                ..InlineStyle::default()
            };
            for line in &mut placement.lines {
                for span in &mut line.spans {
                    span.style = style;
                }
            }
        }
    }

    // A spanning cell may need more vertical space than its starting row.
    // Distribute that extra height across the rows it occupies.
    let mut row_heights = alloc::vec![1usize; row_count];
    for placement in &placements {
        let required = placement.lines.len();
        let current = row_heights[placement.row..placement.row + placement.rowspan]
            .iter()
            .sum::<usize>();
        if required > current {
            let extra = required - current;
            for offset in 0..extra {
                let row = placement.row + (offset % placement.rowspan);
                row_heights[row] = row_heights[row].saturating_add(1).min(128);
            }
        }
    }

    let mut output = Vec::new();
    output.push(table_border(&widths));
    let mut row_offsets = alloc::vec![0usize; row_count];
    for row in 1..row_count {
        row_offsets[row] = row_offsets[row - 1].saturating_add(row_heights[row - 1]);
    }

    for row in 0..row_count {
        for line_index in 0..row_heights[row] {
            let mut line = RenderLine::default();
            append_text(&mut line, "| ", InlineStyle::default(), None);
            let mut column = 0usize;
            while column < column_count {
                let active = placements.iter().find(|placement| {
                    placement.column == column
                        && placement.row <= row
                        && row < placement.row + placement.rowspan
                });
                if let Some(placement) = active {
                    let offset = row_offsets[row]
                        .saturating_sub(row_offsets[placement.row])
                        .saturating_add(line_index);
                    let source = placement.lines.get(offset);
                    let used = source
                        .map_or(0, |item| item.width)
                        .min(placement.inner_width);
                    if let Some(source) = source {
                        for span in &source.spans {
                            append_text(&mut line, &span.text, span.style, span.link);
                        }
                    }
                    let padding = placement.inner_width.saturating_sub(used);
                    if padding > 0 {
                        append_text(
                            &mut line,
                            &" ".repeat(padding),
                            InlineStyle::default(),
                            None,
                        );
                    }
                    column += placement.colspan;
                } else {
                    let cell_width = widths[column];
                    append_text(
                        &mut line,
                        &" ".repeat(cell_width),
                        InlineStyle::default(),
                        None,
                    );
                    column += 1;
                }
                if column >= column_count {
                    append_text(&mut line, " |", InlineStyle::default(), None);
                } else {
                    append_text(&mut line, " | ", InlineStyle::default(), None);
                }
            }
            output.push(line);
        }

        let mut continued_columns = alloc::vec![false; column_count];
        for placement in &placements {
            if placement.row <= row && placement.row + placement.rowspan > row + 1 {
                for column in placement.column..placement.column + placement.colspan {
                    continued_columns[column] = true;
                }
            }
        }
        output.push(table_border_with_rowspan(&widths, &continued_columns));
    }
    output
}

fn table_border_with_rowspan(widths: &[usize], continued: &[bool]) -> RenderLine {
    let mut line = RenderLine::default();
    append_text(&mut line, "+", InlineStyle::default(), None);
    for (index, width) in widths.iter().enumerate() {
        let segment = if continued.get(index).copied().unwrap_or(false) {
            " ".repeat(width.saturating_add(2))
        } else {
            "-".repeat(width.saturating_add(2))
        };
        append_text(&mut line, &segment, InlineStyle::default(), None);
        append_text(&mut line, "+", InlineStyle::default(), None);
    }
    line
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

pub fn line_for_control(lines: &[RenderLine], block_index: usize) -> Option<usize> {
    lines.iter().enumerate().find_map(|(index, line)| {
        (line.block_index == Some(block_index) && line.focusable_control).then_some(index)
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
                        read_only: false,
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
                        read_only: false,
                        checked: false,
                        options: Vec::new(),
                    },
                ],
            }],
            blocks: alloc::vec![
                Block {
                    kind: BlockKind::FormControl {
                        form_index: 0,
                        control_index: 0
                    },
                    runs: Vec::new(),
                    style: ComputedStyle::default(),
                },
                Block {
                    kind: BlockKind::FormControl {
                        form_index: 0,
                        control_index: 1
                    },
                    runs: Vec::new(),
                    style: ComputedStyle::default(),
                },
            ],
            ..Document::default()
        };
        let lines = layout_document(&document, 60);
        let rendered = lines
            .iter()
            .map(RenderLine::plain_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("Username"));
        assert!(rendered.contains("+"));
        assert!(rendered.contains("| alice_"));
        assert!(rendered.contains("| ******_"));
        assert!(!rendered.contains("secret"));
        assert_eq!(
            lines.iter().filter(|line| line.focusable_control).count(),
            2
        );
        let username_focus = line_for_control(&lines, 0).unwrap();
        let password_focus = line_for_control(&lines, 1).unwrap();
        assert!(lines[username_focus].plain_text().contains("alice_"));
        assert!(lines[password_focus].plain_text().contains("******_"));
        assert!(lines.iter().all(|line| line.width <= 60));
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
    fn table_rowspan_reserves_columns_and_draws_merged_cell() {
        let table = Table {
            rows: alloc::vec![
                TableRow {
                    header: false,
                    cells: alloc::vec![
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "Shared".to_string(),
                                style: InlineStyle::default(),
                                link: None,
                            }],
                            colspan: 1,
                            rowspan: 2,
                            style: ComputedStyle::default(),
                        },
                        TableCell {
                            runs: alloc::vec![InlineRun {
                                text: "Top".to_string(),
                                style: InlineStyle::default(),
                                link: None,
                            }],
                            colspan: 1,
                            rowspan: 1,
                            style: ComputedStyle::default(),
                        },
                    ],
                },
                TableRow {
                    header: false,
                    cells: alloc::vec![TableCell {
                        runs: alloc::vec![InlineRun {
                            text: "Lower".to_string(),
                            style: InlineStyle::default(),
                            link: None,
                        }],
                        colspan: 1,
                        rowspan: 1,
                        style: ComputedStyle::default(),
                    }],
                },
            ],
        };
        let lines = layout_table(&table, 40);
        let rendered = lines
            .iter()
            .map(RenderLine::plain_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("Shared"));
        assert!(rendered.contains("Top"));
        assert!(rendered.contains("Lower"));
        assert!(lines.iter().all(|line| line.width <= 40));
        let lower = lines
            .iter()
            .find(|line| line.plain_text().contains("Lower"))
            .unwrap();
        assert!(
            lower.plain_text().find("Lower").unwrap()
                > lower.plain_text().find("Shared").unwrap_or(0)
        );
    }

    #[test]
    fn search_returns_matching_rendered_line() {
        let document = Document::from_plain("Example", "first line\nsecond match\nthird line");
        let lines = layout_document(&document, 80);
        assert_eq!(find_line(&lines, "MATCH", 0), Some(1));
        assert_eq!(find_line(&lines, "match", 2), None);
    }
}
