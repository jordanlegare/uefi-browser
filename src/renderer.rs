use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::document::{BlockKind, Document, InlineRun, InlineStyle};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderLine {
    pub spans: Vec<RenderSpan>,
    pub width: usize,
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
    let mut lines = alloc::vec![RenderLine::default()];
    let mut previous_kind: Option<&BlockKind> = None;
    let mut pending_space = false;

    for block in &document.blocks {
        pending_space = false;
        let adjacent_group = matches!(
            (previous_kind, &block.kind),
            (Some(BlockKind::ListItem { .. }), BlockKind::ListItem { .. })
                | (Some(BlockKind::TableRow { .. }), BlockKind::TableRow { .. })
        );

        if !lines.last().is_some_and(RenderLine::is_empty) && !adjacent_group {
            lines.push(RenderLine::default());
        }

        let mut prefix = String::new();
        let mut block_style = InlineStyle::default();
        let preserve_whitespace = matches!(&block.kind, BlockKind::Preformatted);

        match &block.kind {
            BlockKind::Paragraph => {}
            BlockKind::Heading(level) => {
                block_style.strong = true;
                if *level <= 2 {
                    block_style.underline = true;
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
                block_style.strong = *header;
            }
            BlockKind::DefinitionTerm => block_style.strong = true,
            BlockKind::DefinitionDescription => prefix.push_str("    "),
        }

        if !prefix.is_empty() {
            write_text(
                &mut lines,
                &prefix,
                InlineStyle::default(),
                None,
                width,
                true,
                &mut pending_space,
            );
        }

        for run in &block.runs {
            let mut style = run.style;
            if block_style.strong {
                style.strong = true;
            }
            if block_style.underline {
                style.underline = true;
            }
            write_run(
                &mut lines,
                run,
                style,
                run.link,
                width,
                preserve_whitespace,
                &mut pending_space,
            );
        }

        if !matches!(
            &block.kind,
            BlockKind::ListItem { .. } | BlockKind::TableRow { .. }
        ) && !lines.last().is_some_and(RenderLine::is_empty)
        {
            lines.push(RenderLine::default());
        }
        pending_space = false;
        previous_kind = Some(&block.kind);
    }

    while lines.len() > 1 && lines.last().is_some_and(RenderLine::is_empty) {
        lines.pop();
    }
    lines
}

fn write_run(
    lines: &mut Vec<RenderLine>,
    run: &InlineRun,
    style: InlineStyle,
    link: Option<usize>,
    width: usize,
    preserve_whitespace: bool,
    pending_space: &mut bool,
) {
    write_text(
        lines,
        &run.text,
        style,
        link,
        width,
        preserve_whitespace,
        pending_space,
    );
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

fn append_char(
    lines: &mut Vec<RenderLine>,
    ch: char,
    char_width: usize,
    style: InlineStyle,
    link: Option<usize>,
) {
    let Some(line) = lines.last_mut() else {
        return;
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{Block, Link};

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
            }],
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
    fn recognizes_double_width_and_combining_characters() {
        assert_eq!(character_width('界'), 2);
        assert_eq!(character_width('e'), 1);
        assert_eq!(character_width('\u{0301}'), 0);
    }

    #[test]
    fn search_returns_matching_rendered_line() {
        let document = Document::from_plain("Example", "first line\nsecond match\nthird line");
        let lines = layout_document(&document, 80);
        assert_eq!(find_line(&lines, "MATCH", 0), Some(1));
        assert_eq!(find_line(&lines, "match", 2), None);
    }
}
