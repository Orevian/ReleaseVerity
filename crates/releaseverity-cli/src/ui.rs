//! Terminal rendering: colours only when the terminal supports them, ASCII fallback always available.

use releaseverity_services::core::model::{Status, Verdict};
use std::io::IsTerminal;

#[derive(Clone, Copy)]
pub struct Style {
    pub color: bool,
    pub unicode: bool,
    pub tty: bool,
}

impl Style {
    pub fn detect(no_color: bool, ascii: bool) -> Self {
        let tty = std::io::stdout().is_terminal();
        let mut color =
            tty && !no_color && std::env::var_os("NO_COLOR").is_none() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true);
        if color {
            color = enable_ansi_support::enable_ansi_support().is_ok() || !cfg!(windows);
        }
        let unicode = !ascii && std::env::var_os("RELEASEVERITY_ASCII").is_none();
        #[cfg(windows)]
        if unicode && tty {
            // Make the console render UTF-8 symbols (✓ ⚠ ✗) regardless of the legacy code page.
            #[link(name = "kernel32")]
            extern "system" {
                fn SetConsoleOutputCP(cp: u32) -> i32;
            }
            unsafe { SetConsoleOutputCP(65001) };
        }
        Self { color, unicode, tty }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn status_symbol(&self, s: Status) -> String {
        let (sym, code) = match s {
            Status::Pass => (if self.unicode { "✓" } else { "OK" }, "32"),
            Status::Warn => (if self.unicode { "⚠" } else { "WARN" }, "33"),
            Status::Fail => (if self.unicode { "✗" } else { "FAIL" }, "31"),
            Status::Error => (if self.unicode { "!" } else { "ERR" }, "31"),
            Status::Skipped => ("-", "90"),
        };
        self.paint(code, sym)
    }

    pub fn verdict(&self, v: Verdict, text: &str) -> String {
        let code = match v {
            Verdict::Verified => "1;32",
            Verdict::VerifiedWithWarnings => "1;33",
            Verdict::Failed => "1;31",
            Verdict::Inconclusive => "1;90",
        };
        self.paint(code, text)
    }
}

/// Pad to a display width (counting chars, good enough for our labels).
pub fn pad(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(w - n))
    }
}

/// Plain-text table with a header row.
pub fn table(rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> =
        (0..cols).map(|c| rows.iter().map(|r| r.get(c).map(|s| s.chars().count()).unwrap_or(0)).max().unwrap_or(0)).collect();
    rows.iter()
        .map(|r| {
            (0..cols)
                .map(|c| pad(r.get(c).map(String::as_str).unwrap_or(""), widths[c]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_output_has_no_escape_codes_and_ascii_fallback_works() {
        let s = Style { color: false, unicode: false, tty: false };
        assert_eq!(s.status_symbol(Status::Pass), "OK");
        assert_eq!(s.bold("x"), "x");
        let c = Style { color: true, unicode: true, tty: true };
        assert!(c.status_symbol(Status::Fail).contains("\x1b[31m"));
    }

    #[test]
    fn table_aligns_columns() {
        let t = table(&[vec!["a".into(), "bbb".into()], vec!["cccc".into(), "d".into()]]);
        assert_eq!(t, "a     bbb\ncccc  d");
    }
}
