//! Python `str` indexing over Rust strings: loki.py offsets are code-point indices,
//! its regexes run on masked copies with the same length, and its scanners
//! (masks, bracket matching) walk characters. Everything here is char-indexed.

use fancy_regex::Regex;

/// A string with code-point indexing.
pub struct Text {
    pub s: String,
    pub c: Vec<char>,
    starts: Vec<usize>,
}

impl Text {
    pub fn new(s: &str) -> Text {
        Text::from_chars(s.chars().collect())
    }

    pub fn from_chars(c: Vec<char>) -> Text {
        let mut starts = Vec::with_capacity(c.len() + 1);
        let mut s = String::with_capacity(c.len());
        for ch in &c {
            starts.push(s.len());
            s.push(*ch);
        }
        starts.push(s.len());
        Text { s, c, starts }
    }

    pub fn len(&self) -> usize {
        self.c.len()
    }

    pub fn is_empty(&self) -> bool {
        self.c.is_empty()
    }

    /// Byte offset of a char index (clamped).
    pub fn byte(&self, index: usize) -> usize {
        self.starts[index.min(self.c.len())]
    }

    /// Char index of a byte offset at a char boundary.
    pub fn index(&self, byte: usize) -> usize {
        if self.s.len() == self.c.len() {
            return byte;
        }
        self.starts.partition_point(|&b| b < byte)
    }

    /// `text[a:b]` with Python's clamping.
    pub fn sl(&self, a: usize, b: usize) -> &str {
        let b = b.min(self.c.len());
        let a = a.min(b);
        &self.s[self.byte(a)..self.byte(b)]
    }

    /// `str.find(needle, start)`.
    pub fn find(&self, needle: &str, start: usize) -> Option<usize> {
        if start > self.c.len() {
            return None;
        }
        self.s[self.byte(start)..]
            .find(needle)
            .map(|b| self.index(self.byte(start) + b))
    }

    /// `str.startswith(prefix, index)`.
    pub fn starts_at(&self, index: usize, prefix: &str) -> bool {
        index <= self.c.len() && self.s[self.byte(index)..].starts_with(prefix)
    }

    /// `str.count("\n", 0, end)`.
    pub fn newlines_before(&self, end: usize) -> usize {
        self.c[..end.min(self.c.len())].iter().filter(|&&c| c == '\n').count()
    }

    pub fn at(&self, index: usize) -> Option<char> {
        self.c.get(index).copied()
    }
}

/// A match with char-indexed group spans.
#[derive(Clone, Debug)]
pub struct M {
    pub spans: Vec<Option<(usize, usize)>>,
}

impl M {
    pub fn start(&self) -> usize {
        self.spans[0].map_or(0, |s| s.0)
    }

    pub fn end(&self) -> usize {
        self.spans[0].map_or(0, |s| s.1)
    }

    pub fn get(&self, group: usize) -> Option<(usize, usize)> {
        self.spans.get(group).copied().flatten()
    }

    pub fn group<'t>(&self, text: &'t Text, group: usize) -> Option<&'t str> {
        self.get(group).map(|(a, b)| text.sl(a, b))
    }

    pub fn whole<'t>(&self, text: &'t Text) -> &'t str {
        text.sl(self.start(), self.end())
    }
}

/// A Python-compatible (backtracking, look-around) regular expression.
pub struct Re(Regex);

impl Re {
    pub fn new(pattern: &str) -> Re {
        Re(Regex::new(pattern).unwrap_or_else(|e| panic!("static pattern {pattern}: {e}")))
    }

    fn convert(&self, text: &Text, caps: &fancy_regex::Captures<'_, str>) -> M {
        M {
            spans: (0..caps.len())
                .map(|i| caps.get(i).map(|m| (text.index(m.start()), text.index(m.end()))))
                .collect(),
        }
    }

    /// `pattern.finditer(text)`.
    pub fn iter(&self, text: &Text) -> Vec<M> {
        self.iter_from(text, 0)
    }

    pub fn iter_from(&self, text: &Text, pos: usize) -> Vec<M> {
        let mut found = Vec::new();
        let mut at = text.byte(pos);
        while at <= text.s.len() {
            let Ok(Some(caps)) = self.0.captures_from_pos(text.s.as_str(), at) else {
                break;
            };
            let whole = caps.get(0).expect("group 0");
            found.push(self.convert(text, &caps));
            at = if whole.end() > whole.start() {
                whole.end()
            } else {
                match text.s[whole.end()..].chars().next() {
                    Some(c) => whole.end() + c.len_utf8(),
                    None => break,
                }
            };
        }
        found
    }

    /// `pattern.search(text, pos)`.
    pub fn search(&self, text: &Text, pos: usize) -> Option<M> {
        if pos > text.len() {
            return None;
        }
        match self.0.captures_from_pos(text.s.as_str(), text.byte(pos)) {
            Ok(Some(caps)) => Some(self.convert(text, &caps)),
            _ => None,
        }
    }

    /// `pattern.match(text, pos)`: a match starting exactly at pos.
    pub fn match_at(&self, text: &Text, pos: usize) -> Option<M> {
        self.search(text, pos).filter(|m| m.start() == pos)
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.0.is_match(s).unwrap_or(false)
    }

    /// `re.findall` for patterns without groups (whole matches) on plain strings.
    pub fn find_strs<'s>(&self, s: &'s str) -> Vec<&'s str> {
        self.0.find_iter(s).filter_map(Result::ok).map(|m| m.as_str()).collect()
    }

    /// Group 1 of every match (`re.findall` with one group); `""` when it did not take part.
    pub fn group1_strs<'s>(&self, s: &'s str) -> Vec<&'s str> {
        self.0
            .captures_iter(s)
            .filter_map(Result::ok)
            .map(|c| c.get(1).map_or("", |m| m.as_str()))
            .collect()
    }

    pub fn raw(&self) -> &Regex {
        &self.0
    }
}

/// `blank`: spaces over chars[start:end], newlines kept.
pub fn blank(chars: &mut [char], start: usize, end: usize) {
    let end = end.min(chars.len());
    for c in chars.iter_mut().take(end).skip(start) {
        if *c != '\n' {
            *c = ' ';
        }
    }
}

/// Index of the closing quote, or where an unterminated literal stops.
pub fn closing_quote(text: &[char], start: usize, quote: char, multiline: bool) -> usize {
    let mut index = start;
    while index < text.len() {
        let c = text[index];
        if c == '\\' {
            index += 2;
            continue;
        }
        if c == quote || (c == '\n' && !multiline) {
            return index;
        }
        index += 1;
    }
    text.len()
}

fn find_chars(text: &[char], needle: &[char], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(text.len()));
    }
    (from..text.len().saturating_sub(needle.len() - 1)).find(|&i| text[i..].starts_with(needle))
}

/// End of a `//` or `/*` comment starting at index.
pub fn comment_end(text: &[char], index: usize) -> Option<usize> {
    if text[index..].starts_with(&['/', '/']) {
        return Some(find_chars(text, &['\n'], index).unwrap_or(text.len()));
    }
    if text[index..].starts_with(&['/', '*']) {
        return Some(find_chars(text, &['*', '/'], index + 2).map_or(text.len(), |e| e + 2));
    }
    None
}

const JS_REGEX_PRECEDERS: &str = "(,=:[!&|?{};+-*%<>~^";
const JS_REGEX_KEYWORDS: [&str; 14] = [
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

/// `str.isalnum()` for one character.
pub fn is_alnum(c: char) -> bool {
    c.is_alphanumeric()
}

/// Blank comments and literal contents; quotes and offsets stay in place.
pub fn mask_javascript(text: &Text) -> Text {
    let t = &text.c;
    let mut chars = t.clone();
    let (mut index, mut previous, mut word) = (0usize, String::new(), String::new());
    while index < t.len() {
        let c = t[index];
        if let Some(end) = comment_end(t, index) {
            blank(&mut chars, index, end);
            index = end;
            continue;
        }
        if "'\"`".contains(c) {
            let end = closing_quote(t, index + 1, c, c == '`');
            blank(&mut chars, index + 1, end);
            index = end + 1;
            previous = c.to_string();
            word.clear();
            continue;
        }
        if c == '/'
            && (previous.is_empty()
                || (previous.chars().count() == 1 && JS_REGEX_PRECEDERS.contains(previous.as_str()))
                || JS_REGEX_KEYWORDS.contains(&word.as_str()))
        {
            let (mut end, mut in_class) = (index + 1, false);
            while end < t.len() && t[end] != '\n' {
                if t[end] == '\\' {
                    end += 2;
                    continue;
                }
                if t[end] == '/' && !in_class {
                    break;
                }
                if t[end] == '[' || t[end] == ']' {
                    in_class = t[end] == '[';
                }
                end += 1;
            }
            blank(&mut chars, index + 1, end);
            index = end + 1;
            previous = "/".into();
            word.clear();
            continue;
        }
        if is_alnum(c) || c == '_' || c == '$' {
            if previous == "word" {
                word.push(c);
            } else {
                word = c.to_string();
            }
            previous = "word".into();
        } else if !crate::py::is_space(c) {
            previous = c.to_string();
            word.clear();
        }
        index += 1;
    }
    Text::from_chars(chars)
}

pub fn mask_elixir(text: &Text) -> Text {
    let t = &text.c;
    let mut chars = t.clone();
    let closer = |c: char| match c {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        other => other,
    };
    let mut index = 0;
    while index < t.len() {
        let c = t[index];
        if c == '#' {
            let end = find_chars(t, &['\n'], index).unwrap_or(t.len());
            blank(&mut chars, index, end);
            index = end;
            continue;
        }
        if c == '?' && index + 1 < t.len() && (index == 0 || !(is_alnum(t[index - 1]) || "_?!".contains(t[index - 1])))
        {
            let width = if t[index + 1] == '\\' { 3 } else { 2 };
            blank(&mut chars, index + 1, index + width);
            index += width;
            continue;
        }
        if c == '~' && index + 2 < t.len() && t[index + 1].is_alphabetic() {
            index += 2;
        } else if c != '"' && c != '\'' {
            index += 1;
            continue;
        }
        let opener = t[index];
        let triple: Vec<char> = t[index..(index + 3).min(t.len())].to_vec();
        if triple == ['"', '"', '"'] || triple == ['\'', '\'', '\''] {
            let end = find_chars(t, &triple, index + 3).unwrap_or(t.len());
            blank(&mut chars, index + 3, end);
            index = end + 3;
            continue;
        }
        let end = closing_quote(t, index + 1, closer(opener), true);
        blank(&mut chars, index + 1, end);
        index = end + 1;
    }
    Text::from_chars(chars)
}

static RUST_INTERESTING: std::sync::LazyLock<Re> = std::sync::LazyLock::new(|| Re::new(r#"/[/*]|b?r#*"|["']"#));
static RUST_RAW: std::sync::LazyLock<Re> = std::sync::LazyLock::new(|| Re::new(r##"b?r(#*)""##));
static RUST_CHAR: std::sync::LazyLock<Re> =
    std::sync::LazyLock::new(|| Re::new(r#"'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'\n])'"#));

static GO_INTERESTING: std::sync::LazyLock<Re> = std::sync::LazyLock::new(|| Re::new(r#"/[/*]|["'`]"#));

/// Blank comments and literals in Rust, Go and other C-family source.
pub fn mask_rust(text: &Text) -> Text {
    mask_c_family(text, false)
}

/// `mask_rust(text, go=True)`: also blanks Go backtick raw strings.
pub fn mask_go(text: &Text) -> Text {
    mask_c_family(text, true)
}

fn mask_c_family(text: &Text, go: bool) -> Text {
    let t = &text.c;
    let mut chars = t.clone();
    let mut index = 0;
    let interesting = if go { &GO_INTERESTING } else { &RUST_INTERESTING };
    while let Some(found) = interesting.search(text, index) {
        index = found.start();
        if t[index] == '`' {
            let end = find_chars(t, &['`'], index + 1).unwrap_or(t.len());
            blank(&mut chars, index + 1, end);
            index = end + 1;
            continue;
        }
        if text.starts_at(index, "/*") {
            let (mut depth, mut end) = (1i64, index + 2);
            while end < t.len() && depth != 0 {
                let step = &t[end..(end + 2).min(t.len())];
                if step == ['/', '*'] {
                    depth += 1;
                    end += 2;
                } else if step == ['*', '/'] {
                    depth -= 1;
                    end += 2;
                } else {
                    end += 1;
                }
            }
            blank(&mut chars, index, end);
            index = end;
            continue;
        }
        if text.starts_at(index, "//") {
            let end = find_chars(t, &['\n'], index).unwrap_or(t.len());
            blank(&mut chars, index, end);
            index = end;
            continue;
        }
        if t[index] != '"' && t[index] != '\'' {
            let identifier = index > 0 && (is_alnum(t[index - 1]) || t[index - 1] == '_');
            let raw = RUST_RAW.match_at(text, index);
            match raw {
                Some(raw) if !identifier => {
                    let hashes = raw.group(text, 1).unwrap_or("");
                    let start = raw.end();
                    let closing: Vec<char> = std::iter::once('"').chain(hashes.chars()).collect();
                    let end = find_chars(t, &closing, start).unwrap_or(t.len());
                    blank(&mut chars, start, end);
                    index = end + 1 + hashes.chars().count();
                }
                _ => {
                    index = find_chars(t, &['"'], index).unwrap_or(t.len());
                }
            }
            continue;
        }
        if t[index] == '"' {
            let end = closing_quote(t, index + 1, '"', true);
            blank(&mut chars, index + 1, end);
            index = end + 1;
            continue;
        }
        if let Some(literal) = RUST_CHAR.match_at(text, index) {
            blank(&mut chars, index + 1, literal.end() - 1);
            index = literal.end();
            continue;
        }
        index += 1;
    }
    Text::from_chars(chars)
}

/// Index just past the bracket closing masked[start], or the text end.
pub fn matching_close(masked: &[char], start: usize) -> usize {
    let mut stack: Vec<char> = Vec::new();
    for (index, &c) in masked.iter().enumerate().skip(start) {
        match c {
            '(' => stack.push(')'),
            '[' => stack.push(']'),
            '{' => stack.push('}'),
            _ if stack.last() == Some(&c) => {
                stack.pop();
                if stack.is_empty() {
                    return index + 1;
                }
            }
            _ => {}
        }
    }
    masked.len()
}

/// Top-level argument spans inside the parenthesis at masked[start].
pub fn split_arguments(masked: &[char], start: usize) -> Vec<(usize, usize)> {
    let end = matching_close(masked, start) - 1;
    let (mut spans, mut depth, mut begin) = (Vec::new(), 0i64, start + 1);
    for (index, &c) in masked.iter().enumerate().take(end).skip(start + 1) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                spans.push((begin, index));
                begin = index + 1;
            }
            _ => {}
        }
    }
    if begin < end && masked[begin..end].iter().any(|&c| !crate::py::is_space(c)) {
        spans.push((begin, end));
    }
    spans
}

pub fn expression_end(masked: &[char], start: usize) -> usize {
    let mut depth = 0i64;
    for index in start..masked.len() {
        let c = masked[index];
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return index;
                }
                depth -= 1;
            }
            _ if depth == 0 && (";\n,".contains(c) || masked[index..].starts_with(&['=', '>'])) => {
                return index;
            }
            _ => {}
        }
    }
    masked.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_text_masks_match_python() {
        // python3 -c 'import loki; print(repr(loki.mask_javascript("a = \"x\" // c\nb = /re/g; `t${x}`")))'
        let js = mask_javascript(&Text::new("a = \"x\" // c\nb = /re/g; `t${x}`"));
        assert_eq!(js.s, "a = \" \"     \nb = /  /g; `     `");
        let rust = mask_rust(&Text::new(
            "let s = r#\"a\"b\"#; // x\nlet c = 'q'; /* a /* b */ c */ 'a",
        ));
        assert_eq!(rust.s, "let s = r#\"   \"#;     \nlet c = ' ';                   'a");
        let ex = mask_elixir(&Text::new("x = ~s(a) <> \"b\" # c\n?a"));
        assert_eq!(ex.s, "x = ~s( ) <> \" \"    \n? ");
    }

    #[test]
    fn loki_text_unicode_offsets_are_code_points() {
        let text = Text::new("é = \"ü\"");
        let masked = mask_javascript(&text);
        assert_eq!(masked.s, "é = \" \"");
        assert_eq!(masked.len(), text.len());
        let m = Re::new(r#"""#).iter(&text);
        assert_eq!(m[0].start(), 4);
    }
}
