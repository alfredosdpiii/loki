//! Python string and JSON semantics the engine's output depends on.

use serde_json::Value;

/// `str.isspace()`.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

fn line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// `str.splitlines(keepends)`.
pub fn splitlines(s: &str, keepends: bool) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if !line_break(c) {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r' && chars.peek().map(|&(_, n)| n) == Some('\n') {
            chars.next();
            end += 1;
        }
        lines.push(&s[start..if keepends { end } else { i }]);
        start = end;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// `json.dumps(value)` with the default separators and `ensure_ascii`.
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_string(key, out);
                out.push_str(": ");
                write_value(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn number(n: &serde_json::Number) -> String {
    match n.as_f64() {
        Some(f) if n.is_f64() => float_repr(f),
        _ => n.to_string(),
    }
}

/// `repr(float)`: shortest round-trip digits in Python's layout.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sci = format!("{:e}", x.abs());
    let (mantissa, exponent) = sci.split_once('e').expect("scientific form");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let point = exponent.parse::<i64>().expect("exponent") + 1;
    let sign = if x.is_sign_negative() { "-" } else { "" };
    let body = if -4 < point && point <= 16 {
        let length = digits.len() as i64;
        if point <= 0 {
            format!("0.{}{digits}", "0".repeat((-point) as usize))
        } else if point >= length {
            format!("{digits}{}.0", "0".repeat((point - length) as usize))
        } else {
            format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
        }
    } else {
        let rest = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let e = point - 1;
        format!("{}{rest}e{}{:02}", &digits[..1], if e < 0 { '-' } else { '+' }, e.abs())
    };
    format!("{sign}{body}")
}

/// `round(x, digits)` for floats.
pub fn round(x: f64, digits: usize) -> f64 {
    format!("{x:.digits$}").parse().unwrap_or(x)
}

/// `json.dumps(value, indent=2)`.
pub fn dumps_indent(value: &Value) -> String {
    let mut out = String::new();
    write_indented(value, 0, &mut out);
    out
}

fn write_indented(value: &Value, depth: usize, out: &mut String) {
    let pad = |d: usize| "  ".repeat(d);
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                out.push_str(&pad(depth + 1));
                write_indented(item, depth + 1, out);
            }
            out.push('\n');
            out.push_str(&pad(depth));
            out.push(']');
        }
        Value::Object(map) if !map.is_empty() => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                out.push_str(&pad(depth + 1));
                write_string(key, out);
                out.push_str(": ");
                write_indented(item, depth + 1, out);
            }
            out.push('\n');
            out.push_str(&pad(depth));
            out.push('}');
        }
        other => write_value(other, out),
    }
}

/// `json.dumps(value, sort_keys=True)`.
pub fn dumps_sorted(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by(|a, b| a.chars().cmp(b.chars()));
                Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&map[k]))).collect())
            }
            other => other.clone(),
        }
    }
    dumps(&sorted(value))
}

/// `str(OSError)` for an errno error: `[Errno 2] No such file or directory: 'name'`.
pub fn os_error(error: &std::io::Error, filename: Option<&str>) -> String {
    let Some(code) = error.raw_os_error() else {
        return error.to_string();
    };
    let text = error.to_string();
    let strerror = text.split(" (os error").next().unwrap_or(&text).to_string();
    match filename {
        Some(name) => format!("[Errno {code}] {strerror}: {}", repr_str(name)),
        None => format!("[Errno {code}] {strerror}"),
    }
}

/// `repr(str)` for printable text.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 32 || c as u32 == 127 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()`.
pub fn opcodes<T: Eq + std::hash::Hash>(a: &[T], b: &[T]) -> Vec<(&'static str, usize, usize, usize, usize)> {
    let mut b2j: std::collections::HashMap<&T, Vec<usize>> = std::collections::HashMap::new();
    for (j, item) in b.iter().enumerate() {
        b2j.entry(item).or_default().push(j);
    }
    let longest = |alo: usize, ahi: usize, blo: usize, bhi: usize| -> (usize, usize, usize) {
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for (i, item) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut next: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
            for &j in b2j.get(item).map(Vec::as_slice).unwrap_or(&[]) {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j.checked_sub(1).and_then(|p| j2len.get(&p)).copied().unwrap_or(0) + 1;
                next.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
            j2len = next;
        }
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi && bestj + bestsize < bhi && a[besti + bestsize] == b[bestj + bestsize] {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    };
    let mut queue = vec![(0, a.len(), 0, b.len())];
    let mut blocks = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = longest(alo, ahi, blo, bhi);
        if k > 0 {
            blocks.push((i, j, k));
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    blocks.sort_unstable();
    let (mut i1, mut j1, mut k1) = (0, 0, 0);
    let mut merged = Vec::new();
    for (i2, j2, k2) in blocks {
        if i1 + k1 == i2 && j1 + k1 == j2 {
            k1 += k2;
        } else {
            if k1 > 0 {
                merged.push((i1, j1, k1));
            }
            (i1, j1, k1) = (i2, j2, k2);
        }
    }
    if k1 > 0 {
        merged.push((i1, j1, k1));
    }
    merged.push((a.len(), b.len(), 0));
    let (mut i, mut j) = (0, 0);
    let mut answer = Vec::new();
    for (ai, bj, size) in merged {
        let tag = if i < ai && j < bj {
            "replace"
        } else if i < ai {
            "delete"
        } else if j < bj {
            "insert"
        } else {
            ""
        };
        if !tag.is_empty() {
            answer.push((tag, i, ai, j, bj));
        }
        (i, j) = (ai + size, bj + size);
        if size > 0 {
            answer.push(("equal", ai, i, bj, j));
        }
    }
    answer
}

/// `collections.Counter` with insertion order (what `a - b` iterates).
#[derive(Clone, Debug)]
pub struct Counter<K: Eq + std::hash::Hash + Clone> {
    order: Vec<K>,
    counts: std::collections::HashMap<K, i64>,
}

impl<K: Eq + std::hash::Hash + Clone> Default for Counter<K> {
    fn default() -> Self {
        Counter {
            order: Vec::new(),
            counts: std::collections::HashMap::new(),
        }
    }
}

impl<K: Eq + std::hash::Hash + Clone> Counter<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, key: K) {
        self.add_n(key, 1);
    }

    pub fn add_n(&mut self, key: K, n: i64) {
        match self.counts.get_mut(&key) {
            Some(count) => *count += n,
            None => {
                self.order.push(key.clone());
                self.counts.insert(key, n);
            }
        }
    }

    pub fn get(&self, key: &K) -> i64 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    /// `self[key] -= 1` (an absent key goes to -1, as with Counter).
    pub fn decrement(&mut self, key: &K) {
        self.add_n(key.clone(), -1);
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.order.iter()
    }

    /// `self - other`: positive remainders in `self`'s order.
    pub fn minus(&self, other: &Counter<K>) -> Vec<(K, i64)> {
        self.order
            .iter()
            .filter_map(|key| {
                let left = self.counts[key] - other.get(key);
                (left > 0).then(|| (key.clone(), left))
            })
            .collect()
    }
}

/// `fnmatch.fnmatch` on POSIX (case-sensitive; `*` crosses `/`).
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    let mut re = String::from("(?s)^");
    let p: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < p.len() {
        let c = p[i];
        i += 1;
        match c {
            '*' => {
                while i < p.len() && p[i] == '*' {
                    i += 1;
                }
                re.push_str(".*");
            }
            '?' => re.push('.'),
            '[' => {
                let mut j = i;
                if j < p.len() && p[j] == '!' {
                    j += 1;
                }
                if j < p.len() && p[j] == ']' {
                    j += 1;
                }
                while j < p.len() && p[j] != ']' {
                    j += 1;
                }
                if j >= p.len() {
                    re.push_str("\\[");
                } else {
                    let body: String = p[i..j].iter().collect();
                    i = j + 1;
                    let (negate, body) = match body.strip_prefix('!') {
                        Some(rest) => (true, rest.to_string()),
                        None => (false, body),
                    };
                    if body.is_empty() {
                        re.push_str(if negate { "." } else { "[^\\s\\S]" });
                        continue;
                    }
                    re.push('[');
                    if negate {
                        re.push('^');
                    }
                    for ch in body.chars() {
                        if matches!(ch, '\\' | '[' | ']' | '^' | '&' | '~') {
                            re.push('\\');
                        }
                        re.push(ch);
                    }
                    re.push(']');
                }
            }
            _ => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    regex::Regex::new(&re).is_ok_and(|r| r.is_match(name))
}

/// `shlex.split` (POSIX mode, no comments).
pub fn shlex_split(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(q) => word.push(q),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(n @ ('"' | '\\')) => word.push(n),
                            Some(n) => {
                                word.push('\\');
                                word.push(n);
                            }
                            None => return Err("No escaped character".into()),
                        },
                        Some(q) => word.push(q),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(n) => word.push(n),
                    None => return Err("No escaped character".into()),
                }
            }
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn loki_py_splitlines_matches_python() {
        assert_eq!(splitlines("a\r\nb\rc\n", true), vec!["a\r\n", "b\r", "c\n"]);
        assert_eq!(splitlines("a\u{2028}b", false), vec!["a", "b"]);
        assert_eq!(splitlines("", false), Vec::<&str>::new());
    }

    #[test]
    fn loki_py_dumps_matches_python_json() {
        // python3 -c 'import json; print(json.dumps({"a": [1, "é\n", None, True]}))'
        let value = json!({"a": [1, "é\n😀", null, true]});
        assert_eq!(dumps(&value), r#"{"a": [1, "\u00e9\n\ud83d\ude00", null, true]}"#);
    }

    #[test]
    fn loki_py_float_repr_matches_python() {
        // python3 -c 'print([repr(x) for x in (0.0, 1.0, 0.1, 1e-05, 0.0001, 1e16, 1e15, 12.5, -0.25, 1/3)])'
        let got: Vec<String> = [0.0, 1.0, 0.1, 1e-05, 0.0001, 1e16, 1e15, 12.5, -0.25, 1.0 / 3.0]
            .iter()
            .map(|x| float_repr(*x))
            .collect();
        assert_eq!(
            got,
            [
                "0.0",
                "1.0",
                "0.1",
                "1e-05",
                "0.0001",
                "1e+16",
                "1000000000000000.0",
                "12.5",
                "-0.25",
                "0.3333333333333333"
            ]
        );
        // python3 -c 'print(round(2.675, 2), round(0.125, 2), round(7.45, 1))'
        assert_eq!((round(2.675, 2), round(0.125, 2), round(7.45, 1)), (2.67, 0.12, 7.5));
    }

    #[test]
    fn loki_py_difflib_opcodes_match_python() {
        // python3 -c 'import difflib; print(difflib.SequenceMatcher(None, "abxcd", "abcyd", autojunk=False).get_opcodes())'
        let a: Vec<char> = "abxcd".chars().collect();
        let b: Vec<char> = "abcyd".chars().collect();
        assert_eq!(
            opcodes(&a, &b),
            vec![
                ("equal", 0, 2, 0, 2),
                ("delete", 2, 3, 2, 2),
                ("equal", 3, 4, 2, 3),
                ("insert", 4, 4, 3, 4),
                ("equal", 4, 5, 4, 5)
            ]
        );
        // python3 -c 'import difflib; print(difflib.SequenceMatcher(None, "qabxyz", "abcxyq", autojunk=False).get_opcodes())'
        let a: Vec<char> = "qabxyz".chars().collect();
        let b: Vec<char> = "abcxyq".chars().collect();
        assert_eq!(
            opcodes(&a, &b),
            vec![
                ("delete", 0, 1, 0, 0),
                ("equal", 1, 3, 0, 2),
                ("insert", 3, 3, 2, 3),
                ("equal", 3, 5, 3, 5),
                ("replace", 5, 6, 5, 6)
            ]
        );
    }

    #[test]
    fn loki_py_fnmatch_matches_python() {
        assert!(fnmatch("a/b/.credo.exs", "*/.credo.exs"));
        assert!(fnmatch("x.yml", "?.yml"));
        assert!(fnmatch("b.txt", "[!a].txt"));
        assert!(!fnmatch("a.txt", "[!a].txt"));
        assert!(!fnmatch("buf.yaml.bak", "buf.yaml"));
    }

    #[test]
    fn loki_py_shlex_matches_python() {
        // python3 -c 'import shlex; print(shlex.split("make \"a\\\\b\\\"c\" x\\ y '"'"'q r'"'"' \"\""))'
        assert_eq!(
            shlex_split(r#"make "a\\b\"c" x\ y 'q r' """#).unwrap(),
            vec!["make", "a\\b\"c", "x y", "q r", ""]
        );
        assert_eq!(shlex_split("a 'b").unwrap_err(), "No closing quotation");
    }
}
