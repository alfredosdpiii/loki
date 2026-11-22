//! `json.JSONDecodeError` texts: where CPython's scanner stops and what it says.

struct Fail(&'static str, usize);

struct Scanner<'a> {
    s: &'a [char],
}

enum Delim {
    Closed(usize),
    Comma { comma: usize, next: usize },
}

impl Scanner<'_> {
    fn at(&self, i: usize) -> Option<char> {
        self.s.get(i).copied()
    }

    fn is_digit(&self, i: usize) -> bool {
        self.at(i).is_some_and(|c| c.is_ascii_digit())
    }

    fn scan_digits(&self, mut i: usize) -> usize {
        while self.is_digit(i) {
            i += 1;
        }
        i
    }

    fn skip(&self, mut i: usize) -> usize {
        while matches!(self.at(i), Some(' ' | '\t' | '\n' | '\r')) {
            i += 1;
        }
        i
    }

    fn value(&self, i: usize) -> Result<usize, Fail> {
        let expecting = Fail("Expecting value", i);
        match self.at(i) {
            None => Err(expecting),
            Some('"') => self.string(i + 1),
            Some('{') => self.object(i + 1),
            Some('[') => self.array(i + 1),
            Some(_) => {
                for word in ["null", "true", "false", "NaN", "Infinity", "-Infinity"] {
                    let w: Vec<char> = word.chars().collect();
                    if self.s[i..].starts_with(&w) {
                        return Ok(i + w.len());
                    }
                }
                self.number(i).ok_or(expecting)
            }
        }
    }

    fn scan_exponent(&self, j: usize) -> usize {
        if !matches!(self.at(j), Some('e' | 'E')) {
            return j;
        }
        let mut k = j + 1;
        if matches!(self.at(k), Some('+' | '-')) {
            k += 1;
        }
        if self.is_digit(k) { self.scan_digits(k) } else { j }
    }

    fn number(&self, i: usize) -> Option<usize> {
        let mut j = i + usize::from(self.at(i) == Some('-'));
        match self.at(j) {
            Some('0') => j += 1,
            Some('1'..='9') => j = self.scan_digits(j),
            _ => return None,
        }
        if self.at(j) == Some('.') && self.is_digit(j + 1) {
            j = self.scan_digits(j + 1);
        }
        Some(self.scan_exponent(j))
    }

    fn string(&self, start: usize) -> Result<usize, Fail> {
        let begin = start - 1;
        let mut i = start;
        loop {
            let Some(c) = self.at(i) else {
                return Err(Fail("Unterminated string starting at", begin));
            };
            match c {
                '"' => return Ok(i + 1),
                '\\' => {
                    let Some(escape) = self.at(i + 1) else {
                        return Err(Fail("Unterminated string starting at", begin));
                    };
                    if escape == 'u' {
                        let hex = (i + 2..i + 6).all(|j| self.at(j).is_some_and(|c| c.is_ascii_hexdigit()));
                        if !hex {
                            return Err(Fail("Invalid \\uXXXX escape", i + 1));
                        }
                        i += 6;
                    } else if "\"\\/bfnrt".contains(escape) {
                        i += 2;
                    } else {
                        return Err(Fail("Invalid \\escape", i));
                    }
                }
                c if (c as u32) < 0x20 => return Err(Fail("Invalid control character at", i)),
                _ => i += 1,
            }
        }
    }

    fn next_delim(&self, end: usize, close: char) -> Result<Delim, Fail> {
        let end = self.skip(end);
        match self.at(end) {
            Some(c) if c == close => Ok(Delim::Closed(end + 1)),
            Some(',') => Ok(Delim::Comma {
                comma: end,
                next: self.skip(end + 1),
            }),
            _ => Err(Fail("Expecting ',' delimiter", end)),
        }
    }

    fn object_pair(&self, end: usize) -> Result<usize, Fail> {
        let end = self.skip(self.string(end)?);
        if self.at(end) != Some(':') {
            return Err(Fail("Expecting ':' delimiter", end));
        }
        self.value(self.skip(end + 1))
    }

    fn object(&self, end: usize) -> Result<usize, Fail> {
        let mut end = self.skip(end);
        match self.at(end) {
            Some('}') => return Ok(end + 1),
            Some('"') => end += 1,
            _ => return Err(Fail("Expecting property name enclosed in double quotes", end)),
        }
        loop {
            end = self.object_pair(end)?;
            match self.next_delim(end, '}')? {
                Delim::Closed(done) => return Ok(done),
                Delim::Comma { comma, next } => match self.at(next) {
                    Some('"') => end = next + 1,
                    Some('}') => return Err(Fail("Illegal trailing comma before end of object", comma)),
                    _ => return Err(Fail("Expecting property name enclosed in double quotes", next)),
                },
            }
        }
    }

    fn array(&self, end: usize) -> Result<usize, Fail> {
        let mut end = self.skip(end);
        if self.at(end) == Some(']') {
            return Ok(end + 1);
        }
        loop {
            end = self.value(end)?;
            match self.next_delim(end, ']')? {
                Delim::Closed(done) => return Ok(done),
                Delim::Comma { comma, next } => {
                    if self.at(next) == Some(']') {
                        return Err(Fail("Illegal trailing comma before end of array", comma));
                    }
                    end = next;
                }
            }
        }
    }
}

fn locate(chars: &[char], message: &str, pos: usize) -> String {
    let before = &chars[..pos.min(chars.len())];
    let line = before.iter().filter(|&&c| c == '\n').count() + 1;
    let column = match before.iter().rposition(|&c| c == '\n') {
        Some(newline) => pos - newline,
        None => pos + 1,
    };
    format!("{message}: line {line} column {column} (char {pos})")
}

/// CPython's `str(JSONDecodeError)` for `json.loads(text)`, or None when CPython accepts it.
pub fn python_error(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.first() == Some(&'\u{feff}') {
        return Some(locate(&chars, "Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let scanner = Scanner { s: &chars };
    let start = scanner.skip(0);
    match scanner.value(start) {
        Err(Fail(message, pos)) => Some(locate(&chars, message, pos)),
        Ok(end) => {
            let end = scanner.skip(end);
            (end != chars.len()).then(|| locate(&chars, "Extra data", end))
        }
    }
}

/// The error text loki.py prints for a document serde_json rejected.
pub fn error_text(text: &str, error: &serde_json::Error) -> String {
    python_error(text).unwrap_or_else(|| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_pyjson_errors_match_python() {
        // python3 -c 'import json; json.loads(...)' for each input; printed str(error).
        let cases = [
            (
                "{\"a\": 1,}",
                "Illegal trailing comma before end of object: line 1 column 8 (char 7)",
            ),
            (
                "[1,]",
                "Illegal trailing comma before end of array: line 1 column 3 (char 2)",
            ),
            ("{\"a\" 1}", "Expecting ':' delimiter: line 1 column 6 (char 5)"),
            (
                "{a:1}",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("  ", "Expecting value: line 1 column 3 (char 2)"),
            ("{\"a\": tru}", "Expecting value: line 1 column 7 (char 6)"),
            ("\"abc", "Unterminated string starting at: line 1 column 1 (char 0)"),
            ("\"a\\x\"", "Invalid \\escape: line 1 column 3 (char 2)"),
            ("\"a\u{1}\"", "Invalid control character at: line 1 column 3 (char 2)"),
            ("{\"a\":1} x", "Extra data: line 1 column 9 (char 8)"),
            (
                "[1,\n 2,\n]",
                "Illegal trailing comma before end of array: line 2 column 3 (char 6)",
            ),
            (
                "{",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            ("{\"a\":", "Expecting value: line 1 column 6 (char 5)"),
            ("\"\\u12\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
            ("-", "Expecting value: line 1 column 1 (char 0)"),
            ("1.", "Extra data: line 1 column 2 (char 1)"),
            ("[\"a\\", "Unterminated string starting at: line 1 column 2 (char 1)"),
            (
                "{\"a\":1,",
                "Expecting property name enclosed in double quotes: line 1 column 8 (char 7)",
            ),
            ("nul", "Expecting value: line 1 column 1 (char 0)"),
        ];
        for (input, expected) in cases {
            assert_eq!(python_error(input).as_deref(), Some(expected), "{input:?}");
        }
        assert_eq!(python_error("{\"a\": [1, 2.5e3, null]}"), None);
    }
}
