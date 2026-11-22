//! `json.JSONDecodeError` texts: where CPython's scanner stops and what it says.

struct Fail(&'static str, usize);

struct Scanner<'a> {
    s: &'a [char],
}

fn is_ws(c: Option<char>) -> bool {
    matches!(c, Some(' ' | '\t' | '\n' | '\r'))
}

impl Scanner<'_> {
    fn at(&self, i: usize) -> Option<char> {
        self.s.get(i).copied()
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

    fn number(&self, i: usize) -> Option<usize> {
        let digit = |j: usize| self.at(j).is_some_and(|c| c.is_ascii_digit());
        let mut j = i;
        if self.at(j) == Some('-') {
            j += 1;
        }
        match self.at(j) {
            Some('0') => j += 1,
            Some('1'..='9') => {
                while digit(j) {
                    j += 1;
                }
            }
            _ => return None,
        }
        if self.at(j) == Some('.') && digit(j + 1) {
            j += 1;
            while digit(j) {
                j += 1;
            }
        }
        if matches!(self.at(j), Some('e' | 'E')) {
            let mut k = j + 1;
            if matches!(self.at(k), Some('+' | '-')) {
                k += 1;
            }
            if digit(k) {
                while digit(k) {
                    k += 1;
                }
                j = k;
            }
        }
        Some(j)
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

    fn object(&self, mut end: usize) -> Result<usize, Fail> {
        let mut next = self.at(end);
        if next != Some('"') {
            if is_ws(next) {
                end = self.skip(end);
                next = self.at(end);
            }
            if next == Some('}') {
                return Ok(end + 1);
            }
            if next != Some('"') {
                return Err(Fail("Expecting property name enclosed in double quotes", end));
            }
        }
        end += 1;
        loop {
            end = self.string(end)?;
            if self.at(end) != Some(':') {
                end = self.skip(end);
                if self.at(end) != Some(':') {
                    return Err(Fail("Expecting ':' delimiter", end));
                }
            }
            end += 1;
            if is_ws(self.at(end)) && self.at(end).is_some() {
                end += 1;
                if is_ws(self.at(end)) && self.at(end).is_some() {
                    end = self.skip(end + 1);
                }
            }
            end = self.value(end)?;
            let mut next = self.at(end);
            if next.is_some() && is_ws(next) {
                end = self.skip(end + 1);
                next = self.at(end);
            }
            end += 1;
            match next {
                Some('}') => return Ok(end),
                Some(',') => {}
                _ => return Err(Fail("Expecting ',' delimiter", end - 1)),
            }
            let comma = end - 1;
            end = self.skip(end);
            let next = self.at(end);
            end += 1;
            if next != Some('"') {
                if next == Some('}') {
                    return Err(Fail("Illegal trailing comma before end of object", comma));
                }
                return Err(Fail("Expecting property name enclosed in double quotes", end - 1));
            }
        }
    }

    fn array(&self, mut end: usize) -> Result<usize, Fail> {
        let mut next = self.at(end);
        if is_ws(next) {
            end = self.skip(end + 1);
            next = self.at(end);
        }
        if next == Some(']') {
            return Ok(end + 1);
        }
        loop {
            end = self.value(end)?;
            let mut next = self.at(end);
            if is_ws(next) {
                end = self.skip(end + 1);
                next = self.at(end);
            }
            end += 1;
            match next {
                Some(']') => return Ok(end),
                Some(',') => {}
                _ => return Err(Fail("Expecting ',' delimiter", end - 1)),
            }
            let comma = end - 1;
            if is_ws(self.at(end)) && self.at(end).is_some() {
                end += 1;
                if is_ws(self.at(end)) && self.at(end).is_some() {
                    end = self.skip(end + 1);
                }
            }
            if self.at(end) == Some(']') {
                return Err(Fail("Illegal trailing comma before end of array", comma));
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
