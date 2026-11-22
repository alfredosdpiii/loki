//! nits (github.com/jkomyno/nits): tree-sitter rules for Python, TypeScript, JavaScript and Rust, each with a measured
//! precision per language. [`crate::hygiene`] runs it beside the codehygiene model and reports both.
//!
//! nits is not vendored: upstream ships no license, and its parsers are native wheels. It runs from a Python that
//! can import it: Loki's interpreter, else `uv run --offline` at the pinned commit once uv's cache holds it.

use crate::hygiene::{Squiggle, WarmWorker, drive, parse_value};
use crate::proc::{self, Deadline};
use serde_json::json;
use std::sync::{Mutex, OnceLock};

/// The upstream commit uv runs. A nits installed in Loki's own Python is used as it is.
pub const COMMIT: &str = "67c94b9f76054375f37b2df8e624a2f4d48ec0cc";

/// Upstream turns a rule on by default at this precision; below it, in a file's language, a finding is reported
/// only at level `all`.
const MIN_PRECISION: f64 = 0.80;

const SUFFIXES: [&str; 8] = [".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs"];

/// Reads `{files: [[name, text], ...], all, min_precision}` on stdin and prints, per file,
/// `[[line, rule, "p<precision> <message>"], ...]`.
const DRIVER: &str = r#"
import json, sys
try:
    import nits
except ImportError:
    raise SystemExit(3)
try:
    request = json.load(sys.stdin)
    everything = request["all"]
    floor = None if everything else request["min_precision"]
    found = []
    for name, text in request["files"]:
        lang = nits.lang_for_path(name)
        findings = nits.check_source(text, lang=lang, include_opt_in=everything, min_precision=floor) if lang else []
        found.append([[f.line, f.rule, f"p{nits.precision_of(f.rule, lang):.2f} {f.message}"] for f in findings])
except Exception as error:
    sys.stderr.write(f"{type(error).__name__}: {error}\n")
    raise SystemExit(4)
json.dump(found, sys.stdout)
"#;

fn requirement() -> String {
    format!("git+https://github.com/jkomyno/nits@{COMMIT}")
}

/// Whether nits has a grammar for `name`.
pub fn reads(name: &str) -> bool {
    crate::rules::suffix(name).is_some_and(|suffix| SUFFIXES.contains(&suffix.as_str()))
}

/// The Pythons to try, in order: Loki's own, then uv's with nits from its cache.
pub fn launchers() -> Vec<Vec<String>> {
    let mut found = vec![vec![crate::pyast::interpreter()]];
    if let Some(uv) = proc::which("uv") {
        let args = [
            "run",
            "-q",
            "--offline",
            "--no-project",
            "--with",
            &requirement(),
            "python",
        ];
        found.push(std::iter::once(uv).chain(args.map(String::from)).collect());
    }
    found
}

const SERVER_DRIVER: &str = r#"
import json, sys
try:
    import nits
except ImportError:
    raise SystemExit(3)
for raw in sys.stdin:
    if not raw.strip():
        continue
    request = json.loads(raw)
    args = request["args"]
    if args == "ping":
        sys.stdout.write(json.dumps({"id": request["id"], "result": True}) + "\n")
        sys.stdout.flush()
        continue
    try:
        everything = args["all"]
        floor = None if everything else args["min_precision"]
        found = []
        for name, text in args["files"]:
            lang = nits.lang_for_path(name)
            findings = nits.check_source(text, lang=lang, include_opt_in=everything, min_precision=floor) if lang else []
            found.append([[f.line, f.rule, f"p{nits.precision_of(f.rule, lang):.2f} {f.message}"] for f in findings])
        reply = {"id": request["id"], "result": found}
    except Exception as error:
        reply = {"id": request["id"], "error": f"{type(error).__name__}: {error}"}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
"#;

fn warm_nits_worker() -> &'static Mutex<Option<WarmWorker>> {
    static WORKER: OnceLock<Mutex<Option<WarmWorker>>> = OnceLock::new();
    WORKER.get_or_init(|| Mutex::new(None))
}

/// nits' findings for each `(name, text)`, or why it could not run: its default rules that measure at least
/// [`MIN_PRECISION`] in the file's language, or with `all` every rule, the opt-in ones included.
pub fn score(
    launchers: &[Vec<String>],
    files: &[(&str, String)],
    all: bool,
    deadline: Deadline,
) -> Result<Vec<Vec<Squiggle>>, String> {
    let payload = json!({"files": files, "all": all, "min_precision": MIN_PRECISION});
    if std::env::var_os("ULTRON_LOKI_PYTHON").is_none()
        && launchers == crate::nits::launchers().as_slice()
        && let Ok(mut slot) = warm_nits_worker().lock()
    {
        if slot.is_none() {
            *slot = WarmWorker::start(launchers, SERVER_DRIVER, json!("ping"));
        }
        if let Some(worker) = slot.as_mut() {
            match worker.request(payload.clone()).and_then(|val| {
                parse_value(val).ok_or_else(|| "unreadable reply".to_string())
            }) {
                Ok(found) => return Ok(found),
                Err(_) => {
                    *slot = None;
                }
            }
        }
    }
    let request = payload.to_string();
    let missing = format!(
        "nits is in neither Loki's Python nor uv's cache (`uv run --no-project --with {} python -c pass` fetches it once)",
        requirement()
    );
    drive(launchers, DRIVER, &request, deadline, &missing)
}
