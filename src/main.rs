//! `loki` command line: loki.py's argparse interface over the Rust engine.

use loki::proc::Deadline;
use loki::run::{self, Report};
use loki::{CheckError, config, hook, injected_context, py, resolve};
use serde_json::{Value, json};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod shell_cli;

const COMMANDS: [&str; 14] = [
    "verify-installation",
    "explain",
    "context",
    "elixir",
    "apply",
    "shell",
    "shell-writes",
    "protect",
    "hook",
    "scan",
    "slop",
    "hygiene",
    "daemon",
    "init",
];
const TOP_USAGE: &str = "usage: loki [-h] [--version] [--root ROOT]\n            {verify-installation,explain,context,elixir,apply,shell,shell-writes,protect,hook,scan,slop,hygiene,daemon,init} ...";

fn usage(command: &str) -> &'static str {
    match command {
        "protect" => {
            "usage: loki protect [-h] [--root ROOT] (--file FILE |\n                    --harness {claude,codex,factory}) [--record]\n                    [--format {text,json}] [--python PYTHON]\n                    [--preview {pi,omp,ultron}]"
        }
        "hook" => {
            "usage: loki hook [-h] [--root ROOT] (--file FILE |\n                 --harness {claude,codex,factory}) [--record]\n                 [--format {text,json}] [--python PYTHON]"
        }
        "scan" => {
            "usage: loki scan [-h] [--online] [--strict] [--base BASE] [--ruff-new]\n                 [--python PYTHON]"
        }
        "slop" => "usage: loki slop [-h] [--base BASE] [--json] [--top TOP]",
        "hygiene" => "usage: loki hygiene [-h] [--base BASE] [--file FILE] [--level {on,all}] [--json]",
        "init" => {
            "usage: loki init [-h] [--force] [--dir DIR] [--managed-dir MANAGED_DIR]\n                 [--shell-guard] [--minimal]"
        }
        "verify-installation" => {
            "usage: loki verify-installation [-h] --engine ENGINE\n                                --registration REGISTRATION\n                                --agent-uid AGENT_UID"
        }
        "elixir" => {
            "usage: loki elixir [-h] [--project PROJECT] [--tier {fast,project,deep}]\n                   [--file FILE] [--json] [--credo-new]"
        }
        "apply" => "usage: loki apply [-h] --manifest MANIFEST [--check-only]",
        "daemon" => "usage: loki daemon [-h] {serve,start,stop,status}",
        _ => {
            "usage: loki context [-h] [--root ROOT]\n                    [--event {SessionStart,UserPromptSubmit}]\n                    [--host {ultron}]"
        }
    }
}

/// `loki <command> --help`: the usage, then argparse's option list.
fn help(command: &str) -> String {
    let options = match command {
        "protect" | "hook" => {
            let mut text = "  -h, --help            show this help message and exit\n  --root ROOT\n  --file FILE\n  --harness {claude,codex,factory}\n  --record\n  --format {text,json}\n  --python PYTHON       the project's Python interpreter\n".to_string();
            if command == "protect" {
                text.push_str("  --preview {pi,omp,ultron}\n");
            }
            text
        }
        "scan" => "  -h, --help       show this help message and exit\n  --online\n  --strict\n  --base BASE\n  --ruff-new\n  --python PYTHON  the project's Python interpreter\n".to_string(),
        "slop" => "  -h, --help   show this help message and exit\n  --base BASE  compare against this revision\n  --json\n  --top TOP\n".to_string(),
        "hygiene" => "  -h, --help          show this help message and exit\n  --base BASE         compare against this revision\n  --file FILE         check specific file(s)\n  --level {on,all}    override hygiene level\n  --json              output JSON\n".to_string(),
        "init" => "  -h, --help            show this help message and exit\n  --force\n  --dir DIR\n  --managed-dir MANAGED_DIR\n  --shell-guard\n  --minimal\n".to_string(),
        "verify-installation" => "  -h, --help            show this help message and exit\n  --engine ENGINE\n  --registration REGISTRATION\n  --agent-uid AGENT_UID\n".to_string(),
        "elixir" => "  -h, --help            show this help message and exit\n  --project PROJECT\n  --tier {fast,project,deep}\n  --file FILE\n  --json\n  --credo-new\n".to_string(),
        "apply" => "  -h, --help           show this help message and exit\n  --manifest MANIFEST\n  --check-only\n".to_string(),
        "daemon" => {
            return format!(
                "{}\n\npositional arguments:\n  {{serve,start,stop,status}}\n\noptions:\n  -h, --help            show this help message and exit\n",
                usage(command)
            );
        }
        _ => "  -h, --help            show this help message and exit\n  --root ROOT\n  --event {SessionStart,UserPromptSubmit}\n  --host {ultron}\n".to_string(),
    };
    format!("{}\n\noptions:\n{options}", usage(command))
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Flag,
    Value,
    Int,
    Choice(&'static [&'static str]),
}

fn options(command: &str) -> Vec<(&'static str, Kind)> {
    const HARNESS: &[&str] = &["claude", "codex", "factory"];
    const FORMAT: &[&str] = &["text", "json"];
    match command {
        "protect" | "hook" => {
            let mut list = vec![
                ("--root", Kind::Value),
                ("--file", Kind::Value),
                ("--harness", Kind::Choice(HARNESS)),
                ("--record", Kind::Flag),
                ("--format", Kind::Choice(FORMAT)),
                ("--python", Kind::Value),
            ];
            if command == "protect" {
                list.push(("--preview", Kind::Choice(&["pi", "omp", "ultron"])));
            }
            list
        }
        "scan" => vec![
            ("--online", Kind::Flag),
            ("--strict", Kind::Flag),
            ("--base", Kind::Value),
            ("--ruff-new", Kind::Flag),
            ("--python", Kind::Value),
        ],
        "slop" => vec![("--base", Kind::Value), ("--json", Kind::Flag), ("--top", Kind::Int)],
        "hygiene" => vec![
            ("--base", Kind::Value),
            ("--file", Kind::Value),
            ("--level", Kind::Choice(&["on", "all"])),
            ("--json", Kind::Flag),
        ],
        "init" => vec![
            ("--force", Kind::Flag),
            ("--dir", Kind::Value),
            ("--managed-dir", Kind::Value),
            ("--shell-guard", Kind::Flag),
            ("--minimal", Kind::Flag),
        ],
        "verify-installation" => vec![
            ("--engine", Kind::Value),
            ("--registration", Kind::Value),
            ("--agent-uid", Kind::Int),
        ],
        "elixir" => vec![
            ("--project", Kind::Value),
            ("--tier", Kind::Choice(&["fast", "project", "deep"])),
            ("--file", Kind::Value),
            ("--json", Kind::Flag),
            ("--credo-new", Kind::Flag),
        ],
        "apply" => vec![("--manifest", Kind::Value), ("--check-only", Kind::Flag)],
        "daemon" => vec![],
        _ => vec![
            ("--root", Kind::Value),
            ("--event", Kind::Choice(&["SessionStart", "UserPromptSubmit"])),
            ("--host", Kind::Choice(&["ultron"])),
        ],
    }
}

/// Parsed values: last value per option, all values for `--file`.
#[derive(Default)]
struct Args {
    root: Option<String>,
    command: String,
    values: Vec<(&'static str, String)>,
}

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.values.iter().any(|(n, _)| *n == name)
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

enum ParseError {
    Top(String),
    Sub(String, String),
    Exit(i32),
}

/// argparse treats a token as an option unless it looks like a negative number.
fn optional_like(token: &str) -> bool {
    if !token.starts_with('-') || token == "-" {
        return false;
    }
    let rest = &token[1..];
    let number = !rest.is_empty()
        && (rest.chars().all(|c| c.is_ascii_digit())
            || rest.split_once('.').is_some_and(|(a, b)| {
                a.chars().all(|c| c.is_ascii_digit()) && !b.is_empty() && b.chars().all(|c| c.is_ascii_digit())
            }));
    !number
}

/// `int(text)` as argparse's `type=int` accepts it.
fn python_int(text: &str) -> Option<i64> {
    let trimmed = py::strip(text);
    let (sign, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if !clean.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    clean.parse::<i64>().ok().map(|n| sign * n)
}

fn parse(argv: &[String]) -> Result<Args, ParseError> {
    let mut args = Args::default();
    let mut top_extras: Vec<String> = Vec::new();
    let mut items = argv.iter().peekable();
    let top = |m: String| ParseError::Top(m);
    while let Some(token) = items.next() {
        let (flag, inline) = match token.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (token.clone(), None),
        };
        if flag.starts_with("--") && flag.len() > 2 {
            let matches: Vec<&str> = ["--version", "--root"]
                .into_iter()
                .filter(|o| o.starts_with(flag.as_str()))
                .collect();
            let chosen = if matches.contains(&flag.as_str()) {
                Some(flag.as_str())
            } else if matches.len() == 1 {
                Some(matches[0])
            } else {
                None
            };
            match chosen {
                Some("--version") => {
                    println!("loki {}", loki::VERSION);
                    return Err(ParseError::Exit(0));
                }
                Some(_) => {
                    let value = match inline {
                        Some(v) => v,
                        None => match items.peek() {
                            Some(v) if !optional_like(v) => items.next().cloned().unwrap_or_default(),
                            _ => return Err(top("argument --root: expected one argument".into())),
                        },
                    };
                    args.root = Some(value);
                    continue;
                }
                // argparse keeps going: an unknown option is reported once the command parsed.
                None => {
                    top_extras.push(token.clone());
                    continue;
                }
            }
        }
        if !COMMANDS.contains(&token.as_str()) {
            let listed = COMMANDS.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
            return Err(top(format!(
                "argument command: invalid choice: '{token}' (choose from {listed})"
            )));
        }
        args.command = token.clone();
        break;
    }
    if args.command.is_empty() {
        return Err(top("the following arguments are required: command".into()));
    }
    let command = args.command.clone();
    const PARSED: [&str; 11] = [
        "protect",
        "hook",
        "scan",
        "slop",
        "hygiene",
        "init",
        "context",
        "verify-installation",
        "elixir",
        "apply",
        "daemon",
    ];
    if !PARSED.contains(&command.as_str()) {
        if !top_extras.is_empty() {
            return Err(top(format!("unrecognized arguments: {}", top_extras.join(" "))));
        }
        return Ok(args);
    }
    let sub = |m: String| ParseError::Sub(command.clone(), m);
    let specs = options(&command);
    let mut extras: Vec<String> = Vec::new();
    let mut exclusive: Option<&'static str> = None;
    let rest: Vec<String> = items.cloned().collect();
    let mut index = 0;
    while index < rest.len() {
        let token = &rest[index];
        index += 1;
        if token == "--" {
            extras.extend(rest[index..].iter().cloned());
            break;
        }
        let help_prefix = token.len() > 2
            && "--help".starts_with(token.as_str())
            && !specs.iter().any(|(n, _)| n.starts_with(token.as_str()));
        if token == "-h" || help_prefix {
            print!("{}", help(&command));
            return Err(ParseError::Exit(0));
        }
        if !optional_like(token) || !token.starts_with("--") {
            extras.push(token.clone());
            continue;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (token.clone(), None),
        };
        let exact = specs.iter().find(|(n, _)| *n == flag);
        let candidates: Vec<&(&str, Kind)> = specs.iter().filter(|(n, _)| n.starts_with(flag.as_str())).collect();
        let spec = match (exact, candidates.len()) {
            (Some(spec), _) => *spec,
            (None, 1) => *candidates[0],
            (None, 0) => {
                extras.push(token.clone());
                continue;
            }
            (None, _) => {
                let names = candidates.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
                return Err(sub(format!("ambiguous option: {flag} could match {names}")));
            }
        };
        let (name, kind) = spec;
        if name == "--file" || name == "--harness" {
            match exclusive {
                Some(other) if other != name => {
                    return Err(sub(format!("argument {name}: not allowed with argument {other}")));
                }
                _ => exclusive = Some(name),
            }
        }
        if kind == Kind::Flag {
            if inline.is_some() {
                return Err(sub(format!(
                    "argument {name}: ignored explicit argument '{}'",
                    inline.unwrap_or_default()
                )));
            }
            args.values.push((name, String::new()));
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None if index < rest.len() && !optional_like(&rest[index]) => {
                index += 1;
                rest[index - 1].clone()
            }
            None => return Err(sub(format!("argument {name}: expected one argument"))),
        };
        match kind {
            Kind::Choice(choices) if !choices.contains(&value.as_str()) => {
                let listed = choices.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
                return Err(sub(format!(
                    "argument {name}: invalid choice: '{value}' (choose from {listed})"
                )));
            }
            Kind::Int if python_int(&value).is_none() => {
                return Err(sub(format!("argument {name}: invalid int value: '{value}'")));
            }
            _ => {}
        }
        if name == "--root" {
            args.root = Some(value);
        } else {
            args.values.push((name, value));
        }
    }
    // `daemon`'s positional action: the first remaining word.
    if command == "daemon" && !extras.is_empty() {
        let action = extras.remove(0);
        const ACTIONS: [&str; 4] = ["serve", "start", "stop", "status"];
        if !ACTIONS.contains(&action.as_str()) {
            let listed = ACTIONS.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
            return Err(sub(format!(
                "argument action: invalid choice: '{action}' (choose from {listed})"
            )));
        }
        args.values.push(("action", action));
    }
    let required: &[&str] = match command.as_str() {
        "verify-installation" => &["--engine", "--registration", "--agent-uid"],
        "apply" => &["--manifest"],
        "daemon" => &["action"],
        _ => &[],
    };
    let missing: Vec<&str> = required.iter().filter(|name| !args.has(name)).copied().collect();
    if !missing.is_empty() {
        return Err(sub(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        )));
    }
    if matches!(command.as_str(), "protect" | "hook") && exclusive.is_none() {
        return Err(sub("one of the arguments --file --harness is required".into()));
    }
    top_extras.extend(extras);
    if !top_extras.is_empty() {
        return Err(top(format!("unrecognized arguments: {}", top_extras.join(" "))));
    }
    Ok(args)
}

fn root_of(args: &Args) -> PathBuf {
    resolve(Path::new(args.root.as_deref().unwrap_or(".")))
}

fn context(args: &Args) -> ExitCode {
    let root = root_of(args);
    let host = args.get("--host");
    let loaded = config::load_config(&root).map_err(|e| match e {
        config::ConfigError::Invalid(m) | config::ConfigError::Guard(_, m) => m,
    });
    match loaded.and_then(|c| injected_context(&c, host)) {
        Ok(text) => {
            let mut output = json!({"hookSpecificOutput": {
                "hookEventName": args.get("--event").unwrap_or("SessionStart"),
                "additionalContext": text,
            }});
            if host.is_some()
                && let Some(map) = output.as_object_mut()
            {
                map.insert(
                    "loki".into(),
                    json!({"version": loki::VERSION, "formats": ["text", "json"]}),
                );
            }
            println!("{}", py::dumps(&output));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("loki: context unavailable: {message}");
            ExitCode::from(2)
        }
    }
}

fn read_stdin_json(what: &str) -> Result<Value, CheckError> {
    let mut raw = Vec::new();
    std::io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| CheckError::os(&e, None))?;
    let text = loki::proc::decode(&raw)
        .map_err(CheckError::Value)?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    if text.chars().count() > 4 * 1024 * 1024 {
        return Err(CheckError::Value(format!("{what} input exceeds 4 MiB")));
    }
    serde_json::from_str(&text).map_err(|e| CheckError::Value(loki::pyjson::error_text(&text, &e)))
}

/// The protect/hook body of a `--harness` or `hook` run: what blocks and what is only reported.
fn check(args: &Args, root: &Path, config: &config::Config) -> Result<Report, CheckError> {
    let deadline = Deadline::after(20.0);
    let mut warnings: Vec<String> = Vec::new();
    let harness = args.get("--harness");
    if args.get("--format") == Some("json") && harness.is_some() {
        return Err(CheckError::Value("--format json requires --file".into()));
    }
    let (paths, payload) = match harness {
        Some(harness) => {
            let payload = read_stdin_json("hook")?;
            (loki::harness_paths(&payload, harness)?, Some(payload))
        }
        None => (run::file_paths(&args.all("--file"))?, None),
    };
    loki::evidence::targets(&paths);
    let messages = if args.command == "protect" {
        run::protect_violations(
            root,
            config,
            &paths,
            payload.as_ref(),
            harness.unwrap_or(""),
            deadline,
            &mut warnings,
        )?
    } else {
        run::hook_violations(root, config, &paths, args.get("--python"), deadline, &mut warnings)?
    };
    Ok(Report::new(messages, warnings))
}

fn guard(args: &Args) -> ExitCode {
    let root = root_of(args);
    let harness = args.get("--harness");
    let checked = run::load(&root)
        .inspect_err(|error| run::failure_evidence(error, "invalid-policy"))
        .and_then(|config| {
            if args.command == "protect" && harness.is_none() {
                let preview = args.get("--preview");
                let payload = match preview {
                    Some(_) => Some(
                        read_stdin_json("preview")
                            .inspect_err(|error| run::failure_evidence(error, "invalid-input"))?,
                    ),
                    None => None,
                };
                run::protect_with(&root, &config, &args.all("--file"), preview.zip(payload.as_ref()))
            } else {
                check(args, &root, &config).inspect_err(|error| run::failure_evidence(error, "invalid-input"))
            }
        });
    let (status, stdout, stderr) = rendered(
        &args.command,
        checked,
        args.get("--format") == Some("json"),
        harness.is_some(),
    );
    eprint!("{stderr}");
    print!("{stdout}");
    ExitCode::from(status)
}

/// What `protect` and `hook` print: the JSON report for `--format json`; a failed check's error, or blocking
/// findings (then advisories and unchecked notes), on stderr with status 2; else the warnings, which a `--harness`
/// run also hands back as hook context.
fn rendered(command: &str, checked: Result<Report, CheckError>, json: bool, harness: bool) -> (u8, String, String) {
    let report = match checked {
        Ok(report) => report,
        Err(error) => {
            let text = error.describe();
            let stdout = if json {
                format!("{}\n", py::dumps(&loki::hook_report(command, &[], &[], Some(&text))))
            } else {
                String::new()
            };
            return (2, stdout, format!("loki: {text}\n"));
        }
    };
    let mut stdout = if json {
        format!("{}\n", py::dumps(&report.json(command)))
    } else {
        String::new()
    };
    if report.blocked() {
        let prefix = if command == "hook" {
            "loki: post-write check failed; files are already changed.\n"
        } else {
            ""
        };
        return (2, stdout, format!("{prefix}{}\n", report.refusal_lines().join("\n")));
    }
    if report.warnings.is_empty() {
        return (0, stdout, String::new());
    }
    let text = report.warnings.join("\n");
    if harness {
        let event = if command == "protect" {
            "PreToolUse"
        } else {
            "PostToolUse"
        };
        let context = json!({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}});
        stdout.push_str(&format!("{}\n", py::dumps(&context)));
    }
    (0, stdout, format!("{text}\n"))
}

/// `loki elixir`: the analysis tiers of a Mix project, or with `--credo-new` the Credo issues the work tree adds.
fn elixir(args: &Args) -> ExitCode {
    let project = resolve(Path::new(args.get("--project").unwrap_or(".")));
    let json = args.has("--json");
    let result = if args.has("--credo-new") {
        loki::elixir::credo_new_violations(&project, Deadline::none()).map(|findings| {
            if json {
                println!("{}", py::dumps(&json!({"tool": "credo", "findings": findings})));
            } else {
                println!("{}", findings.join("\n"));
            }
            u8::from(!findings.is_empty())
        })
    } else {
        let files: Vec<String> = args.all("--file").iter().map(|f| loki::apply::as_posix(f)).collect();
        loki::elixir::elixir_analysis(&project, args.get("--tier").unwrap_or("project"), &files).map(|report| {
            if json {
                let items: Vec<Value> = report.iter().map(|check| check.to_json()).collect();
                println!("{}", py::dumps(&Value::from(items)));
            } else {
                for check in &report {
                    println!("[{}] {}", check.tool, check.status);
                    if !check.output.is_empty() {
                        println!("{}", check.output);
                    }
                }
            }
            u8::from(report.iter().any(|check| check.status != "PASS"))
        })
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() => {
            eprintln!("loki: Elixir analysis unavailable: {}", error.message());
            ExitCode::from(1)
        }
        Err(other) => {
            eprintln!("loki: {}", other.describe());
            ExitCode::from(1)
        }
    }
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// `scan` and `slop`: the policy loads first, then the command runs.
fn audit(args: &Args) -> ExitCode {
    let root = root_of(args);
    let config = match config::load_config(&root) {
        Ok(config) => config,
        Err(config::ConfigError::Invalid(m)) => {
            eprintln!("loki: invalid hook input: {m}");
            return ExitCode::from(1);
        }
        Err(config::ConfigError::Guard(kind, m)) => {
            eprintln!("loki: guard error: {kind}: {m}");
            return ExitCode::from(1);
        }
    };
    let report = |error: CheckError| {
        match error {
            CheckError::Value(m) => eprintln!("loki: {m}"),
            other if other.is_os() => eprintln!("loki: {}", other.message()),
            other => eprintln!("loki: {}", other.describe()),
        }
        ExitCode::from(1)
    };
    if args.command == "slop" {
        let top = args.get("--top").and_then(python_int).unwrap_or(10);
        return match loki::slop::slop_command(&root, &config, args.get("--base"), args.has("--json"), top) {
            Ok(code) => exit(code),
            Err(error) => report(error),
        };
    }
    if args.has("--ruff-new") {
        return match hook::ruff_new_violations(&root, args.get("--base"), None, Deadline::none()) {
            Ok(findings) => {
                if !findings.is_empty() {
                    println!("{}", findings.join("\n"));
                }
                exit(i32::from(!findings.is_empty()))
            }
            Err(hook::RuffError::MissingConfig(m)) => report(CheckError::Value(m)),
            Err(hook::RuffError::Other(error)) => report(error),
        };
    }
    let strict = args.has("--strict") || loki::strict();
    match loki::scan::scan(
        &root,
        &config,
        args.has("--online"),
        strict,
        args.get("--base"),
        args.get("--python"),
    ) {
        Ok(code) => exit(code),
        Err(error) => report(error),
    }
}

fn init(args: &Args) -> ExitCode {
    let result = if args.has("--minimal") {
        if args.has("--shell-guard") || args.get("--managed-dir").is_some() {
            Err(CheckError::Value(
                "--minimal installs only .loki/; it takes neither --shell-guard nor --managed-dir".into(),
            ))
        } else {
            loki::scan::install_minimal(args.get("--dir").unwrap_or("."), args.has("--force"))
        }
    } else {
        loki::init::init(
            args.get("--dir").unwrap_or("."),
            args.has("--force"),
            args.has("--shell-guard"),
            args.get("--managed-dir"),
        )
        .map_err(CheckError::Value)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", loki::scan::init_error_line(&error));
            ExitCode::from(1)
        }
    }
}

/// Set for the run a `--record` wrapper starts: the file its evidence goes to.
const RECORD_CHILD: &str = "LOKI_RECORD_EVIDENCE";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(path) = std::env::var_os(RECORD_CHILD) {
        loki::evidence::start();
        let code = dispatch(&argv);
        let evidence = loki::evidence::take().unwrap_or_default();
        let document =
            json!({"findings": evidence.findings, "policies": evidence.policies, "targets": evidence.targets});
        let _ = std::fs::write(path, document.to_string());
        return code;
    }
    // A repository's warm daemon runs the command when one is up (`LOKI_DAEMON=0`: never).
    match loki::daemon::client(&argv, &mut std::io::stdin()) {
        loki::daemon::Forwarded::Ran(reply) => {
            print!("{}", reply.stdout);
            eprint!("{}", reply.stderr);
            return exit(reply.exit);
        }
        // Forwarding read stdin before the daemon failed: run here on what it read.
        loki::daemon::Forwarded::LocalWith(raw) => return local_with(&argv, &raw),
        loki::daemon::Forwarded::Local => {}
    }
    if argv.iter().any(|arg| arg == "--record") {
        return record(&argv);
    }
    dispatch(&argv)
}

/// This engine run on `argv` with `stdin` as its input, never forwarded.
fn local_with(argv: &[String], stdin: &str) -> ExitCode {
    let run = || -> std::io::Result<i32> {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(argv)
            .env("LOKI_DAEMON", "0")
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            use std::io::Write;
            let _ = input.write_all(stdin.as_bytes());
        }
        Ok(child.wait()?.code().unwrap_or(2))
    };
    match run() {
        Ok(code) => exit(code),
        Err(error) => {
            eprintln!("loki: {}", py::os_error(&error, None));
            ExitCode::from(2)
        }
    }
}

/// `main` with `--record`: the run's diagnostics are passed through, then its event (the operation, outcome,
/// targets, the policies it read and the rules it applied) is appended for `loki explain`. The run itself goes
/// to a child of this engine, which reports its evidence in a private file.
fn record(argv: &[String]) -> ExitCode {
    let started = std::time::Instant::now();
    let run = || -> std::io::Result<(i32, String, loki::evidence::Evidence)> {
        let directory = tempfile::Builder::new().prefix("loki-record-").tempdir()?;
        let file = directory.path().join("evidence.json");
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(argv)
            .env(RECORD_CHILD, &file)
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let status = output.status.code().unwrap_or(2);
        let collected: Value = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let list = |key: &str| collected[key].as_array().cloned().unwrap_or_default();
        let evidence = loki::evidence::Evidence {
            findings: list("findings"),
            policies: list("policies"),
            targets: list("targets")
                .iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect(),
        };
        Ok((status, stderr, evidence))
    };
    let (status, diagnostic, mut evidence) = match run() {
        Ok(ran) => ran,
        Err(error) => (2, format!("loki: {error}\n"), loki::evidence::Evidence::default()),
    };
    eprint!("{diagnostic}");
    let operation = argv
        .iter()
        .find(|arg| matches!(arg.as_str(), "protect" | "hook" | "shell"))
        .map_or("invalid", String::as_str);
    let root = match argv.iter().position(|arg| arg == "--root") {
        Some(index) if index + 1 < argv.len() => resolve(Path::new(&argv[index + 1])),
        _ => resolve(Path::new(".")),
    };
    if status != 0 && evidence.findings.is_empty() {
        evidence
            .findings
            .push(json!({"rule": "unclassified-failure", "path": null}));
    }
    let outcome = if status != 0 {
        "deny"
    } else if !diagnostic.is_empty() {
        "warning"
    } else {
        "allow"
    };
    if let Err(error) = loki::evidence::record_event(&root, operation, outcome, started, &evidence) {
        eprintln!("loki: evidence unavailable: {}", py::os_error(&error, None));
        return ExitCode::from(2);
    }
    exit(status)
}

fn hygiene_cmd(args: &Args) -> ExitCode {
    let root = root_of(args);
    let config = match config::load_config(&root) {
        Ok(config) => config,
        Err(config::ConfigError::Invalid(m) | config::ConfigError::Guard(_, m)) => {
            eprintln!("loki: {m}");
            return ExitCode::from(1);
        }
    };
    let configured = config.get("hygiene").and_then(Value::as_str);
    let env_level = std::env::var(loki::hygiene::HYGIENE_ENV).ok();
    let level = match args.get("--level") {
        Some("all") => loki::hygiene::Level::All,
        Some("on") => loki::hygiene::Level::On,
        _ => match env_level.as_deref().or(configured) {
            Some("all") => loki::hygiene::Level::All,
            Some("off") => loki::hygiene::Level::Off,
            _ => loki::hygiene::Level::On,
        },
    };
    let files = args.all("--file");
    let notes = if !files.is_empty() {
        loki::hygiene::written(&root, &files, level)
    } else {
        let base = args.get("--base").unwrap_or("HEAD");
        loki::hygiene::changed(&root, base, level)
    };
    if args.has("--json") {
        let (not_checked, findings): (Vec<String>, Vec<String>) = notes
            .into_iter()
            .partition(|note| note.starts_with(loki::run::NOT_CHECKED));
        println!("{}", json!({ "findings": findings, "not_checked": not_checked }));
    } else if !notes.is_empty() {
        println!("{}", notes.join("\n"));
    }
    ExitCode::SUCCESS
}

fn dispatch(argv: &[String]) -> ExitCode {
    if let Some(code) = shell_cli::dispatch(argv) {
        return code;
    }
    let args = match parse(argv) {
        Ok(args) => args,
        Err(ParseError::Exit(code)) => {
            loki::evidence::finding("invalid-cli", None);
            return exit(code);
        }
        Err(ParseError::Top(message)) => {
            loki::evidence::finding("invalid-cli", None);
            eprintln!("{TOP_USAGE}\nloki: error: {message}");
            return ExitCode::from(2);
        }
        Err(ParseError::Sub(command, message)) => {
            loki::evidence::finding("invalid-cli", None);
            eprintln!("{}\nloki {command}: error: {message}", usage(&command));
            return ExitCode::from(2);
        }
    };
    match args.command.as_str() {
        "context" => context(&args),
        "protect" | "hook" => guard(&args),
        "scan" | "slop" => audit(&args),
        "hygiene" => hygiene_cmd(&args),
        "init" => init(&args),
        "elixir" => elixir(&args),
        "daemon" => {
            let (status, stdout, stderr) =
                loki::daemon::command(args.get("action").unwrap_or_default(), &root_of(&args));
            print!("{stdout}");
            eprint!("{stderr}");
            exit(status)
        }
        "apply" => {
            let manifest = PathBuf::from(args.get("--manifest").unwrap_or_default());
            match loki::apply::apply_transaction(&root_of(&args), &manifest, args.has("--check-only")) {
                Ok(text) => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("loki: {}", error.message());
                    ExitCode::from(2)
                }
            }
        }
        "verify-installation" => {
            let mut paths = vec![PathBuf::from(args.get("--engine").unwrap_or_default())];
            paths.extend(args.all("--registration").into_iter().map(PathBuf::from));
            let uid = args.get("--agent-uid").and_then(python_int).unwrap_or_default();
            let findings = loki::installation::installation_violations(&paths, uid);
            for finding in &findings {
                println!("{finding}");
            }
            if findings.is_empty() {
                println!(
                    "Ownership/mode checks passed; ACLs, privileged access and host activation require operator verification"
                );
            }
            ExitCode::from(u8::from(!findings.is_empty()))
        }
        other => unreachable!("`parse` accepts no command {other}"),
    }
}
