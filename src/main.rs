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

const USAGES: &[(&str, &str)] = &[
    (
        "protect",
        "usage: loki protect [-h] [--root ROOT] (--file FILE |\n                    --harness {agy,claude,codex,factory}) [--record]\n                    [--format {text,json}] [--python PYTHON]\n                    [--preview {pi,omp,ultron}]",
    ),
    (
        "hook",
        "usage: loki hook [-h] [--root ROOT] (--file FILE |\n                 --harness {agy,claude,codex,factory}) [--record]\n                 [--format {text,json}] [--python PYTHON]",
    ),
    (
        "scan",
        "usage: loki scan [-h] [--online] [--strict] [--base BASE] [--ruff-new]\n                 [--python PYTHON]",
    ),
    ("slop", "usage: loki slop [-h] [--base BASE] [--json] [--top TOP]"),
    (
        "hygiene",
        "usage: loki hygiene [-h] [--base BASE] [--file FILE] [--level {on,all}] [--json]",
    ),
    (
        "init",
        "usage: loki init [-h] [--force] [--dir DIR] [--managed-dir MANAGED_DIR]\n                 [--shell-guard] [--minimal]",
    ),
    (
        "verify-installation",
        "usage: loki verify-installation [-h] --engine ENGINE\n                                --registration REGISTRATION\n                                --agent-uid AGENT_UID",
    ),
    (
        "elixir",
        "usage: loki elixir [-h] [--project PROJECT] [--tier {fast,project,deep}]\n                   [--file FILE] [--json] [--credo-new]",
    ),
    ("apply", "usage: loki apply [-h] --manifest MANIFEST [--check-only]"),
    ("daemon", "usage: loki daemon [-h] {serve,start,stop,status}"),
];

const DEFAULT_USAGE: &str = "usage: loki context [-h] [--root ROOT]\n                    [--event {SessionStart,UserPromptSubmit}]\n                    [--host {agy,ultron}]";

fn usage(command: &str) -> &'static str {
    USAGES
        .iter()
        .find(|&&(name, _)| name == command)
        .map_or(DEFAULT_USAGE, |&(_, text)| text)
}

const PROTECT_HELP_OPTIONS: &str = "  -h, --help            show this help message and exit\n  --root ROOT\n  --file FILE\n  --harness {agy,claude,codex,factory}\n  --record\n  --format {text,json}\n  --python PYTHON       the project's Python interpreter\n";

const HELP_OPTIONS: &[(&str, &str)] = &[
    ("hook", PROTECT_HELP_OPTIONS),
    (
        "scan",
        "  -h, --help       show this help message and exit\n  --online\n  --strict\n  --base BASE\n  --ruff-new\n  --python PYTHON  the project's Python interpreter\n",
    ),
    (
        "slop",
        "  -h, --help   show this help message and exit\n  --base BASE  compare against this revision\n  --json\n  --top TOP\n",
    ),
    (
        "hygiene",
        "  -h, --help          show this help message and exit\n  --base BASE         compare against this revision\n  --file FILE         check specific file(s)\n  --level {on,all}    override hygiene level\n  --json              output JSON\n",
    ),
    (
        "init",
        "  -h, --help            show this help message and exit\n  --force\n  --dir DIR\n  --managed-dir MANAGED_DIR\n  --shell-guard\n  --minimal\n",
    ),
    (
        "verify-installation",
        "  -h, --help            show this help message and exit\n  --engine ENGINE\n  --registration REGISTRATION\n  --agent-uid AGENT_UID\n",
    ),
    (
        "elixir",
        "  -h, --help            show this help message and exit\n  --project PROJECT\n  --tier {fast,project,deep}\n  --file FILE\n  --json\n  --credo-new\n",
    ),
    (
        "apply",
        "  -h, --help           show this help message and exit\n  --manifest MANIFEST\n  --check-only\n",
    ),
];

const DEFAULT_HELP_OPTIONS: &str = "  -h, --help            show this help message and exit\n  --root ROOT\n  --event {SessionStart,UserPromptSubmit}\n  --host {agy,ultron}\n";

/// `loki <command> --help`: the usage, then argparse's option list.
fn help(command: &str) -> String {
    if command == "daemon" {
        return format!(
            "{}\n\npositional arguments:\n  {{serve,start,stop,status}}\n\noptions:\n  -h, --help            show this help message and exit\n",
            usage(command)
        );
    }
    if command == "protect" {
        return format!(
            "{}\n\noptions:\n{PROTECT_HELP_OPTIONS}  --preview {{pi,omp,ultron}}\n",
            usage(command)
        );
    }
    let options = HELP_OPTIONS
        .iter()
        .find(|&&(name, _)| name == command)
        .map_or(DEFAULT_HELP_OPTIONS, |&(_, text)| text);
    format!("{}\n\noptions:\n{options}", usage(command))
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Flag,
    Value,
    Int,
    Choice(&'static [&'static str]),
}

const HARNESS_CHOICES: &[&str] = &["agy", "claude", "codex", "factory"];
const FORMAT_CHOICES: &[&str] = &["text", "json"];
const PREVIEW_CHOICES: &[&str] = &["pi", "omp", "ultron"];
const LEVEL_CHOICES: &[&str] = &["on", "all"];
const TIER_CHOICES: &[&str] = &["fast", "project", "deep"];
const EVENT_CHOICES: &[&str] = &["SessionStart", "UserPromptSubmit"];
const HOST_CHOICES: &[&str] = &["agy", "ultron"];

const GUARD_OPTIONS: &[(&str, Kind)] = &[
    ("--root", Kind::Value),
    ("--file", Kind::Value),
    ("--harness", Kind::Choice(HARNESS_CHOICES)),
    ("--record", Kind::Flag),
    ("--format", Kind::Choice(FORMAT_CHOICES)),
    ("--python", Kind::Value),
    ("--preview", Kind::Choice(PREVIEW_CHOICES)),
];

const OPTION_SPECS: &[(&str, &[(&str, Kind)])] = &[
    ("protect", GUARD_OPTIONS),
    ("hook", GUARD_OPTIONS.split_at(6).0),
    (
        "scan",
        &[
            ("--online", Kind::Flag),
            ("--strict", Kind::Flag),
            ("--base", Kind::Value),
            ("--ruff-new", Kind::Flag),
            ("--python", Kind::Value),
        ],
    ),
    (
        "slop",
        &[("--base", Kind::Value), ("--json", Kind::Flag), ("--top", Kind::Int)],
    ),
    (
        "hygiene",
        &[
            ("--base", Kind::Value),
            ("--file", Kind::Value),
            ("--level", Kind::Choice(LEVEL_CHOICES)),
            ("--json", Kind::Flag),
        ],
    ),
    (
        "init",
        &[
            ("--force", Kind::Flag),
            ("--dir", Kind::Value),
            ("--managed-dir", Kind::Value),
            ("--shell-guard", Kind::Flag),
            ("--minimal", Kind::Flag),
        ],
    ),
    (
        "verify-installation",
        &[
            ("--engine", Kind::Value),
            ("--registration", Kind::Value),
            ("--agent-uid", Kind::Int),
        ],
    ),
    (
        "elixir",
        &[
            ("--project", Kind::Value),
            ("--tier", Kind::Choice(TIER_CHOICES)),
            ("--file", Kind::Value),
            ("--json", Kind::Flag),
            ("--credo-new", Kind::Flag),
        ],
    ),
    ("apply", &[("--manifest", Kind::Value), ("--check-only", Kind::Flag)]),
    ("daemon", &[]),
];

const DEFAULT_OPTION_SPECS: &[(&str, Kind)] = &[
    ("--root", Kind::Value),
    ("--event", Kind::Choice(EVENT_CHOICES)),
    ("--host", Kind::Choice(HOST_CHOICES)),
];

fn options(command: &str) -> &'static [(&'static str, Kind)] {
    OPTION_SPECS
        .iter()
        .find(|&&(name, _)| name == command)
        .map_or(DEFAULT_OPTION_SPECS, |&(_, specs)| specs)
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

fn resolve_top_flag(flag: &str) -> Option<&'static str> {
    let matches: Vec<&str> = ["--version", "--root"]
        .into_iter()
        .filter(|o| o.starts_with(flag))
        .collect();
    if matches.contains(&flag) {
        Some(if flag == "--version" { "--version" } else { "--root" })
    } else if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

fn parse_top_option<'a>(
    flag: &str,
    inline: Option<String>,
    token: &str,
    items: &mut std::iter::Peekable<std::slice::Iter<'a, String>>,
    args: &mut Args,
    top_extras: &mut Vec<String>,
) -> Result<(), ParseError> {
    match resolve_top_flag(flag) {
        Some("--version") => {
            println!("loki {}", loki::VERSION);
            Err(ParseError::Exit(0))
        }
        Some(_) => {
            let value = match inline {
                Some(v) => v,
                None => match items.peek() {
                    Some(v) if !optional_like(v) => items.next().cloned().unwrap_or_default(),
                    _ => return Err(ParseError::Top("argument --root: expected one argument".into())),
                },
            };
            args.root = Some(value);
            Ok(())
        }
        // argparse keeps going: an unknown option is reported once the command parsed.
        None => {
            top_extras.push(token.to_string());
            Ok(())
        }
    }
}

fn parse_top(argv: &[String]) -> Result<(Args, Vec<String>, Vec<String>), ParseError> {
    let mut args = Args::default();
    let mut top_extras = Vec::new();
    let mut items = argv.iter().peekable();
    while let Some(token) = items.next() {
        let (flag, inline) = match token.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (token.clone(), None),
        };
        if flag.starts_with("--") && flag.len() > 2 {
            parse_top_option(&flag, inline, token, &mut items, &mut args, &mut top_extras)?;
            continue;
        }
        if !COMMANDS.contains(&token.as_str()) {
            let listed = COMMANDS.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
            return Err(ParseError::Top(format!(
                "argument command: invalid choice: '{token}' (choose from {listed})"
            )));
        }
        args.command = token.clone();
        break;
    }
    if args.command.is_empty() {
        return Err(ParseError::Top("the following arguments are required: command".into()));
    }
    Ok((args, top_extras, items.cloned().collect()))
}

fn resolve_sub_option(
    specs: &[(&'static str, Kind)],
    flag: &str,
    command: &str,
) -> Result<Option<(&'static str, Kind)>, ParseError> {
    if let Some(&spec) = specs.iter().find(|(n, _)| *n == flag) {
        return Ok(Some(spec));
    }
    let candidates: Vec<&(&str, Kind)> = specs.iter().filter(|(n, _)| n.starts_with(flag)).collect();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(Some(*candidates[0])),
        _ => {
            let names = candidates.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
            Err(ParseError::Sub(
                command.to_string(),
                format!("ambiguous option: {flag} could match {names}"),
            ))
        }
    }
}

fn validate_option_value(command: &str, name: &str, kind: Kind, value: &str) -> Result<(), ParseError> {
    match kind {
        Kind::Choice(choices) if !choices.contains(&value) => {
            let listed = choices.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
            Err(ParseError::Sub(
                command.to_string(),
                format!("argument {name}: invalid choice: '{value}' (choose from {listed})"),
            ))
        }
        Kind::Int if python_int(value).is_none() => Err(ParseError::Sub(
            command.to_string(),
            format!("argument {name}: invalid int value: '{value}'"),
        )),
        _ => Ok(()),
    }
}

fn check_exclusive(command: &str, name: &'static str, exclusive: &mut Option<&'static str>) -> Result<(), ParseError> {
    if name != "--file" && name != "--harness" {
        return Ok(());
    }
    if let Some(other) = *exclusive
        && other != name
    {
        return Err(ParseError::Sub(
            command.to_string(),
            format!("argument {name}: not allowed with argument {other}"),
        ));
    }
    *exclusive = Some(name);
    Ok(())
}

fn take_option_value(
    command: &str,
    name: &str,
    inline: Option<String>,
    rest: &[String],
    index: &mut usize,
) -> Result<String, ParseError> {
    match inline {
        Some(v) => Ok(v),
        None if *index < rest.len() && !optional_like(&rest[*index]) => {
            *index += 1;
            Ok(rest[*index - 1].clone())
        }
        None => Err(ParseError::Sub(
            command.to_string(),
            format!("argument {name}: expected one argument"),
        )),
    }
}

fn apply_sub_option(
    args: &mut Args,
    spec: (&'static str, Kind),
    inline: Option<String>,
    rest: &[String],
    index: &mut usize,
    exclusive: &mut Option<&'static str>,
) -> Result<(), ParseError> {
    let (name, kind) = spec;
    check_exclusive(&args.command, name, exclusive)?;
    if kind == Kind::Flag {
        if let Some(val) = inline {
            return Err(ParseError::Sub(
                args.command.clone(),
                format!("argument {name}: ignored explicit argument '{val}'"),
            ));
        }
        args.values.push((name, String::new()));
        return Ok(());
    }
    let value = take_option_value(&args.command, name, inline, rest, index)?;
    validate_option_value(&args.command, name, kind, &value)?;
    if name == "--root" {
        args.root = Some(value);
    } else {
        args.values.push((name, value));
    }
    Ok(())
}

fn is_help_token(token: &str, specs: &[(&str, Kind)]) -> bool {
    token == "-h"
        || (token.len() > 2 && "--help".starts_with(token) && !specs.iter().any(|(n, _)| n.starts_with(token)))
}

fn parse_sub_args(args: &mut Args, rest: &[String]) -> Result<(Vec<String>, Option<&'static str>), ParseError> {
    let specs = options(&args.command);
    let mut extras = Vec::new();
    let mut exclusive = None;
    let mut index = 0;
    while index < rest.len() {
        let token = &rest[index];
        index += 1;
        if token == "--" {
            extras.extend(rest[index..].iter().cloned());
            break;
        }
        if is_help_token(token, specs) {
            print!("{}", help(&args.command));
            return Err(ParseError::Exit(0));
        }
        if !optional_like(token) || !token.starts_with("--") {
            extras.push(token.clone());
            continue;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((f, v)) => (f, Some(v.to_string())),
            None => (token.as_str(), None),
        };
        let Some(spec) = resolve_sub_option(specs, flag, &args.command)? else {
            extras.push(token.clone());
            continue;
        };
        apply_sub_option(args, spec, inline, rest, &mut index, &mut exclusive)?;
    }
    Ok((extras, exclusive))
}

fn parse_daemon_action(args: &mut Args, extras: &mut Vec<String>) -> Result<(), ParseError> {
    if args.command != "daemon" || extras.is_empty() {
        return Ok(());
    }
    let action = extras.remove(0);
    const ACTIONS: [&str; 4] = ["serve", "start", "stop", "status"];
    if !ACTIONS.contains(&action.as_str()) {
        let listed = ACTIONS.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
        return Err(ParseError::Sub(
            args.command.clone(),
            format!("argument action: invalid choice: '{action}' (choose from {listed})"),
        ));
    }
    args.values.push(("action", action));
    Ok(())
}

fn finalize_sub_args(
    args: &mut Args,
    mut extras: Vec<String>,
    mut top_extras: Vec<String>,
    exclusive: Option<&'static str>,
) -> Result<(), ParseError> {
    let command = args.command.clone();
    let sub = |m: String| ParseError::Sub(command.clone(), m);
    // `daemon`'s positional action: the first remaining word.
    parse_daemon_action(args, &mut extras)?;
    let required: &[&str] = match args.command.as_str() {
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
    if matches!(args.command.as_str(), "protect" | "hook") && exclusive.is_none() {
        return Err(sub("one of the arguments --file --harness is required".into()));
    }
    top_extras.extend(extras);
    if !top_extras.is_empty() {
        return Err(ParseError::Top(format!(
            "unrecognized arguments: {}",
            top_extras.join(" ")
        )));
    }
    Ok(())
}

fn parse(argv: &[String]) -> Result<Args, ParseError> {
    let (mut args, top_extras, rest) = parse_top(argv)?;
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
    if !PARSED.contains(&args.command.as_str()) {
        if !top_extras.is_empty() {
            return Err(ParseError::Top(format!(
                "unrecognized arguments: {}",
                top_extras.join(" ")
            )));
        }
        return Ok(args);
    }
    let (extras, exclusive) = parse_sub_args(&mut args, &rest)?;
    finalize_sub_args(&mut args, extras, top_extras, exclusive)?;
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
            if host == Some("agy") {
                let output = json!({"injectSteps": [{"systemMessage": {"systemMessage": text}}]});
                println!("{}", py::dumps(&output));
                return ExitCode::SUCCESS;
            }
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
        harness,
    );
    eprint!("{stderr}");
    print!("{stdout}");
    ExitCode::from(status)
}

/// Antigravity (`agy`) hook stdout contract: `PreToolUse` returns `{"decision": "allow"|"deny", "reason"?: ...}`
/// on exit 0; `PostToolUse` returns `{}` on exit 0 with diagnostics on stderr.
fn render_agy(command: &str, checked: Result<Report, CheckError>) -> (u8, String, String) {
    let report = match checked {
        Ok(report) => report,
        Err(error) => {
            let reason = format!("loki: {}", error.describe());
            let stdout = if command == "protect" {
                format!("{}\n", py::dumps(&json!({"decision": "deny", "reason": reason})))
            } else {
                "{}\n".into()
            };
            return (0, stdout, format!("{reason}\n"));
        }
    };
    if report.blocked() {
        let prefix = if command == "hook" {
            "loki: post-write check failed; files are already changed.\n"
        } else {
            ""
        };
        let detail = format!("{prefix}{}", report.refusal_lines().join("\n"));
        let stdout = if command == "protect" {
            format!("{}\n", py::dumps(&json!({"decision": "deny", "reason": detail})))
        } else {
            "{}\n".into()
        };
        return (0, stdout, format!("{detail}\n"));
    }
    let stderr = if report.warnings.is_empty() {
        String::new()
    } else {
        format!("{}\n", report.warnings.join("\n"))
    };
    let stdout = if command == "protect" {
        format!("{}\n", py::dumps(&json!({"decision": "allow"})))
    } else {
        "{}\n".into()
    };
    (0, stdout, stderr)
}

/// What `protect` and `hook` print: the JSON report for `--format json`; a failed check's error, or blocking
/// findings (then advisories and unchecked notes), on stderr with status 2; else the warnings, which a `--harness`
/// run also hands back as hook context.
fn rendered(
    command: &str,
    checked: Result<Report, CheckError>,
    json: bool,
    harness: Option<&str>,
) -> (u8, String, String) {
    if harness == Some("agy") {
        return render_agy(command, checked);
    }
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
    if harness.is_some() {
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

fn report_audit_error(error: CheckError) -> ExitCode {
    match error {
        CheckError::Value(m) => eprintln!("loki: {m}"),
        other if other.is_os() => eprintln!("loki: {}", other.message()),
        other => eprintln!("loki: {}", other.describe()),
    }
    ExitCode::from(1)
}

fn run_ruff_new(args: &Args, root: &Path) -> ExitCode {
    match hook::ruff_new_violations(root, args.get("--base"), None, Deadline::none()) {
        Ok(findings) => {
            if !findings.is_empty() {
                println!("{}", findings.join("\n"));
            }
            exit(i32::from(!findings.is_empty()))
        }
        Err(hook::RuffError::MissingConfig(m)) => report_audit_error(CheckError::Value(m)),
        Err(hook::RuffError::Other(error)) => report_audit_error(error),
    }
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
    if args.command == "slop" {
        let top = args.get("--top").and_then(python_int).unwrap_or(10);
        return match loki::slop::slop_command(&root, &config, args.get("--base"), args.has("--json"), top) {
            Ok(code) => exit(code),
            Err(error) => report_audit_error(error),
        };
    }
    if args.has("--ruff-new") {
        return run_ruff_new(args, &root);
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
        Err(error) => report_audit_error(error),
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

fn run_record_child(argv: &[String]) -> std::io::Result<(i32, String, loki::evidence::Evidence)> {
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
}

fn record_outcome(status: i32, diagnostic: &str) -> &'static str {
    if status != 0 {
        "deny"
    } else if !diagnostic.is_empty() {
        "warning"
    } else {
        "allow"
    }
}

/// `main` with `--record`: the run's diagnostics are passed through, then its event (the operation, outcome,
/// targets, the policies it read and the rules it applied) is appended for `loki explain`. The run itself goes
/// to a child of this engine, which reports its evidence in a private file.
fn record(argv: &[String]) -> ExitCode {
    let started = std::time::Instant::now();
    let (status, diagnostic, mut evidence) = match run_record_child(argv) {
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
    let outcome = record_outcome(status, &diagnostic);
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

fn report_parse_error(error: ParseError) -> ExitCode {
    loki::evidence::finding("invalid-cli", None);
    match error {
        ParseError::Exit(code) => exit(code),
        ParseError::Top(message) => {
            eprintln!("{TOP_USAGE}\nloki: error: {message}");
            ExitCode::from(2)
        }
        ParseError::Sub(command, message) => {
            eprintln!("{}\nloki {command}: error: {message}", usage(&command));
            ExitCode::from(2)
        }
    }
}

fn run_daemon(args: &Args) -> ExitCode {
    let (status, stdout, stderr) = loki::daemon::command(args.get("action").unwrap_or_default(), &root_of(args));
    print!("{stdout}");
    eprint!("{stderr}");
    exit(status)
}

fn run_apply(args: &Args) -> ExitCode {
    let manifest = PathBuf::from(args.get("--manifest").unwrap_or_default());
    match loki::apply::apply_transaction(&root_of(args), &manifest, args.has("--check-only")) {
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

fn run_verify_installation(args: &Args) -> ExitCode {
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

type Handler = fn(&Args) -> ExitCode;

const HANDLERS: &[(&str, Handler)] = &[
    ("context", context),
    ("protect", guard),
    ("hook", guard),
    ("scan", audit),
    ("slop", audit),
    ("hygiene", hygiene_cmd),
    ("init", init),
    ("elixir", elixir),
    ("daemon", run_daemon),
    ("apply", run_apply),
    ("verify-installation", run_verify_installation),
];

fn dispatch(argv: &[String]) -> ExitCode {
    if let Some(code) = shell_cli::dispatch(argv) {
        return code;
    }
    let args = match parse(argv) {
        Ok(args) => args,
        Err(error) => return report_parse_error(error),
    };
    match HANDLERS.iter().find(|&&(cmd, _)| cmd == args.command) {
        Some(&(_, handler)) => handler(&args),
        None => unreachable!("`parse` accepts no command {}", args.command),
    }
}
