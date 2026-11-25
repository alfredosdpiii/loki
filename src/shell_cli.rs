//! CLI for `shell`, `shell-writes` and `explain`, dispatched before the core parser.

use loki::{CheckError, py, resolve, shell};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const TOP_USAGE: &str = "usage: loki [-h] [--version] [--root ROOT]\n            {verify-installation,explain,context,elixir,apply,shell,shell-writes,protect,hook,scan,slop,daemon,init} ...";
const COMMANDS: [&str; 3] = ["shell", "shell-writes", "explain"];

fn usage(command: &str) -> &'static str {
    match command {
        "shell" => "usage: loki shell [-h] --harness {agy,claude,codex,factory,omp,pi} [--record]",
        "shell-writes" => "usage: loki shell-writes [-h] [--harness {agy,claude,codex,factory,omp,pi,ultron}]",
        _ => "usage: loki explain [-h] [--limit LIMIT]",
    }
}

fn arg_error(command: &str, message: &str) -> ExitCode {
    loki::evidence::finding("invalid-cli", None);
    eprintln!("{}\nloki {command}: error: {message}", usage(command));
    ExitCode::from(2)
}

fn read_payload() -> Result<Value, CheckError> {
    let mut raw = String::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .map_err(|e| CheckError::Value(e.to_string()))?;
    if raw.chars().count() > 4 * 1024 * 1024 {
        return Err(CheckError::Value("shell envelope exceeds 4 MiB".into()));
    }
    let payload: Value = serde_json::from_str(&raw).map_err(|e| CheckError::Value(e.to_string()))?;
    if !payload.is_object() {
        return Err(CheckError::Value("invalid shell envelope".into()));
    }
    Ok(payload)
}

fn report(result: Result<Option<String>, CheckError>) -> ExitCode {
    let (status, stderr) = shell::shell_report(result);
    eprint!("{stderr}");
    ExitCode::from(status)
}

struct ParsedArgs {
    root: PathBuf,
    command: String,
    harness: Option<String>,
    limit: i64,
}

fn parse_choice(command: &str, value: Option<String>, choices: &[&str]) -> Result<String, ExitCode> {
    let Some(value) = value else {
        return Err(arg_error(command, "argument --harness: expected one argument"));
    };
    if !choices.contains(&value.as_str()) {
        let listed = choices.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
        let message = format!("argument --harness: invalid choice: '{value}' (choose from {listed})");
        return Err(arg_error(command, &message));
    }
    Ok(value)
}

fn parse_limit(command: &str, value: Option<String>) -> Result<i64, ExitCode> {
    let Some(value) = value else {
        return Err(arg_error(command, "argument --limit: expected one argument"));
    };
    py::strip(&value)
        .parse::<i64>()
        .map_err(|_| arg_error(command, &format!("argument --limit: invalid int value: '{value}'")))
}

fn parse_option(
    command: &str,
    item: &str,
    items: &mut impl Iterator<Item = String>,
    harness: &mut Option<String>,
    limit: &mut i64,
) -> Result<(), ExitCode> {
    let choices: &[&str] = if command == "shell" {
        &["agy", "claude", "codex", "factory", "omp", "pi"]
    } else {
        &["agy", "claude", "codex", "factory", "omp", "pi", "ultron"]
    };
    match (command, item) {
        ("shell" | "shell-writes", "--harness") => {
            *harness = Some(parse_choice(command, items.next(), choices)?);
        }
        // `--record` is handled around the whole run (main's record wrapper).
        ("shell", "--record") => {}
        ("explain", "--limit") => {
            *limit = parse_limit(command, items.next())?;
        }
        (_, other) => {
            loki::evidence::finding("invalid-cli", None);
            eprintln!("{TOP_USAGE}\nloki: error: unrecognized arguments: {other}");
            return Err(ExitCode::from(2));
        }
    }
    Ok(())
}

fn split_eq_tokens(argv: &[String]) -> impl Iterator<Item = String> + '_ {
    argv.iter().flat_map(|a| match a.split_once('=') {
        Some((flag, value)) if flag.starts_with("--") => vec![flag.to_string(), value.to_string()],
        _ => vec![a.clone()],
    })
}

fn parse_args(argv: &[String]) -> Option<Result<ParsedArgs, ExitCode>> {
    let mut items = split_eq_tokens(argv);
    let mut root: Option<PathBuf> = None;
    let command = loop {
        match items.next()?.as_str() {
            "--root" => root = Some(PathBuf::from(items.next()?)),
            name if COMMANDS.contains(&name) => break name.to_string(),
            _ => return None,
        }
    };
    let (mut harness, mut limit) = (None, 20i64);
    while let Some(item) = items.next() {
        if let Err(code) = parse_option(&command, &item, &mut items, &mut harness, &mut limit) {
            return Some(Err(code));
        }
    }
    Some(Ok(ParsedArgs {
        root: resolve(&root.unwrap_or_else(|| PathBuf::from("."))),
        command,
        harness,
        limit,
    }))
}

fn run_explain(limit: i64) -> ExitCode {
    match shell::explain(Path::new("."), limit) {
        Ok(lines) => {
            lines.iter().for_each(|line| println!("{line}"));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("loki: {message}");
            ExitCode::from(1)
        }
    }
}

fn report_agy_shell(result: Result<Option<String>, CheckError>) -> ExitCode {
    let (status, stderr) = shell::shell_report(result);
    if status == 0 {
        println!("{}", py::dumps(&serde_json::json!({"decision": "allow"})));
    } else {
        let reason = stderr.trim_end_matches('\n');
        println!("{}", py::dumps(&serde_json::json!({"decision": "deny", "reason": reason})));
        eprint!("{stderr}");
    }
    ExitCode::SUCCESS
}

fn run_shell(root: &Path, command: &str, harness: Option<String>) -> ExitCode {
    let Some(harness) = harness else {
        return arg_error(command, "the following arguments are required: --harness");
    };
    let result = read_payload().and_then(|payload| {
        let cwd = shell::shell_cwd(&payload, &harness, root)?;
        let cmd = shell::shell_command(&payload, &harness)?;
        shell::shell_violation(cmd, root, &cwd)
    });
    if harness == "agy" {
        return report_agy_shell(result);
    }
    report(result)
}

/// Handles `shell`, `shell-writes` and `explain`; `None` for every other command.
pub fn dispatch(argv: &[String]) -> Option<ExitCode> {
    let parsed = match parse_args(argv)? {
        Ok(parsed) => parsed,
        Err(code) => return Some(code),
    };
    Some(match parsed.command.as_str() {
        "explain" => run_explain(parsed.limit),
        "shell" => run_shell(&parsed.root, &parsed.command, parsed.harness),
        _ => {
            let result = read_payload().and_then(|payload| match parsed.harness.as_deref() {
                Some(h) if h != "ultron" => {
                    let cwd = shell::shell_cwd(&payload, h, &parsed.root)?;
                    let cmd = shell::shell_command(&payload, h)?;
                    shell::shell_writes_violation(cmd, &parsed.root, &cwd, &cwd)
                }
                _ => shell::shell_writes(&parsed.root, &payload, Path::new(".")),
            });
            if parsed.harness.as_deref() == Some("agy") {
                report_agy_shell(result)
            } else {
                report(result)
            }
        }
    })
}
