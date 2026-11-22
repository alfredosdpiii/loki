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
        "shell" => "usage: loki shell [-h] --harness {claude,factory,omp,pi} [--record]",
        "shell-writes" => "usage: loki shell-writes [-h] [--harness {ultron}]",
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

/// Handles `shell`, `shell-writes` and `explain`; `None` for every other command.
pub fn dispatch(argv: &[String]) -> Option<ExitCode> {
    let mut items = argv.iter().flat_map(|a| match a.split_once('=') {
        Some((flag, value)) if flag.starts_with("--") => vec![flag.to_string(), value.to_string()],
        _ => vec![a.clone()],
    });
    let mut root: Option<PathBuf> = None;
    let command = loop {
        match items.next()?.as_str() {
            "--root" => root = Some(PathBuf::from(items.next()?)),
            name if COMMANDS.contains(&name) => break name.to_string(),
            _ => return None,
        }
    };
    let (mut harness, mut record, mut limit) = (None::<String>, false, 20i64);
    while let Some(item) = items.next() {
        let choices: &[&str] = match command.as_str() {
            "shell" => &["claude", "factory", "omp", "pi"],
            _ => &["ultron"],
        };
        match (command.as_str(), item.as_str()) {
            ("shell" | "shell-writes", "--harness") => {
                let Some(value) = items.next() else {
                    return Some(arg_error(&command, "argument --harness: expected one argument"));
                };
                if !choices.contains(&value.as_str()) {
                    let listed = choices.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
                    let message = format!("argument --harness: invalid choice: '{value}' (choose from {listed})");
                    return Some(arg_error(&command, &message));
                }
                harness = Some(value);
            }
            ("shell", "--record") => record = true,
            ("explain", "--limit") => {
                let Some(value) = items.next() else {
                    return Some(arg_error(&command, "argument --limit: expected one argument"));
                };
                match py::strip(&value).parse::<i64>() {
                    Ok(n) => limit = n,
                    Err(_) => {
                        return Some(arg_error(
                            &command,
                            &format!("argument --limit: invalid int value: '{value}'"),
                        ));
                    }
                }
            }
            (_, other) => {
                loki::evidence::finding("invalid-cli", None);
                eprintln!("{TOP_USAGE}\nloki: error: unrecognized arguments: {other}");
                return Some(ExitCode::from(2));
            }
        }
    }
    let root = resolve(&root.unwrap_or_else(|| PathBuf::from(".")));
    Some(match command.as_str() {
        "explain" => match shell::explain(Path::new("."), limit) {
            Ok(lines) => {
                lines.iter().for_each(|line| println!("{line}"));
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("loki: {message}");
                ExitCode::from(1)
            }
        },
        "shell" => {
            let Some(harness) = harness else {
                return Some(arg_error(&command, "the following arguments are required: --harness"));
            };
            // `--record` is handled around the whole run (main's record wrapper).
            let _ = record;
            report(read_payload().and_then(|payload| {
                if !payload["tool_input"].is_object() {
                    return Err(CheckError::Value("invalid shell envelope".into()));
                }
                let cwd = shell::shell_cwd(&payload, &harness, &root)?;
                shell::shell_violation(&payload["tool_input"]["command"], &root, &cwd)
            }))
        }
        _ => report(read_payload().and_then(|payload| shell::shell_writes(&root, &payload, Path::new(".")))),
    })
}
