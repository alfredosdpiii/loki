//! The interpreter a session's project runs on (`loki.ts` `findProjectPython`), which Loki asks whether a newly
//! imported module exists (`LOKI_PYTHON` for the engine). Not the interpreter that parses Python for Loki
//! (`ULTRON_LOKI_PYTHON`), whose packages are not the project's.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const LOKI_PROJECT_PYTHON_ENV: &str = "ULTRON_LOKI_PROJECT_PYTHON";

/// Prints the interpreter's path, then 1 when it belongs to a virtual or conda environment (any Python 2.7+).
pub const ENVIRONMENT_PROBE: &str = "import os, sys\nprint(sys.executable)\nbase = getattr(sys, 'base_prefix', sys.prefix)\nconda = os.path.isdir(os.path.join(sys.prefix, 'conda-meta'))\nprint(int(base != sys.prefix or hasattr(sys, 'real_prefix') or conda))";

/// The session variables the probe runs with (TypeScript passes the whole session environment): what `python`
/// needs to resolve the same interpreter `bash()` would, through a venv, conda, pyenv or uv.
pub const PROBE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "PYENV_ROOT",
    "PYENV_VERSION",
    "PYTHONHOME",
    "PYTHONPATH",
    "UV_PROJECT_ENVIRONMENT",
    "LANG",
    "LC_ALL",
];

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// `findProjectPython(cwd, env)` over the session environment `var`:
/// - `ULTRON_LOKI_PROJECT_PYTHON`;
/// - nothing when `LOKI_PYTHON` is set (left to the engine);
/// - the `python` (else `python3`) on the session's `PATH`, run in `cwd`, when it belongs to a virtual or conda
///   environment (the first one found decides; a bare system interpreter says nothing about the project);
/// - `.venv` or `venv` in `cwd`.
pub fn find_project_python(cwd: &Path, var: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let set = |key: &str| var(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(named) = set(LOKI_PROJECT_PYTHON_ENV) {
        return Some(named);
    }
    if set("LOKI_PYTHON").is_some() {
        return None;
    }
    let env: Vec<(String, String)> = PROBE_ENV
        .iter()
        .filter_map(|name| Some((name.to_string(), var(name)?)))
        .collect();
    probe_environment(cwd, &env).or_else(|| venv_python(cwd))
}

/// The `python`/`python3` of the session's `PATH` when it is a virtual or conda environment's.
fn probe_environment(cwd: &Path, env: &[(String, String)]) -> Option<String> {
    let path = env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.as_str())?;
    for command in ["python", "python3"] {
        let Some(executable) = crate::compat::which_in(command, path) else {
            continue;
        };
        let Some(stdout) = run_probe(&executable, cwd, env) else {
            continue;
        };
        let mut lines = stdout.trim().lines();
        let (found, environment) = (lines.next().unwrap_or_default(), lines.next().unwrap_or_default());
        let found = found.trim_end_matches('\r');
        // The first one found is what `python` means here, whichever kind it is.
        if !found.is_empty() && Path::new(found).is_absolute() && environment.trim_end_matches('\r') == "1" {
            return Some(found.to_string());
        }
        return None;
    }
    None
}

fn venv_python(cwd: &Path) -> Option<String> {
    [".venv", "venv"].iter().find_map(|directory| {
        ["bin/python", "bin/python3", "Scripts/python.exe"]
            .iter()
            .map(|relative| cwd.join(directory).join(relative))
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.display().to_string())
    })
}

/// The probe's stdout when it exits 0 within the timeout; the child is killed otherwise.
fn run_probe(executable: &Path, cwd: &Path, env: &[(String, String)]) -> Option<String> {
    let bound = crate::child::Bound {
        timeout: Some(PROBE_TIMEOUT),
        ..Default::default()
    };
    let out = crate::child::run(
        Command::new(executable)
            .args(["-c", ENVIRONMENT_PROBE])
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
        None,
        bound,
    )
    .ok()?;
    out.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
