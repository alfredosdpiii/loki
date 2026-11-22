//! `subprocess.run` with loki.py's deadline (`command_timeout`) and error texts.

use crate::{CheckError, py};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const COMMAND_TIMEOUT: f64 = 120.0;

/// A hook's overall deadline: `time.monotonic() + 20`, or none.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(pub Option<Instant>);

impl Deadline {
    pub fn none() -> Deadline {
        Deadline(None)
    }

    pub fn after(seconds: f64) -> Deadline {
        Deadline(Some(Instant::now() + Duration::from_secs_f64(seconds)))
    }

    /// `command_timeout`: seconds left, at most 120.
    pub fn timeout(&self) -> Result<f64, CheckError> {
        let remaining = match self.0 {
            None => COMMAND_TIMEOUT,
            Some(at) => COMMAND_TIMEOUT.min(at.saturating_duration_since(Instant::now()).as_secs_f64()),
        };
        if remaining <= 0.0 {
            return Err(CheckError::Value("loki: hook deadline exceeded".into()));
        }
        Ok(remaining)
    }
}

pub struct Output {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why a command did not run to completion: `OSError` or `TimeoutExpired`.
#[derive(Debug)]
pub enum RunError {
    Os(&'static str, String),
    Timeout(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Os(_, m) | RunError::Timeout(m) => f.write_str(m),
        }
    }
}

/// `str(list)` of a command, as Python prints it in `TimeoutExpired`.
fn command_repr(command: &[String]) -> String {
    format!(
        "[{}]",
        command.iter().map(|c| py::repr_str(c)).collect::<Vec<_>>().join(", ")
    )
}

/// Run `command` in `cwd`, feeding `input`, killed after `timeout` seconds.
pub fn run(
    command: &[String],
    cwd: &Path,
    input: Option<&[u8]>,
    env: &[(&str, &str)],
    timeout: f64,
) -> Result<Output, RunError> {
    let mut builder = Command::new(&command[0]);
    builder
        .args(&command[1..])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        builder.env(key, value);
    }
    let bound = crate::child::Bound {
        timeout: Some(Duration::from_secs_f64(timeout.max(0.0))),
        ..Default::default()
    };
    let running = crate::child::start(&mut builder, input, bound).map_err(|e| {
        let name = if e.kind() == std::io::ErrorKind::NotFound {
            Some(command[0].as_str())
        } else {
            None
        };
        // CPython names the cwd when chdir fails and the program when exec fails.
        let name = if !cwd.is_dir() {
            Some(cwd.to_str().unwrap_or(""))
        } else {
            name
        };
        RunError::Os(crate::os_kind(&e), py::os_error(&e, name))
    })?;
    let out = running.finish();
    let status = match out.end {
        crate::child::End::Exited(Some(status)) => status,
        crate::child::End::Exited(None) => {
            return Err(RunError::Os(
                "OSError",
                "the command's exit status could not be read".into(),
            ));
        }
        crate::child::End::TimedOut | crate::child::End::Cancelled => {
            return Err(RunError::Timeout(format!(
                "Command '{}' timed out after {} seconds",
                command_repr(command),
                py::float_repr(timeout)
            )));
        }
    };
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        -status.signal().unwrap_or(0)
    });
    Ok(Output {
        code,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// Text-mode output: `errors="replace"` decoding and universal newlines.
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n").replace('\r', "\n")
}

/// `shutil.which(name)`.
pub fn which(name: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let executable =
        |path: &Path| std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    if name.contains('/') {
        return executable(Path::new(name)).then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .map(|dir| {
            if dir.is_empty() {
                Path::new(".").join(name)
            } else {
                Path::new(dir).join(name)
            }
        })
        .find(|candidate| executable(candidate))
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

/// `Path.read_text(encoding="utf-8")`: strict UTF-8 with universal newlines.
pub fn read_text(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| py::os_error(&e, path.to_str()))?;
    let text = decode(&bytes)?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `bytes.decode("utf-8")` with CPython's error text.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_string()),
        Err(error) => {
            let position = error.valid_up_to();
            let byte = bytes[position];
            Err(match error.error_len() {
                None if bytes.len() - position > 1 => format!(
                    "'utf-8' codec can't decode bytes in position {position}-{}: unexpected end of data",
                    bytes.len() - 1
                ),
                None => format!(
                    "'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: unexpected end of data"
                ),
                Some(_) if (0x80..0xc2).contains(&byte) || byte > 0xf4 => {
                    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: invalid start byte")
                }
                Some(_) => format!(
                    "'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: invalid continuation byte"
                ),
            })
        }
    }
}
