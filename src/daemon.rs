//! `loki daemon serve|start|stop|status` and the client that forwards `protect`, `hook` and `shell` to it
//! (loki.py `daemon_*`): one daemon per repository on a private Unix socket (`~/.cache/loki/d/<id>`, mode 0600 in
//! a 0700 directory, peers of other users ignored). The daemon only changes where the engine runs, never what it
//! decides: a request names the engine's digest and a daemon of another engine answers `stale` and exits; any
//! failure before a reply runs the command locally. It exits after 30 idle minutes, when its repository is gone,
//! or when its engine changed.
//!
//! The Rust engine has no analyzers to keep warm (loki.py's TypeScript worker and dmypy), so the daemon runs each
//! request as a fresh engine process with the request's argv, environment, directory and stdin. Unlike loki.py, a
//! hook never starts a daemon unasked: only `LOKI_DAEMON=1` (or `daemon start`) does.

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const COMMANDS: [&str; 3] = ["protect", "hook", "shell"];
const IDLE: Duration = Duration::from_secs(30 * 60);
const REQUEST: Duration = Duration::from_secs(60);
const RECHECK: Duration = Duration::from_secs(30);

/// Waits up to `timeout` for a connection to accept on `listener`.
fn readable(listener: &UnixListener, timeout: Duration) -> std::io::Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let timeout = Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    match poll(&mut [PollFd::new(listener, PollFlags::IN)], Some(&timeout)) {
        Ok(n) => Ok(n > 0),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

/// `daemon_paths`: the socket and lock of `root`'s daemon, none when the socket path would not fit a
/// `sockaddr_un` (107 bytes).
pub fn daemon_paths(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let identity = crate::compat::sha256_hex(crate::resolve(root).as_os_str().as_encoded_bytes())[..16].to_string();
    let directory = home().join(".cache/loki/d");
    let socket = directory.join(&identity);
    if socket.as_os_str().len() > 107 {
        return None;
    }
    Some((socket, directory.join(format!("{identity}.lock"))))
}

/// The engine a daemon serves: this executable's digest (a rebuilt engine makes a running daemon stale).
pub fn engine_digest() -> String {
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(crate::compat::sha256_hex)
        .unwrap_or_default()
}

/// `daemon_autostart`: start one detached daemon for `root` (a lock younger than 120 s means one is starting);
/// never blocks the caller.
pub fn autostart(root: &Path, paths: &(PathBuf, PathBuf)) {
    let (_, lock) = paths;
    let Some(parent) = lock.parent() else { return };
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .is_err()
    {
        return;
    }
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(lock);
    if created.is_err() {
        let fresh = std::fs::metadata(lock)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < Duration::from_secs(120));
        if fresh {
            return;
        }
        let _ = std::fs::remove_file(lock);
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock)
            .is_err()
        {
            return;
        }
    }
    let Ok(engine) = std::env::current_exe() else { return };
    use std::os::unix::process::CommandExt;
    let _ = Command::new(engine)
        .args(["--root".as_ref(), root.as_os_str(), "daemon".as_ref(), "serve".as_ref()])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
}

/// The repository a command line names (`--root`, else the working directory).
pub fn root_of(argv: &[String]) -> PathBuf {
    match argv.iter().position(|a| a == "--root") {
        Some(index) if index + 1 < argv.len() => crate::resolve(Path::new(&argv[index + 1])),
        _ => crate::resolve(Path::new(".")),
    }
}

pub struct Reply {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
}

pub enum Forwarded {
    /// The daemon ran it.
    Ran(Reply),
    /// Run it locally (`LOKI_DAEMON=0`, not a daemon command, no daemon).
    Local,
    /// Run it locally on this stdin, which forwarding already read (the daemon failed before a reply).
    LocalWith(String),
}

/// `daemon_client`: forward `argv` to the repository's daemon. `stdin` is read only for commands that take it.
pub fn client(argv: &[String], stdin: &mut dyn Read) -> Forwarded {
    match forward(argv, stdin) {
        Ok(reply) => Forwarded::Ran(reply),
        Err(Some(raw)) => Forwarded::LocalWith(raw),
        Err(None) => Forwarded::Local,
    }
}

fn forward(argv: &[String], stdin: &mut dyn Read) -> Result<Reply, Option<String>> {
    let setting = std::env::var("LOKI_DAEMON").unwrap_or_default();
    if setting == "0" || !argv.iter().any(|a| COMMANDS.contains(&a.as_str())) {
        return Err(None);
    }
    let root = root_of(argv);
    let paths = daemon_paths(&root).ok_or(None)?;
    if !paths.0.exists() {
        if setting == "1" {
            autostart(&root, &paths);
        }
        return Err(None);
    }
    let mut raw = String::new();
    if argv.iter().any(|a| a == "--harness" || a == "--preview") && stdin.read_to_string(&mut raw).is_err() {
        return Err(None);
    }
    let consumed = || Some(raw.clone());
    let env: serde_json::Map<String, Value> = std::env::vars().map(|(k, v)| (k, Value::String(v))).collect();
    let request = json!({
        "engine": engine_digest(),
        "argv": argv,
        "stdin": raw,
        "cwd": std::env::current_dir().map_err(|_| consumed())?.to_string_lossy(),
        "env": env,
    });
    let reply = (|| -> std::io::Result<Value> {
        let mut connection = UnixStream::connect(&paths.0)?;
        connection.set_read_timeout(Some(REQUEST))?;
        connection.set_write_timeout(Some(REQUEST))?;
        connection.write_all(format!("{request}\n").as_bytes())?;
        connection.shutdown(std::net::Shutdown::Write)?;
        let mut text = String::new();
        connection.read_to_string(&mut text)?;
        serde_json::from_str(&text).map_err(std::io::Error::other)
    })()
    .map_err(|_| consumed())?;
    if reply
        .get("stale")
        .is_some_and(|s| s != &Value::Bool(false) && !s.is_null())
    {
        return Err(consumed());
    }
    let exit = reply.get("exit").and_then(Value::as_i64).ok_or_else(consumed)? as i32;
    let text = |key: &str| reply[key].as_str().unwrap_or_default().to_string();
    Ok(Reply {
        exit,
        stdout: text("stdout"),
        stderr: text("stderr"),
    })
}

/// `daemon_command`: `serve` in the foreground; `start`, `stop` and `status` report on it. The status line and
/// the exit status.
pub fn command(action: &str, root: &Path) -> (i32, String, String) {
    if action == "serve" {
        return serve(root);
    }
    let Some(paths) = daemon_paths(root) else {
        return (
            1,
            String::new(),
            "loki: daemon unavailable: socket path too long\n".into(),
        );
    };
    let mut running = false;
    if paths.0.exists()
        && let Ok(mut probe) = UnixStream::connect(&paths.0)
    {
        let _ = probe.set_write_timeout(Some(Duration::from_secs(2)));
        running = action != "stop" || probe.write_all(br#"{"engine": "stop"}"#).is_ok();
    }
    if action == "start" && !running {
        autostart(root, &paths);
    }
    let state = if running { "running" } else { "not running" };
    (
        0,
        format!("loki daemon: {state} ({})\n", paths.0.display()),
        String::new(),
    )
}

/// `daemon_serve`: answer forwarded runs until idle for 30 minutes, the repository is gone, the engine changed,
/// or a request names another engine (`stop` does).
fn serve(root: &Path) -> (i32, String, String) {
    let Some((socket, lock)) = daemon_paths(root) else {
        return (1, String::new(), "loki: daemon socket path too long\n".into());
    };
    let Some(directory) = socket.parent() else {
        return (1, String::new(), "loki: daemon socket path too long\n".into());
    };
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .is_err()
        || std::fs::metadata(directory).map(|m| m.uid()).ok() != Some(rustix::process::getuid().as_raw())
    {
        return (
            1,
            String::new(),
            "loki: daemon directory is not owned by this user\n".into(),
        );
    }
    let engine = engine_digest();
    let started = Instant::now();
    eprintln!(
        "loki daemon: warmed in {:.1}s; TypeScript workers 0, dmypy off",
        started.elapsed().as_secs_f64()
    );
    let _ = std::fs::remove_file(&socket);
    let served = (|| -> std::io::Result<()> {
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let mut idle_since = Instant::now();
        // loki.py looks again after each connection and each 30-second accept timeout.
        let mut checked = Instant::now();
        loop {
            if checked.elapsed() >= RECHECK {
                checked = Instant::now();
                if !root.is_dir() || engine_digest() != engine {
                    break;
                }
            }
            let wait = RECHECK
                .saturating_sub(checked.elapsed())
                .min(IDLE.saturating_sub(idle_since.elapsed()));
            if !readable(&listener, wait)? {
                if idle_since.elapsed() >= IDLE {
                    break;
                }
                continue;
            }
            let connection = match listener.accept() {
                Ok((connection, _)) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            idle_since = Instant::now();
            checked = Instant::now().checked_sub(RECHECK).unwrap_or(checked);
            if !answer(connection, &engine) {
                break;
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&lock);
    match served {
        Ok(()) => (0, String::new(), String::new()),
        Err(error) => (
            1,
            String::new(),
            format!("loki: {}\n", crate::py::os_error(&error, None)),
        ),
    }
}

/// Serve one connection; false when the daemon must stop (a request for another engine).
fn answer(mut connection: UnixStream, engine: &str) -> bool {
    let _ = connection.set_nonblocking(false);
    let _ = connection.set_read_timeout(Some(REQUEST));
    let _ = connection.set_write_timeout(Some(REQUEST));
    // Peers of another user are ignored. Only linux can ask (SO_PEERCRED); elsewhere the socket is 0600 in
    // a 0700 directory, so whoever connects far enough to write to it is the user.
    #[cfg(target_os = "linux")]
    let same_user = rustix::net::sockopt::socket_peercred(&connection)
        .map(|credentials| credentials.uid == rustix::process::getuid())
        .unwrap_or(true);
    #[cfg(not(target_os = "linux"))]
    let same_user = true;
    if !same_user {
        return true;
    }
    let mut text = String::new();
    if connection.read_to_string(&mut text).is_err() {
        return true;
    }
    let Ok(request) = serde_json::from_str::<Value>(&text) else {
        return true;
    };
    if request["engine"].as_str() != Some(engine) {
        let _ = connection.write_all(br#"{"stale": true}"#);
        return false;
    }
    let reply = run(&request);
    let _ = connection.write_all(reply.to_string().as_bytes());
    true
}

/// `daemon_request`: the forwarded command, run as a fresh engine with the request's argv, environment,
/// directory and stdin (stopped after 60 seconds).
fn run(request: &Value) -> Value {
    let failed = |message: String| json!({ "exit": 2, "stdout": "", "stderr": message });
    let Ok(engine) = std::env::current_exe() else {
        return failed("loki: daemon error: no engine\n".into());
    };
    let argv: Vec<String> = request["argv"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str().map(String::from))
        .collect();
    let mut command = Command::new(engine);
    command
        .args(&argv)
        .current_dir(request["cwd"].as_str().unwrap_or("/"))
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in request["env"].as_object().into_iter().flatten() {
        if let Some(value) = value.as_str() {
            command.env(key, value);
        }
    }
    // The run is the daemon's: it never forwards again.
    command.env("LOKI_DAEMON", "0");
    let bound = crate::child::Bound {
        timeout: Some(REQUEST),
        ..Default::default()
    };
    let input = request["stdin"].as_str().unwrap_or_default().as_bytes();
    let out = match crate::child::run(&mut command, Some(input), bound) {
        Ok(out) => out,
        Err(error) => {
            return failed(format!(
                "loki: daemon error: OSError: {}\n",
                crate::py::os_error(&error, None)
            ));
        }
    };
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    match out.end {
        crate::child::End::Exited(status) => json!({
            "exit": status.and_then(|s| s.code()).unwrap_or(2),
            "stdout": text(&out.stdout),
            "stderr": text(&out.stderr),
        }),
        crate::child::End::TimedOut | crate::child::End::Cancelled => {
            failed("loki: daemon error: TimeoutExpired: the run took over 60 seconds\n".into())
        }
    }
}
