//! Loki's one-time setup for a session (loki.ts `setupLoki`, `autoInitEligibility`, `autoCommitSkipReason`,
//! `commitLoki`): a Git repository without `.loki/` gets the minimal install where that is allowed, and `.loki/` is
//! committed on its own where that is allowed. What happened becomes the session's one transcript note.
//!
//! Git runs from the session's `PATH` with only the session's named variables (the lookup is not enumerable), and
//! a command past its time limit is stopped: SIGTERM, then SIGKILL, to the child alone (TypeScript signals its
//! process group; nothing here signals a group).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const LOKI_AUTOCOMMIT_ENV: &str = "ULTRON_LOKI_AUTOCOMMIT";
pub const LOKI_AUTOINIT_ENV: &str = "ULTRON_LOKI_AUTOINIT";

const OFF_VALUES: [&str; 5] = ["off", "0", "false", "no", "none"];
const COMMIT_MESSAGE: &str = "Add Loki guardrails";
const GIT_TIMEOUT_MS: u64 = 10_000;
const COMMIT_TIMEOUT_MS: u64 = 30_000;

/// The variables git sees: what it, its hooks and a signer need, read from the session's environment.
const GIT_VARIABLES: [&str; 22] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "GNUPGHOME",
    "SSH_AUTH_SOCK",
    "CI",
    crate::compat::WORKTREE_ENV,
];

/// The session a setup is for: its directory, home, environment lookup and the global `loki` settings.
pub struct SetupContext<'a> {
    pub cwd: &'a Path,
    pub home: &'a Path,
    pub var: &'a dyn Fn(&str) -> Option<String>,
    /// The global `loki` settings (`autoInit`, `autoCommit`, `ignoreRepos`); anything else reads as unset.
    pub settings: &'a Value,
}

impl SetupContext<'_> {
    fn trimmed(&self, key: &str) -> Option<String> {
        (self.var)(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }

    fn git_env(&self, extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = GIT_VARIABLES
            .iter()
            .filter_map(|key| (self.var)(key).map(|value| (key.to_string(), value)))
            .collect();
        env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        env
    }

    fn git(&self, root: &Path, args: &[&str], timeout_ms: u64, extra: &[(&str, &str)]) -> Run {
        let mut env = self.git_env(extra);
        env.push(("GIT_OPTIONAL_LOCKS".into(), "0".into()));
        run("git", args, root, &env, timeout_ms)
    }
}

/// What the setup did: nothing to say, a note now, or a note once `.loki/` is committed ([`commit_notice`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setup {
    Quiet,
    Notice(String),
    Commit(PathBuf),
}

/// `runProcess`'s result: the exit status (none when it did not finish), output, and why it did not run or finish.
struct Run {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    error: Option<String>,
}

fn run(program: &str, args: &[&str], cwd: &Path, env: &[(String, String)], timeout_ms: u64) -> Run {
    let failed = |error: String| Run {
        status: None,
        stdout: String::new(),
        stderr: String::new(),
        error: Some(error),
    };
    // SIGTERM first (git removes its index.lock on SIGTERM, never on SIGKILL), SIGKILL 2 s later; only this child
    // is signalled.
    let bound = crate::child::Bound {
        timeout: Some(Duration::from_millis(timeout_ms)),
        stop: crate::child::Stop {
            group: false,
            term_grace: Some(Duration::from_secs(2)),
        },
        keep: None,
    };
    let spawned = crate::child::run(
        Command::new(program)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
        bound,
    );
    let out = match spawned {
        Ok(out) => out,
        // Node's spawn error for a program that is not there.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return failed(format!("spawn {program} ENOENT"));
        }
        Err(error) => return failed(error.to_string()),
    };
    let error = match out.end {
        crate::child::End::Exited(Some(_)) => None,
        crate::child::End::Exited(None) => Some("the exit status could not be read".to_string()),
        crate::child::End::TimedOut | crate::child::End::Cancelled => Some(format!(
            "timed out after {} s",
            (timeout_ms as f64 / 100.0).round() / 10.0
        )),
    };
    Run {
        status: out.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        error,
    }
}

/// `firstLine`: the first non-empty trimmed line.
fn first_line(text: &str) -> String {
    text.split('\n')
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn is_off(value: &str) -> bool {
    OFF_VALUES.contains(&value.trim().to_lowercase().as_str())
}

/// `lokiAutoInit`: ULTRON_LOKI_AUTOINIT, else the `loki.autoInit` setting, else on.
fn auto_init(context: &SetupContext<'_>) -> bool {
    match context.trimmed(LOKI_AUTOINIT_ENV) {
        Some(raw) => !is_off(&raw),
        None => context.settings.get("autoInit") != Some(&Value::Bool(false)),
    }
}

/// `lokiAutoCommit`: ULTRON_LOKI_AUTOCOMMIT, else the `loki.autoCommit` setting, else on.
fn auto_commit(context: &SetupContext<'_>) -> bool {
    match context.trimmed(LOKI_AUTOCOMMIT_ENV) {
        Some(raw) => !is_off(&raw),
        None => context.settings.get("autoCommit") != Some(&Value::Bool(false)),
    }
}

/// `gitRoot`: the Git work tree containing `cwd`, or none outside one.
pub fn git_root(context: &SetupContext<'_>, cwd: &Path) -> Option<PathBuf> {
    let result = context.git(cwd, &["rev-parse", "--show-toplevel"], GIT_TIMEOUT_MS, &[]);
    let root = result.stdout.trim();
    (result.status == Some(0) && !root.is_empty()).then(|| crate::abspath(cwd, Path::new(root)))
}

fn is_ultron_worktree(context: &SetupContext<'_>, path: &Path) -> bool {
    context.trimmed(crate::compat::WORKTREE_ENV).is_some()
        || path
            .components()
            .any(|part| part.as_os_str() == crate::compat::WORKTREES_DIR)
}

fn expand_home(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn writable(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok()
}

/// `autoInitEligibility`: the repository root `.loki/` may be created in, if any.
fn auto_init_eligibility(context: &SetupContext<'_>) -> Option<PathBuf> {
    if !auto_init(context) || context.trimmed("CI").is_some() {
        return None;
    }
    let root = git_root(context, context.cwd)?;
    if is_ultron_worktree(context, &root) {
        return None;
    }
    let home = crate::abspath(context.cwd, context.home);
    if root == home || root.parent().is_none() {
        return None;
    }
    if root.components().any(|part| part.as_os_str() == "node_modules") {
        return None;
    }
    let ignored = context
        .settings
        .get("ignoreRepos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|path| crate::abspath(context.cwd, expand_home(path, &home)) == root);
    if ignored || !writable(&root) {
        return None;
    }
    Some(root)
}

/// Git operations whose state files mean a commit now would be part of them.
const IN_PROGRESS: [(&str, &str); 6] = [
    ("MERGE_HEAD", "a merge is in progress"),
    ("rebase-merge", "a rebase is in progress"),
    ("rebase-apply", "a rebase or am is in progress"),
    ("CHERRY_PICK_HEAD", "a cherry-pick is in progress"),
    ("REVERT_HEAD", "a revert is in progress"),
    ("BISECT_LOG", "a bisect is in progress"),
];

/// `autoCommitSkipReason`: why `.loki/` must not be committed now, or none when it may be. Runs only after
/// [`auto_init_eligibility`], which already refused CI and sub-agent worktrees.
fn auto_commit_skip_reason(context: &SetupContext<'_>, root: &Path) -> Option<String> {
    if !auto_commit(context) {
        return Some(if context.trimmed(LOKI_AUTOCOMMIT_ENV).is_some() {
            "auto-commit is off (ULTRON_LOKI_AUTOCOMMIT)".into()
        } else {
            "auto-commit is off (loki.autoCommit setting)".into()
        });
    }
    for (name, reason) in IN_PROGRESS {
        let path = context.git(root, &["rev-parse", "--git-path", name], GIT_TIMEOUT_MS, &[]);
        if path.status != Some(0) {
            return Some("Git state could not be read".into());
        }
        if crate::abspath(root, Path::new(path.stdout.trim())).exists() {
            return Some(reason.into());
        }
    }
    if context
        .git(root, &["symbolic-ref", "-q", "HEAD"], GIT_TIMEOUT_MS, &[])
        .status
        != Some(0)
    {
        return Some("HEAD is detached".into());
    }
    if context
        .git(
            root,
            &["check-ignore", "-q", "--", ".loki/loki.py"],
            GIT_TIMEOUT_MS,
            &[],
        )
        .status
        == Some(0)
    {
        return Some(".loki is gitignored".into());
    }
    None
}

/// `commitLoki`: commit `.loki/` and nothing else (`git add .loki`, then a pathspec-limited commit), hooks and
/// signing as configured, nothing able to prompt; on failure `.loki/` is unstaged again (back to HEAD). The short
/// sha, or why not.
pub fn commit_loki(context: &SetupContext<'_>, root: &Path, timeout_ms: Option<u64>) -> Result<String, String> {
    let quiet = [
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_EDITOR", "true"),
        ("GIT_SEQUENCE_EDITOR", "true"),
        ("GIT_ASKPASS", "true"),
    ];
    let timeout_ms = timeout_ms.unwrap_or(COMMIT_TIMEOUT_MS);
    let added = context.git(root, &["add", "--", ".loki"], timeout_ms, &quiet);
    if added.status != Some(0) {
        let detail = Some(first_line(&added.stderr))
            .filter(|l| !l.is_empty())
            .or(added.error)
            .unwrap_or_else(|| "unknown".into());
        return Err(format!("git add failed: {detail}"));
    }
    let committed = run(
        "git",
        &["commit", "-q", "-m", COMMIT_MESSAGE, "--", ".loki"],
        root,
        &context.git_env(&quiet),
        timeout_ms,
    );
    if committed.status != Some(0) {
        // Back to what HEAD has: another session may have committed `.loki/` meanwhile (its commit is why this one
        // had nothing to commit), and removing that from the index would stage its deletion. Without a HEAD (no
        // commit yet) nothing is tracked, so it is only removed from the index.
        let reset = context.git(root, &["reset", "-q", "--", ".loki"], GIT_TIMEOUT_MS, &quiet);
        if reset.status != Some(0) {
            context.git(
                root,
                &["rm", "--cached", "-r", "-q", "--ignore-unmatch", "--", ".loki"],
                GIT_TIMEOUT_MS,
                &quiet,
            );
        }
        let detail = match committed.error {
            Some(error) if error.starts_with("timed out") => format!("{error} (a hook or a signing prompt?)"),
            Some(error) => error,
            None => [first_line(&committed.stderr), first_line(&committed.stdout)]
                .into_iter()
                .find(|l| !l.is_empty())
                .unwrap_or_else(|| format!("exit status {}", committed.status.unwrap_or_default())),
        };
        return Err(format!("git commit failed: {detail}"));
    }
    let head = context.git(root, &["rev-parse", "--short", "HEAD"], GIT_TIMEOUT_MS, &[]);
    Ok(head.stdout.trim().to_string())
}

/// The setup part of `setupLoki` (Loki not off): a repository without `.loki/loki.py` gets the minimal install
/// where [`auto_init_eligibility`] allows it; then the note says it could not, that it is not committed and why,
/// or that the commit follows ([`Setup::Commit`]).
pub fn setup(context: &SetupContext<'_>) -> Setup {
    let root = git_root(context, context.cwd).unwrap_or_else(|| crate::abspath(Path::new("/"), context.cwd));
    if root.join(".loki").join("loki.py").is_file() {
        return Setup::Quiet;
    }
    let Some(eligible) = auto_init_eligibility(context) else {
        return Setup::Quiet;
    };
    if let Err(error) = crate::scan::install_minimal_files(&eligible.display().to_string(), false) {
        let reason = first_line(&crate::scan::init_error_line(&error));
        return Setup::Notice(format!(
            "Loki could not create .loki/: {reason}. It runs with its default policy."
        ));
    }
    match auto_commit_skip_reason(context, &eligible) {
        Some(skip) => Setup::Notice(format!(
            "Loki set up in .loki/ (not committed: {skip}). Commit it to enable post-write checks: git add .loki && git commit -m \"Add Loki guardrails\" -- .loki"
        )),
        None => Setup::Commit(eligible),
    }
}

/// The note once `.loki/` in `root` was committed, or why it was not.
pub fn commit_notice(context: &SetupContext<'_>, root: &Path) -> String {
    match commit_loki(context, root, None) {
        Ok(sha) => format!("Loki set up and committed ({sha}): .loki/ holds the guardrail engine and policy."),
        Err(reason) => format!(
            "Loki set up in .loki/ but not committed ({reason}). Before-write checks run with the default policy; commit .loki/ to enable post-write checks."
        ),
    }
}
