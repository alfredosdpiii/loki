//! Child processes with a bound: [`run`] spawns a command, feeds its stdin, drains its output while it runs, and
//! stops it past a timeout or on cancel. [`Watched`] is the child underneath: a thread of its own waits for the exit
//! (`waitid` with `WNOWAIT`, so the pid stays the child's until it is reaped under the lock), which lets other
//! threads wait for it with a deadline and signal it without ever reaching a reaped, reused pid.

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Once the child is reaped, how long its output may take to close: a process it left running can hold the pipes
/// open, and its output is what arrived by then.
pub const PIPE_GRACE: Duration = Duration::from_secs(2);

/// How a run is bounded and stopped.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bound {
    /// Stopped once it runs longer.
    pub timeout: Option<Duration>,
    pub stop: Stop,
    /// At most this many bytes of each output stream are kept (the last ones); `None`: all of it.
    pub keep: Option<usize>,
}

/// How a child is stopped.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stop {
    /// The child runs in a process group of its own, and the whole group is signalled.
    pub group: bool,
    /// SIGTERM first and SIGKILL after this grace; `None`: SIGKILL at once.
    pub term_grace: Option<Duration>,
}

/// Why a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// It exited by itself (`None`: its status could not be read).
    Exited(Option<ExitStatus>),
    TimedOut,
    Cancelled,
}

/// A finished [`run`]: how it ended and the output it wrote (only from the streams the command piped).
#[derive(Debug)]
pub struct Output {
    pub end: End,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Some output was dropped by [`Bound::keep`].
    pub cut: bool,
}

impl Output {
    /// The exit status of a run that exited by itself.
    pub fn status(&self) -> Option<ExitStatus> {
        match self.end {
            End::Exited(status) => status,
            End::TimedOut | End::Cancelled => None,
        }
    }

    /// It exited by itself with 0.
    pub fn success(&self) -> bool {
        self.status().is_some_and(|s| s.success())
    }

    pub fn code(&self) -> Option<i32> {
        self.status().and_then(|s| s.code())
    }
}

/// Runs `command` to its end ([`start`], then [`Running::finish`]).
pub fn run(command: &mut Command, input: Option<&[u8]>, bound: Bound) -> std::io::Result<Output> {
    Ok(start(command, input, bound)?.finish())
}

/// Spawns `command` with stdin piped and fed `input` (closed after it; `None`: stdin is null), in a process group of
/// its own when `bound.stop.group`. stdout and stderr are as the command set them; the piped ones are drained from
/// now on.
pub fn start(command: &mut Command, input: Option<&[u8]>, bound: Bound) -> std::io::Result<Running> {
    command.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    if bound.stop.group {
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        let input = input.to_vec();
        // A child may exit, or stop reading, before it took all of it.
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let (sender, done) = mpsc::channel();
    let streams: [Option<Box<dyn Read + Send>>; 2] = [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    let kept: [Arc<Mutex<Kept>>; 2] = Default::default();
    let mut readers = 0;
    for (stream, kept) in streams.into_iter().zip(&kept) {
        let Some(stream) = stream else { continue };
        let (sender, kept) = (sender.clone(), kept.clone());
        readers += 1;
        std::thread::spawn(move || {
            read_kept(stream, &kept, bound.keep);
            let _ = sender.send(());
        });
    }
    Ok(Running {
        watched: Watched::new(child),
        bound,
        kept,
        done,
        readers,
    })
}

/// The output of one stream so far.
#[derive(Default)]
struct Kept {
    bytes: Vec<u8>,
    cut: bool,
}

impl Kept {
    fn take(kept: &Mutex<Kept>, keep: Option<usize>) -> Kept {
        let mut kept = std::mem::take(&mut *kept.lock().unwrap_or_else(PoisonError::into_inner));
        if let Some(keep) = keep
            && kept.bytes.len() > keep
        {
            kept.bytes.drain(..kept.bytes.len() - keep);
            kept.cut = true;
        }
        kept
    }
}

/// A child [`start`] spawned.
pub struct Running {
    watched: Watched,
    bound: Bound,
    kept: [Arc<Mutex<Kept>>; 2],
    done: mpsc::Receiver<()>,
    readers: usize,
}

impl Running {
    /// Its [`Watched`], to cancel it from elsewhere ([`Watched::cancel`]).
    pub fn watched(&self) -> &Watched {
        &self.watched
    }

    /// Waits for the end: it exits, the timeout passes or it is cancelled (it is stopped then), and returns its
    /// output.
    pub fn finish(self) -> Output {
        let deadline = self.bound.timeout.map(|timeout| Instant::now() + timeout);
        let end = match self.watched.wait_until(deadline) {
            Waited::Ended(status) => End::Exited(status),
            Waited::Cancelled => End::Cancelled,
            Waited::Running => End::TimedOut,
        };
        if !matches!(end, End::Exited(_)) {
            self.watched.stop(self.bound.stop);
            self.watched.wait();
        }
        let grace = Instant::now() + PIPE_GRACE;
        for _ in 0..self.readers {
            if self
                .done
                .recv_timeout(grace.saturating_duration_since(Instant::now()))
                .is_err()
            {
                break;
            }
        }
        let [stdout, stderr] = self.kept.each_ref().map(|kept| Kept::take(kept, self.bound.keep));
        Output {
            end,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            cut: stdout.cut || stderr.cut,
        }
    }
}

/// Reads all of `stream` into `kept`, holding at most about twice `keep` bytes.
fn read_kept(mut stream: impl Read, kept: &Mutex<Kept>, keep: Option<usize>) {
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
                kept.bytes.extend_from_slice(&chunk[..n]);
                if let Some(keep) = keep
                    && kept.bytes.len() > keep.saturating_mul(2).max(chunk.len())
                {
                    let excess = kept.bytes.len() - keep;
                    kept.bytes.drain(..excess);
                    kept.cut = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

#[derive(Default)]
struct State {
    /// Reaped, with its status (`None`: the wait failed).
    reaped: Option<Option<ExitStatus>>,
    cancelled: bool,
}

/// What [`Watched::wait_until`] saw.
enum Waited {
    Ended(Option<ExitStatus>),
    Cancelled,
    Running,
}

/// A spawned child whose exit a thread of its own waits for. Clones share the child.
#[derive(Clone)]
pub struct Watched {
    pid: Pid,
    shared: Arc<(Mutex<State>, Condvar)>,
}

impl Watched {
    /// Takes over `child` (take its pipes first): from now on its exit is waited for here.
    pub fn new(mut child: Child) -> Self {
        let pid = Pid::from_child(&child);
        let shared: Arc<(Mutex<State>, Condvar)> = Arc::default();
        let waiter = shared.clone();
        std::thread::spawn(move || {
            // Wait without reaping, so a signal sent under the lock below never reaches another process.
            while let Err(rustix::io::Errno::INTR) =
                rustix::process::waitid(WaitId::Pid(pid), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT)
            {}
            let mut state = waiter.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.reaped = Some(child.wait().ok());
            drop(state);
            waiter.1.notify_all();
        });
        Self { pid, shared }
    }

    pub fn id(&self) -> u32 {
        self.pid.as_raw_nonzero().get().unsigned_abs()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Its exit status once it ended (`None` while it runs, or when its status could not be read).
    pub fn status(&self) -> Option<ExitStatus> {
        self.state().reaped.flatten()
    }

    pub fn ended(&self) -> bool {
        self.state().reaped.is_some()
    }

    /// Blocks until it ended; its exit status.
    pub fn wait(&self) -> Option<ExitStatus> {
        let state = self.state();
        let state = self
            .shared
            .1
            .wait_while(state, |state| state.reaped.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        state.reaped.flatten()
    }

    /// Blocks until it ended or `timeout` passed; whether it ended.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let state = self.state();
        let (state, _) = self
            .shared
            .1
            .wait_timeout_while(state, timeout, |state| state.reaped.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        state.reaped.is_some()
    }

    /// Wakes a [`Running::finish`] waiting on it, which stops it.
    pub fn cancel(&self) {
        self.state().cancelled = true;
        self.shared.1.notify_all();
    }

    fn wait_until(&self, deadline: Option<Instant>) -> Waited {
        let mut state = self.state();
        loop {
            if let Some(status) = state.reaped {
                return Waited::Ended(status);
            }
            if state.cancelled {
                return Waited::Cancelled;
            }
            state = match deadline {
                None => self.shared.1.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Waited::Running;
                    }
                    self.shared
                        .1
                        .wait_timeout(state, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }

    /// Sends `signal` to it (its group with `group`) unless it was reaped.
    fn signal(&self, signal: Signal, group: bool) {
        let state = self.state();
        if state.reaped.is_none() {
            let _ = if group {
                rustix::process::kill_process_group(self.pid, signal)
            } else {
                rustix::process::kill_process(self.pid, signal)
            };
        }
    }

    /// Stops it as `stop` says; returns once SIGKILL was sent or it ended within the grace.
    pub fn stop(&self, stop: Stop) {
        if let Some(grace) = stop.term_grace {
            self.signal(Signal::TERM, stop.group);
            if self.wait_timeout(grace) {
                return;
            }
        }
        self.signal(Signal::KILL, stop.group);
    }
}
