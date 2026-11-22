//! `scan --online` (loki.py `registry_url`, `dependency_violation`, `slopsquatting_violations`): every declared
//! dependency that is not a private package is looked up in its public registry (npm, PyPI, crates.io, the Go
//! module proxy, Hex), eight at a time; a missing package is a likely hallucinated ("slopsquatted") name, and a
//! registry that cannot answer is said so, never taken as a pass.
//!
//! `LOKI_REGISTRY_OVERRIDE` (tests only) sends every lookup to `<base>/<registry host>/<path>` instead.

use crate::config::Config;
use serde_json::Value;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);
const WORKERS: usize = 8;
/// Test hook: the base URL that stands in for every registry host.
pub const OVERRIDE_ENV: &str = "LOKI_REGISTRY_OVERRIDE";

/// `go_proxy_name`: the module path with each capital letter as `!` and its lower case.
pub fn go_proxy_name(module: &str) -> String {
    module
        .chars()
        .map(|c| {
            if c.is_uppercase() {
                format!("!{}", c.to_lowercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// `urllib.parse.quote(text, safe)`: UTF-8 bytes percent-encoded except letters, digits, `_.-~` and `safe`.
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        let c = byte as char;
        if byte.is_ascii_alphanumeric() || "_.-~".contains(c) || (byte.is_ascii() && safe.contains(c)) {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `registry_url`: where a package of `ecosystem` is looked up.
pub fn registry_url(ecosystem: &str, name: &str) -> String {
    let quoted = quote(name, if ecosystem == "go" { "/" } else { "" });
    match ecosystem {
        "npm" => format!("https://registry.npmjs.org/{quoted}"),
        "pypi" => format!("https://pypi.org/pypi/{quoted}/json"),
        "crates" => format!("https://crates.io/api/v1/crates/{quoted}"),
        "go" => format!("https://proxy.golang.org/{}/@latest", quote(&go_proxy_name(name), "/")),
        _ => format!("https://hex.pm/api/packages/{quoted}"),
    }
}

/// How one lookup ended: the HTTP status, or why there was none (urllib's `URLError` text).
pub type Lookup = Result<u16, String>;

/// `dependency_violation`: none when the registry has the package; a 404 is a missing package, any other
/// status or failure an unavailable check.
pub fn dependency_violation(ecosystem: &str, name: &str, lookup: Lookup) -> Option<String> {
    match lookup {
        Ok(status) if status < 400 => None,
        Ok(404) => Some(format!("{ecosystem}: package not found: {name}")),
        Ok(status) => Some(format!(
            "{ecosystem}: registry check unavailable: {name}: HTTP {status}"
        )),
        Err(error) => Some(format!("{ecosystem}: registry check unavailable: {name}: {error}")),
    }
}

/// The URL actually requested: the registry's, or under [`OVERRIDE_ENV`] the stand-in's.
fn effective(url: &str) -> String {
    match std::env::var(OVERRIDE_ENV) {
        Ok(base) if !base.is_empty() => {
            let rest = url.strip_prefix("https://").unwrap_or(url);
            format!("{}/{rest}", base.trim_end_matches('/'))
        }
        _ => url.to_string(),
    }
}

/// urllib's text for a request that got no response.
fn url_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "<urlopen error timed out>".into();
    }
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            if io.raw_os_error().is_some() {
                return format!("<urlopen error {}>", crate::py::os_error(io, None));
            }
            if io.kind() == std::io::ErrorKind::ConnectionRefused {
                return "<urlopen error [Errno 111] Connection refused>".into();
            }
        }
        source = current.source();
    }
    format!("<urlopen error {error}>")
}

/// GET `url` with the registry client; the response status (redirects followed), or the failure.
pub fn fetch(url: &str) -> Lookup {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("<urlopen error {e}>"))?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent("loki/1")
            .build()
            .map_err(|e| format!("<urlopen error {e}>"))?;
        let response = client.get(effective(url)).send().await.map_err(|e| url_error(&e))?;
        Ok(response.status().as_u16())
    })
}

/// `slopsquatting_violations`: the declared dependencies outside `private_packages` that their registries do
/// not have, or could not be asked about, in manifest order.
pub fn slopsquatting_violations(root: &std::path::Path, config: &Config) -> Vec<String> {
    slopsquatting_with(root, config, &fetch)
}

/// [`slopsquatting_violations`] over any `lookup` (tests).
pub fn slopsquatting_with(
    root: &std::path::Path,
    config: &Config,
    lookup: &(dyn Fn(&str) -> Lookup + Sync),
) -> Vec<String> {
    let private: Vec<String> = config
        .get("private_packages")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|i| i.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let dependencies: Vec<(String, String)> = crate::hook::manifest_dependencies(root)
        .into_iter()
        .filter(|(_, name)| !private.iter().any(|prefix| name.starts_with(prefix.as_str())))
        .collect();
    let mut results: Vec<Option<String>> = vec![None; dependencies.len()];
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots = std::sync::Mutex::new(&mut results);
    std::thread::scope(|scope| {
        for _ in 0..WORKERS.min(dependencies.len()) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Some((ecosystem, name)) = dependencies.get(index) else {
                        return;
                    };
                    let found = dependency_violation(ecosystem, name, lookup(&registry_url(ecosystem, name)));
                    slots.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[index] = found;
                }
            });
        }
    });
    results.into_iter().flatten().collect()
}
