//! The analyzers Loki's per-language checks run, as `ultron setup` lists them (setup's `LOKI_ANALYZERS`), and the
//! version of the engine this build bundles.

/// One analyzer: what Loki uses it for, the command line that shows it is installed, and how to install it.
pub struct Analyzer {
    pub name: &'static str,
    pub language: &'static str,
    pub command: &'static str,
    pub args: &'static [&'static str],
    pub install_hint: &'static str,
}

pub const ANALYZERS: [Analyzer; 8] = [
    Analyzer {
        name: "ruff",
        language: "Python",
        command: "ruff",
        args: &["--version"],
        install_hint: "uv tool install ruff (or pipx install ruff)",
    },
    Analyzer {
        name: "mypy",
        language: "Python types",
        command: "mypy",
        args: &["--version"],
        install_hint: "uv tool install mypy (or pipx install mypy)",
    },
    Analyzer {
        name: "tsc",
        language: "TypeScript types",
        command: "tsc",
        args: &["--version"],
        install_hint: "npm i -D typescript in the project (node_modules/.bin/tsc is used when present)",
    },
    Analyzer {
        name: "oxlint",
        language: "JavaScript/TypeScript",
        command: "oxlint",
        args: &["--version"],
        install_hint: "npm i -D oxlint @oxlint/plugins in the project (node_modules/.bin/oxlint is used when present)",
    },
    Analyzer {
        name: "golangci-lint",
        language: "Go",
        command: "golangci-lint",
        args: &["--version"],
        install_hint: "https://golangci-lint.run/welcome/install/",
    },
    Analyzer {
        name: "clippy",
        language: "Rust",
        command: "cargo",
        args: &["clippy", "--version"],
        install_hint: "rustup component add clippy",
    },
    Analyzer {
        name: "credo",
        language: "Elixir",
        command: "mix",
        args: &["--version"],
        install_hint: "install Elixir, then add {:credo, only: [:dev, :test]} to the project's mix.exs deps",
    },
    Analyzer {
        name: "sobelow",
        language: "Phoenix security",
        command: "mix",
        args: &["--version"],
        install_hint: "install Elixir, then add {:sobelow, only: [:dev, :test]} to the project's mix.exs deps",
    },
];

/// `bundledLokiVersion`: version of this standalone Loki build.
pub fn bundled_version() -> String {
    crate::VERSION.to_string()
}
