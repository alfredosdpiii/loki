#!/usr/bin/env bash
# Generates one compact, real-output GIF per Loki firing scenario.
# Every block/finding is real output from the installed `loki` binary.
#
# Usage: bash docs/demo/record-scenarios.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/docs/demo"
LOKI_BIN="${LOKI_BIN:-$ROOT/target/release/loki}"
export ASCIINEMA_CONFIG_HOME="${ASCIINEMA_CONFIG_HOME:-/tmp/asciinema-cfg}"

run_write_scenario() {
  local name="$1" title="$2" rows="$3" path="$4" content="$5"
  local script
  script=$(mktemp /tmp/loki-scen-XXXXXX.sh)
  cat >"$script" <<'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail
DEMO="$(mktemp -d)/repo"
trap 'rm -rf "$DEMO"' EXIT
export LOKI_DAEMON=0 GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid
bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' cyan=$'\e[36m' magenta=$'\e[35m' reset=$'\e[0m'

mkdir -p "$DEMO" && cd "$DEMO"
git init -q
"$LOKI_BIN" init --minimal --dir . >/dev/null 2>&1
git add -A && git commit -qm "Install Loki"

printf '\033[2J\033[H'
printf '%sLoki%s %s· %s%s\n\n' "$cyan$bold" "$reset" "$dim" "$SCEN_TITLE" "$reset"
sleep 0.5
printf '%sagent%s %s→ Write%s %s\n' "$magenta$bold" "$reset" "$dim" "$reset" "$SCEN_PATH"
sed 's/^/    /' <<<"$SCEN_CONTENT" | sed "s/^/$dim/;s/$/$reset/"
sleep 0.6

payload=$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "tool_name": "Write", "tool_input": {"file_path": sys.argv[2], "content": sys.argv[3]}}))' "$PWD" "$SCEN_PATH" "$SCEN_CONTENT")
set +e
output=$("$LOKI_BIN" --root "$PWD" protect --harness claude <<<"$payload" 2>&1)
status=$?
set -e
printf '\n'
if [ "$status" -ne 0 ]; then
  printf '%s✗ blocked before write%s\n' "$red$bold" "$reset"
  grep -v "hook command failed" <<<"$output" | fold -s -w 90 | sed "s/^/  $red/;s/$/$reset/"
else
  printf '%s✓ allowed%s\n' "$green$bold" "$reset"
fi
sleep 2.4
SCRIPT_EOF
  chmod +x "$script"
  LOKI_BIN="$LOKI_BIN" SCEN_TITLE="$title" SCEN_PATH="$path" SCEN_CONTENT="$content" \
    asciinema rec --cols 94 --rows "$rows" --overwrite -c "bash $script" "$OUT/$name.cast" >/dev/null 2>&1
  agg "$OUT/$name.cast" "$OUT/$name.gif" >/dev/null 2>&1
  rm -f "$script"
  printf 'rendered %s.gif (%s)\n' "$name" "$(du -h "$OUT/$name.gif" | cut -f1)"
}

run_bash_scenario() {
  local name="$1" title="$2" rows="$3" cmd="$4"
  local script
  script=$(mktemp /tmp/loki-scen-XXXXXX.sh)
  cat >"$script" <<'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail
DEMO="$(mktemp -d)/repo"
trap 'rm -rf "$DEMO"' EXIT
export LOKI_DAEMON=0 GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid
bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' cyan=$'\e[36m' magenta=$'\e[35m' reset=$'\e[0m'

mkdir -p "$DEMO" && cd "$DEMO"
git init -q
printf 'x = 1\n' > app.py
"$LOKI_BIN" init --minimal --dir . >/dev/null 2>&1
git add -A && git commit -qm "Install Loki"

printf '\033[2J\033[H'
printf '%sLoki%s %s· %s%s\n\n' "$cyan$bold" "$reset" "$dim" "$SCEN_TITLE" "$reset"
sleep 0.5
printf '%sagent%s %s→ Bash%s %s\n' "$magenta$bold" "$reset" "$dim" "$reset" "$SCEN_CMD"
sleep 0.6

payload=$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "tool_name": "Bash", "tool_input": {"command": sys.argv[2]}}))' "$PWD" "$SCEN_CMD")
set +e
output=$("$LOKI_BIN" --root "$PWD" shell --harness claude <<<"$payload" 2>&1)
status=$?
set -e
printf '\n'
if [ "$status" -ne 0 ]; then
  printf '%s✗ blocked%s\n' "$red$bold" "$reset"
  grep -v "hook command failed" <<<"$output" | fold -s -w 90 | sed "s/^/  $red/;s/$/$reset/"
else
  printf '%s✓ allowed%s\n' "$green$bold" "$reset"
fi
sleep 2.4
SCRIPT_EOF
  chmod +x "$script"
  LOKI_BIN="$LOKI_BIN" SCEN_TITLE="$title" SCEN_CMD="$cmd" \
    asciinema rec --cols 94 --rows "$rows" --overwrite -c "bash $script" "$OUT/$name.cast" >/dev/null 2>&1
  agg "$OUT/$name.cast" "$OUT/$name.gif" >/dev/null 2>&1
  rm -f "$script"
  printf 'rendered %s.gif (%s)\n' "$name" "$(du -h "$OUT/$name.gif" | cut -f1)"
}

# 1. Python SQL injection, SSRF & unsafe yaml.load
run_write_scenario "scenario-python-security" \
  "Python security: SQL injection, SSRF & unsafe yaml.load" 20 \
  "api/users.py" \
'import requests, yaml

def fetch_user(cursor, request):
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    requests.get(request.args["callback_url"])
    return yaml.load(request.data)'

# 2. Rust SQL injection & disabled TLS verification
run_write_scenario "scenario-rust-security" \
  "Rust security: format! SQL injection & disabled TLS" 16 \
  "src/db.rs" \
'pub async fn load(pool: &Pool, user: &str) {
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE name = '\''{}'\''", user))
        .execute(pool).await;
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(true).build();
}'

# 3. Rust anti-slop & safety (placeholder, unflushed BufWriter, unchecked index, missing SAFETY)
run_write_scenario "scenario-rust-safety" \
  "Rust anti-slop: todo!(), unflushed BufWriter & unchecked index" 22 \
  "src/store.rs" \
'use std::io::{BufWriter, Write};

pub fn save(file: std::fs::File, items: &[u8], idx: usize) -> u8 {
    let mut w = BufWriter::new(file);
    let _ = w.write_all(items);
    if items.is_empty() { todo!() }
    unsafe { *items.get_unchecked(idx) }
}'

# 4. Python anti-slop (tautological test & silent except: pass)
run_write_scenario "scenario-python-antislop" \
  "Python anti-slop: tautological test & silent except: pass" 20 \
  "tests/test_auth.py" \
'def test_parse_token(raw):
    assert parse_token(raw) == parse_token(raw)

def cleanup(path):
    try:
        remove(path)
    except Exception:
        pass'

# 5. Elixir structural DateTime sort
run_write_scenario "scenario-elixir-safety" \
  "Elixir safety: structural DateTime sort" 15 \
  "lib/events.ex" \
'defmodule Events do
  def latest(items) do
    Enum.sort_by(items, & &1.inserted_at)
  end
end'

# 6. GitHub Actions untrusted script injection
run_write_scenario "scenario-actions-injection" \
  "GitHub Actions: untrusted event field in run step" 16 \
  ".github/workflows/triage.yml" \
'name: Triage
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title: ${{ github.event.issue.title }}"'

# 7. Unresolved merge-conflict markers
run_write_scenario "scenario-conflict-marker" \
  "Any file: unresolved merge-conflict markers" 15 \
  "notes.txt" \
'<<<<<<< HEAD
version = 1
=======
version = 2
>>>>>>> branch'

# 8. Destructive Git blocked
run_bash_scenario "scenario-shell-git" \
  "Shell guard: destructive Git command blocked" 12 \
  "git reset --hard"

# 9. Shell redirect write-bypass blocked
run_bash_scenario "scenario-shell-bypass" \
  "Shell guard: redirect bypassing write checks blocked" 12 \
  'echo "x = 2" > app.py'

# 10. Protected policy file tamper blocked
run_write_scenario "scenario-policy-tamper" \
  "Policy protection: editing .loki/loki.json blocked" 13 \
  ".loki/loki.json" \
'{"rule_packs": []}'

# 11. Structural sloppiness (`loki slop` + `--base HEAD`)
LOKI_BIN="$LOKI_BIN" asciinema rec --cols 96 --rows 28 --overwrite \
  -c "LOKI_BIN=$LOKI_BIN bash $OUT/slop.sh" "$OUT/scenario-slop.cast" >/dev/null 2>&1
agg "$OUT/scenario-slop.cast" "$OUT/scenario-slop.gif" >/dev/null 2>&1
printf 'rendered scenario-slop.gif (%s)\n' "$(du -h "$OUT/scenario-slop.gif" | cut -f1)"
