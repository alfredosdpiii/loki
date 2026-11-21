#!/usr/bin/env bash
# Scripted terminal demo for the README codehygiene + nits GIF. Every finding
# shown is real output from Loki's installed hooks and `loki hygiene`; only the
# typing is simulated.
#
#   asciinema rec --cols 96 --rows 28 -c "bash docs/demo/hygiene.sh" docs/demo/hygiene.cast
#   agg --cols 96 --rows 28 docs/demo/hygiene.cast docs/demo/hygiene.gif
set -euo pipefail

LOKI="$(cd "$(dirname "$0")/../.." && pwd)/loki.py"
DEMO="$(mktemp -d)/store"
export LOKI_DAEMON=0 GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid

command -v loki >/dev/null 2>&1 || loki() { python3 "$LOKI" "$@"; }

bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m'
cyan=$'\e[36m' magenta=$'\e[35m' reset=$'\e[0m'

type_out() {
  local text="$1"
  for ((i = 0; i < ${#text}; i++)); do
    printf '%s' "${text:i:1}"
    sleep 0.025
  done
}

command_line() {
  printf '%s$ %s' "$green" "$reset"
  type_out "$1"
  printf '\n'
  sleep 0.3
}

say() {
  printf '\n%s# %s%s\n' "$dim" "$1" "$reset"
  sleep 0.7
}

agent_write() {
  local path="$1" content="$2" payload status output
  printf '%sagent%s %s→ Write%s %s\n' "$magenta$bold" "$reset" "$dim" "$reset" "$path"
  sed 's/^/    /' <<<"$content" | head -n 18 | sed "s/^/$dim/;s/$/$reset/"
  sleep 0.6
  payload=$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "tool_name": "Write", "tool_input": {"file_path": sys.argv[2], "content": sys.argv[3]}}))' "$PWD" "$path" "$content")
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" > "$path"
  set +e
  output=$(python3 .loki/loki.py hook --harness claude <<<"$payload" 2>&1)
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s✗ post-write check failed%s\n' "$red$bold" "$reset"
    sed "s/^/  $red/;s/$/$reset/" <<<"$output" | head -n 6
  else
    local notes
    notes=$(grep -E 'loki/(nits|hygiene)-' <<<"$output" | grep -v '^{' | awk '!seen[$0]++' || true)
    if [ -n "$notes" ]; then
      printf '%s✓ written%s %s(hygiene + nits notes on added lines)%s\n' "$green$bold" "$reset" "$yellow" "$reset"
      fold -s -w 90 <<<"$notes" | sed "s/^/  $yellow/;s/$/$reset/"
    else
      printf '%s✓ clean (0 hygiene or nits findings)%s\n' "$green$bold" "$reset"
    fi
  fi
  sleep 2.0
}

mkdir -p "$DEMO" && cd "$DEMO"
git init -q
cat > store.py <<'EOF'
import pathlib

LIMIT = 10
EOF
python3 "$LOKI" init --dir . >/dev/null 2>&1
git add -A && git commit -qm "Install Loki"

clear
printf '%sLoki%s %s· codehygiene + nits on every write (added lines only)%s\n' "$cyan$bold" "$reset" "$dim" "$reset"
sleep 1.0

say "Agent adds error-handling shortcuts to store.py"
agent_write store.py 'import pathlib

LIMIT = 10


def load_items(path: str) -> list[str]:
    try:
        return pathlib.Path(path).read_text().splitlines()
    except OSError:
        return []


def clear_cache(path: str) -> None:
    try:
        pathlib.Path(path).unlink()
    except Exception:
        pass
'

say "Audit all modified and untracked files on demand"
command_line "loki hygiene"
python3 .loki/loki.py hygiene | fold -s -w 92 | sed "s/^/$yellow/;s/$/$reset/"
sleep 2.2

say "Agent fixes both findings properly"
agent_write store.py 'import pathlib

LIMIT = 10


def load_items(path: str) -> list[str]:
    return pathlib.Path(path).read_text(encoding="utf-8").splitlines()


def clear_cache(path: str) -> None:
    pathlib.Path(path).unlink(missing_ok=True)
'

say "Verify the whole branch is clean"
command_line "loki hygiene --json"
python3 .loki/loki.py hygiene --json
sleep 2.5
