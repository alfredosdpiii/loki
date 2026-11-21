#!/usr/bin/env bash
# Scripted terminal demo for the README landmines + Oxlint GIF. Every diagnostic
# shown is real output from Loki's installed hooks and vendored landmines
# plugins under Oxlint; only the typing is simulated.
#
#   asciinema rec --cols 96 --rows 34 --overwrite -c "bash docs/demo/landmines.sh" docs/demo/landmines.cast
#   agg docs/demo/landmines.cast docs/demo/landmines.gif
set -euo pipefail

LOKI="$(cd "$(dirname "$0")/../.." && pwd)/loki.py"
OXLINT_DIR="${LOKI_DEMO_OXLINT:-$HOME/.cache/loki-demo/oxlint/node_modules}"
DEMO="$(mktemp -d)/app"
export LOKI_DAEMON=0 LOKI_HYGIENE=off GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid

bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m'
cyan=$'\e[36m' magenta=$'\e[35m' reset=$'\e[0m'

say() {
  printf '\n%s# %s%s\n' "$dim" "$1" "$reset"
  sleep 0.7
}

agent_write() {
  local path="$1" content="$2" payload status output
  printf '%sagent%s %s→ Write%s %s\n' "$magenta$bold" "$reset" "$dim" "$reset" "$path"
  sed 's/^/    /' <<<"$content" | head -n 12 | sed "s/^/$dim/;s/$/$reset/"
  sleep 0.6
  payload=$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "tool_name": "Write", "tool_input": {"file_path": sys.argv[2], "content": sys.argv[3]}}))' "$PWD" "$path" "$content")
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" > "$path"
  set +e
  output=$(python3 .loki/loki.py hook --harness claude <<<"$payload" 2>&1)
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s✗ blocked by Oxlint + landmines%s\n' "$red$bold" "$reset"
    grep 'oxlint:' <<<"$output" | fold -s -w 90 | sed "s/^/  $red/;s/$/$reset/" | head -n 10
  else
    printf '%s✓ clean (0 Oxlint or landmines errors)%s\n' "$green$bold" "$reset"
  fi
  sleep 2.2
}

mkdir -p "$DEMO/src" && cd "$DEMO"
git init -q
printf '{"name":"demo","private":true,"type":"module"}\n' > package.json
printf 'node_modules/\n' > .gitignore
ln -s "$OXLINT_DIR" node_modules
cat > src/calc.ts <<'EOF'
export function double(n: number) {
  return n * 2;
}
EOF
python3 "$LOKI" init --dir . >/dev/null 2>&1
git add -A && git commit -qm "Install Loki"

clear
printf '%sLoki%s %s· vendored landmines + anti-slop Oxlint rules (zero extra npm deps)%s\n' "$cyan$bold" "$reset" "$dim" "$reset"
sleep 1.0

say "Agent adds a fixed sleep, flake retry, prose comment and explicit return type"
agent_write src/calc.test.ts '// wait for background work to settle
import { test, expect } from "vitest";
import { double } from "./calc.ts";

export function sample(): number {
  return double(21);
}

test("doubles input", { retry: 2 }, async () => {
  await new Promise((resolve) => setTimeout(resolve, 200));
  expect(sample()).toBe(42);
});
'

say "Agent removes the shortcuts and tests the real function directly"
agent_write src/calc.test.ts 'import { test, expect } from "vitest";
import { double } from "./calc.ts";

test("doubles input", () => {
  expect(double(21)).toBe(42);
});
'

sleep 2.0
