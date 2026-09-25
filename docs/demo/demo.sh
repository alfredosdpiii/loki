#!/usr/bin/env bash
# Scripted terminal demo for the README GIF. Every result shown is real output
# from Loki's installed Claude Code hooks; only the typing is simulated.
#
#   asciinema rec -c "bash docs/demo/demo.sh" docs/demo/demo.cast
#   agg docs/demo/demo.cast docs/demo/demo.gif
set -euo pipefail

LOKI="$(cd "$(dirname "$0")/../.." && pwd)/loki.py"
TYPESCRIPT="${LOKI_DEMO_TYPESCRIPT:-$HOME/.cache/loki-bench/ts/node_modules/typescript}"
OXLINT="${LOKI_DEMO_OXLINT:-$HOME/.cache/loki-bench/oxlint/node_modules}"
DEMO="$(mktemp -d)/shop"
export LOKI_DAEMON=0 GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid

# `loki` is the installed CLI; fall back to this checkout's engine, which is the same code.
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
  sleep 0.8
}

# Send one Claude Code Write through Loki's installed pre-hook, and on success
# write the file and run the post-hook, exactly as the host would.
agent_write() {
  local path="$1" content="$2" payload status output
  printf '%sagent%s %s→ Write%s %s\n' "$magenta$bold" "$reset" "$dim" "$reset" "$path"
  sed 's/^/    /' <<<"$content" | head -n 6 | sed "s/^/$dim/;s/$/$reset/"
  sleep 0.6
  payload=$(python3 -c 'import json,sys; print(json.dumps({"cwd": sys.argv[1], "tool_name": "Write", "tool_input": {"file_path": sys.argv[2], "content": sys.argv[3]}}))' "$PWD" "$path" "$content")
  set +e
  output=$(python3 .loki/loki.py protect --harness claude <<<"$payload" 2>&1)
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s✗ blocked before the write%s\n' "$red$bold" "$reset"
    grep -v "hook command failed" <<<"$output" | fold -s -w 92 | sed "s/^/  $red/;s/$/$reset/"
    sleep 2.2
    return
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" > "$path"
  set +e
  output=$(python3 .loki/loki.py hook --harness claude <<<"$payload" 2>&1)
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s✗ post-write check failed%s\n' "$red$bold" "$reset"
    sed "s/^/  $red/;s/$/$reset/" <<<"$output" | head -n 4
  else
    printf '%s✓ allowed%s\n' "$green$bold" "$reset"
    grep -o 'loki/slop[^"]*' <<<"$output" | awk '!seen[$0]++' | head -n 2 | fold -s -w 92 | sed "s/^/  $yellow/;s/$/$reset/" || true
  fi
  sleep 1.6
}

mkdir -p "$DEMO" && cd "$DEMO"
git init -q
mkdir -p src node_modules/.bin
ln -s "$TYPESCRIPT" node_modules/typescript
ln -s "$OXLINT/.bin/oxlint" node_modules/.bin/oxlint
ln -s "$OXLINT/@oxlint" node_modules/@oxlint
printf 'node_modules/\n' > .gitignore
cat > tsconfig.json <<'EOF'
{"compilerOptions": {"strict": true, "noEmit": true, "target": "ES2022",
 "module": "ESNext", "moduleResolution": "Bundler"}, "include": ["src/**/*.ts"]}
EOF
cat > src/prices.ts <<'EOF'
export function totalCents(items: { cents: number }[]): number {
  return items.reduce((sum, item) => sum + item.cents, 0);
}
EOF
cat > src/checkout.ts <<'EOF'
import { totalCents } from "./prices";
export const due: number = totalCents([{ cents: 250 }]);
EOF

clear
printf '%sLoki%s %s· deterministic guardrails for AI coding agents%s\n' "$cyan$bold" "$reset" "$dim" "$reset"
sleep 1

say "Install Loki into a repository"
command_line "loki init --dir ."
loki init --dir . >/dev/null 2>&1
git add -A && git commit -qm "Install Loki"
printf '%s✓%s hooks for Claude Code, Codex, Factory, Pi and OMP\n' "$green" "$reset"
sleep 1.2

say "The agent renders user comments with innerHTML"
agent_write src/comments.ts 'export function show(node: HTMLElement, comment: string) {
  node.innerHTML = comment;
}'

say "It pastes a live API key into config"
agent_write src/config.ts 'export const stripeKey = "sk_live_51Hq8TzK2m9XbV4dLpQ7rW3nY6cF0aJ";'

say "It changes a function and breaks a caller in another file"
agent_write src/prices.ts 'export function totalCents(items: { cents: number }[]): string {
  return (items.reduce((sum, item) => sum + item.cents, 0) / 100).toFixed(2);
}'

say "It fixes the XSS the right way"
agent_write src/comments.ts 'export function show(node: HTMLElement, comment: string) {
  node.textContent = comment;
}'

say "It adds a sprawling function: allowed, but flagged as a new hotspot"
agent_write src/discounts.ts 'export function discount(tier: string, cents: number, coupon?: string): number {
  if (tier === "t0" && coupon) return cents * 90 / 100;
  if (tier === "t1") return cents * 89 / 100;
  if (tier === "t2") return cents * 88 / 100;
  if (tier === "t3" && coupon) return cents * 87 / 100;
  if (tier === "t4") return cents * 86 / 100;
  if (tier === "t5") return cents * 85 / 100;
  if (tier === "t6" && coupon) return cents * 84 / 100;
  if (tier === "t7") return cents * 83 / 100;
  if (tier === "t8") return cents * 82 / 100;
  if (tier === "t9" && coupon) return cents * 81 / 100;
  if (tier === "t10") return cents * 80 / 100;
  if (tier === "t11") return cents * 79 / 100;
  return cents;
}'

say "Audit structural sloppiness at any time"
command_line "loki slop"
loki slop | grep -v "^Verbosity\|^clone" | head -n 5
sleep 3
