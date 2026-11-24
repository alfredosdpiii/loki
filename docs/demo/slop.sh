#!/usr/bin/env bash
# Scripted terminal demo for `loki slop` (complexity erosion, token-normalized
# clones, import cycles, branch diffing with `--base`, and `slop.exclude`).
#
#   asciinema rec --cols 96 --rows 32 --overwrite -c "bash docs/demo/slop.sh" docs/demo/slop.cast
#   agg docs/demo/slop.cast docs/demo/slop.gif
set -euo pipefail

LOKI_BIN="${LOKI_BIN:-loki}"
DEMO="$(mktemp -d)/slop-demo"
trap 'rm -rf "$DEMO"' EXIT
export LOKI_DAEMON=0 GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid

bold=$'\e[1m' dim=$'\e[2m' green=$'\e[32m' yellow=$'\e[33m'
cyan=$'\e[36m' reset=$'\e[0m'

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
  sleep 0.25
}

say() {
  printf '\n%s# %s%s\n' "$dim" "$1" "$reset"
  sleep 0.65
}

mkdir -p "$DEMO/src" "$DEMO/fixtures" && cd "$DEMO"
git init -q
cat > src/a.py <<'EOF'
import src.b

def calc_discount(tier, total, coupon, vip, holiday, region, items, member, rush, bulk):
    rate = 0.0
    if tier == "gold" and total > 100:
        rate += 0.15
    elif tier == "silver" or vip:
        rate += 0.10
    if coupon and not holiday:
        rate += 0.05
    if region == "us" and items > 3:
        rate += 0.02
    elif region == "eu" or member:
        rate += 0.03
    if rush and bulk:
        rate -= 0.04
    elif bulk and total > 500:
        rate += 0.08
    return max(0.0, min(0.5, rate))
EOF

cat > src/b.py <<'EOF'
import src.a

def calc_rebate(level, amount, code, star, festive, zone, count, subscriber, urgent, wholesale):
    pct = 0.0
    if level == "gold" and amount > 100:
        pct += 0.15
    elif level == "silver" or star:
        pct += 0.10
    if code and not festive:
        pct += 0.05
    if zone == "us" and count > 3:
        pct += 0.02
    elif zone == "eu" or subscriber:
        pct += 0.03
    if urgent and wholesale:
        pct -= 0.04
    elif wholesale and amount > 500:
        pct += 0.08
    return max(0.0, min(0.5, pct))
EOF

cat > fixtures/frozen_gen.py <<'EOF'
# Frozen fixture: automatically excluded from production slop metrics
def fixture_clone(a, b, c, d, e, f, g, h, i, j):
    return [a, b, c, d, e, f, g, h, i, j] * 20
EOF

"$LOKI_BIN" init --minimal --dir . >/dev/null 2>&1
git add -A && git commit -qm "Initial commit"

printf '\033[2J\033[H'
printf '%sLoki%s %s· structural sloppiness (complexity · clones · import cycles)%s\n' "$cyan$bold" "$reset" "$dim" "$reset"
sleep 0.9

say "Measure the whole repository (fixtures excluded automatically)"
command_line "loki slop"
"$LOKI_BIN" --root "$PWD" slop | sed "s/^/$yellow/;s/$/$reset/"
sleep 2.2

say "Refactor src/b.py to reuse src/a.py and break the cycle"
cat > src/b.py <<'EOF'
def apply_rate(total: float, rate: float) -> float:
    return round(total * (1.0 - rate), 2)
EOF
cat > src/a.py <<'EOF'
def calc_discount(tier: str, total: float) -> float:
    if tier == "gold" and total > 100:
        return 0.15
    if tier == "silver":
        return 0.10
    return 0.0
EOF

say "Compare against HEAD with --base"
command_line "loki slop --base HEAD"
"$LOKI_BIN" --root "$PWD" slop --base HEAD | sed "s/^/$green/;s/$/$reset/"
sleep 2.4
