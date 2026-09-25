# Interrupted setup-invalid run

Do not use this directory as a product scorecard.

The runner incorrectly replaced Loki's shipped rule packs with
`["elixir", "phoenix"]` in Phoenix fixtures. `elixir` is not a valid rule-pack
name. The resulting pre-hook denials reflect malformed benchmark configuration,
not security detection or legitimate-control rejection by a valid installation.

The run was stopped after that problem was identified. Its completed records and
original manifest remain unchanged. No final summary was produced.

The corrected runner preserves the shipped rule packs, changes only the declared
shell-command grant, and validates the installed policy through `context` before
collecting observations. A regression test validates the rule-pack list through
the product parser.
