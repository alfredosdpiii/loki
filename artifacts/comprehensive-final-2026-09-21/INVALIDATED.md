# Interrupted reservation-confounded run

Do not use this directory as a product scorecard.

The runner reused one fixture and daemon across three repetitions, while using a
different session ID for each repetition. Interlinked correctly retained the
first session's file reservations and blocked later sessions. Scoring those
coordination denials as false positives would be invalid.

The run was stopped. Completed records and the original manifest remain unchanged.
The corrected runner gives each repetition its own repository, home, and daemon.
Later trials warm startup with two read-only git-status hook envelopes before the
case begins, using the same session throughout that trial. Multi-step workflows
use unique tool-use IDs and one session. Neither product's rules are changed.
