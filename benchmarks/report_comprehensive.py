"""Render a scorecard from complete frozen evidence, without rerunning products."""

import argparse
import hashlib
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from benchmarks.comprehensive import classify, percentile, save

CAUGHT = {"prevented", "detected_after_write"}
FALSE_BLOCKS = {"false_block", "false_post_block"}


def feedback_lines(stage):
    """Decode the host envelope before matching; JSON '\\n' is not a line break."""
    if not stage:
        return []
    parts = []
    for handler in stage["handlers"]:
        raw = handler["stdout"]
        try:
            value = json.loads(raw)
        except ValueError:
            value = {}
            if handler["exit"] == 2:
                parts.append(raw)
        if isinstance(value, dict):
            specific = value.get("hookSpecificOutput", {})
            for text in (
                value.get("reason"),
                specific.get("additionalContext")
                if isinstance(specific, dict)
                else None,
                specific.get("permissionDecisionReason")
                if isinstance(specific, dict)
                else None,
            ):
                if isinstance(text, str):
                    parts.append(text)
        if handler["exit"] == 2:
            parts.append(handler["stderr"])
    return [
        line
        for part in parts
        for line in part.splitlines()
        if not any(
            notice in line
            for notice in (
                "MODULE_TYPELESS_PACKAGE_JSON",
                "Reparsing as ES module",
                "module syntax was detected",
            )
        )
    ]


def targeted(stage, markers):
    return any(
        re.search(pattern, line, re.I)
        for line in feedback_lines(stage)
        for pattern in markers
    )


def scored_outcome(event, step):
    pre = {**event["pre"], "targeted": targeted(event["pre"], step.get("markers", []))}
    post = (
        {**event["post"], "targeted": targeted(event["post"], step.get("markers", []))}
        if event["post"]
        else None
    )
    return classify(step["kind"], pre, post)


def measurements(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    summary = json.loads((directory / "summary.json").read_text())
    if not summary["identity_unchanged"]:
        raise ValueError("product or benchmark identity changed")
    records = [
        json.loads(path.read_text()) for path in sorted(directory.glob("record-*.json"))
    ]
    expected = {
        (case, product, profile) for case, product, profile in manifest["schedule"]
    }
    actual = [(item["case"], item["product"], item["profile"]) for item in records]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError("incomplete or duplicate benchmark records")
    cases = {case["id"]: case for case in manifest["corpus"]["cases"]}
    rows = []
    for record in records:
        case = cases[record["case"]]
        for index, step in enumerate(case["steps"]):
            observations = [
                event for event in record.get("events", []) if event["step"] == index
            ]
            if "error" not in record and len(observations) != manifest["runs"]:
                raise ValueError("missing repetitions")
            outcomes = {scored_outcome(event, step) for event in observations}
            stages = [
                stage
                for event in observations
                for stage in (event["pre"], event["post"])
                if stage
            ]
            rows.append(
                {
                    "case": case["id"],
                    "step": index,
                    "pair": case["pair"],
                    "family": case["family"],
                    "language": case["language"],
                    "product": record["product"],
                    "profile": record["profile"],
                    "kind": step["kind"],
                    "outcomes": sorted(outcomes),
                    "provisional_outcomes": sorted(
                        {event["outcome"] for event in observations}
                    ),
                    "scoring_corrections": [
                        {
                            "repetition": event["repetition"],
                            "from": event["outcome"],
                            "to": scored_outcome(event, step),
                        }
                        for event in observations
                        if event["outcome"] != scored_outcome(event, step)
                    ],
                    "caught_all_runs": (
                        not record.get("error")
                        and bool(outcomes)
                        and outcomes <= CAUGHT
                    ),
                    "prevented_all_runs": (
                        not record.get("error") and outcomes == {"prevented"}
                    ),
                    "false_block_any_run": bool(outcomes & FALSE_BLOCKS),
                    "inconsistent": len(outcomes) > 1,
                    "error": record.get("error"),
                    "coverage_warning": any(
                        stage["coverage_warning"] for stage in stages
                    ),
                    "feedback": any(stage["feedback_present"] for stage in stages),
                    "post_modified": any(
                        event["post_modified_written_bytes"] for event in observations
                    ),
                    "pre_modified": any(
                        event["pre_modified_bytes"] for event in observations
                    ),
                    "samples": [
                        {
                            "cache_state": event["cache_state"],
                            "pre_ms": event["pre"]["ms"],
                            "post_ms": event["post"]["ms"] if event["post"] else None,
                            "total_ms": event["pre"]["ms"]
                            + (event["post"]["ms"] if event["post"] else 0),
                        }
                        for event in observations
                    ],
                    "scans": record.get("audit_scans", []),
                }
            )
    return manifest, rows


def counts(rows):
    bad = [row for row in rows if row["kind"] == "defect"]
    good = [row for row in rows if row["kind"] == "control"]
    return {
        "defects": len(bad),
        "caught": sum(row["caught_all_runs"] for row in bad),
        "prevented": sum(row["prevented_all_runs"] for row in bad),
        "controls": len(good),
        "false_blocks": sum(row["false_block_any_run"] for row in good),
        "control_feedback": sum(row["feedback"] for row in good),
        "coverage_warning": sum(row["coverage_warning"] for row in rows),
        "errors": sum(bool(row["error"]) for row in rows),
        "inconsistent": sum(row["inconsistent"] for row in rows),
    }


def latency(rows):
    result = {}
    for cache in ("first-invocation", "startup-warmed"):
        samples = [
            sample
            for row in rows
            for sample in row["samples"]
            if sample["cache_state"] == cache
        ]
        result[cache] = {}
        for field in ("pre_ms", "post_ms", "total_ms"):
            values = [sample[field] for sample in samples if sample[field] is not None]
            result[cache][field] = (
                {
                    "n": len(values),
                    "median": round(statistics.median(values), 2),
                    "p95": round(percentile(values, 0.95), 2),
                    "max": round(max(values), 2),
                }
                if values
                else None
            )
    return result


def render(directory):
    manifest, rows = measurements(directory)
    groups = defaultdict(list)
    for row in rows:
        groups[(row["profile"], row["product"])].append(row)
    lines = [
        "# Installed-hook lifecycle benchmark",
        "",
        "This is a synthetic, author-written benchmark, "
        "not an independent product ranking.",
        "Both products ran unchanged. Repeated timings are not extra accuracy cases.",
        "A caught defect requires a matching diagnostic on every repetition.",
        "Post-write detection means the bytes already landed.",
        "",
        f"Corpus version: {manifest['corpus']['version']}.",
        f"Corpus SHA-256: `{manifest['corpus']['sha256']}`.",
        f"Repetitions: {manifest['runs']}. Schedule seed: {manifest['seed']}.",
        manifest["configuration"],
        "Loki project type-check opt-in: "
        + (
            "enabled."
            if any(Path(path).name == "configured.py" for path in manifest["identity"])
            else "not enabled."
        ),
        "",
        "## Matched results",
        "",
        "| Profile / product | Caught defects | Prevented before write | "
        "False blocks | Control feedback | Coverage warnings | Infrastructure errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    results = {}
    for (profile, product), subset in sorted(groups.items()):
        key = f"{profile}/{product}"
        score = counts(subset)
        results[key] = {"counts": score, "latency": latency(subset)}
        lines.append(
            f"| {key} | {score['caught']}/{score['defects']} | "
            f"{score['prevented']}/{score['defects']} | "
            f"{score['false_blocks']}/{score['controls']} | "
            f"{score['control_feedback']}/{score['controls']} | "
            f"{score['coverage_warning']}/{len(subset)} | {score['errors']} |"
        )
    lines += [
        "",
        "Control feedback includes legitimate advisory "
        "and unavailable-coverage notices.",
        "It is not a false-positive count. "
        "False blocks include any blocked repetition.",
        "Infrastructure errors stay in denominators and earn no detection credit.",
        "",
        "## Shared-analyzer results by language",
        "",
        "| Language | Product | Caught | Pre-write | False blocks |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for language in sorted({row["language"] for row in rows}):
        for product in ("loki", "interlinked"):
            subset = [
                row
                for row in rows
                if row["language"] == language
                and row["product"] == product
                and row["profile"] == "shared"
            ]
            if not subset:
                continue
            score = counts(subset)
            lines.append(
                f"| {language} | {product} | {score['caught']}/{score['defects']} | "
                f"{score['prevented']}/{score['defects']} | "
                f"{score['false_blocks']}/{score['controls']} |"
            )
    lines += [
        "",
        "## Paired cases",
        "",
        "A successful pair catches the defect on every run "
        "and never blocks its control.",
        "Pair counts exclude standalone admission, scaling, debt, and workflow cases.",
        "",
        "| Profile / product | Successful pairs |",
        "| --- | ---: |",
    ]
    for (profile, product), subset in sorted(groups.items()):
        pairs = defaultdict(list)
        for row in subset:
            if row["pair"]:
                pairs[row["pair"]].append(row)
        passed = sum(
            len(pair) == 2
            and all(
                row["caught_all_runs"]
                if row["kind"] == "defect"
                else not row["false_block_any_run"]
                and not row["error"]
                and "unavailable" not in row["outcomes"]
                for row in pair
            )
            for pair in pairs.values()
        )
        lines.append(f"| {profile}/{product} | {passed}/{len(pairs)} |")
    lines += [
        "",
        "## Hook latency",
        "",
        "Milliseconds, including process and sandbox startup. "
        "Post-write latency excludes denied writes.",
        "First invocation uses a fresh product process/fixture, "
        "not cold OS page caches.",
        "Startup-warmed trials use their own fresh fixture/daemon, with two "
        "git-status hook envelopes first. No compiler-result cache is prewarmed.",
        "Pooled timings mix languages and different amounts of work; "
        "do not treat them as a speed ranking.",
        "",
        "| Profile / product | Cache | Pre median / p95 | "
        "Post median / p95 | Total median / p95 |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for key, data in sorted(results.items()):
        for cache, metrics in data["latency"].items():
            cells = [
                f"{metrics[field]['median']:.2f} / {metrics[field]['p95']:.2f}"
                if metrics[field]
                else "not measured"
                for field in ("pre_ms", "post_ms", "total_ms")
            ]
            lines.append(f"| {key} | {cache} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Explicit Go/Rust audit commands",
        "",
        "Separate from ordinary hooks. Loki runs `scan --base HEAD`; "
        "Interlinked runs `verify --json`.",
        "The commands have product-defined scopes. "
        "No claim of identical internal checks.",
        "",
        "| Product | Targeted defects found | Controls exiting zero |",
        "| --- | ---: | ---: |",
    ]
    for product in ("loki", "interlinked"):
        scans = [
            scan
            for row in rows
            if row["product"] == product and row["profile"] == "shared"
            for scan in row["scans"]
        ]
        bad = [scan for scan in scans if scan["kind"] == "defect"]
        good = [scan for scan in scans if scan["kind"] == "control"]
        lines.append(
            f"| {product} | {sum(scan['targeted'] for scan in bad)}/{len(bad)} | "
            f"{sum(scan['exit'] == 0 for scan in good)}/{len(good)} |"
        )
    lines += ["", "## Misses and unrelated blocks", ""]
    for row in rows:
        if (
            row["profile"] == "shared"
            and row["kind"] == "defect"
            and not row["caught_all_runs"]
        ):
            outcome = ", ".join(row["outcomes"]) or "infrastructure error"
            lines.append(
                f"- {row['product']}: `{row['case']}` step {row['step']}: {outcome}."
            )
    lines += ["", "## False blocks and instability", ""]
    for row in rows:
        if row["false_block_any_run"] or row["inconsistent"] or row["error"]:
            outcome = ", ".join(row["outcomes"]) or "infrastructure error"
            lines.append(
                f"- {row['profile']}/{row['product']}: `{row['case']}` "
                f"step {row['step']}: {outcome}."
            )
    lines += [
        "",
        "## Scoring audit",
        "",
        "The final scorer decodes native JSON and matches diagnostic lines, "
        "not regexes spanning escaped newlines. It excludes Node module-format "
        "notices from targeted detection. Raw records retain provisional outcomes.",
        "Corrections are listed below and in scorecard.json.",
        "",
    ]
    for row in rows:
        if row["scoring_corrections"]:
            lines.append(
                f"- {row['profile']}/{row['product']} `{row['case']}`: "
                f"{row['provisional_outcomes']} -> {row['outcomes']}."
            )
    changes = Counter(row["product"] for row in rows if row["post_modified"])
    lines += [
        "",
        "## Coverage and limitations",
        "",
        f"Steps with post-hook byte changes: {dict(changes)}.",
        "Steps with unexpected pre-hook byte changes: "
        f"{sum(row['pre_modified'] for row in rows)}.",
        "",
        *["- " + note for note in manifest["limitations"]],
        "- Cases include intentional policy violations, compiler errors, "
        "and semantic security gaps.",
        "- No live model writes, production repositories, "
        "long-running autonomous sessions, or cloud services.",
        "- The missing-JS profile removes project-local JS tools; "
        "it is not a no-tools machine.",
        "- The main profile supplies Biome's recommended config to both products "
        "and uses installed product policy otherwise.",
        "- Source formatting for Go, Rust, and Elixir happens before each proposed "
        "edit, outside measured hook time.",
        "- Native command hooks are invoked as installed. Separate live-host "
        "probes only establish startup activation.",
        "",
        "Raw handler output, exact corpus, schedule, tool versions, hashes, "
        "and audit output are in adjacent JSON files.",
    ]
    save(
        directory / "scorecard.json",
        {
            "groups": results,
            "rows": rows,
            "reporter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
    )
    with (directory / "report.md").open("x") as stream:
        stream.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    render(args.directory.resolve())


if __name__ == "__main__":
    main()
