"""Run the comprehensive lifecycle runner on the independently authored holdout.

The holdout cases in holdout_cases.json were written by a separate agent that was
not allowed to read either product's rules, templates or the development corpus.
Loki rules were not tuned on these cases before the first recorded run.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from benchmarks import comprehensive, corpus  # noqa: E402

# LOKI_HOLDOUT_CASES selects another blind holdout, e.g. holdout2_cases.json.
CASES = Path(
    os.environ.get("LOKI_HOLDOUT_CASES")
    or Path(__file__).with_name("holdout_cases.json")
).resolve()
original_manifest = corpus.manifest
original_identity = comprehensive.identity
original_save = comprehensive.save


def cases():
    result = []
    for item in json.loads(CASES.read_text()):
        name = f"{CASES.stem.removesuffix('_cases')}/{item['language']}/{item['name']}"
        for phase in ("defect", "control"):
            result.append(
                {
                    "id": f"{name}/{phase}",
                    "pair": name,
                    "language": item["language"],
                    "family": item.get("category", "bug"),
                    "base": item.get("base", {}),
                    "steps": [
                        corpus.step(
                            item["path"],
                            item[phase],
                            phase,
                            item["markers"] if phase == "defect" else (),
                        )
                    ],
                }
            )
    return result


def manifest():
    items = cases()
    ids = [case["id"] for case in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate holdout IDs")
    encoded = json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    return {
        "version": CASES.stem,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "cases": items,
    }


def identity(args):
    return {
        **original_identity(args),
        **{
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__).resolve(), CASES)
        },
    }


def save(path, value):
    if path.name == "manifest.json":
        value = {
            **value,
            "scope": (
                "Independently authored holdout cases through installed Claude "
                "pre/post lifecycles; no models; no Bash payload execution."
            ),
        }
    return original_save(path, value)


def main():
    corpus.manifest = manifest
    comprehensive.identity = identity
    comprehensive.save = save
    try:
        return comprehensive.main()
    finally:
        corpus.manifest = original_manifest
        comprehensive.identity = original_identity
        comprehensive.save = original_save


if __name__ == "__main__":
    raise SystemExit(main())
