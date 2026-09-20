from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "loki.py"

if "loki" not in sys.modules:
    spec = importlib.util.spec_from_file_location("loki", ENGINE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {ENGINE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["loki"] = module
    spec.loader.exec_module(module)
