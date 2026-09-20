from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch


@contextlib.contextmanager
def temporary_root() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


def write_file(root: Path, relative: str, content: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def capture_output(function, *args, **kwargs) -> tuple[object, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = function(*args, **kwargs)
    return result, stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def argv(*arguments: str) -> Iterator[None]:
    with patch.object(sys, "argv", ["loki", *arguments]):
        yield
