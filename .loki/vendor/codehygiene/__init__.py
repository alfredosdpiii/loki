"""1.58-bit ternary weight-space programmed System One model for code readability and hygiene."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from functools import lru_cache
import json
import math
import os
from pathlib import Path
import sys
from typing import Any
import numpy as np

__version__ = "0.4.0"
__all__ = [
    "ARCHETYPE_NAMES", "MAX_COLS", "MAX_REL_DIST", "Result", "SCORE_NAMES",
    "SQUIGGLE_KINDS", "SQUIGGLE_MESSAGES", "Squiggle", "encode_byte_grid",
    "lint", "load_weights", "main", "render_report", "rl_reward", "score",
    "unpack_ternary_archive",
]

MAX_COLS = 128
MAX_REL_DIST = 32
_SKETCH_DIM = 40
_POW3 = 3 ** np.arange(5, dtype=np.uint8)

_CODE_EXTS = frozenset({
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".c", ".h",
    ".cc", ".cpp", ".hpp", ".rs", ".go", ".zig", ".java", ".cs", ".lua", ".rb",
    ".php", ".swift", ".kt", ".scala", ".sh",
})
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "target",
    "build", "dist", "venv", ".venv", ".tox", ".mypy_cache", ".pytest_cache",
})

_SPEC = (
    ("deep_nesting", "Deep nesting; flatten with guard clauses"),
    ("poor_naming", "Over-abstracted (*Factory), cryptic short name, or magic index"),
    ("noisy_comment", "Comment restates code or leaves TODO/lint noise"),
    ("swallowed_error", "Ignored error or silent fallback value"),
    ("dense_line", "Long line, chained calls, or nested ternary"),
    ("special_casing", "Stacked hardcoded special-case branches"),
    ("duplicate_block", "Duplicated logic block"),
    ("cramped_layout", "Unbroken statement wall or inconsistent indent"),
)
SQUIGGLE_KINDS = tuple(kind for kind, _ in _SPEC)
SQUIGGLE_MESSAGES = dict(_SPEC)

SCORE_NAMES = (
    "flatness", "naming", "simplicity",
    "comments", "error_handling", "layout",
)
ARCHETYPE_NAMES = (
    "minimal", "clean", "enterprise",
    "dense", "slop",
)
_N_SCORES = len(SCORE_NAMES)
_SCORE_LOGIT_END = 2 + 4 * _N_SCORES
_STYLE_LOGIT_END = _SCORE_LOGIT_END + len(ARCHETYPE_NAMES)

_LEVELS = np.array([0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0], dtype=np.float32)
_ANSI = ("\033[1m", "\033[2m", "\033[33m", "\033[36m", "\033[32m", "\033[31m", "\033[0m")


@dataclass
class Squiggle:
    line: int
    col_start: int
    col_end: int
    probability: float
    kind: str
    message: str


@dataclass
class Result:
    score: float
    rl_hygiene: float
    scores: dict[str, float]
    archetype: str
    archetype_probs: dict[str, float]
    squiggles: list[Squiggle]
    line_probs: np.ndarray

    def to_dict(self) -> dict[str, Any]:
        items = [{**asdict(sq), "probability": round(sq.probability, 4)} for sq in self.squiggles]
        return {
            "score": round(self.score, 4),
            "rl_hygiene": round(self.rl_hygiene, 4),
            "scores": {name: round(val, 4) for name, val in self.scores.items()},
            "archetype": self.archetype,
            "archetype_probs": {name: round(val, 4) for name, val in self.archetype_probs.items()},
            "squiggles": items,
        }


def _relu(arr: np.ndarray) -> np.ndarray:
    return np.maximum(arr, 0.0)


def _sigmoid(arr: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(arr, -30.0, 30.0)))


def _softmax(arr: np.ndarray) -> np.ndarray:
    shifted = np.exp(arr - np.max(arr, axis=-1, keepdims=True))
    return shifted / np.sum(shifted, axis=-1, keepdims=True)


def _l2_norm(arr: np.ndarray, eps: float = 2.5) -> np.ndarray:
    return arr / np.sqrt(np.sum(arr * arr, axis=-1, keepdims=True) + eps)


def _conv1d(cells: np.ndarray, kernel: np.ndarray, bias: np.ndarray) -> np.ndarray:
    num_lines, num_cols, _ = cells.shape
    k_size, _, out_channels = kernel.shape
    active_in = np.flatnonzero(np.any(kernel != 0, axis=(0, 2)))
    sub_cells = cells[:, :, active_in]
    sub_kern = np.ascontiguousarray(kernel[:, active_in, :])

    pad = (k_size - 1) // 2
    pad_widths = ((0, 0), (pad, k_size - 1 - pad), (0, 0))
    padded = np.pad(sub_cells, pad_widths) if k_size > 1 else sub_cells
    stride_cols = num_cols + k_size - 1
    flat_in = padded.reshape(-1, len(active_in))
    span = num_lines * stride_cols - (k_size - 1)

    flat_out = np.empty((num_lines * stride_cols, out_channels), dtype=np.float32)
    flat_out[:span] = bias
    for offset in range(k_size):
        k_slice = sub_kern[offset]
        if k_slice.any():
            flat_out[:span] += flat_in[offset : offset + span] @ k_slice
    return flat_out.reshape(num_lines, stride_cols, out_channels)[:, :num_cols, :]


def _sink_attn(
    state: np.ndarray,
    wq: np.ndarray,
    wk: np.ndarray,
    wv: np.ndarray,
    wo: np.ndarray,
    b_rel: np.ndarray,
    b_sink: np.ndarray,
) -> np.ndarray:
    """Multi-head relative-offset attention across lines with an unmatched-query sink logit."""
    num_lines, num_heads = state.shape[0], b_sink.shape[0]
    head_dim = wq.shape[1] // num_heads
    q_proj, k_proj, v_proj = (
        (state @ weight).reshape(num_lines, num_heads, -1).transpose(1, 0, 2)
        for weight in (wq, wk, wv)
    )

    line_idx = np.arange(num_lines)
    rel_dist = line_idx[None, :] - line_idx[:, None]
    rel_idx = np.clip(rel_dist, -MAX_REL_DIST, MAX_REL_DIST) + MAX_REL_DIST

    scale = np.sqrt(float(head_dim))
    attn_logits = (q_proj @ k_proj.transpose(0, 2, 1)) / scale + b_rel[:, rel_idx]
    sink_col = np.broadcast_to(b_sink[:, None, None], (num_heads, num_lines, 1))
    attn_weights = _softmax(np.concatenate([attn_logits, sink_col], axis=-1))[:, :, :num_lines]
    merged = (attn_weights @ v_proj).transpose(1, 0, 2).reshape(num_lines, -1)
    return merged @ wo


def encode_byte_grid(code: str, max_lines: int = 2048) -> tuple[np.ndarray, list[str]]:
    """Convert raw source text into a (lines, 128) uint8 grid of 7-bit ASCII codes."""
    lines = (code.expandtabs(2).splitlines() or [""])[:max_lines]
    grid = np.zeros((len(lines), MAX_COLS), dtype=np.uint8)
    for row, text in enumerate(lines):
        if not text:
            continue
        clipped = text[:MAX_COLS]
        if clipped.isascii():
            ascii_codes = np.frombuffer(clipped.encode("ascii"), dtype=np.uint8)
        else:
            codepoints = np.frombuffer(clipped.encode("utf-32-le"), dtype=np.uint32)
            ascii_codes = np.minimum(codepoints, 127).astype(np.uint8)
        grid[row, : len(ascii_codes)] = np.where(ascii_codes == 0, 32, ascii_codes)
    return grid, lines


def _forward(params: dict[str, np.ndarray], grid: np.ndarray) -> tuple[np.ndarray, ...]:
    # Block 0: byte/column embeddings + causal quote and comment masks -> cells (L, W, 52)
    width = grid.shape[1]
    emb = params["tok_emb"][grid] + params["col_emb"][None, :width, :]
    lex = _relu(_conv1d(emb, params["pre_conv3_w"], params["pre_conv3_b"]))

    lex_cat = np.concatenate([emb, lex], axis=-1)
    prefix1 = params["W_causal1"][:width, :width] @ (lex_cat @ params["pref1_proj"])
    gates = _relu(
        np.concatenate([emb, lex, prefix1], axis=-1) @ params["gate1_w"] + params["gate1_b"]
    )
    prefix2 = params["W_causal2"][:width, :width] @ (gates @ params["pref2_proj"])
    cells = _relu(
        np.concatenate([emb, lex, gates, prefix2], axis=-1) @ params["col_fuse_w"]
        + params["col_fuse_b"]
    )

    # Block 1: k=3/7/13 pattern convolutions + 40-dim SimHash stem sketches -> state (L, N_Z)
    conv3 = _relu(_conv1d(cells, params["conv3_w"], params["conv3_b"])).sum(axis=1)
    conv7 = _relu(_conv1d(cells, params["conv7_w"], params["conv7_b"])).sum(axis=1)
    conv13 = _relu(_conv1d(cells, params["conv13_w"], params["conv13_b"])).sum(axis=1)
    col_sums = cells.sum(axis=1) @ params["col_sum_proj"]

    raw_sketch = _relu(_conv1d(cells, params["sketch_w"], params["sketch_b"])).sum(axis=1)
    sketch = _relu(raw_sketch) - _relu(raw_sketch - 1.0)
    line_feats = np.concatenate([col_sums, conv3, conv7, conv13], axis=-1)
    line_hidden = _relu(line_feats @ params["lmlp1_w"] + params["lmlp1_b"])
    line_stats = line_hidden @ params["lmlp2_w"] + params["lmlp2_b"]
    state = np.concatenate(
        [line_stats, _l2_norm(sketch[:, :_SKETCH_DIM]), _l2_norm(sketch[:, _SKETCH_DIM:])],
        axis=-1,
    )

    # Block 2: two cross-line sink-attention + context-MLP passes over [-32..+32] offsets
    for layer in ("1", "2"):
        state = state + _sink_attn(
            state,
            params[f"attn{layer}_wq"],
            params[f"attn{layer}_wk"],
            params[f"attn{layer}_wv"],
            params[f"attn{layer}_wo"],
            params[f"attn{layer}_brel"],
            params[f"attn{layer}_bsink"],
        )
        ctx_hidden = _relu(state @ params[f"cmlp{layer}_w"] + params[f"cmlp{layer}_b"])
        state = state + ctx_hidden @ params[f"cmlp{layer}_2_w"] + params[f"cmlp{layer}_2_b"]

    # Block 3: per-line squiggle probabilities + active-line pooling into System One logits
    line_probs = _sigmoid(state @ params["sq_w"] + params["sq_b"])
    active_gate = _sigmoid(state @ params["pool_gate_w"] + params["pool_gate_b"])
    doc_mean = (state * active_gate).sum(axis=0) / (active_gate.sum(axis=0) + 1e-5)
    doc_max = (_relu(state) * active_gate).max(axis=0)
    doc_vec = np.concatenate([doc_mean, doc_max], axis=-1)
    doc_hidden = _relu(doc_vec @ params["doc1_w"] + params["doc1_b"])
    logits = doc_hidden @ params["doc2_w"] + params["doc2_b"]

    noul_probs = _sigmoid(logits[:2])
    score_grid = logits[2:_SCORE_LOGIT_END].reshape(_N_SCORES, 4)
    subscores = (_softmax(score_grid) * _LEVELS[None, :]).sum(axis=-1)
    style_probs = _softmax(logits[_SCORE_LOGIT_END:_STYLE_LOGIT_END])
    return line_probs, noul_probs, subscores, style_probs


def unpack_ternary_archive(
    trit_buf: np.ndarray,
    vec_buf: np.ndarray,
    meta_str: str,
) -> dict[str, np.ndarray]:
    """Unpack 5-trit-per-byte {-1, 0, +1} matrices and fold 1D per-channel scales."""
    trit_part, vec_part = meta_str.split("|")
    vecs: dict[str, np.ndarray] = {}
    vec_offset = 0
    for entry in vec_part.split(" ; "):
        name, dims, count_str = entry.split(":")
        count = int(count_str)
        shape = tuple(int(dim) for dim in dims.split(","))
        vecs[name] = vec_buf[vec_offset : vec_offset + count].reshape(shape).astype(np.float32)
        vec_offset += count

    unpacked_digits = (((trit_buf[:, None] // _POW3) % 3 + 1) % 3).astype(np.int8) - 1
    flat_trits = unpacked_digits.ravel()
    params: dict[str, np.ndarray] = {}
    byte_offset = 0

    for entry in trit_part.split(" ; "):
        name, dims, packed_len_str = entry.split(":")
        packed_len = int(packed_len_str)
        shape = tuple(int(dim) for dim in dims.split(","))
        num_elems = math.prod(shape)
        trit_start = byte_offset * 5
        mat = flat_trits[trit_start : trit_start + num_elems].reshape(shape).astype(np.float32)
        byte_offset += packed_len

        scale_key = f"{name[:-2]}_s" if name.endswith("_w") else f"{name}_s"
        if name == "col_sum_proj":
            scale_key = "col_sum_s"
        if scale_key in vecs:
            mat = mat * vecs[scale_key]
        params[name] = mat

    for name, val in vecs.items():
        if not name.endswith("_s"):
            params[name] = val
    return params


@lru_cache(maxsize=2)
def load_weights(path: str | Path | None = None) -> dict[str, np.ndarray]:
    target = Path(path) if path else Path(__file__).with_name("weights.npz")
    with np.load(target) as archive:
        if "trits" in archive.files:
            return unpack_ternary_archive(
                archive["trits"], archive["vecs"], str(archive["meta"].item())
            )
        return {name: archive[name].astype(np.float32) for name in archive.files}


def score(
    code: str,
    *,
    threshold: float = 0.55,
    weights: dict[str, np.ndarray] | None = None,
) -> Result:
    grid, lines = encode_byte_grid(code)
    line_probs, heads, subscores, styles = _forward(weights or load_weights(), grid)
    squiggles: list[Squiggle] = []

    for idx, raw_line in enumerate(lines):
        best_kind = int(np.argmax(line_probs[idx]))
        prob = float(line_probs[idx, best_kind])
        if prob < threshold:
            continue
        stripped = raw_line.lstrip(" ")
        col_start = len(raw_line) - len(stripped) + 1 if stripped else 1
        kind = SQUIGGLE_KINDS[best_kind]
        squiggles.append(
            Squiggle(
                line=idx + 1,
                col_start=col_start,
                col_end=max(col_start, len(raw_line)),
                probability=prob,
                kind=kind,
                message=SQUIGGLE_MESSAGES[kind],
            )
        )

    return Result(
        score=float(heads[0]),
        rl_hygiene=float(heads[1]),
        scores=dict(zip(SCORE_NAMES, map(float, subscores))),
        archetype=ARCHETYPE_NAMES[int(np.argmax(styles))],
        archetype_probs=dict(zip(ARCHETYPE_NAMES, map(float, styles))),
        squiggles=squiggles,
        line_probs=line_probs,
    )


def lint(code: str, *, threshold: float = 0.55) -> list[Squiggle]:
    return score(code, threshold=threshold).squiggles


def rl_reward(
    code: str,
    tests_passed: bool | float = True,
    *,
    weight: float = 0.25,
    hygiene_blend: float = 0.5,
) -> float:
    gate = float(tests_passed)
    if gate <= 0.0:
        return 0.0
    res = score(code)
    blended = (1.0 - hygiene_blend) * res.score + hygiene_blend * res.rl_hygiene
    return gate * (1.0 + weight * blended)


def render_report(
    label: str,
    src: str,
    thresh: float = 0.55,
    color: bool = True,
    res: Result | None = None,
) -> str:
    _, lines = encode_byte_grid(src, max_lines=100_000)
    result = res or score(src, threshold=thresh)
    bold, dim, yel, cyan, grn, red, rst = _ANSI if color else ("",) * 7
    tone = (red, yel, grn)[int(result.score >= 0.40) + int(result.score >= 0.70)]
    style_pct = result.archetype_probs[result.archetype] * 100

    out = [
        f"{bold}{label}{rst}",
        f"  score: {tone}{result.score:.3f}{rst}  rl_hygiene: {cyan}{result.rl_hygiene:.3f}{rst}  "
        f"style: {bold}{result.archetype}{rst} ({style_pct:.0f}%)",
    ]
    for name, val in result.scores.items():
        filled = int(round(max(0.0, min(1.0, val)) * 16))
        bar = "#" * filled + "." * (16 - filled)
        out.append(f"    {name:15s} {bar} {val:.2f}")
    if not result.squiggles:
        return "\n".join([*out, f"\n  {grn}ok - no squiggles (threshold {thresh:.2f}){rst}"])

    out.append(f"\n  {yel}{len(result.squiggles)} squiggle(s):{rst}")
    for sq in result.squiggles:
        src_line = lines[sq.line - 1]
        indent_pad = " " * (sq.col_start - 1)
        wavy = "~" * max(1, min(len(src_line) - sq.col_start + 1, 72))
        tag = f"[{sq.kind} {sq.probability:.2f}]"
        out.append(f"  {dim}{sq.line:4d} |{rst} {src_line}")
        out.append(f"       {dim}|{rst} {indent_pad}{yel}{wavy} {tag}{rst} {dim}{sq.message}{rst}")
    return "\n".join(out)


def _walk_dir(root: Path) -> list[Path]:
    found: list[Path] = []
    for cur_dir, subdirs, filenames in os.walk(root):
        subdirs[:] = sorted(
            name for name in subdirs
            if not name.startswith(".") and name not in _SKIP_DIRS and not name.endswith(".egg-info")
        )
        base = Path(cur_dir)
        found.extend(
            base / fname for fname in sorted(filenames) if Path(fname).suffix.lower() in _CODE_EXTS
        )
    return found


def _expand_paths(specs: list[str]) -> list[Path]:
    expanded: list[Path] = []
    for spec in specs:
        matches = sorted(Path().glob(spec)) if any(ch in spec for ch in "*?[") else [Path(spec)]
        for path in matches:
            expanded.extend(_walk_dir(path) if path.is_dir() else [path])
    return expanded


def main(argv: list[str] | None = None) -> int:
    desc = "A 13 KB, 1.58-bit ternary weight-space programmed System One model for code hygiene."
    parser = argparse.ArgumentParser(prog="codehygiene", description=desc)
    parser.add_argument("files", nargs="*", help="Files, directories, or globs (stdin if piped)")
    parser.add_argument("-t", "--threshold", type=float, default=0.55, help="Squiggle threshold")
    parser.add_argument("--check", action="store_true", help="Exit 1 when squiggles are found")
    parser.add_argument("--json", action="store_true", help="Output structured JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if not args.files and sys.stdin.isatty():
        parser.print_help()
        return 0
    paths = _expand_paths(args.files)
    targets = [(path.as_posix(), path.read_text("utf-8", "replace")) for path in paths]
    if not args.files:
        targets = [("<stdin>", sys.stdin.read())]
    if not targets:
        return 0

    runs = [(label, src, score(src, threshold=args.threshold)) for label, src in targets]
    exit_code = 1 if (args.check and any(res.squiggles for _, _, res in runs)) else 0
    if args.json:
        payloads = [res.to_dict() for _, _, res in runs]
        is_single = len(payloads) == 1 and (not args.files or not Path(args.files[0]).is_dir())
        body = payloads[0] if is_single else dict(zip((lbl for lbl, _, _ in runs), payloads))
        print(json.dumps(body, indent=2))
        return exit_code

    reports = [
        render_report(lbl, src, args.threshold, not args.no_color, res)
        for lbl, src, res in runs
    ]
    print("\n\n".join(reports))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
