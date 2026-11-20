# codehygiene (vendored)

`__init__.py` and `weights.npz` are copied unchanged from https://github.com/brianbell-x/codehygiene at commit
`423c7e1` (version 0.4.0, 2026-11-15). `loki.py` reads both and runs them.

- `__init__.py` sha256 `3c991bf39392e2d06bc2c3da152f3857c8a263a079530091942e17f0625f1848`
- `weights.npz` sha256 `85a3d926cd71f0f6024b0ee1e0cb5223980c046203bf8fbcf68a6598ee9c0e0d`

License: MIT, as declared in upstream's `pyproject.toml` (`license = {text = "MIT"}`). Upstream ships no LICENSE
file and names no copyright holder; the author is Brian Bell (github.com/brianbell-x).

To update: copy the two files from a newer commit, change the commit and hashes above, and run
`uv run pytest -q tests/test_hygiene.py`.
