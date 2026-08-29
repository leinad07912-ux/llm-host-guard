"""Model file hygiene: pickle weights, malformed GGUF/safetensors, weak permissions."""
from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

from core import Ctx, Finding

NAME = "models"
PICKLE_EXT = {".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt"}
MAX_FILES = 5000


def default_dirs(ctx: Ctx) -> list[Path]:
    h = ctx.home
    cands = [
        h / ".ollama" / "models", Path("/usr/share/ollama/.ollama/models"),
        h / ".cache" / "huggingface" / "hub", h / ".cache" / "lm-studio" / "models",
        h / ".lmstudio" / "models", h / "jan" / "models", h / ".jan" / "models",
        h / ".cache" / "gpt4all", h / "models",
    ]
    cands += ctx.extra_model_dirs
    return [p for p in cands if p.is_dir()]


def check_gguf(p: Path) -> str | None:
    """Return problem string or None."""
    try:
        with p.open("rb") as f:
            magic = f.read(4)
            if magic != b"GGUF":
                return "bad magic (not GGUF despite extension)"
            ver, = struct.unpack("<I", f.read(4))
            if not 1 <= ver <= 3:
                return f"unknown GGUF version {ver}"
            n_tensors, n_kv = struct.unpack("<QQ", f.read(16))
            if n_tensors > 1_000_000 or n_kv > 1_000_000:
                return f"implausible header (tensors={n_tensors}, kv={n_kv}) — crafted file?"
    except (OSError, struct.error):
        return "truncated header"
    return None


def check_safetensors(p: Path) -> str | None:
    try:
        size = p.stat().st_size
        with p.open("rb") as f:
            n, = struct.unpack("<Q", f.read(8))
            if n > size or n > 100_000_000:
                return f"header length {n} exceeds file size {size} — crafted file?"
            if f.read(1) != b"{":
                return "header is not JSON"
    except (OSError, struct.error):
        return "truncated header"
    return None


def run(ctx: Ctx) -> list[Finding]:
    dirs = default_dirs(ctx)
    if not dirs:
        return [Finding(NAME, "INFO", "No model directories found", "Pass --model-dir to scan a custom path.")]
    out, pickles, bad, ww, n = [], [], [], [], 0
    for d in dirs:
        try:
            if d.stat().st_mode & stat.S_IWOTH:
                ww.append(str(d))
        except OSError:
            pass
        for root, _, files in os.walk(d, followlinks=False):
            for fn in files:
                n += 1
                if n > MAX_FILES:
                    break
                p = Path(root) / fn
                ext = p.suffix.lower()
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or st.st_size == 0 or ".no_exist" in root:
                    continue
                if st.st_mode & stat.S_IWOTH:
                    ww.append(str(p))
                if ext in PICKLE_EXT:
                    pickles.append(str(p))
                elif ext == ".gguf" and (err := check_gguf(p)):
                    bad.append(f"{p}: {err}")
                elif ext == ".safetensors" and (err := check_safetensors(p)):
                    bad.append(f"{p}: {err}")
    if pickles:
        out.append(Finding(NAME, "HIGH", f"{len(pickles)} pickle-format weight file(s) — execute code on load",
                           "torch.load on .pt/.bin/.ckpt runs arbitrary Python inside the file. A poisoned "
                           "download = RCE the moment the model loads. Examples: " + "; ".join(pickles[:3]),
                           "Prefer .safetensors / .gguf; convert with `safetensors` or `convert_hf_to_gguf.py`; "
                           "only load pickles from publishers you trust and verify sha256.",
                           {"files": pickles[:50]}))
    if bad:
        out.append(Finding(NAME, "HIGH", f"{len(bad)} malformed model file(s)",
                           "Header fails sanity checks — could be corruption or a file crafted to hit a parser CVE. "
                           + "; ".join(bad[:3]),
                           "Delete and re-download from the original source; verify checksum.",
                           {"files": bad[:50]}))
    if ww:
        out.append(Finding(NAME, "MED", f"{len(ww)} world-writable model path(s)",
                           "Any local user or compromised service can swap model weights. " + "; ".join(ww[:3]),
                           "chmod o-w on the model directory and files.", {"paths": ww[:50]}))
    if not out:
        out.append(Finding(NAME, "OK", f"Scanned {n} files in {len(dirs)} model dir(s): no pickle weights, headers sane"))
    return out
