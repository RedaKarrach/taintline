"""Cheap lexical provenance measures used for data-flow taint.

Two asymmetric measures over character n-gram shingles:

* ``containment(src, dst)``  - what fraction of *src* appears inside *dst*.
  "How much of the secret leaked into this request?"
* ``provenance(src, dst)``   - what fraction of *dst* originates from *src*.
  "How much of this tool call was lifted from the untrusted page?"

Shingles are 8 characters by default: long enough that natural-language
collisions are rare, short enough to catch secrets exfiltrated in chunks.
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")
_DEST_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_DEST_URL = re.compile(r"https?://([^/\s\"'<>]+)", re.I)
_DEST_PATH = re.compile(r"(?:[A-Za-z]:)?(?:/|\\|~/)[\w./\\~-]{3,}")
_DEST_HANDLE = re.compile(r"(?<![\w@])[#@][A-Za-z][\w-]{2,}")


def normalize(s: str) -> str:
    return _WS.sub(" ", (s or "")).strip().lower()


def ngrams(s: str, n: int = 8) -> set[str]:
    s = normalize(s)
    if len(s) < n:
        return {s} if s else set()
    return {s[i : i + n] for i in range(len(s) - n + 1)}


def containment(src: str, dst: str, n: int = 8) -> float:
    a = ngrams(src, n)
    if not a:
        return 0.0
    b = ngrams(dst, n)
    return len(a & b) / len(a)


def provenance(src: str, dst: str, n: int = 8) -> float:
    b = ngrams(dst, n)
    if not b:
        return 0.0
    a = ngrams(src, n)
    return len(a & b) / len(b)


def shared_ngrams(src: str, dst: str, n: int = 8) -> set[str]:
    return ngrams(src, n) & ngrams(dst, n)


def significant_tokens(s: str, min_len: int = 12) -> set[str]:
    """Tokens long enough to be identifiers/secrets rather than words."""
    return {t for t in re.split(r"[\s,;\"'`<>()\[\]{}]+", s or "") if len(t) >= min_len}


def covered_positions(secret: str, dst: str, min_run: int = 6) -> set[int]:
    """Indices of ``secret`` whose surrounding ``min_run``-char window appears in
    ``dst``. Robust to arbitrary chunking: tiling the secret across several
    destinations unions to full coverage, which 8-gram shingles cannot do when a
    chunk is shorter than the shingle or splits mid-shingle.
    """
    s = normalize(secret)
    d = normalize(dst)
    if not s or not d:
        return set()
    if len(s) < min_run:
        return set(range(len(s))) if s in d else set()
    covered: set[int] = set()
    for i in range(len(s) - min_run + 1):
        if s[i : i + min_run] in d:
            covered.update(range(i, i + min_run))
    return covered


def destinations(text: str) -> set[str]:
    """Extract outbound destination identifiers from tool arguments."""
    out: set[str] = set()
    for m in _DEST_EMAIL.finditer(text):
        out.add(m.group(0).lower())
    # Capture URL hosts, then blank out the URLs so the path scanner below does
    # not re-match their scheme/host tails (e.g. "s://host/path").
    scrubbed = text
    for m in _DEST_URL.finditer(text):
        host = m.group(1).lower().split(":")[0]
        out.add(host)
    scrubbed = re.sub(r"https?://\S+", " ", text, flags=re.I)
    for m in _DEST_PATH.finditer(scrubbed):
        cand = m.group(0).lower().replace("\\", "/")
        if "://" in cand or cand.count("/") == 0:
            continue
        out.add(cand)
    for m in _DEST_HANDLE.finditer(text):
        out.add(m.group(0).lower())
    return out


def destination_authorized(dests: set[str], principal_text: str) -> tuple[bool, list[str]]:
    """True when at least one destination was named by the human principal."""
    if not dests:
        return False, []
    low = normalize(principal_text)
    hits = [d for d in dests if d and d in low]
    return bool(hits), hits
