"""Content heuristics: prompt-injection signals and secret detection.

These are deliberately transparent, regex-based scorers. They are *not* the
detection logic by themselves; they feed confidence values into the taint
engine, which reasons about where content came from and where it went.
A page that says "ignore previous instructions" is only interesting when the
agent subsequently acts on it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# (signal name, regex, weight). Combined with noisy-OR so stacking signals
# raises confidence smoothly without exceeding 1.0.
_INJECTION_SIGNALS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "override_instructions",
        re.compile(r"\b(ignore|disregard|forget)\b.{0,25}\b(previous|prior|above|earlier|all)\b.{0,15}\b(instruction|direction|rule|prompt|guideline)s?\b", re.I | re.S),
        0.60,
    ),
    (
        "role_reassignment",
        re.compile(r"\b(you are now|from now on,? you|act as (an?|the) (unrestricted|unfiltered|new)|new (system )?instructions?\s*:|system (prompt|message)\s*:)", re.I),
        0.45,
    ),
    (
        "concealment",
        re.compile(r"\b(do not|don't|never|without)\b.{0,30}\b(tell|inform|mention|reveal|notify|show|alert|disclos\w+)\b.{0,40}\b(user|human|owner|operator|anyone)\b", re.I | re.S),
        0.55,
    ),
    (
        "ai_directed_imperative",
        re.compile(r"\b(ai|assistant|agent|model|llm|bot|copilot)\b.{0,30}\b(must|should|needs? to|is required to|has to|will now)\b", re.I),
        0.35,
    ),
    (
        "exfil_instruction",
        re.compile(r"\b(send|post|forward|upload|transmit|submit|exfiltrate|email|paste|put)\b.{0,80}\b(to|at|into)\b\s+(https?://|[\w.+-]+@[\w-]+\.[\w.-]+|the (following|this) (url|address|endpoint|server))", re.I | re.S),
        0.45,
    ),
    (
        "secret_targeting",
        re.compile(r"\b(api[ _-]?keys?|passwords?|secrets?|tokens?|credentials?|private keys?|\.env\b|id_rsa|aws_secret|access[ _-]?keys?|session cookies?)\b", re.I),
        0.25,
    ),
    (
        "tool_invocation_directive",
        re.compile(r"\b(call|invoke|use|run|execute|trigger)\b\s+(the\s+)?(tool|function|command|action|plugin)\b", re.I),
        0.30,
    ),
    (
        "hidden_html_comment",
        re.compile(r"<!--.{10,}?-->", re.S),
        0.25,
    ),
    (
        "zero_width_chars",
        re.compile(r"[​‌‍⁠﻿]{3,}"),
        0.45,
    ),
    (
        "markdown_image_beacon",
        re.compile(r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*\)", re.I),
        0.50,
    ),
    (
        "attention_marker",
        re.compile(r"\b(important|urgent|attention|note to (the )?(ai|assistant|agent)|system note|admin override)\b\s*[:!]", re.I),
        0.20,
    ),
    (
        "base64_blob",
        re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])"),
        0.15,
    ),
    (
        "jailbreak_persona",
        re.compile(r"\b(DAN|do anything now|developer mode|no restrictions|without any (safety|ethical) (guidelines|restrictions|filters))\b", re.I),
        0.50,
    ),
    (
        "memory_persistence_directive",
        re.compile(r"\b(remember|store|save|memori[sz]e)\b.{0,30}\b(this|these|the following)\b.{0,30}\b(instruction|rule|preference|always|every time)", re.I | re.S),
        0.35,
    ),
]


@dataclass(frozen=True)
class InjectionScore:
    score: float
    signals: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"score": round(self.score, 3), "signals": list(self.signals)}


_WEIGHTS = {name: w for name, _, w in _INJECTION_SIGNALS}
# Evidence that content was deliberately hidden or encoded. Except for hidden
# Unicode tag text (which has essentially no benign use outside emoji flags,
# filtered by length), these only count alongside a content signal: zero-width
# joiners appear in emoji and some scripts, mixed scripts in some brand names.
_OBFUSCATION_WEIGHTS = {
    "hidden_unicode_tags": 0.6,
    "homoglyph_obfuscation": 0.35,
    "invisible_char_obfuscation": 0.25,
    "encoded_instruction": 0.35,
    "spaced_letter_obfuscation": 0.2,
}
_WEIGHTS.update(_OBFUSCATION_WEIGHTS)


def _signals_in(text: str) -> set[str]:
    return {name for name, rx, _ in _INJECTION_SIGNALS if rx.search(text)}


def score_injection(text: str) -> InjectionScore:
    """Return a noisy-OR combined injection likelihood in [0, 1].

    Signals are collected over the original text *and* every de-obfuscated view
    (``taintline.normalize.detection_views``); the obfuscation techniques found
    are themselves signals.
    """
    if not text:
        return InjectionScore(0.0, ())
    from taintline.normalize import detection_views

    views = detection_views(text)
    original = _signals_in(text)
    names = set(original)
    decoded_extra: set[str] = set()
    for view_name, view_text in views.views.items():
        found = _signals_in(view_text)
        if view_name in ("decoded_blobs", "unicode_tags", "rot13", "reversed"):
            decoded_extra |= found - original
        names |= found

    obf = views.obfuscation
    content = set(names)
    tag_text = views.views.get("unicode_tags", "")
    if len(tag_text) >= 8 and (" " in tag_text or content):
        names.add("hidden_unicode_tags")
    if content:
        if obf.get("homoglyphs"):
            names.add("homoglyph_obfuscation")
        if obf.get("invisible_chars", 0) >= 2:
            names.add("invisible_char_obfuscation")
        if obf.get("spaced_letters"):
            names.add("spaced_letter_obfuscation")
        if decoded_extra - {"base64_blob", "secret_targeting"}:
            names.add("encoded_instruction")

    if not names:
        return InjectionScore(0.0, ())
    # secret_targeting alone (a page about password managers) is noise;
    # only count it in combination with an imperative signal.
    if names <= {"secret_targeting", "attention_marker"}:
        return InjectionScore(0.05, tuple(sorted(names)))
    prod = 1.0
    for n in names:
        prod *= 1.0 - _WEIGHTS[n]
    return InjectionScore(round(1.0 - prod, 4), tuple(sorted(names)))


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------

# Patterns capture the full secret as group 0 unless they define a named
# group ``val`` (used when the secret is embedded in an assignment). Optional
# prefixes use non-capturing groups so group 0 is always the whole token.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*(?P<val>[A-Za-z0-9/+=]{40})")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|db_pass|secret)\s*[=:]\s*['\"]?(?P<val>[^\s'\"]{8,})")),
    ("generic_hex_secret", re.compile(r"(?i)\b(?:token|secret|key|auth)[\w-]*\s*[=:]\s*['\"]?(?P<val>[0-9a-f]{32,})")),
]


@dataclass(frozen=True)
class SecretHit:
    kind: str
    value: str

    def redacted(self) -> str:
        v = self.value
        if len(v) <= 8:
            return "*" * len(v)
        return v[:4] + "…" + v[-3:]


def find_secrets(text: str) -> list[SecretHit]:
    if not text:
        return []
    hits: list[SecretHit] = []
    seen: set[str] = set()
    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.groupdict().get("val") or m.group(0)
            if value in seen:
                continue
            seen.add(value)
            hits.append(SecretHit(kind, value))
    return hits


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())
