"""Adversarial normalization: undo the obfuscations attackers use to slip
prompt injections past pattern matching, and to smuggle secrets out encoded.

``detection_views(text)`` returns the original text plus decoded / folded
*views* of it. Injection scoring runs over every view and keeps the union of
signals; the obfuscation itself is recorded as a signal, because benign content
almost never hides text in invisible Unicode tag characters or mixes Cyrillic
letters into Latin words.

``payload_views(text)`` returns decodings relevant to data-flow tracking
(base64 / hex / percent-encoding / reversal), so a secret that leaves the
boundary encoded is still recognized.

Techniques handled
------------------
* Unicode compatibility forms (fullwidth, mathematical alphanumerics) - NFKC
* zero-width and bidi control characters, soft hyphens
* Unicode *tag* characters (U+E0000 block): invisible "ASCII smuggling"
* homoglyphs: Cyrillic / Greek look-alikes mixed into Latin words
* HTML entities and percent-encoding
* base64 and hex blobs that decode to readable text
* spaced-out letters ("i g n o r e")
* leetspeak ("1gn0r3")
* ROT13 and reversed text

A module-level switch lets the evaluation harness measure detection with and
without hardening (``with hardening(False): ...``).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import unquote

_HARDENING = True


def hardening_enabled() -> bool:
    return _HARDENING


@contextmanager
def hardening(enabled: bool) -> Iterator[None]:
    """Temporarily enable/disable adversarial normalization (for evaluation)."""
    global _HARDENING
    prev = _HARDENING
    _HARDENING = enabled
    try:
        yield
    finally:
        _HARDENING = prev


_INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_TAGS = re.compile("[\U000e0000-\U000e007f]+")

_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic
        "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
        "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
        "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
        # Greek
        "α": "a", "ο": "o", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }
)
_CONFUSABLE_CHARS = set("авекмнорстухѕіјԁԛԝӏɡАВЕКМНОРСТУХЅІЈαοειλκνρτυχΑΒΕΖΗΙΚΜΝΟΡΤΥΧ")
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SPACED = re.compile(r"(?<![A-Za-z])((?:[A-Za-z][ .\-_·•*]{1,2}){3,}[A-Za-z])(?![A-Za-z])")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _try_b64(token: str) -> str | None:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if len(text) < 8 or _printable_ratio(text) < 0.9:
        return None
    # require something word-like, not random printable bytes
    return text if re.search(r"[A-Za-z]{3,}", text) else None


def _try_hex(token: str) -> str | None:
    try:
        text = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if len(text) >= 8 and _printable_ratio(text) >= 0.9 and re.search(r"[A-Za-z]{3,}", text) else None


def decode_tags(text: str) -> str:
    """Decode Unicode tag characters (U+E0020..U+E007E map to ASCII)."""
    out = []
    for m in _TAGS.finditer(text):
        out.append("".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E))
    return " ".join(x for x in out if x)


def mixed_script_words(text: str) -> int:
    """Words that mix Latin letters with Cyrillic/Greek look-alikes."""
    n = 0
    for w in _WORD.findall(text):
        has_latin = any("a" <= c.lower() <= "z" for c in w)
        if has_latin and any(c in _CONFUSABLE_CHARS for c in w):
            n += 1
    return n


@dataclass
class Views:
    original: str
    views: dict[str, str] = field(default_factory=dict)  # name -> derived text (differs from original)
    obfuscation: dict[str, int] = field(default_factory=dict)  # technique -> count

    def all_texts(self) -> list[tuple[str, str]]:
        return [("original", self.original), *self.views.items()]


def detection_views(text: str) -> Views:
    v = Views(original=text or "")
    if not text or not _HARDENING:
        return v

    tags = decode_tags(text)
    if tags:
        v.views["unicode_tags"] = tags
        v.obfuscation["unicode_tags"] = len(tags)

    invisible = len(_INVISIBLE.findall(text))
    base = _TAGS.sub("", _INVISIBLE.sub("", text))
    if invisible:
        v.obfuscation["invisible_chars"] = invisible

    nfkc = unicodedata.normalize("NFKC", base)
    if nfkc != base and sum(1 for a, b in zip(nfkc, base, strict=False) if a != b) >= 3:
        v.obfuscation["compat_forms"] = 1

    mixed = mixed_script_words(nfkc)
    folded = nfkc.translate(_HOMOGLYPHS)
    if mixed:
        v.obfuscation["homoglyphs"] = mixed

    if "&" in folded and re.search(r"&#?\w+;", folded):
        unescaped = html.unescape(folded)
        if unescaped != folded:
            v.obfuscation["html_entities"] = 1
            folded = unescaped
    if len(_PCT.findall(folded)) >= 3:
        unq = unquote(folded)
        if unq != folded:
            v.obfuscation["percent_encoding"] = 1
            folded = unq

    spaced = _SPACED.sub(lambda m: re.sub(r"[ .\-_·•*]", "", m.group(1)), folded)
    if spaced != folded:
        v.obfuscation["spaced_letters"] = 1
        folded = spaced

    if folded != text:
        v.views["normalized"] = folded

    leet = folded.translate(_LEET)
    if leet != folded:
        v.views["leet"] = leet

    decoded: list[str] = []
    for m in _B64.finditer(folded):
        d = _try_b64(m.group(0))
        if d:
            decoded.append(d)
    for m in _HEX.finditer(folded):
        d = _try_hex(m.group(0))
        if d:
            decoded.append(d)
    if decoded:
        v.views["decoded_blobs"] = "\n".join(decoded)

    v.views["rot13"] = codecs.encode(folded, "rot13")
    v.views["reversed"] = folded[::-1]
    return v


def payload_views(text: str) -> list[str]:
    """Texts to search for leaked secrets: the original plus decodings an
    exfiltrating agent might apply (base64, hex, percent-encoding, reversal)."""
    out = [text or ""]
    if not text or not _HARDENING:
        return out
    if len(_PCT.findall(text)) >= 2:
        out.append(unquote(text))
    for m in _B64.finditer(text):
        tok = m.group(0)
        t = tok.replace("-", "+").replace("_", "/")
        t += "=" * (-len(t) % 4)
        try:
            raw = base64.b64decode(t, validate=True)
            dec = raw.decode("utf-8")
            if _printable_ratio(dec) >= 0.9:
                out.append(dec)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    for m in _HEX.finditer(text):
        try:
            dec = bytes.fromhex(m.group(0)).decode("utf-8")
            if _printable_ratio(dec) >= 0.9:
                out.append(dec)
        except (ValueError, UnicodeDecodeError):
            pass
    out.append(text[::-1])
    return out
