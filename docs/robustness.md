# Adversarial robustness

A detector is only as good as its weakest assumption. taintline includes an
**evasion fuzzer** that attacks its own detections and reports, honestly, which
layer catches what.

## The fuzzer

`taintline/fuzz.py` takes the canonical indirect-injection credential-theft
attack and mutates it along two axes an attacker controls:

- **how the injection is obfuscated** — invisible Unicode tag characters,
  homoglyphs, zero-width characters, base64, spaced letters, leetspeak, fullwidth
  forms, HTML entities, ROT13, and a plain-language **paraphrase** with no
  trigger phrases;
- **how the secret leaves** — plain, base64, hex, reversed, percent-encoded, or
  chunked across many requests.

Every variant is analyzed with adversarial hardening OFF and ON, broken down per
layer: the injection-text layer, the data-flow layer, the behavioural sequence
layer, any forensic finding, and the runtime guard.

## What it shows (bundled synthetic suite, 66 variants)

| layer | hardening OFF | hardening ON |
|---|---:|---:|
| injection-text (TL-INJ-*) | ~18% | ~91% |
| data-flow (TL-EXF-*) | ~50% | 100% |
| behavioural sequence (TL-SEQ-001) | 100% | 100% |
| any forensic finding | 100% | 100% |
| runtime guard blocked | 100% | 100% |

The honest conclusions:

1. **Single pattern-based layers are evadable.** Obfuscation guts the
   injection-text layer; encoding guts the data-flow layer. This is expected and
   is *why* taintline is layered.
2. **Hardening (`taintline/normalize.py`) sharply recovers them.** It de-obfuscates
   before scoring — NFKC, zero-width/tag stripping, homoglyph folding, base64/hex
   decoding, entity/percent decoding, de-spacing — and treats the obfuscation
   itself as a signal, while taking care not to flag benign uses (emoji ZWJ
   sequences, flag tag characters, foreign-language prose, JWTs, data URIs).
3. **The behavioural layer and the guard do not depend on phrasing or encoding.**
   "Read a credential, then send it somewhere the user never named" is true
   regardless of how the instruction was written or how the secret was encoded,
   so these hold at 100% — including against the pure paraphrase that defeats the
   injection-text regex entirely.

That paraphrase is the documented limitation: no regex understands semantics, so
the injection-*text* layer will miss a well-written one. The system still
contains it, because detection and prevention key off the *actions and data
movement*, not the words.

Run it yourself:

```python
from taintline.fuzz import run_matrix, summarize
print(summarize(run_matrix(hardened=False)))
print(summarize(run_matrix(hardened=True)))
```

The guarantees are encoded as tests in `tests/test_fuzz.py`, so a regression that
reopens an evasion path fails CI.
