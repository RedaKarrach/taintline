"""Signed evidence pack: a single, verifiable bundle for the incident record.

A pack gathers everything about an incident into one JSON document:

* the evidence manifest (raw-file SHA-256 + per-event hash chain);
* the findings, IOCs, blast-radius assessment and a STIX 2.1 bundle;
* a canonical SHA-256 over all of the above (the pack digest).

The pack is then sealed with an **Ed25519 detached signature** over that digest.
Verification recomputes the digest and checks the signature, so a pack proves
both *integrity* (nothing was altered) and *authenticity* (it was produced by
the holder of the signing key) - the chain-of-custody properties a court or an
auditor needs. Keys are generated and stored as PEM; the private key never
enters the pack.

No pickling, no custom crypto: Ed25519 via the ``cryptography`` package.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from taintline import __version__


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pack_digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


# --------------------------------------------------------------------- keys


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 key."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def _fingerprint(public_pem: str) -> str:
    raw = load_public_key(public_pem).public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------- build


def build_evidence_pack(
    manifest: dict[str, Any],
    findings: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    blast_radius: dict[str, Any],
    stix_bundle: dict[str, Any],
    private_pem: str | None = None,
    public_pem: str | None = None,
    case_id: str | None = None,
) -> dict[str, Any]:
    """Assemble and (optionally) sign an evidence pack."""
    body = {
        "schema": "taintline-evidence-pack/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": "taintline", "version": __version__},
        "case_id": case_id,
        "manifest": manifest,
        "findings": findings,
        "iocs": iocs,
        "blast_radius": blast_radius,
        "stix": stix_bundle,
    }
    digest = pack_digest(body)
    pack: dict[str, Any] = {"body": body, "digest": {"alg": "sha256", "value": digest}}

    if private_pem:
        sk = load_private_key(private_pem)
        signature = sk.sign(digest.encode())
        if public_pem is None:
            public_pem = sk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        pack["signature"] = {
            "alg": "ed25519",
            "value": base64.b64encode(signature).decode(),
            "public_key_pem": public_pem,
            "key_fingerprint": _fingerprint(public_pem),
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }
    return pack


def verify_evidence_pack(pack: dict[str, Any], expected_public_pem: str | None = None) -> dict[str, Any]:
    """Verify a pack's digest and (if present) its signature.

    Returns a dict of boolean checks plus an overall ``ok``. If
    ``expected_public_pem`` is given, the pack's embedded key must match it -
    this is how a verifier pins the key instead of trusting whatever the pack
    carries.
    """
    result: dict[str, Any] = {"digest_ok": False, "signed": False, "signature_ok": None, "key_matches_expected": None}
    body = pack.get("body", {})
    recomputed = pack_digest(body)
    stored = pack.get("digest", {}).get("value")
    result["digest_ok"] = recomputed == stored
    result["recomputed_digest"] = recomputed

    sig = pack.get("signature")
    if sig:
        result["signed"] = True
        result["key_fingerprint"] = sig.get("key_fingerprint")
        pub_pem = sig.get("public_key_pem", "")
        if expected_public_pem is not None:
            result["key_matches_expected"] = _fingerprint(pub_pem) == _fingerprint(expected_public_pem)
            pub_pem = expected_public_pem
        try:
            load_public_key(pub_pem).verify(base64.b64decode(sig["value"]), stored.encode())
            result["signature_ok"] = True
        except (InvalidSignature, ValueError, KeyError):
            result["signature_ok"] = False

    result["ok"] = bool(
        result["digest_ok"]
        and (result["signature_ok"] in (True, None))
        and (result["key_matches_expected"] in (True, None))
    )
    return result
