#!/usr/bin/env python3
"""Servicio de aprobacion humana: firma y verificacion Ed25519 (SPEC-001)."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

SIGNATURE_ALGORITHM = "Ed25519"


def canonical_payload(approval: dict) -> bytes:
    payload = {
        "spec_id": approval.get("spec_id"),
        "version": approval.get("version"),
        "approver": approval.get("approver"),
        "approved_at": approval.get("approved_at"),
        "fingerprint": approval.get("fingerprint"),
        "scope": approval.get("scope"),
        "authorization_event_id": approval.get("authorization_event_id"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_approval(approval: dict, private_key_pem: bytes) -> dict:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(canonical_payload(approval))
    record = dict(approval)
    record["algorithm"] = SIGNATURE_ALGORITHM
    record["signature"] = base64.b64encode(signature).decode("ascii")
    record["signed_at"] = approval.get("approved_at") or "1970-01-01"
    record["signer"] = approval.get("approver") or "unknown"
    return record


def verify_approval(approval: dict, public_key_pem: bytes | None = None) -> bool:
    if not approval.get("verified") or bool(approval.get("revoked", False)):
        return False
    if not approval.get("signature") or approval.get("algorithm") != SIGNATURE_ALGORITHM:
        return False
    if public_key_pem is None:
        public_key_pem = approval.get("public_key")
    if public_key_pem is None:
        public_key_pem = _public_key_from_env()
    if public_key_pem is None:
        return False
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            base64.b64decode(approval.get("signature")),
            canonical_payload(approval),
        )
    except Exception:
        return False
    return True


def _public_key_from_env() -> bytes | None:
    pem = os.environ.get("SPEC_GUARDIAN_ED25519_PUBLIC_KEY")
    if not pem:
        return None
    return pem.encode("utf-8")
