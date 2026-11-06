#!/usr/bin/env python3
"""Servicio de aprobacion humana: firma y verificacion Ed25519 (SPEC-001)."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

SIGNATURE_ALGORITHM = "Ed25519"
AUTHORIZATION_FORMAT_VERSION = "1.0.0"


def canonical_payload(approval: dict) -> bytes:
    payload = {
        "spec_id": approval.get("spec_id"),
        "version": approval.get("version"),
        "approver": approval.get("approver"),
        "approved_at": approval.get("approved_at"),
        "fingerprint": approval.get("fingerprint"),
        "scope": approval.get("scope"),
        "authorization_event_id": approval.get("authorization_event_id"),
        "key_id": approval.get("key_id"),
        "project": approval.get("project"),
        "operations": approval.get("operations") or [],
        "authorized_paths": approval.get("authorized_paths") or [],
        "requirements": approval.get("requirements") or [],
        "tasks": approval.get("tasks") or [],
        "issuer": approval.get("issuer") or approval.get("approver") or "unknown",
        "authorization_format_version": approval.get("authorization_format_version") or AUTHORIZATION_FORMAT_VERSION,
        "expires_at": approval.get("expires_at"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_approval(approval: dict, private_key_pem: bytes | None = None, key_id: str | None = None, human_authenticated: bool = False) -> dict | None:
    """Firma una aprobacion humana autenticada.

    Sin un evento de aprobacion humana autenticado no se genera firma: la firma
    solo puede producirse despues de esa autenticacion.
    """
    if not human_authenticated or private_key_pem is None or not key_id:
        return None
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signed_approval = dict(approval)
    signed_approval["key_id"] = key_id
    signed_approval["issuer"] = approval.get("issuer") or approval.get("approver") or "unknown"
    signed_approval["authorization_format_version"] = approval.get("authorization_format_version") or AUTHORIZATION_FORMAT_VERSION
    signed_approval["operations"] = approval.get("operations") or []
    signed_approval["authorized_paths"] = approval.get("authorized_paths") or []
    signed_approval["requirements"] = approval.get("requirements") or []
    signed_approval["tasks"] = approval.get("tasks") or []
    signature = private_key.sign(canonical_payload(signed_approval))
    record = dict(approval)
    record["key_id"] = key_id
    record["algorithm"] = SIGNATURE_ALGORITHM
    record["signature"] = base64.b64encode(signature).decode("ascii")
    record["signed_at"] = approval.get("approved_at") or "1970-01-01"
    record["signer"] = approval.get("approver") or "unknown"
    return record


class TrustedKeyStore:
    """Almacen de claves confiables para la verificacion de firmas Ed25519.

    Solo las claves registradas aqui por la autoridad de confianza pueden usarse
    para verificar aprobaciones. Ninguna clave se acepta por defecto y ninguna se
    extrae del registro de aprobacion bajo verificacion.
    """

    def __init__(self, trusted_keys: dict | None = None) -> None:
        self._trusted_keys: dict[str, bytes] = {}
        if trusted_keys:
            for key_id, public_key_pem in trusted_keys.items():
                if public_key_pem and self.register(str(key_id), public_key_pem):
                    self._trusted_keys[str(key_id)] = public_key_pem

    def register(self, key_id: str, public_key_pem: bytes) -> bool:
        key = str(key_id or "")
        if not key or not public_key_pem:
            return False
        try:
            serialization.load_pem_public_key(public_key_pem)
        except Exception:
            return False
        self._trusted_keys[key] = public_key_pem
        return True

    def resolve(self, key_id: str) -> bytes | None:
        key = str(key_id or "")
        if not key:
            return None
        return self._trusted_keys.get(key)

    def known_key_ids(self) -> list:
        return sorted(self._trusted_keys.keys())


DEFAULT_KEY_ID = "KEY-2026-11-05-001"
DEFAULT_KEY_STORE = TrustedKeyStore()


def get_default_key_store() -> TrustedKeyStore:
    """Devuelve la tienda de claves confiables, inicializandola desde el entorno."""
    store = DEFAULT_KEY_STORE
    pem = os.environ.get("SPEC_GUARDIAN_ED25519_PUBLIC_KEY")
    key_id = os.environ.get("SPEC_GUARDIAN_ED25519_KEY_ID") or DEFAULT_KEY_ID
    if pem and not store.resolve(key_id):
        store.register(key_id, pem.encode("utf-8"))
    return store


def verify_approval(approval: dict | None, key_store: TrustedKeyStore | None = None, key_id: str | None = None, now: object = None) -> bool:
    """Verifica una aprobacion firmada con una clave de la tienda confiable.

    El registro bajo verificacion no aporta claves: la clave se resuelve desde el
    KeyStore controlado por la autoridad de confianza. Cualquier error de firma,
    caducidad o integridad produce una denegacion controlada.
    """
    if not isinstance(approval, dict):
        return False
    if not approval.get("verified"):
        return False
    if approval.get("revoked") is True:
        return False
    if approval.get("algorithm") != SIGNATURE_ALGORITHM:
        return False
    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return False
    resolved_key_id = str(approval.get("key_id") or key_id or "")
    if not resolved_key_id:
        return False
    store = key_store if key_store is not None else get_default_key_store()
    public_key_pem = store.resolve(resolved_key_id)
    if not public_key_pem:
        return False
    try:
        signature_bytes = base64.b64decode(signature.strip(), validate=True)
        if not signature_bytes:
            return False
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(signature_bytes, canonical_payload(approval))
    except Exception:
        return False
    approver = approval.get("approver")
    issuer = approval.get("issuer") or approver or "unknown"
    if not isinstance(approver, str) or not approver or str(issuer) != str(approver):
        return False
    if not approval.get("spec_id") or not approval.get("version") or not approval.get("fingerprint"):
        return False
    if now is None:
        now = datetime.now(timezone.utc)
    expires_at = approval.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            return False
    return True
