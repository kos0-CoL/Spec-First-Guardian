#!/usr/bin/env python3
"""Registro de revocaciones independiente (SPEC-001).

El registro no vive bajo el control del agente: se carga desde un directorio de
configuracion protegido, fuera del workspace, con permisos restrictivos, y su
contenido va firmado por la autoridad de confianza. Cualquier estado distinto de
una lectura integra y verificada se considera no comprobado y bloquea nuevas
operaciones de implementacion.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import approval_service
from approval_service import TrustedKeyStore, _parse_iso, _within, canonical_revocation_envelope

logger = logging.getLogger("spec_guardian.revocations")

STATUS_OK = "ok_no_revocations"
STATUS_REVOKED = "revoked"
STATUS_MISSING = "registry_missing"
STATUS_CORRUPT = "registry_corrupt"
STATUS_UNREADABLE = "registry_unreadable"
STATUS_UNVERIFIED = "registry_unverified"
STATUS_UNPROTECTED = "registry_unprotected"

ENTRY_REQUIRED_FIELDS = ("authorization_event_id", "spec_id", "revoked", "revoked_by", "revoked_at")


@dataclass(frozen=True)
class RevocationCheck:
    """Resultado de una comprobacion de revocaciones."""

    status: str
    reason: str = ""

    @property
    def checked(self) -> bool:
        """La comprobacion se realizo de forma fiable (con o sin revocacion)."""
        return self.status in (STATUS_OK, STATUS_REVOKED)

    @property
    def revoked(self) -> bool:
        return self.status == STATUS_REVOKED


def default_revocations_dir() -> Path:
    """Directorio de configuracion del supervisor (fuera del workspace)."""
    configured = os.environ.get("SPEC_GUARDIAN_REVOCATIONS_DIR")
    if configured and configured.strip():
        return Path(configured.strip())
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "spec-guardian" / "revocations"


class RevocationRegistry:
    """Registro firmado de revocaciones para una SPEC concreta."""

    def __init__(self, path: Path | str, key_store: TrustedKeyStore | None = None, workspace_root: Path | str | None = None) -> None:
        self.path = Path(path)
        self.key_store = key_store if key_store is not None else TrustedKeyStore.unconfigured()
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None

    @classmethod
    def for_spec(cls, spec_id: str, key_store: TrustedKeyStore | None = None, workspace_root: Path | str | None = None, registry_dir: Path | str | None = None) -> "RevocationRegistry":
        directory = Path(registry_dir) if registry_dir is not None else default_revocations_dir()
        return cls(directory / f"{spec_id}.json", key_store=key_store, workspace_root=workspace_root)

    def _protection_problem(self) -> str | None:
        try:
            resolved = self.path.resolve()
            info = resolved.stat()
        except OSError:
            return None
        if self.workspace_root is not None and _within(resolved, self.workspace_root):
            return "el registro de revocaciones esta dentro del workspace del agente"
        if stat.S_IMODE(info.st_mode) & 0o022:
            return "los permisos del registro permiten escritura ajena"
        return None

    def check(self, spec_id: str, version: str | None, authorization_event_id: str) -> RevocationCheck:
        """Devuelve el estado de revocacion; nunca convierte errores en lista vacia."""
        if not self.key_store.configured:
            return RevocationCheck(STATUS_UNVERIFIED, self.key_store.error or "almacen de confianza no configurado")
        if not str(spec_id or "").strip():
            return RevocationCheck(STATUS_CORRUPT, "spec_id ausente")
        if not self.path.exists():
            return RevocationCheck(STATUS_MISSING, "registro de revocaciones ausente")
        protection = self._protection_problem()
        if protection:
            return RevocationCheck(STATUS_UNPROTECTED, protection)
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return RevocationCheck(STATUS_UNREADABLE, "registro de revocaciones ilegible")
        try:
            data = json.loads(raw)
        except ValueError:
            return RevocationCheck(STATUS_CORRUPT, "JSON invalido en el registro de revocaciones")
        if not isinstance(data, dict):
            return RevocationCheck(STATUS_CORRUPT, "estructura del registro invalida")
        if str(data.get("spec_id") or "") != str(spec_id):
            return RevocationCheck(STATUS_CORRUPT, "el registro no corresponde a la SPEC")
        entries = data.get("revocations")
        if not isinstance(entries, list):
            return RevocationCheck(STATUS_CORRUPT, "lista de revocaciones ausente")
        signature = data.get("signature")
        key_id = str(data.get("key_id") or "")
        if not isinstance(signature, str) or not signature.strip() or not key_id:
            return RevocationCheck(STATUS_UNVERIFIED, "registro de revocaciones sin firma")
        key = self.key_store.entry(key_id)
        if key is None or key.revoked:
            return RevocationCheck(STATUS_UNVERIFIED, "clave del registro de revocaciones no confiable")
        try:
            signature_bytes = base64.b64decode(signature.strip(), validate=True)
            public_key = approval_service.serialization.load_pem_public_key(key.public_key_pem)
            public_key.verify(signature_bytes, canonical_revocation_envelope(str(spec_id), entries))
        except (binascii.Error, ValueError, TypeError):
            return RevocationCheck(STATUS_UNVERIFIED, "firma del registro de revocaciones invalida")
        except Exception:
            return RevocationCheck(STATUS_UNVERIFIED, "no se pudo verificar el registro de revocaciones")
        for entry in entries:
            if not isinstance(entry, dict):
                return RevocationCheck(STATUS_CORRUPT, "entrada de revocacion invalida")
            if any(field not in entry for field in ENTRY_REQUIRED_FIELDS):
                return RevocationCheck(STATUS_CORRUPT, "entrada de revocacion incompleta")
            if entry.get("revoked") is not True:
                return RevocationCheck(STATUS_CORRUPT, "entrada de revocacion sin efecto")
            if str(entry.get("spec_id") or "") != str(spec_id):
                return RevocationCheck(STATUS_CORRUPT, "entrada de revocacion de otra SPEC")
            if not str(entry.get("revoked_by") or "").strip():
                return RevocationCheck(STATUS_CORRUPT, "revocacion sin usuario")
            if _parse_iso(entry.get("revoked_at")) is None:
                return RevocationCheck(STATUS_CORRUPT, "fecha de revocacion invalida")
            entry_version = entry.get("version")
            if entry_version is not None and version is not None and str(entry_version) != str(version):
                continue
            if str(entry.get("authorization_event_id") or "") == str(authorization_event_id or ""):
                return RevocationCheck(STATUS_REVOKED, "la autorizacion fue revocada por accion humana")
        return RevocationCheck(STATUS_OK, "sin revocaciones aplicables")


def sign_registry(spec_id: str, revocations: list, signer) -> dict:
    """Construye un registro firmado (uso exclusivo de la autoridad de confianza)."""
    payload = canonical_revocation_envelope(spec_id, revocations)
    signature = signer.sign(payload)
    return {
        "spec_id": str(spec_id),
        "revocations": list(revocations),
        "key_id": signer.key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
