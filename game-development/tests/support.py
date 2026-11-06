"""Soporte de pruebas: autoridad, almacen de confianza y registros temporales.

El proveedor de identidad de este modulo es SIMULADO y solo se acepta con
``environment="test"``; el servicio de aprobacion lo rechaza en produccion.
Las claves se escriben en directorios temporales fuera del workspace, con
permisos 0600, igual que exige la configuracion real del supervisor.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import approval_service
import revocation_registry

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = REPO_ROOT
AUTHORITY = "spec-guardian-authority"
KEY_ID = "KEY-TEST-001"


def now_iso(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).replace(microsecond=0).isoformat()


def temp_dir(prefix: str = "sg-test-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


class SimulatedIdentityProvider(approval_service.IdentityProvider):
    """Proveedor de identidad de pruebas (nunca valido en produccion)."""

    is_simulated = True
    configured = True

    def __init__(self, subject: str = "usuario", issuer: str = "https://idp.test", method: str = "simulated") -> None:
        self.subject = subject
        self.issuer = issuer
        self.method = method
        self.calls = 0

    def authenticate(self, approval_event: dict):
        self.calls += 1
        if not isinstance(approval_event, dict):
            return None
        if approval_event.get("type") != "human_approval" or approval_event.get("confirmed") is not True:
            return None
        if str(approval_event.get("subject") or "") != self.subject:
            return None
        return approval_service.HumanIdentity(
            method=self.method,
            issuer=self.issuer,
            subject=self.subject,
            audience="spec-guardian",
            authenticated_at=now_iso(-1),
            expires_at=now_iso(30),
        )


def make_signer(key_id: str = KEY_ID, issuer: str = AUTHORITY, directory: Path | None = None):
    directory = directory or temp_dir("sg-keys-")
    private_key = Ed25519PrivateKey.generate()
    key_path = directory / "signing_key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer = approval_service.FileSignerBackend(key_path, key_id, issuer, workspace_root=WORKSPACE)
    if not signer.available:
        raise RuntimeError(f"firma de pruebas no disponible: {signer.error}")
    return signer, public_pem, directory


def make_key_store(public_pem: bytes, key_id: str = KEY_ID, issuer: str = AUTHORITY, subject: str = "usuario", revoked: bool = False, directory: Path | None = None):
    directory = directory or temp_dir("sg-store-")
    path = directory / "trusted_keys.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "issuer": issuer,
                        "subject": subject,
                        "public_key_pem": public_pem.decode("ascii"),
                        "revoked": revoked,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    store = approval_service.TrustedKeyStore.from_config_file(path, workspace_root=WORKSPACE)
    if not store.configured:
        raise RuntimeError(f"almacen de pruebas no disponible: {store.error}")
    return store, directory


def make_service(provider=None, signer=None, store=None, environment: str = "test") -> approval_service.ApprovalService:
    return approval_service.ApprovalService(provider=provider or SimulatedIdentityProvider(), signer=signer, key_store=store, environment=environment)


def approve(
    spec_text: str,
    *,
    signer,
    store,
    provider=None,
    spec_id: str = "SPEC-001",
    version: str = "1.0.0",
    project: str = "Spec-First-Guardian",
    scope: str = "IMPLEMENTACION",
    operations=None,
    authorized_paths=None,
    requirements=None,
    tasks=None,
    expires_at: str | None = None,
    approver: str | None = None,
    environment: str = "test",
):
    provider = provider or SimulatedIdentityProvider()
    service = approval_service.ApprovalService(provider=provider, signer=signer, key_store=store, environment=environment)
    request = service.register_request(
        spec_id=spec_id,
        project=project,
        version=version,
        spec_text=spec_text,
        expected_approver=approver or provider.subject,
        scope=scope,
        operations=operations if operations is not None else ["create_file", "modify_file", "delete_file"],
        authorized_paths=authorized_paths if authorized_paths is not None else ["src/code.py"],
        requirements=requirements if requirements is not None else ["RF-001"],
        tasks=tasks if tasks is not None else ["TASK-001"],
        expires_at=expires_at,
    )
    if request is None:
        return None, service
    event = {"type": "human_approval", "subject": provider.subject, "confirmed": True}
    return service.approve_request(request["request_id"], event), service


def make_registry(directory: Path, spec_id: str, entries: list, signer, store, workspace_root: Path = WORKSPACE):
    payload = revocation_registry.sign_registry(spec_id, entries, signer)
    path = Path(directory) / f"{spec_id}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
    registry = revocation_registry.RevocationRegistry(path, key_store=store, workspace_root=workspace_root)
    return registry, path


DRAFT_SPEC = """---
spec_id: SPEC-001
title: Especificacion de prueba
status: DRAFT
version: 0.1.0
author: tester
created_at: "2026-11-05"
---

# SPEC-001 — Especificacion de prueba

## Identificación

- ID: SPEC-001
- Versión: 0.1.0
- Estado: DRAFT

## Contexto

- Problema: prueba de autorizacion.

## Objetivos

- Resultado esperado: operaciones autorizadas.

## Fuera de alcance

- Produccion.

## Requisitos funcionales

- RF-001: crear codigo autorizado.

## Requisitos no funcionales

- Seguridad: denegacion por defecto.

## Diseño técnico

- Arquitectura: gate de implementacion.

## Restricciones

- Tecnologías permitidas: Python.

## Criterios de aceptación

- SA-01: la operacion autorizada se ejecuta.
- SA-02: la operacion no autorizada se deniega.

## Estrategia de validación

- Pruebas unitarias y de integracion.

## Riesgos y dependencias

- Riesgo: configuracion incompleta.

## Plan de implementación

- Tareas: TASK-001 crear codigo.

## Trazabilidad

- RF-001 → TASK-001.

## Aprobación

- Registro de aprobación: externo y firmado.
"""

APPROVED_SPEC = (
    DRAFT_SPEC.replace("status: DRAFT", "status: APPROVED")
    .replace("version: 0.1.0", "version: 1.0.0")
    .replace("Versión: 0.1.0", "Versión: 1.0.0")
    .replace("Estado: DRAFT", "Estado: APPROVED")
)


def write_spec(text: str, directory: Path | None = None) -> Path:
    directory = directory or temp_dir("sg-spec-")
    path = Path(directory) / "SPEC-001.md"
    path.write_text(text, encoding="utf-8")
    return path


def operation(workspace_root: Path, **overrides) -> dict:
    data = {
        "agent": "agente-1",
        "project": "Spec-First-Guardian",
        "spec_id": "SPEC-001",
        "version": "1.0.0",
        "requirement": "RF-001",
        "task": "TASK-001",
        "operation_type": "create_file",
        "path": "src/code.py",
        "workspace_root": str(workspace_root),
    }
    data.update(overrides)
    return data
