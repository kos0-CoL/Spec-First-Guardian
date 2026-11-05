import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import validate as spec_validator
import approval_service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "technical-specification.md"

DRAFT_SPEC = """---
spec_id: SPEC-001
status: DRAFT
version: 0.1.0
author: "[nombre]"
created_at: "YYYY-MM-DD"
approver: null
approved_at: null
---

# SPEC-001 — [Título]

## Identificación

- ID: SPEC-001

## Contexto

- Problema: test.

## Objetivos

- Resultado esperado: test.

## Fuera de alcance

- Ninguna.

## Requisitos funcionales

- RF-001: requisito.

## Requisitos no funcionales

- Rendimiento: ok.

## Diseño técnico

- Arquitectura: ok.

## Restricciones

- Reglas globales: ok.

## Criterios de aceptación

- Criterio.

## Estrategia de validación

- Pruebas.

## Riesgos y dependencias

- Riesgo: bajo.

## Plan de implementación

- Tareas: plan.

## Aprobación

- Versión presentada: 0.1.0
- Estado: DRAFT
- Registro: pendiente.
"""

APPROVED_SPEC = DRAFT_SPEC.replace("status: DRAFT", "status: APPROVED").replace("version: 0.1.0", "version: 1.0.0").replace("approver: null", "approver: usuario").replace("approved_at: null", 'approved_at: "2026-11-05"').replace("## Aprobación\n\n- Versión presentada: 0.1.0\n- Estado: DRAFT", "## Aprobación\n\n- Versión presentada: 1.0.0\n- Estado: APPROVED")


def write_temp(content: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


def ed25519_signed_approval(fingerprint: str, **overrides) -> dict:
    approval = {
        "spec_id": "SPEC-001",
        "version": "1.0.0",
        "approver": "usuario",
        "approved_at": "2026-11-05",
        "fingerprint": fingerprint,
        "scope": "ALCANCE_TOTAL",
        "authorization_event_id": "EVENT-2026-11-05-001",
        "verified": True,
        "revoked": False,
    }
    approval.update(overrides)
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signed = approval_service.sign_approval(approval, private_key_pem)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signed["public_key"] = public_key_pem.decode("ascii")
    return signed


class TestSpecValidator(unittest.TestCase):
    def test_allowed_statuses_are_canonical(self):
        self.assertEqual(
            list(spec_validator.ALLOWED_STATUSES),
            ["DRAFT", "UNDER_REVIEW", "PENDING_USER_APPROVAL", "APPROVED", "REJECTED", "SUPERSEDED", "ARCHIVED"],
        )

    def test_draft_is_document_valid_but_not_approved_for_implementation(self):
        path = write_temp(DRAFT_SPEC)
        try:
            result = spec_validator.validate_spec(path)
            self.assertTrue(result["document_valid"])
            self.assertFalse(result["approval_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_approved_with_ed25519_signed_approval_is_allowed(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval = ed25519_signed_approval(fingerprint)
            result = spec_validator.validate_spec(path, approval=approval)
            self.assertTrue(result["document_valid"])
            self.assertTrue(result["requirements_valid"])
            self.assertTrue(result["approval_valid"])
            self.assertTrue(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_approved_without_verifiable_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            result = spec_validator.validate_spec(path)
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_tampered_ed25519_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval = ed25519_signed_approval(fingerprint)
            approval["fingerprint"] = "0" * 64
            result = spec_validator.validate_spec(path, approval=approval)
            self.assertFalse(result["approval_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_revoked_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval = ed25519_signed_approval(fingerprint)
            approval["revoked"] = True
            result = spec_validator.validate_spec(path, approval=approval)
            self.assertFalse(result["approval_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_incomplete_spec_is_invalid(self):
        path = write_temp(DRAFT_SPEC.replace("## Aprobación", "## Se Opcional"))
        try:
            result = spec_validator.validate_spec(path)
            self.assertFalse(result["document_valid"])
            self.assertTrue(result["errors"])
        finally:
            path.unlink()

    def test_template_generates_valid_spec_and_blocks_implementation(self):
        content = TEMPLATE_PATH.read_text(encoding="utf-8")
        example = (
            content.replace("spec_id: SPEC-001", "spec_id: SPEC-101")
            .replace('title: "[nombre de la especificación]"', 'title: "Especificacion de prueba"')
            .replace('author: "[nombre]"', 'author: "tester"')
            .replace('created_at: "YYYY-MM-DD"', 'created_at: "2026-11-05"')
            .replace("# SPEC-001 — [Título]", "# SPEC-101 — Especificacion de prueba")
            .replace("- Estado: [DRAFT | UNDER_REVIEW | PENDING_USER_APPROVAL | APPROVED | REJECTED | SUPERSEDED | ARCHIVED]", "- Estado: DRAFT")
        )
        path = write_temp(example)
        try:
            result = spec_validator.validate_spec(path)
            self.assertTrue(result["document_valid"])
            self.assertTrue(result["requirements_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
