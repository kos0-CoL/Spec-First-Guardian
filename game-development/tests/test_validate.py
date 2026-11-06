import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import validate as spec_validator
import enforce
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


def ed25519_signed_approval(fingerprint: str, key_id: str = "KEY-TEST-001", **overrides) -> tuple:
    approval = {
        "spec_id": "SPEC-001",
        "version": "1.0.0",
        "approver": "usuario",
        "project": "Spec-First-Guardian",
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
    approval_event = {"type": "human_approval", "user_id": "usuario", "approval_id": "EVENT-2026-11-05-001"}
    human_service = approval_service.HumanApprovalService(provider=SimulatedHumanProvider())
    signed = approval_service.sign_approval(
        approval,
        private_key_pem,
        key_id=key_id,
        approval_event=approval_event,
        approval_service=human_service,
    )
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_store = approval_service.TrustedKeyStore(admin_authenticated=True)
    key_store.register(key_id, public_key_pem, admin_authenticated=True)
    return signed, key_store


class SimulatedHumanProvider:
    def __init__(self, user_id: str = "usuario") -> None:
        self.user_id = user_id

    def authenticate(self, approval_event) -> bool:
        return bool(
            isinstance(approval_event, dict)
            and approval_event.get("type") == "human_approval"
            and str(approval_event.get("user_id") or "") == self.user_id
        )


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
            approval, key_store = ed25519_signed_approval(fingerprint)
            result = spec_validator.validate_spec(path, approval=approval, key_store=key_store)
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
            approval, key_store = ed25519_signed_approval(fingerprint)
            approval["fingerprint"] = "0" * 64
            result = spec_validator.validate_spec(path, approval=approval, key_store=key_store)
            self.assertFalse(result["approval_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_revoked_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval, key_store = ed25519_signed_approval(fingerprint)
            approval["revoked"] = True
            result = spec_validator.validate_spec(path, approval=approval, key_store=key_store)
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


    def test_expired_ed25519_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval, key_store = ed25519_signed_approval(fingerprint, expires_at="2020-01-01T00:00:00Z")
            result = spec_validator.validate_spec(path, approval=approval, key_store=key_store)
            self.assertFalse(result["approval_valid"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_agent_generated_self_certified_approval_is_blocked(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval, key_store = ed25519_signed_approval(fingerprint)
            # La clave generada por el agente no esta registrada en la tienda confiable.
            untrusted_store = approval_service.TrustedKeyStore()
            approval["public_key"] = key_store.resolve("KEY-TEST-001").decode("ascii")
            approval["verified"] = True
            result = spec_validator.validate_spec(path, approval=approval, key_store=untrusted_store)
            self.assertFalse(result["approval_verified"])
            self.assertFalse(result["implementation_allowed"])
        finally:
            path.unlink()

    def test_authorize_operation_rejects_unauthorized_scope(self):
        fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
        approval, key_store = ed25519_signed_approval(fingerprint, scope="INVENTARIO", operations=["create_inventory"], authorized_paths=["src/inventory"])
        operation_in_scope = {
            "agent": "agente-1",
            "project": "Spec-First-Guardian",
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "requirement": "RF-001",
            "task": "TASK-001",
            "operation_type": "create_inventory",
            "path": "src/inventory",
        }
        operation_out_scope = {
            "agent": "agente-1",
            "project": "Spec-First-Guardian",
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "requirement": "RF-001",
            "task": "TASK-001",
            "operation_type": "create_auth",
            "path": "src/auth",
        }
        self.assertTrue(spec_validator.authorize_operation(approval, operation_in_scope, key_store=key_store))
        self.assertFalse(spec_validator.authorize_operation(approval, operation_out_scope, key_store=key_store))

    def test_authorize_operation_requires_matching_version_and_project(self):
        fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
        approval, key_store = ed25519_signed_approval(fingerprint)
        operation = {
            "agent": "agente-1",
            "project": "Spec-First-Guardian",
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "requirement": "RF-001",
            "task": "TASK-001",
            "operation_type": "create_code",
            "path": "src/code.py",
        }
        self.assertTrue(spec_validator.authorize_operation(approval, operation, key_store=key_store))
        self.assertFalse(spec_validator.authorize_operation(approval, dict(operation, version="0.9.0"), key_store=key_store))
        self.assertFalse(spec_validator.authorize_operation(approval, dict(operation, project="Otro-Repo"), key_store=key_store))
        self.assertFalse(spec_validator.authorize_operation(approval, {k: v for k, v in operation.items() if k != "requirement"}, key_store=key_store))

    def test_enforce_operation_context_blocks_unauthorized_operation(self):
        fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
        approval, key_store = ed25519_signed_approval(fingerprint, scope="INVENTARIO", operations=["create_inventory"], authorized_paths=["src/inventory"])
        operation = {
            "agent": "agente-1",
            "project": "Spec-First-Guardian",
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "requirement": "RF-001",
            "task": "TASK-001",
            "operation_type": "create_auth",
            "path": "src/auth",
        }
        decision = enforce.evaluate_write("create_auth", Path("."), task_id="TASK-001", operation_context=operation)
        self.assertFalse(decision["allowed"])

    def test_signing_without_authenticated_human_event_is_denied(self):
        approval = {
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "approver": "usuario",
            "approved_at": "2026-11-05",
            "fingerprint": "0" * 64,
            "scope": "ALCANCE_TOTAL",
            "authorization_event_id": "EVENT-2026-11-05-001",
            "verified": True,
            "revoked": False,
        }
        private_key = Ed25519PrivateKey.generate()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.assertIsNone(approval_service.sign_approval(approval, private_key_pem, key_id="KEY-TEST-002", approval_event={"type": "agent_self_service"}))

    def test_enforce_operation_context_blocks_path_traversal(self):
        fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
        approval, key_store = ed25519_signed_approval(fingerprint)
        operation = {
            "agent": "agente-1",
            "project": "Spec-First-Guardian",
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "requirement": "RF-001",
            "task": "TASK-001",
            "operation_type": "create_code",
            "path": "../../etc/cron.d/evil",
        }
        decision = enforce.evaluate_write("create_code", Path("."), task_id="TASK-001", operation_context=operation)
        self.assertFalse(decision["allowed"])

    def test_enforce_without_operation_context_is_denied(self):
        decision = enforce.evaluate_write("create_code", Path("."), task_id="TASK-001")
        self.assertFalse(decision["allowed"])

    def test_authorize_operation_rejects_modified_spec_hash(self):
        path = write_temp(APPROVED_SPEC)
        try:
            fingerprint = hashlib.sha256(APPROVED_SPEC.encode("utf-8")).hexdigest()
            approval, key_store = ed25519_signed_approval(fingerprint)
            operation = {
                "agent": "agente-1",
                "project": "Spec-First-Guardian",
                "spec_id": "SPEC-001",
                "version": "1.0.0",
                "requirement": "RF-001",
                "task": "TASK-001",
                "operation_type": "create_code",
                "path": "src/code.py",
            }
            modified_spec = APPROVED_SPEC.replace("Problema: test.", "Problema: test modificado.")
            modified_path = write_temp(modified_spec)
            try:
                self.assertTrue(spec_validator.authorize_operation(approval, operation, key_store=key_store, spec_path=path))
                self.assertFalse(spec_validator.authorize_operation(approval, operation, key_store=key_store, spec_path=modified_path))
            finally:
                modified_path.unlink()
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
