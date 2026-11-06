import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import approval_service  # noqa: E402
import revocation_registry  # noqa: E402
import validate as spec_validator  # noqa: E402
import support  # noqa: E402

TEMPLATE_PATH = TESTS_DIR.parent / "templates" / "technical-specification.md"


def registry_with_entries(spec_id: str, entries: list, signer, store, directory=None):
    return support.make_registry(directory or support.temp_dir("sg-reg-"), spec_id, entries, signer, store)


def approved_fixture(spec_text: str = support.APPROVED_SPEC, **approval_kwargs):
    signer, public_pem, _ = support.make_signer()
    store, _ = support.make_key_store(public_pem)
    record, _ = support.approve(spec_text, signer=signer, store=store, **approval_kwargs)
    registry, _ = registry_with_entries("SPEC-001", [], signer, store)
    return record, store, registry, signer


class TestValidacionDocumental(unittest.TestCase):
    def test_allowed_statuses_are_canonical(self):
        self.assertEqual(
            list(spec_validator.ALLOWED_STATUSES),
            ["DRAFT", "UNDER_REVIEW", "PENDING_USER_APPROVAL", "APPROVED", "REJECTED", "SUPERSEDED", "ARCHIVED"],
        )

    def test_draft_is_document_valid_but_not_implementable(self):
        path = support.write_spec(support.DRAFT_SPEC)
        result = spec_validator.validate_spec(path)
        self.assertTrue(result["document_valid"])
        self.assertTrue(result["requirements_valid"])
        self.assertFalse(result["approval_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_missing_section_invalidates_document(self):
        path = support.write_spec(support.DRAFT_SPEC.replace("## Trazabilidad", "## Otro"))
        result = spec_validator.validate_spec(path)
        self.assertFalse(result["document_valid"])
        self.assertTrue(any("trazabilidad" in error for error in result["errors"]))

    def test_schema_rejects_invalid_status_and_version(self):
        broken = support.DRAFT_SPEC.replace("status: DRAFT", "status: BORRADOR").replace("version: 0.1.0", "version: uno")
        path = support.write_spec(broken)
        result = spec_validator.validate_spec(path)
        self.assertFalse(result["document_valid"])
        self.assertTrue(any("esquema" in error.lower() for error in result["errors"]))

    def test_template_is_detected_as_incomplete_and_not_approvable(self):
        path = support.write_spec(TEMPLATE_PATH.read_text(encoding="utf-8"))
        result = spec_validator.validate_spec(path)
        self.assertFalse(result["template_complete"])
        self.assertFalse(result["document_valid"])
        self.assertTrue(any("marcadores pendientes" in error for error in result["errors"]))

    def test_completed_template_is_valid_but_not_implementable(self):
        content = TEMPLATE_PATH.read_text(encoding="utf-8")
        content = re.sub(r"\[[^\]\n]+\]", "contenido", content)
        content = content.replace("YYYY-MM-DD", "2026-11-05")
        path = support.write_spec(content)
        result = spec_validator.validate_spec(path)
        self.assertTrue(result["template_complete"])
        self.assertTrue(result["document_valid"])
        self.assertTrue(result["requirements_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_frontmatter_approval_metadata_is_not_trusted(self):
        text = support.APPROVED_SPEC.replace("author: tester", 'author: tester\napprover: usuario\napproved_at: "2026-11-05"')
        path = support.write_spec(text)
        result = spec_validator.validate_spec(path)
        self.assertFalse(result["approval_valid"])
        self.assertFalse(result["implementation_allowed"])
        self.assertIsNone(result["approver"])


class TestAprobacionFirmada(unittest.TestCase):
    def test_signed_approval_with_identity_and_scope_is_allowed(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture()
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertTrue(result["document_valid"])
        self.assertTrue(result["requirements_valid"])
        self.assertTrue(result["approval_valid"])
        self.assertTrue(result["approval_verified"])
        self.assertTrue(result["identity_valid"])
        self.assertTrue(result["revocation_check_valid"])
        self.assertTrue(result["scope_valid"])
        self.assertTrue(result["implementation_allowed"])

    def test_approved_spec_without_approval_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        _, store, registry, _ = approved_fixture()
        result = spec_validator.validate_spec(path, key_store=store, registry=registry)
        self.assertFalse(result["approval_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_tampered_fingerprint_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture()
        record["fingerprint"] = "0" * 64
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["approval_verified"])
        self.assertFalse(result["implementation_allowed"])

    def test_unknown_key_id_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, _, registry, _ = approved_fixture()
        other_signer, other_public, _ = support.make_signer(key_id="KEY-OTRA")
        other_store, _ = support.make_key_store(other_public, key_id="KEY-OTRA")
        result = spec_validator.validate_spec(path, approval=record, key_store=other_store, registry=registry)
        self.assertFalse(result["approval_verified"])
        self.assertFalse(result["implementation_allowed"])

    def test_agent_supplied_public_key_is_ignored(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture()
        record["public_key"] = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        record["verified"] = True
        record["signature_valid"] = True
        unconfigured = approval_service.TrustedKeyStore.unconfigured("sin configuracion")
        result = spec_validator.validate_spec(path, approval=record, key_store=unconfigured, registry=registry)
        self.assertFalse(result["approval_verified"])
        self.assertFalse(result["implementation_allowed"])

    def test_invalid_signature_encoding_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture()
        record["signature"] = "no-base64!!"
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["approval_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_wrong_algorithm_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture()
        record["algorithm"] = "HMAC-SHA256"
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["approval_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_expired_approval_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, _ = approved_fixture(expires_at="2020-01-01T00:00:00+00:00")
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["approval_verified"])
        self.assertFalse(result["implementation_allowed"])

    def test_revoked_key_in_trust_store_is_blocked(self):
        signer, public_pem, _ = support.make_signer()
        revoked_store, _ = support.make_key_store(public_pem, revoked=True)
        record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=revoked_store)
        path = support.write_spec(support.APPROVED_SPEC)
        registry, _ = registry_with_entries("SPEC-001", [], signer, revoked_store)
        result = spec_validator.validate_spec(path, approval=record, key_store=revoked_store, registry=registry)
        self.assertFalse(result["approval_verified"])
        self.assertFalse(result["implementation_allowed"])

    def test_approver_must_match_authenticated_identity(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=store, approver="otra-persona")
        self.assertIsNone(record)

    def test_simulated_provider_cannot_sign_in_production(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=store, environment="production")
        self.assertIsNone(record)

    def test_unauthenticated_event_cannot_sign(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        service = support.make_service(signer=signer, store=store)
        request = service.register_request(
            spec_id="SPEC-001",
            project="Spec-First-Guardian",
            version="1.0.0",
            spec_text=support.APPROVED_SPEC,
            expected_approver="usuario",
            scope="IMPLEMENTACION",
            operations=["create_file"],
            authorized_paths=["src/code.py"],
            requirements=["RF-001"],
            tasks=["TASK-001"],
        )
        self.assertIsNotNone(request)
        self.assertIsNone(service.approve_request(request["request_id"], {"type": "agent_self_service"}))
        self.assertIsNone(service.approve_request(request["request_id"], {"type": "human_approval", "subject": "usuario", "confirmed": False}))
        self.assertIsNone(service.approve_request("REQ-DESCONOCIDA", {"type": "human_approval", "subject": "usuario", "confirmed": True}))

    def test_service_without_provider_cannot_sign(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        service = approval_service.ApprovalService(provider=None, signer=signer, key_store=store, environment="test")
        self.assertFalse(service.signing_available)
        request = service.register_request(
            spec_id="SPEC-001",
            project="Spec-First-Guardian",
            version="1.0.0",
            spec_text=support.APPROVED_SPEC,
            expected_approver="usuario",
            scope="IMPLEMENTACION",
            operations=["create_file"],
            authorized_paths=["src/code.py"],
            requirements=["RF-001"],
            tasks=["TASK-001"],
        )
        self.assertIsNone(service.approve_request(request["request_id"], {"type": "human_approval", "subject": "usuario", "confirmed": True}))

    def test_empty_scope_request_is_rejected(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        service = support.make_service(signer=signer, store=store)
        self.assertIsNone(
            service.register_request(
                spec_id="SPEC-001",
                project="Spec-First-Guardian",
                version="1.0.0",
                spec_text=support.APPROVED_SPEC,
                expected_approver="usuario",
                scope="ALCANCE_TOTAL",
                operations=[],
                authorized_paths=[],
                requirements=[],
                tasks=[],
            )
        )

    def test_signing_key_inside_workspace_is_unavailable(self):
        key_dir = support.temp_dir("sg-ws-")
        signer, _, _ = support.make_signer(directory=key_dir)
        self.assertTrue(signer.available)
        inside = approval_service.FileSignerBackend(
            key_path=key_dir / "signing_key.pem",
            key_id="KEY-TEST-001",
            issuer=support.AUTHORITY,
            workspace_root=key_dir,
        )
        self.assertFalse(inside.available)
        self.assertIn("workspace", inside.error)


class TestRevocaciones(unittest.TestCase):
    def test_checked_registry_without_revocations_allows(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, signer = approved_fixture()
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertTrue(result["revocation_check_valid"])
        self.assertFalse(result["revoked"])
        self.assertTrue(result["implementation_allowed"])

    def test_revoked_authorization_is_blocked(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, signer = approved_fixture()
        entry = {
            "authorization_event_id": record["authorization_event_id"],
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "revoked": True,
            "revoked_by": "usuario",
            "revoked_at": support.now_iso(),
            "reason": "cambio de alcance",
        }
        revoked_registry, _ = registry_with_entries("SPEC-001", [entry], signer, store)
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=revoked_registry)
        self.assertTrue(result["revocation_check_valid"])
        self.assertTrue(result["revoked"])
        self.assertFalse(result["implementation_allowed"])

    def test_missing_registry_blocks(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, _, _ = approved_fixture()
        missing = revocation_registry.RevocationRegistry.for_spec(
            "SPEC-001", key_store=store, workspace_root=support.WORKSPACE, registry_dir=support.temp_dir("sg-empty-")
        )
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=missing)
        self.assertFalse(result["revocation_check_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_corrupt_registry_blocks(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, _, signer = approved_fixture()
        directory = support.temp_dir("sg-corrupt-")
        registry_path = directory / "SPEC-001.json"
        registry_path.write_text("{ no es json", encoding="utf-8")
        registry = revocation_registry.RevocationRegistry(registry_path, key_store=store, workspace_root=support.WORKSPACE)
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["revocation_check_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_tampered_registry_signature_blocks(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, registry, signer = approved_fixture()
        payload = json.loads(registry.path.read_text(encoding="utf-8"))
        payload["revocations"] = [
            {
                "authorization_event_id": "EVT-OTRO",
                "spec_id": "SPEC-001",
                "revoked": True,
                "revoked_by": "usuario",
                "revoked_at": support.now_iso(),
            }
        ]
        registry.path.write_text(json.dumps(payload), encoding="utf-8")
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry)
        self.assertFalse(result["revocation_check_valid"])
        self.assertFalse(result["implementation_allowed"])

    def test_registry_inside_workspace_is_unprotected(self):
        path = support.write_spec(support.APPROVED_SPEC)
        record, store, _, signer = approved_fixture()
        workspace = support.temp_dir("sg-ws-reg-")
        registry, _ = support.make_registry(workspace, "SPEC-001", [], signer, store, workspace_root=workspace)
        result = spec_validator.validate_spec(path, approval=record, key_store=store, registry=registry, workspace_root=support.WORKSPACE)
        self.assertFalse(result["revocation_check_valid"])
        self.assertFalse(result["implementation_allowed"])


class TestAutorizacionPorOperacion(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-op-")
        (self.workspace / "src").mkdir()
        self.spec_path = support.write_spec(support.APPROVED_SPEC)
        self.record, self.store, self.registry, self.signer = approved_fixture()

    def authorize(self, **overrides):
        return spec_validator.authorize_operation(
            self.record,
            support.operation(self.workspace, **overrides),
            key_store=self.store,
            spec_path=self.spec_path,
            registry=self.registry,
            workspace_root=self.workspace,
        )

    def test_operation_within_scope_is_authorized(self):
        self.assertTrue(self.authorize())

    def test_project_mismatch_is_denied(self):
        self.assertFalse(self.authorize(project="Otro-Proyecto"))

    def test_version_mismatch_is_denied(self):
        self.assertFalse(self.authorize(version="0.9.0"))

    def test_unauthorized_task_is_denied(self):
        self.assertFalse(self.authorize(task="TASK-999"))

    def test_unauthorized_requirement_is_denied(self):
        self.assertFalse(self.authorize(requirement="RF-999"))

    def test_unauthorized_operation_type_is_denied(self):
        self.assertFalse(self.authorize(operation_type="execute_script"))

    def test_path_outside_authorized_paths_is_denied(self):
        self.assertFalse(self.authorize(path="src/otro.py"))

    def test_path_traversal_is_denied(self):
        self.assertFalse(self.authorize(path="../../etc/passwd"))

    def test_absolute_path_is_denied(self):
        self.assertFalse(self.authorize(path="/etc/passwd"))

    def test_symlink_escape_is_denied(self):
        outside = support.temp_dir("sg-outside-")
        (self.workspace / "link").symlink_to(outside, target_is_directory=True)
        self.assertFalse(self.authorize(path="link/evil.py"))

    def test_incomplete_context_is_denied(self):
        operation = support.operation(self.workspace)
        operation.pop("workspace_root")
        self.assertFalse(
            spec_validator.authorize_operation(
                self.record, operation, key_store=self.store, spec_path=self.spec_path, registry=self.registry
            )
        )
        self.assertFalse(self.authorize(agent=""))

    def test_missing_spec_path_is_denied(self):
        self.assertFalse(
            spec_validator.authorize_operation(
                self.record,
                support.operation(self.workspace),
                key_store=self.store,
                registry=self.registry,
                workspace_root=self.workspace,
            )
        )

    def test_modified_spec_is_denied(self):
        self.assertTrue(self.authorize())
        self.spec_path.write_text(support.APPROVED_SPEC.replace("Problema: prueba de autorizacion.", "Problema: modificado."), encoding="utf-8")
        self.assertFalse(self.authorize())

    def test_revoked_authorization_denies_operation(self):
        entry = {
            "authorization_event_id": self.record["authorization_event_id"],
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "revoked": True,
            "revoked_by": "usuario",
            "revoked_at": support.now_iso(),
        }
        registry, _ = registry_with_entries("SPEC-001", [entry], self.signer, self.store)
        self.assertFalse(
            spec_validator.authorize_operation(
                self.record,
                support.operation(self.workspace),
                key_store=self.store,
                spec_path=self.spec_path,
                registry=registry,
                workspace_root=self.workspace,
            )
        )

    def test_empty_scope_never_authorizes(self):
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        service = support.make_service(signer=signer, store=store)
        request = service.register_request(
            spec_id="SPEC-001",
            project="Spec-First-Guardian",
            version="1.0.0",
            spec_text=support.APPROVED_SPEC,
            expected_approver="usuario",
            scope="ALCANCE_TOTAL",
            operations=[],
            authorized_paths=[],
            requirements=[],
            tasks=[],
        )
        self.assertIsNone(request)


class TestSeguridadDeRutas(unittest.TestCase):
    def test_is_safe_path_accepts_nested_relative_path(self):
        workspace = support.temp_dir("sg-path-")
        (workspace / "src").mkdir()
        self.assertTrue(spec_validator.is_safe_path(workspace, "src/code.py"))

    def test_is_safe_path_rejects_traversal_absolute_and_symlink(self):
        workspace = support.temp_dir("sg-path-")
        outside = support.temp_dir("sg-path-out-")
        (workspace / "link").symlink_to(outside, target_is_directory=True)
        self.assertFalse(spec_validator.is_safe_path(workspace, "../fuera.py"))
        self.assertFalse(spec_validator.is_safe_path(workspace, "/etc/passwd"))
        self.assertFalse(spec_validator.is_safe_path(workspace, "link/fuera.py"))
        self.assertFalse(spec_validator.is_safe_path(workspace, ""))


if __name__ == "__main__":
    unittest.main()
