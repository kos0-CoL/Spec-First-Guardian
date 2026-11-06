import json
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import enforce  # noqa: E402
import implementation_gate  # noqa: E402
import support  # noqa: E402


class TestImplementationGate(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-gate-")
        (self.workspace / "src").mkdir()
        self.spec_path = support.write_spec(support.APPROVED_SPEC)
        self.record, self.store, self.registry, self.signer = None, None, None, None
        signer, public_pem, _ = support.make_signer()
        store, _ = support.make_key_store(public_pem)
        record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=store)
        registry, _ = support.make_registry(support.temp_dir("sg-gate-reg-"), "SPEC-001", [], signer, store)
        self.record, self.store, self.registry, self.signer = record, store, registry, signer
        self.audit = support.temp_dir("sg-audit-") / "audit.jsonl"

    def gate(self, audit_path=None):
        return implementation_gate.ImplementationGate(
            approval=self.record,
            spec_path=self.spec_path,
            key_store=self.store,
            registry=self.registry,
            audit_path=audit_path or self.audit,
            workspace_root=self.workspace,
        )

    def test_operation_without_context_is_denied(self):
        decision = self.gate().execute({})
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.executed)
        self.assertTrue(any("contexto incompleto" in reason for reason in decision.reasons))

    def test_unauthorized_path_is_denied_without_writing(self):
        request = support.operation(self.workspace, path="src/otro.py")
        decision = self.gate().execute(request)
        self.assertFalse(decision.allowed)
        self.assertFalse((self.workspace / "src" / "otro.py").exists())

    def test_authorized_create_file_is_executed_and_audited(self):
        request = support.operation(self.workspace, content="print('hola')\n")
        decision = self.gate().execute(request)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.executed)
        target = self.workspace / "src" / "code.py"
        self.assertTrue(target.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "print('hola')\n")
        self.assertEqual(decision.digest, __import__("hashlib").sha256(b"print('hola')\n").hexdigest())
        self.assertTrue(self.audit.exists())
        records = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(any(item["decision"]["executed"] for item in records))

    def test_create_existing_file_is_denied(self):
        target = self.workspace / "src" / "code.py"
        target.write_text("previo", encoding="utf-8")
        decision = self.gate().execute(support.operation(self.workspace, content="nuevo"))
        self.assertFalse(decision.allowed)
        self.assertEqual(target.read_text(encoding="utf-8"), "previo")

    def test_modify_and_delete_are_executed(self):
        target = self.workspace / "src" / "code.py"
        target.write_text("previo", encoding="utf-8")
        modify = support.operation(self.workspace, operation_type="modify_file", content="actualizado")
        self.assertTrue(self.gate().execute(modify).executed)
        self.assertEqual(target.read_text(encoding="utf-8"), "actualizado")
        delete = support.operation(self.workspace, operation_type="delete_file")
        self.assertTrue(self.gate().execute(delete).executed)
        self.assertFalse(target.exists())

    def test_symlink_target_is_denied(self):
        outside = support.temp_dir("sg-gate-out-")
        (self.workspace / "src" / "link").symlink_to(outside / "evil.py")
        request = support.operation(self.workspace, path="src/link")
        decision = self.gate().execute(request)
        self.assertFalse(decision.allowed)
        self.assertFalse((outside / "evil.py").exists())

    def test_unprotected_operation_is_denied(self):
        request = support.operation(self.workspace, operation_type="execute_script")
        decision = self.gate().execute(request)
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.executed)

    def test_audit_failure_denies_operation(self):
        target = self.workspace / "src" / "code.py"
        request = support.operation(self.workspace, content="contenido")
        decision = self.gate(audit_path=Path("/proc/spec-guardian/audit.jsonl")).execute(request)
        self.assertFalse(decision.allowed)
        self.assertFalse(target.exists())

    def test_revoked_authorization_blocks_gate(self):
        entry = {
            "authorization_event_id": self.record["authorization_event_id"],
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "revoked": True,
            "revoked_by": "usuario",
            "revoked_at": support.now_iso(),
        }
        signer = self.signer
        revoked_registry, _ = support.make_registry(support.temp_dir("sg-gate-rev-"), "SPEC-001", [entry], signer, self.store)
        gate = implementation_gate.ImplementationGate(
            approval=self.record,
            spec_path=self.spec_path,
            key_store=self.store,
            registry=revoked_registry,
            audit_path=self.audit,
            workspace_root=self.workspace,
        )
        decision = gate.execute(support.operation(self.workspace, content="x"))
        self.assertFalse(decision.allowed)
        self.assertFalse((self.workspace / "src" / "code.py").exists())


class TestEnforceCLI(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-enforce-")
        (self.workspace / "src").mkdir()
        self.spec_path = support.write_spec(support.APPROVED_SPEC)
        signer, public_pem, _ = support.make_signer()
        self.store, _ = support.make_key_store(public_pem)
        self.record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=self.store)
        self.registry, _ = support.make_registry(support.temp_dir("sg-enforce-reg-"), "SPEC-001", [], signer, self.store)

    def test_evaluate_without_context_is_denied(self):
        decision = enforce.evaluate_write("create_file", self.spec_path)
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["executed"])

    def test_evaluate_with_context_does_not_write(self):
        gate = implementation_gate.ImplementationGate(
            approval=self.record,
            spec_path=self.spec_path,
            key_store=self.store,
            registry=self.registry,
            audit_path=support.temp_dir("sg-enforce-audit-") / "audit.jsonl",
            workspace_root=self.workspace,
        )
        decision = gate.authorize(support.operation(self.workspace, content="no escribir"))
        self.assertTrue(decision.allowed)
        self.assertFalse((self.workspace / "src" / "code.py").exists())

    def test_cli_requires_context(self):
        with self.assertRaises(SystemExit):
            enforce.main(["evaluate", "--spec", str(self.spec_path)])


if __name__ == "__main__":
    unittest.main()
