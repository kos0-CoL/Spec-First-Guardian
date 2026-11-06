import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import audit_chain  # noqa: E402
import authority_client  # noqa: E402
import enforce  # noqa: E402
import implementation_gate  # noqa: E402
import support  # noqa: E402


class TestImplementationGate(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-gate-")
        (self.workspace / "src").mkdir()
        self.spec_path = support.write_spec(support.APPROVED_SPEC, directory=self.workspace)
        signer, public_pem, _ = support.make_signer()
        self.store, _ = support.make_key_store(public_pem)
        self.record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=self.store)
        self.signer = signer
        self.registry, _ = support.make_registry(support.temp_dir("sg-gate-reg-"), "SPEC-001", [], signer, self.store)
        self.audit = support.temp_dir("sg-audit-") / "audit.jsonl"

    def gate(self, approval=None, audit_path=None, workspace_root=None):
        return implementation_gate.ImplementationGate(
            approval=approval if approval is not None else self.record,
            spec_path=self.spec_path,
            key_store=self.store,
            registry=self.registry,
            audit_path=audit_path or self.audit,
            workspace_root=workspace_root or self.workspace,
        )

    def test_operation_without_context_is_denied(self):
        decision = self.gate().execute({})
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.executed)
        self.assertTrue(any("contexto incompleto" in reason for reason in decision.reasons))

    def test_unauthorized_path_is_denied_without_writing(self):
        decision = self.gate().execute(support.operation(self.workspace, path="src/otro.py"))
        self.assertFalse(decision.allowed)
        self.assertFalse((self.workspace / "src" / "otro.py").exists())

    def test_authorized_create_file_is_executed_and_audited(self):
        content = "print('hola')\n"
        decision = self.gate().execute(support.operation(self.workspace, content=content))
        self.assertTrue(decision.allowed, decision.reasons)
        self.assertTrue(decision.executed)
        self.assertTrue(decision.audit_complete)
        target = self.workspace / "src" / "code.py"
        self.assertEqual(target.read_text(encoding="utf-8"), content)
        self.assertEqual(decision.digest, hashlib.sha256(content.encode("utf-8")).hexdigest())
        stages = [json.loads(line)["event"]["stage"] for line in self.audit.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(stages, ["intent", "result"])

    def test_spec_outside_workspace_is_denied(self):
        outside = support.write_spec(support.APPROVED_SPEC)
        gate = implementation_gate.ImplementationGate(
            approval=self.record,
            spec_path=outside,
            key_store=self.store,
            registry=self.registry,
            audit_path=self.audit,
            workspace_root=self.workspace,
        )
        decision = gate.execute(support.operation(self.workspace, content="x"))
        self.assertFalse(decision.allowed)
        self.assertFalse((self.workspace / "src" / "code.py").exists())

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
        decision = self.gate().execute(support.operation(self.workspace, path="src/link"))
        self.assertFalse(decision.allowed)
        self.assertFalse((outside / "evil.py").exists())

    def test_unprotected_operation_is_denied(self):
        decision = self.gate().execute(support.operation(self.workspace, operation_type="execute_script"))
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.executed)

    def test_audit_failure_denies_operation(self):
        target = self.workspace / "src" / "code.py"
        decision = self.gate(audit_path=Path("/proc/spec-guardian/audit.jsonl")).execute(
            support.operation(self.workspace, content="contenido")
        )
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.executed)
        self.assertFalse(decision.audit_complete)
        self.assertFalse(target.exists())

    def test_incomplete_audit_blocks_new_operations(self):
        chain = audit_chain.AuditChain(self.audit)
        chain.append({"stage": "initialization"})
        chain.mark_incomplete("prueba de bloqueo", {"test": True})
        decision = self.gate().execute(support.operation(self.workspace, content="x"))
        self.assertFalse(decision.allowed)
        self.assertFalse((self.workspace / "src" / "code.py").exists())
        chain.block_path.unlink()
        chain._write_health("HEALTHY")
        chain._poisoned = False
        allowed = self.gate().execute(support.operation(self.workspace, content="y"))
        self.assertTrue(allowed.allowed, allowed.reasons)
        self.assertTrue((self.workspace / "src" / "code.py").exists())

    def test_revoked_authorization_blocks_gate(self):
        entry = {
            "authorization_event_id": self.record["authorization_event_id"],
            "spec_id": "SPEC-001",
            "version": "1.0.0",
            "revoked": True,
            "revoked_by": "usuario",
            "revoked_at": support.now_iso(),
        }
        revoked_registry, _ = support.make_registry(support.temp_dir("sg-gate-rev-"), "SPEC-001", [entry], self.signer, self.store)
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


class TestEnforceClient(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-enforce-")
        (self.workspace / "src").mkdir()
        self.spec_path = support.write_spec(support.APPROVED_SPEC, directory=self.workspace)
        signer, public_pem, _ = support.make_signer()
        self.store, _ = support.make_key_store(public_pem)
        self.record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=self.store)
        self.registry, _ = support.make_registry(support.temp_dir("sg-enforce-reg-"), "SPEC-001", [], signer, self.store)

    def test_without_context_is_denied(self):
        decision = enforce.evaluate_write("create_file")
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["executed"])

    def test_without_authority_is_denied(self):
        signer, public_pem, _ = support.make_signer()
        config = authority_client.ClientConfig(
            socket_path=support.temp_dir("sg-enforce-run-") / "no-existe.sock",
            service_uid=os.getuid(),
            socket_gid=os.getgid(),
            public_key_pem=public_pem.decode("ascii"),
        )
        decision = enforce.apply_write(
            "create_file",
            operation_context=support.operation(self.workspace, content="x"),
            client_config=config,
        )
        self.assertFalse(decision["allowed"])
        self.assertTrue(any("BLOQUEADA" in reason for reason in decision["reasons"]))

    def test_authorize_without_execution(self):
        gate = implementation_gate.ImplementationGate(
            approval=self.record,
            spec_path=self.spec_path,
            key_store=self.store,
            registry=self.registry,
            audit_path=support.temp_dir("sg-enforce-audit-") / "audit.jsonl",
            workspace_root=self.workspace,
        )
        decision = gate.authorize(support.operation(self.workspace, content="no escribir"))
        self.assertTrue(decision.allowed, decision.reasons)
        self.assertFalse((self.workspace / "src" / "code.py").exists())

    def test_cli_requires_context(self):
        with self.assertRaises(SystemExit):
            enforce.main(["evaluate"])


if __name__ == "__main__":
    unittest.main()
