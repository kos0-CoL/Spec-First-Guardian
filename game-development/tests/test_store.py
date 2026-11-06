"""Pruebas del almacen durable: transacciones, cadena y migracion.

Verifican el contrato de SPEC-ARCH-001 RF-001/RF-002/RF-005/RF-006 sin afirmar
nada sobre aislamiento del sistema operativo ni sobre persistencia fisica real
ante corte de energia.
"""

import hashlib
import json
import os
import sqlite3
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import audit_chain  # noqa: E402
import authority_store  # noqa: E402
import support  # noqa: E402


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def pending_request(record, request_id="REQ-" + "a" * 32, challenge="d" * 64):
    return {
        "request_id": request_id,
        "spec_id": record["spec_id"],
        "project": record["project"],
        "version": record["version"],
        "fingerprint": record["fingerprint"],
        "expected_approver": "usuario",
        "scope": "IMPLEMENTACION",
        "operations": ["create_file"],
        "authorized_paths": ["src/code.py"],
        "requirements": ["RF-001"],
        "tasks": ["TASK-001"],
        "expires_at": None,
        "registered_at": support.now_iso(),
        "spec_path": "SPEC-001.md",
        "scope_hash": "c" * 64,
        "challenge_hash": hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
        "challenge_expires_at": support.now_iso(30),
        "challenge_used": False,
        "oidc_state": "state",
        "oidc_nonce": "nonce",
        "session_id": "session",
        "status": "PENDING_USER_APPROVAL",
    }


def signed_record(event_id="EVT-" + "e" * 32):
    signer, public_pem, _ = support.make_signer()
    store, _ = support.make_key_store(public_pem)
    record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=store)
    record["authorization_event_id"] = event_id
    return record, store


class TestSQLiteStore(unittest.TestCase):
    def setUp(self):
        self.directory = support.temp_dir("sg-store-")
        self.path = self.directory / "authority.sqlite3"
        self.store = authority_store.SQLiteAuthorityStore(self.path)

    def commit(self, store=None, record=None, request_id="REQ-" + "a" * 32, request=None):
        store = store or self.store
        record = record or signed_record()[0]
        request = request or pending_request(record, request_id)
        store.save_request(request)
        return store.commit_approval(
            request_id=request_id,
            challenge_hash=request["challenge_hash"],
            record=record,
            context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
            audit_event={"stage": "approval", "request_id": request_id},
        )

    # -- configuracion durable -------------------------------------------
    def test_uses_wal_and_full_synchronous(self):
        self.assertEqual(self.store.journal_mode(), "wal")
        self.assertEqual(self.store.synchronous_mode(), "full")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_group_readable_store_is_rejected(self):
        os.chmod(self.path, 0o640)
        with self.assertRaises(authority_store.StoreError):
            authority_store.SQLiteAuthorityStore(self.path)

    def test_corrupt_store_fails_closed(self):
        corrupt = self.directory / "corrupt.sqlite3"
        corrupt.write_bytes(b"esto no es sqlite\n")
        os.chmod(corrupt, 0o600)
        with self.assertRaises(authority_store.StoreError):
            authority_store.SQLiteAuthorityStore(corrupt)

    # -- transaccion de aprobacion ---------------------------------------
    def test_commit_persists_grant_state_and_event_together(self):
        seq = self.commit()
        request = self.store.get_request("REQ-" + "a" * 32)
        approval, context = self.store.get_grant("SPEC-001", "1.0.0")
        self.assertEqual(request["status"], "APPROVED")
        self.assertTrue(request["challenge_used"])
        self.assertEqual(approval["authorization_event_id"], request["authorization_event_id"])
        self.assertEqual(context["project"], "Spec-First-Guardian")
        events = self.store.events()
        self.assertEqual(events[-1]["seq"], seq)
        self.assertEqual(events[-1]["event"]["stage"], "approval")
        self.assertTrue(self.store.verify_chain()[0])

    def test_failure_during_audit_rolls_back_state_and_grant(self):
        record = signed_record()[0]
        request = pending_request(record)
        self.store.save_request(request)
        before = len(self.store.events())
        with mock.patch.object(
            self.store, "_append_event", side_effect=audit_chain.AuditError("fallo simulado")
        ):
            with self.assertRaises(audit_chain.AuditError):
                self.store.commit_approval(
                    request_id=request["request_id"],
                    challenge_hash=request["challenge_hash"],
                    record=record,
                    context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
                    audit_event={"stage": "approval"},
                )
        stored = self.store.get_request(request["request_id"])
        self.assertEqual(stored["status"], "PENDING_USER_APPROVAL")
        self.assertFalse(stored["challenge_used"])
        with self.assertRaises(authority_store.StoreConflict):
            self.store.get_grant("SPEC-001", "1.0.0")
        self.assertEqual(len(self.store.events()), before)

    def test_concurrent_commits_produce_exactly_one_grant(self):
        record = signed_record()[0]
        request = pending_request(record)
        self.store.save_request(request)
        barrier = threading.Barrier(6)
        outcomes = []

        def worker():
            store = authority_store.SQLiteAuthorityStore(self.path)
            barrier.wait()
            try:
                store.commit_approval(
                    request_id=request["request_id"],
                    challenge_hash=request["challenge_hash"],
                    record=record,
                    context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
                    audit_event={"stage": "approval"},
                )
                outcomes.append("committed")
            except authority_store.StoreConflict:
                outcomes.append("conflict")

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(outcomes.count("committed"), 1, outcomes)
        self.assertEqual(outcomes.count("conflict"), 5, outcomes)
        self.assertEqual(sum(1 for event in self.store.events() if event["event"]["stage"] == "approval"), 1)

    def test_replay_identifier_is_durable_and_unique(self):
        record = signed_record(event_id="EVT-" + "1" * 32)[0]
        request = pending_request(record)
        self.store.save_request(request)
        self.store.commit_approval(
            request_id=request["request_id"],
            challenge_hash=request["challenge_hash"],
            record=record,
            context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
            audit_event={"stage": "approval"},
            replay=[("oidc_nonce", "f" * 64, support.now_iso(30))],
        )
        second_record = signed_record(event_id="EVT-" + "2" * 32)[0]
        second = pending_request(second_record, request_id="REQ-" + "b" * 32)
        self.store.save_request(second)
        with self.assertRaises(authority_store.StoreConflict):
            self.store.commit_approval(
                request_id=second["request_id"],
                challenge_hash=second["challenge_hash"],
                record=second_record,
                context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
                audit_event={"stage": "approval"},
                replay=[("oidc_nonce", "f" * 64, support.now_iso(30))],
            )
        self.assertEqual(self.store.get_request(second["request_id"])["status"], "PENDING_USER_APPROVAL")

    # -- integridad de la cadena -----------------------------------------
    def test_chain_detects_tampering(self):
        self.store.append_event({"stage": "one"})
        self.store.append_event({"stage": "two"})
        connection = sqlite3.connect(str(self.path))
        try:
            connection.execute("UPDATE audit_events SET event=? WHERE seq=1", ('{"stage":"alterado"}',))
            connection.commit()
        finally:
            connection.close()
        valid, reason, _ = self.store.verify_chain()
        self.assertFalse(valid)
        self.assertIn("hash", reason)

    def test_unhealthy_store_blocks_events(self):
        self.store.mark_incomplete("fallo simulado", {"op": "create_file"})
        with self.assertRaises(audit_chain.AuditError):
            self.store.append_event({"stage": "blocked"})
        record = self.store.clear_incomplete("admin", "revisado")
        self.assertEqual(record["event"]["stage"], "reconciled")
        self.store.append_event({"stage": "allowed"})

    def test_invalid_health_state_blocks(self):
        connection = sqlite3.connect(str(self.path))
        try:
            connection.execute("UPDATE health SET state='DESCONOCIDO' WHERE id=1")
            connection.commit()
        finally:
            connection.close()
        self.assertTrue(self.store.audit_blocked())


class TestLegacyMigration(unittest.TestCase):
    def setUp(self):
        self.root = support.temp_dir("sg-migrate-")
        self.requests = self.root / "requests"
        self.approvals = self.root / "approvals"
        self.requests.mkdir()
        self.approvals.mkdir()
        self.audit_log = self.root / "audit.jsonl"

        signer, public_pem, _ = support.make_signer()
        self.store, _ = support.make_key_store(public_pem)
        self.record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=self.store)

        request = pending_request(self.record)
        request_path = self.requests / f"{request['request_id']}.json"
        request_path.write_text(
            json.dumps({"request": request, "integrity": digest(request)}, indent=2), encoding="utf-8"
        )
        grant_path = self.approvals / "SPEC-001-1.0.0.json"
        grant_path.write_text(
            json.dumps(
                {
                    "approval": self.record,
                    "context": {"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self._write_chain(
            [
                {"stage": "request", "request_id": request["request_id"]},
                {"stage": "challenge", "request_id": request["request_id"]},
                {"stage": "approval", "request_id": request["request_id"]},
            ]
        )
        self.files = [request_path, grant_path, self.audit_log]
        self.before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.files}

    def _write_chain(self, events):
        lines = []
        previous = audit_chain.GENESIS
        for index, event in enumerate(events, start=1):
            record = {"seq": index, "at": support.now_iso(), "prev": previous, "event": event}
            record["hash"] = hashlib.sha256(canonical(record)).hexdigest()
            previous = record["hash"]
            lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
        self.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def migrate(self, store=None):
        store = store or authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        return store.migrate_legacy(
            requests_dir=self.requests,
            approvals_dir=self.approvals,
            audit_log=self.audit_log,
            key_store=self.store,
        )

    def test_imports_verified_evidence_and_preserves_originals(self):
        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        result = self.migrate(store)
        self.assertEqual(result["requests"], 1)
        self.assertEqual(result["grants"], 1)
        self.assertEqual(result["legacy_events"], 3)
        self.assertEqual(result["imported_events"], 3)
        self.assertTrue(store.verify_chain()[0])
        approval, _ = store.get_grant("SPEC-001", "1.0.0")
        self.assertEqual(approval["authorization_event_id"], self.record["authorization_event_id"])
        for path in self.files:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.before[path])

    def test_migration_is_idempotent_and_records_result(self):
        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        self.migrate(store)
        events_after_first = len(store.events())
        second = self.migrate(store)
        self.assertTrue(second["already_migrated"])
        self.assertEqual(len(store.events()), events_after_first)
        verified = store.verify_store()
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["migration"]["status"], "completed")
        self.assertEqual(verified["grants"], 1)

    def test_corrupt_request_refuses_migration_without_changes(self):
        path = self.requests / ("REQ-" + "a" * 32 + ".json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["request"]["authorized_paths"] = ["src/otro.py"]
        path.write_text(json.dumps(payload), encoding="utf-8")
        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        with self.assertRaises(authority_store.MigrationError):
            self.migrate(store)
        self.assertFalse(any(event["event"]["stage"] == "storage_migration" for event in store.events()))
        with self.assertRaises(authority_store.StoreConflict):
            store.get_grant("SPEC-001", "1.0.0")

    def test_tampered_legacy_chain_is_refused(self):
        lines = self.audit_log.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace('"challenge"', '"alterado"')
        self.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        with self.assertRaises(authority_store.MigrationError):
            self.migrate(store)

    def test_chain_that_cannot_be_spliced_is_refused(self):
        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
        store.append_event({"stage": "nuevo"})
        with self.assertRaises(authority_store.MigrationError):
            self.migrate(store)


if __name__ == "__main__":
    unittest.main()
