import os
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import audit_chain  # noqa: E402
import safe_fs  # noqa: E402
import support  # noqa: E402
import workspace_guard  # noqa: E402


class TestSafeFilesystem(unittest.TestCase):
    def setUp(self):
        self.root = support.temp_dir("sg-fs-")
        (self.root / "src").mkdir()
        self.fd = safe_fs.open_root(self.root)

    def tearDown(self):
        if self.fd is not None:
            os.close(self.fd)

    def test_create_modify_overwrite_delete(self):
        digest = safe_fs.write_file(self.fd, "src/a.py", b"uno", mode="create")
        self.assertEqual(digest, __import__("hashlib").sha256(b"uno").hexdigest())
        safe_fs.write_file(self.fd, "src/a.py", b"dos", mode="modify")
        self.assertEqual(safe_fs.read_file(self.fd, "src/a.py"), b"dos")
        safe_fs.write_file(self.fd, "src/a.py", b"tres", mode="overwrite")
        self.assertEqual(safe_fs.read_file(self.fd, "src/a.py"), b"tres")
        safe_fs.delete_file(self.fd, "src/a.py")
        self.assertFalse((self.root / "src" / "a.py").exists())

    def test_create_existing_fails(self):
        safe_fs.write_file(self.fd, "src/a.py", b"uno", mode="create")
        with self.assertRaises(FileExistsError):
            safe_fs.write_file(self.fd, "src/a.py", b"dos", mode="create")

    def test_traversal_and_absolute_paths_are_rejected(self):
        for bad in ("../fuera.py", "src/../../fuera.py", "/etc/passwd", "", "src//a.py", "src\\a.py", "./src/a.py"):
            with self.assertRaises(safe_fs.UnsafePathError):
                safe_fs.split_relative(bad)

    def test_symlink_component_is_not_followed(self):
        outside = support.temp_dir("sg-fs-out-")
        (self.root / "enlace").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(safe_fs.UnsafePathError):
            safe_fs.write_file(self.fd, "enlace/evil.py", b"x", mode="create")
        self.assertFalse((outside / "evil.py").exists())

    def test_final_symlink_cannot_be_written_through(self):
        outside = support.temp_dir("sg-fs-out2-")
        target = outside / "objetivo.py"
        target.write_text("original", encoding="utf-8")
        (self.root / "src" / "enlace.py").symlink_to(target)
        with self.assertRaises(safe_fs.UnsafePathError):
            safe_fs.read_file(self.fd, "src/enlace.py")
        with self.assertRaises(safe_fs.UnsafePathError):
            safe_fs.write_file(self.fd, "src/enlace.py", b"x", mode="modify")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_descriptor_anchoring_survives_directory_swap(self):
        """Tras abrir el descriptor, cambiar la ruta no redirige la escritura."""
        outside = support.temp_dir("sg-fs-out3-")
        original_fd = self.fd
        moved = self.root.with_name(self.root.name + "-movido")
        os.rename(self.root, moved)
        (self.root).symlink_to(outside, target_is_directory=True)
        try:
            safe_fs.write_file(original_fd, "src/anclado.py", b"seguro", mode="create")
        finally:
            os.close(original_fd)
            self.fd = None
            os.unlink(self.root)
            os.rename(moved, self.root)
        self.assertTrue((self.root / "src" / "anclado.py").exists())
        self.assertFalse((outside / "src" / "anclado.py").exists())


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.directory = support.temp_dir("sg-audit-")
        self.chain = audit_chain.AuditChain(self.directory / "audit.jsonl")

    def test_chain_is_valid_and_detects_tampering(self):
        self.chain.append({"stage": "intent", "n": 1})
        self.chain.append({"stage": "result", "n": 1})
        valid, reason, count = self.chain.verify()
        self.assertTrue(valid, reason)
        self.assertEqual(count, 2)
        lines = (self.directory / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"n":1', '"n":9')
        (self.directory / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        valid, reason, _ = self.chain.verify()
        self.assertFalse(valid)
        self.assertIn("alterado", reason)

    def test_incomplete_marker_blocks_and_reconciles(self):
        self.assertFalse(self.chain.is_blocked())
        self.chain.mark_incomplete("fallo simulado", {"op": "create_file"})
        self.assertTrue(self.chain.is_blocked())
        event = self.chain.clear_incomplete("tester", "reconciliado")
        self.assertFalse(self.chain.is_blocked())
        self.assertEqual(event["event"]["stage"], "reconciled")

    def test_append_to_unwritable_path_raises(self):
        chain = audit_chain.AuditChain(Path("/proc/spec-guardian/audit.jsonl"))
        with self.assertRaises(audit_chain.AuditError):
            chain.append({"stage": "intent"})


class TestWorkspaceGuard(unittest.TestCase):
    def setUp(self):
        self.root = support.temp_dir("sg-ws-")
        (self.root / "src").mkdir()
        (self.root / "src" / "a.py").write_text("x", encoding="utf-8")

    def test_same_uid_is_never_protected(self):
        report = workspace_guard.verify(self.root, os.getuid(), [os.getuid()])
        self.assertFalse(report.protected)
        self.assertTrue(report.same_uid)
        self.assertTrue(any("comparten UID" in problem for problem in report.problems))

    def test_foreign_owner_is_not_protected(self):
        report = workspace_guard.verify(self.root, os.getuid() + 1000, [os.getuid()])
        self.assertFalse(report.protected)
        self.assertTrue(any("no pertenece" in problem for problem in report.problems))

    def test_missing_agent_identity_cannot_claim_protection(self):
        report = workspace_guard.verify(self.root, os.getuid(), [])
        self.assertFalse(report.protected)

    def test_world_writable_entry_is_reported(self):
        (self.root / "src" / "b.py").write_text("x", encoding="utf-8")
        os.chmod(self.root / "src" / "b.py", 0o666)
        report = workspace_guard.verify(self.root, os.getuid() + 1000, [os.getuid()])
        self.assertFalse(report.protected)
        self.assertTrue(any("escribible" in problem for problem in report.problems))


if __name__ == "__main__":
    unittest.main()
