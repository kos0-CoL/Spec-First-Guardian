"""Pruebas de la frontera de proceso: servicio de autoridad por socket Unix.

No demuestran aislamiento del sistema operativo entre UID distintos (eso exige
dos cuentas reales y se verifica con ``install_authority.sh`` y
``workspace_guard.py``); demuestran el contrato del servicio: credenciales de
par, desafio de un solo uso, almacen de solicitudes con integridad, delegacion,
revocacion y ejecucion de escrituras dentro del proceso de autoridad.
"""

import base64
import json
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
sys.path.insert(0, str(TESTS_DIR))

import approval_service  # noqa: E402
import authority_client  # noqa: E402
import authority_service  # noqa: E402
import revocation_registry  # noqa: E402
import support  # noqa: E402


def bootstrap(directory: Path, workspace: Path, **overrides):
    config_path = authority_service._bootstrap(directory)
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    raw["projects"] = {"Spec-First-Guardian": str(workspace)}
    raw.update(overrides)
    config_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    os.chmod(config_path, 0o600)
    config = authority_service.AuthorityConfig.load(config_path)
    problems = authority_service.preflight(config)
    # A test bootstrap intentionally shares one UID and does not claim OS isolation.
    problems = [problem for problem in problems if "workspace NO PROTEGIDO" not in problem]
    if problems:
        raise AssertionError(f"preflight inesperado: {problems}")
    authority = authority_service.Authority(config)
    signer = approval_service.FileSignerBackend(config.signing_key_file, config.key_id, config.issuer)
    registry_path = config.revocations_dir / "SPEC-001.json"
    registry_path.write_text(json.dumps(revocation_registry.sign_registry("SPEC-001", [], signer)), encoding="utf-8")
    os.chmod(registry_path, 0o600)
    server = authority_service.AuthorityServer(authority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not config.socket_path.exists() and time.time() < deadline:
        time.sleep(0.02)
    # La configuracion del cliente la escribe el bootstrap test-only y se carga
    # con las mismas comprobaciones que la instalada por root.
    client = authority_client.client_from_protected_config(Path(directory).resolve() / "client.json")
    return SimpleNamespace(server=server, authority=authority, config=config, client=client, thread=thread)


class AuthorityTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = support.temp_dir("sg-auth-ws-")
        (self.workspace / "src").mkdir()
        support.write_spec(support.APPROVED_SPEC, directory=self.workspace)
        for current, dirs, files in os.walk(self.workspace):
            os.chmod(current, 0o755)
            for name in files:
                os.chmod(Path(current) / name, 0o644)
        self.base = support.temp_dir("sg-auth-")
        self.ctx = bootstrap(self.base, self.workspace)

    def tearDown(self):
        self.ctx.server.stop()
        self.ctx.thread.join(timeout=5)

    # -- utilidades -------------------------------------------------------
    def request(self, **overrides):
        payload = {
            "project": "Spec-First-Guardian",
            "spec": "SPEC-001.md",
            "scope": "IMPLEMENTACION",
            "operations": ["create_file", "modify_file", "delete_file"],
            "paths": ["src/code.py"],
            "requirements": ["RF-001"],
            "tasks": ["TASK-001"],
        }
        payload.update(overrides)
        return self.ctx.client.request_approval(**payload)

    def approved(self, **overrides):
        request = self.request(**overrides)
        challenge = self.ctx.client.challenge(request["request_id"])
        offset = 0
        reviewed_pages = 0
        while offset < challenge["review"]["spec_length"]:
            page = self.ctx.client.spec_page(request["request_id"], challenge["fingerprint"], offset)
            offset = page["next_offset"]
            reviewed_pages += 1
        result = self.ctx.client.approve(
            request["request_id"], challenge["challenge"],
            test_identity={"subject": "usuario", "confirmed": True},
            scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"],
            review_pages=reviewed_pages, oidc_state=challenge["oidc_state"],
            session_id=challenge["session_id"],
        )
        return request, result

    def operation(self, **overrides):
        return support.operation(self.workspace, **overrides)

    # -- estado -----------------------------------------------------------
    def test_status_reports_test_isolation_and_signing(self):
        status = self.ctx.client.status()
        self.assertEqual(status["environment"], "test")
        self.assertEqual(status["isolation"], "not_enforced")
        self.assertTrue(status["signing_available"])
        self.assertTrue(status["audit_chain"]["valid"], status["audit_chain"])

    # -- flujo positivo ---------------------------------------------------
    def test_approval_and_authorized_write(self):
        request, approval = self.approved()
        record = approval["approval"]
        self.assertEqual(record["key_id"], "KEY-TEST-001")
        self.assertEqual(record["fingerprint"], request["fingerprint"])
        decision = self.ctx.client.authorize(self.operation(), content="print('ok')\n")
        self.assertTrue(decision["allowed"], decision["reasons"])
        self.assertTrue(decision["executed"])
        self.assertTrue(decision["audit_complete"])
        self.assertEqual(decision["agent"], "agente-1")
        self.assertEqual((self.workspace / "src" / "code.py").read_text(encoding="utf-8"), "print('ok')\n")
        verification = self.ctx.client.call("verify_approval", {"spec_id": "SPEC-001", "version": "1.0.0"})
        self.assertTrue(verification["verified"])
        self.assertTrue(verification["identity_bound"])
        self.assertTrue(verification["revocation"]["status"].startswith("ok"))

    def test_audit_records_request_challenge_approval_intent_result(self):
        self.approved()
        self.ctx.client.authorize(self.operation(), content="x")
        valid, reason, count = self.ctx.authority.audit.verify()
        self.assertTrue(valid, reason)
        stages = []
        for line in (self.ctx.config.audit_log).read_text(encoding="utf-8").splitlines():
            if line.strip():
                stages.append(json.loads(line)["event"]["stage"])
        for stage in ("request", "challenge", "approval", "intent", "result"):
            self.assertIn(stage, stages)

    def test_challenge_is_single_use(self):
        request = self.request()
        challenge = self.ctx.client.challenge(request["request_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.approve(request["request_id"], challenge["challenge"], test_identity={"subject": "usuario", "confirmed": True}, scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"], review_pages=1, oidc_state=challenge["oidc_state"], session_id=challenge["session_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.approve(request["request_id"], challenge["challenge"], test_identity={"subject": "usuario", "confirmed": True}, scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"], review_pages=1, oidc_state=challenge["oidc_state"], session_id=challenge["session_id"])
        self.ctx.client.approve(request["request_id"], challenge["challenge"], test_identity={"subject": "usuario", "confirmed": True}, scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"], review_pages=1, oidc_state=challenge["oidc_state"], session_id=challenge["session_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.challenge(request["request_id"])

    def test_wrong_challenge_is_denied(self):
        request = self.request()
        challenge = self.ctx.client.challenge(request["request_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.approve(request["request_id"], "desafio-inventado", test_identity={"subject": "usuario", "confirmed": True}, scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"], review_pages=1, oidc_state=challenge["oidc_state"], session_id=challenge["session_id"])

    def test_unconfirmed_identity_is_denied(self):
        request = self.request()
        challenge = self.ctx.client.challenge(request["request_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.approve(request["request_id"], challenge["challenge"], test_identity={"subject": "usuario", "confirmed": False}, scope_hash=challenge["scope_hash"], review_fingerprint=challenge["fingerprint"], review_pages=1, oidc_state=challenge["oidc_state"], session_id=challenge["session_id"])

    # -- integridad -------------------------------------------------------
    def test_tampered_stored_request_is_rejected(self):
        request = self.request()
        path = self.ctx.authority._request_path(request["request_id"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["request"]["authorized_paths"] = ["src/otro.py"]
        path.write_text(json.dumps(payload), encoding="utf-8")
        # La integridad se comprueba al cargar: ni siquiera se emite desafio.
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.challenge(request["request_id"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.approve(request["request_id"], "cualquiera", test_identity={"subject": "usuario", "confirmed": True})

    def test_modified_spec_after_approval_is_denied(self):
        self.approved()
        spec = self.workspace / "SPEC-001.md"
        spec.write_text(spec.read_text(encoding="utf-8") + "\n<!-- cambio posterior -->\n", encoding="utf-8")
        decision = self.ctx.client.authorize(self.operation(), content="x")
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["executed"])
        self.assertFalse((self.workspace / "src" / "code.py").exists())

    def test_document_without_identifiers_is_not_approvable(self):
        with self.assertRaises(authority_client.AuthorityDenied):
            self.request(requirements=["RF-999"])
        with self.assertRaises(authority_client.AuthorityDenied):
            self.request(operations=["execute_script"])

    # -- alcance e identidad ---------------------------------------------
    def test_operation_outside_scope_is_denied(self):
        self.approved()
        decision = self.ctx.client.authorize(self.operation(path="src/otro.py"), content="x")
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["executed"])
        self.assertFalse((self.workspace / "src" / "otro.py").exists())

    def test_unknown_agent_is_denied(self):
        self.approved()
        with self.assertRaises(authority_client.AuthorityDenied):
            # La identidad del agente se resuelve antes de autorizar: es un error de protocolo.
            self.ctx.client.authorize(self.operation(agent="intruso"), content="x")

    def test_delegated_subagent_is_allowed_with_chain(self):
        self.approved()
        delegated = self.operation(agent="subagente-1", delegation=[{"from": "agente-1", "to": "subagente-1"}])
        decision = self.ctx.client.authorize(delegated, content="sub")
        self.assertTrue(decision["allowed"], decision["reasons"])
        self.assertEqual(decision["agent"], "subagente-1")

    def test_subagent_without_chain_is_denied(self):
        self.approved()
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.authorize(self.operation(agent="subagente-1"), content="x")

    def test_undelegated_subagent_is_denied(self):
        self.approved()
        chain = [{"from": "agente-1", "to": "subagente-2"}]
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.authorize(self.operation(agent="subagente-2", delegation=chain), content="x")

    # -- revocacion -------------------------------------------------------
    def test_revocation_blocks_new_operations(self):
        request, approval = self.approved()
        self.ctx.client.revoke(
            spec_id="SPEC-001",
            version="1.0.0",
            authorization_event_id=approval["approval"]["authorization_event_id"],
            reason="prueba de revocacion",
        )
        decision = self.ctx.client.authorize(self.operation(), content="x")
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["executed"])
        self.assertFalse((self.workspace / "src" / "code.py").exists())
        verification = self.ctx.client.call("verify_approval", {"spec_id": "SPEC-001", "version": "1.0.0"})
        self.assertTrue(verification["revocation"]["revoked"])

    # -- ACL y bloqueo ----------------------------------------------------
    def test_admin_operations_require_admin_uid(self):
        with self.assertRaises(authority_service.Denied):
            self.ctx.server._handle(999999, {"method": "pending", "payload": {}})
        with self.assertRaises(authority_service.Denied):
            self.ctx.server._handle(999999, {"method": "authorize", "payload": {"operation": {}}})

    def test_incomplete_audit_blocks_operations(self):
        self.approved()
        self.ctx.authority.audit.mark_incomplete("prueba", {})
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.authorize(self.operation(), content="x")
        self.ctx.client.reconcile("reconciliado en prueba")
        decision = self.ctx.client.authorize(self.operation(), content="x")
        self.assertTrue(decision["allowed"], decision["reasons"])

    def test_unknown_method_is_denied(self):
        with self.assertRaises(authority_client.AuthorityDenied):
            self.ctx.client.call("borrar_todo")

    def test_challenge_shows_content_and_scope(self):
        request = self.request()
        review = self.ctx.client.challenge(request["request_id"])["review"]
        self.assertIn("SPEC-001", review["preview"])
        self.assertEqual(review["operations"], ["create_file", "modify_file", "delete_file"])
        self.assertEqual(review["paths"], ["src/code.py"])
        self.assertEqual(review["spec_sha256"], request["fingerprint"])

    def test_environment_cannot_inject_trust(self):
        """Cambiar variables del proceso no altera el almacen de la autoridad."""
        rogue_signer, rogue_pem, _ = support.make_signer(key_id="KEY-ROGUE-001")
        rogue_store, _ = support.make_key_store(rogue_pem, key_id="KEY-ROGUE-001", subject="usuario")
        forged, _ = support.approve(
            support.APPROVED_SPEC,
            signer=rogue_signer,
            store=rogue_store,
            scope="TOTAL",
        )
        rogue_path = support.temp_dir("sg-rogue-") / "trusted.json"
        os.environ["SPEC_GUARDIAN_TRUSTED_KEYS"] = str(rogue_path)
        try:
            self.assertFalse(self.ctx.authority.service.verify(forged))
            self.assertFalse(approval_service.verify_approval(forged, key_store=self.ctx.authority.key_store))
        finally:
            os.environ.pop("SPEC_GUARDIAN_TRUSTED_KEYS", None)


class _RogueAuthority:
    """Socket falso: imita la respuesta de atestacion, no puede firmarla."""

    def __init__(self, path: Path, expected_fingerprint: str) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.path = Path(path)
        self.expected_fingerprint = expected_fingerprint
        self.key = Ed25519PrivateKey.generate()
        self.messages: list = []
        self._stop = threading.Event()
        self._socket = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        # Mismos permisos que el socket legitimo: la denegacion debe venir de la
        # atestacion, no de los metadatos del archivo.
        os.chmod(self.path, 0o660)
        server.listen(4)
        server.settimeout(0.2)
        self._socket = server
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                connection.settimeout(2.0)
                with connection.makefile("rwb") as stream:
                    line = stream.readline(65536)
                    if not line:
                        continue
                    message = json.loads(line)
                    self.messages.append(message)
                    nonce = str((message.get("payload") or {}).get("nonce") or "")
                    pid = os.getpid()
                    statement = authority_client.attestation_statement(nonce, os.getuid(), pid)
                    signature = self.key.sign(statement)
                    response = {
                        "ok": True,
                        "result": {
                            "service_uid": os.getuid(),
                            "pid": pid,
                            "nonce": nonce,
                            "public_key_sha256": self.expected_fingerprint,
                            "signature": base64.b64encode(signature).decode("ascii"),
                        },
                    }
                    stream.write(json.dumps(response).encode("utf-8") + b"\n")
                    stream.flush()
                    connection.settimeout(0.5)
                    try:
                        extra = stream.readline(65536)
                    except (OSError, socket.timeout):
                        extra = b""
                    if extra:
                        self.messages.append(json.loads(extra))
            finally:
                connection.close()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        self._thread.join(timeout=5)
        try:
            self.path.unlink()
        except OSError:
            pass


class TestClientAuthentication(unittest.TestCase):
    """P0: el cliente solo acepta al servicio legitimo, sin configuracion sustituible."""

    def setUp(self):
        self.workspace = support.temp_dir("sg-authc-ws-")
        (self.workspace / "src").mkdir()
        support.write_spec(support.APPROVED_SPEC, directory=self.workspace)
        self.base = support.temp_dir("sg-authc-")
        self.ctx = bootstrap(self.base, self.workspace)
        self.config_path = self.ctx.client.config.source

    def tearDown(self):
        self.ctx.server.stop()
        self.ctx.thread.join(timeout=5)

    def _copy_config(self, **overrides) -> Path:
        raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        raw.update(overrides)
        target = support.temp_dir("sg-authc-cfg-") / "client.json"
        target.write_text(json.dumps(raw), encoding="utf-8")
        os.chmod(target, 0o600)
        return target

    def test_legitimate_authority_is_accepted(self):
        status = self.ctx.client.status()
        self.assertEqual(status["environment"], "test")
        self.assertEqual(self.ctx.client.config.service_uid, os.getuid())

    def test_expected_uid_is_mandatory(self):
        path = self._copy_config()
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw.pop("expected_service_uid")
        path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(authority_client.AuthorityUnavailable):
            authority_client.ClientConfig.load(path)
        with self.assertRaises(authority_client.AuthorityUnavailable):
            authority_client.ClientConfig(socket_path=path, service_uid=None, socket_gid=os.getgid(), public_key_pem="")

    def test_service_uid_cannot_be_none_or_root(self):
        for value in (None, 0, -1, True):
            with self.assertRaises(authority_client.AuthorityUnavailable):
                authority_client.ClientConfig(
                    socket_path=self.ctx.config.socket_path,
                    service_uid=value,
                    socket_gid=os.getgid(),
                    public_key_pem=self.ctx.client.config.public_key_pem,
                )

    def test_environment_cannot_redirect_socket_or_uid(self):
        rogue_path = self.base / "run" / "rogue.sock"
        with mock.patch.dict(
            os.environ,
            {
                "SPEC_GUARDIAN_AUTHORITY_SOCKET": str(rogue_path),
                "SPEC_GUARDIAN_AUTHORITY_UID": "999999",
            },
        ):
            reloaded = authority_client.client_from_protected_config(self.config_path)
            self.assertEqual(reloaded.config.socket_path, self.ctx.config.socket_path)
            self.assertEqual(reloaded.config.service_uid, os.getuid())
            self.assertEqual(reloaded.status()["environment"], "test")

    def test_socket_from_another_uid_is_denied(self):
        config = authority_client.ClientConfig(
            socket_path=self.ctx.config.socket_path,
            service_uid=os.getuid() + 1,
            socket_gid=os.getgid(),
            public_key_pem=self.ctx.client.config.public_key_pem,
        )
        with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
            authority_client.AuthorityClient(config).status()
        self.assertIn("propietario del socket", str(caught.exception))

    def test_peer_uid_mismatch_is_denied(self):
        credentials = (os.getpid(), os.getuid() + 1, os.getgid())
        with mock.patch.object(authority_client.AuthorityClient, "_peer_credentials", return_value=credentials):
            with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
                self.ctx.client.status()
        self.assertIn("identidad esperada", str(caught.exception))

    def test_unavailable_peer_credentials_are_denied(self):
        class NoCredentials:
            def getsockopt(self, *args, **kwargs):
                raise OSError("SO_PEERCRED no disponible")

        with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
            authority_client.AuthorityClient._peer_credentials(NoCredentials())
        self.assertIn("SO_PEERCRED", str(caught.exception))
        with mock.patch.object(
            authority_client.AuthorityClient,
            "_peer_credentials",
            side_effect=authority_client.AuthorityUnavailable("credenciales del par no disponibles"),
        ):
            with self.assertRaises(authority_client.AuthorityUnavailable):
                self.ctx.client.status()

    def test_fake_socket_is_denied_without_forwarding_the_request(self):
        rogue = _RogueAuthority(self.ctx.config.socket_path, self.ctx.client.config.public_key_sha256)
        self.addCleanup(rogue.stop)
        rogue.start()
        with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
            self.ctx.client.status()
        self.assertIn("firma", str(caught.exception).lower())
        self.assertEqual([message.get("method") for message in rogue.messages], ["attest"])

    def test_replaced_socket_symlink_is_denied(self):
        link = self.base / "run" / "link.sock"
        link.symlink_to(self.ctx.config.socket_path)
        config = authority_client.ClientConfig(
            socket_path=link,
            service_uid=os.getuid(),
            socket_gid=os.getgid(),
            public_key_pem=self.ctx.client.config.public_key_pem,
        )
        with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
            authority_client.AuthorityClient(config).status()
        self.assertIn("enlace simbolico", str(caught.exception))

    def test_disconnected_service_is_denied(self):
        self.ctx.server.stop()
        self.ctx.thread.join(timeout=5)
        with self.assertRaises(authority_client.AuthorityUnavailable):
            self.ctx.client.status()

    def test_unprotected_client_config_is_rejected(self):
        path = self._copy_config()
        os.chmod(path, 0o666)
        with self.assertRaises(authority_client.AuthorityUnavailable):
            authority_client.ClientConfig.load(path)
        readable = self._copy_config()
        os.chmod(readable, 0o644)
        self.assertEqual(authority_client.ClientConfig.load(readable).service_uid, os.getuid())
        link = support.temp_dir("sg-authc-link-") / "client.json"
        link.symlink_to(self.config_path)
        with self.assertRaises(authority_client.AuthorityUnavailable):
            authority_client.ClientConfig.load(link)

    def test_client_config_in_writable_directory_is_rejected(self):
        directory = support.temp_dir("sg-authc-dir-")
        os.chmod(directory, 0o775)
        target = directory / "client.json"
        target.write_text(self.config_path.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(target, 0o644)
        with self.assertRaises(authority_client.AuthorityUnavailable) as caught:
            authority_client.ClientConfig.load(target)
        self.assertIn("directorio", str(caught.exception))

    def test_client_config_path_must_be_absolute(self):
        with self.assertRaises(authority_client.AuthorityUnavailable):
            authority_client.ClientConfig.load("client.json")

    def test_attestation_statement_is_shared_with_the_service(self):
        self.assertEqual(authority_client.ATTESTATION_PREFIX, authority_service.ATTESTATION_PREFIX)
        self.assertEqual(
            authority_client.attestation_statement("a" * 64, 1000, 42),
            authority_service.attestation_statement("a" * 64, 1000, 42),
        )

    def test_nonce_reuse_is_denied_by_the_service(self):
        nonce = "b" * 64
        self.ctx.authority.attest(os.getuid(), {"nonce": nonce})
        with self.assertRaises(authority_service.Denied):
            self.ctx.authority.attest(os.getuid(), {"nonce": nonce})


class TestProductionPreflight(unittest.TestCase):
    def _config(self, base: Path, **overrides):
        workspace = base / "workspace"
        workspace.mkdir(exist_ok=True)
        for name in ("state", "revocations", "run"):
            (base / name).mkdir(exist_ok=True)
            os.chmod(base / name, 0o700)
        trusted = base / "trusted.json"
        trusted.write_text("{}", encoding="utf-8")
        os.chmod(trusted, 0o600)
        uid = os.getuid()
        raw = {
            "environment": "production",
            "socket_path": str(base / "run" / "authority.sock"),
            "state_dir": str(base / "state"),
            "projects": {"Spec-First-Guardian": str(workspace)},
            "admin_uids": [uid],
            "clients": [{"uid": uid, "agents": ["agente-1"], "delegates": {}}],
            "approver": "usuario",
            "trusted_keys_file": str(trusted),
            "revocations_dir": str(base / "revocations"),
            "audit_log": str(base / "state" / "audit.jsonl"),
            "signing_key_file": None,
            "key_id": "KEY-1",
            "issuer": "spec-guardian-authority",
            "oidc": {},
            "require_distinct_uid": True,
            "allow_simulated_identity": False,
        }
        raw.update(overrides)
        path = base / "authority.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        os.chmod(path, 0o600)
        return authority_service.AuthorityConfig.load(path)

    def test_production_rejects_same_uid_and_missing_oidc(self):
        config = self._config(support.temp_dir("sg-prod-"))
        problems = authority_service.preflight(config)
        self.assertTrue(any("como cliente de agente" in problem for problem in problems), problems)
        self.assertTrue(any("OIDC" in problem for problem in problems), problems)
        self.assertTrue(any("clave de firma" in problem for problem in problems), problems)

    def test_config_inside_workspace_is_rejected(self):
        base = support.temp_dir("sg-prod2-")
        workspace = base / "workspace"
        workspace.mkdir()
        with self.assertRaises(authority_service.ConfigError):
            self._config(base, audit_log=str(workspace / "audit.jsonl"))

    def test_check_mode_refuses_insecure_config(self):
        base = support.temp_dir("sg-prod3-")
        config = self._config(base)
        self.assertEqual(authority_service.main(["--config", str(config.path), "--check"]), 2)


class TestTrustStoreConstruction(unittest.TestCase):
    def test_hand_built_store_never_verifies(self):
        signer, public_pem, _ = support.make_signer()
        real_store, _ = support.make_key_store(public_pem)
        record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=real_store)
        forged = approval_service.TrustedKeyStore(
            {
                "KEY-TEST-001": approval_service.TrustedKey(
                    key_id="KEY-TEST-001",
                    issuer=support.AUTHORITY,
                    subject="usuario",
                    public_key_pem=public_pem,
                )
            },
            source=Path("/tmp/almacen-inventado.json"),
        )
        self.assertFalse(forged.configured)
        self.assertFalse(approval_service.verify_approval(record, key_store=forged))
        self.assertTrue(real_store.configured)
        self.assertTrue(approval_service.verify_approval(record, key_store=real_store))


if __name__ == "__main__":
    unittest.main()
