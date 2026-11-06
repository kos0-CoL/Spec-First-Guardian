#!/usr/bin/env python3
"""Servicio de autoridad de Spec-First Guardian (dominio B).

Este proceso es el unico que:

* carga la clave privada Ed25519;
* mantiene el almacen de claves de confianza;
* firma autorizaciones;
* mantiene el registro de revocaciones;
* ejecuta escrituras autorizadas en el workspace protegido;
* escribe la auditoria.

Los agentes (dominio A) no importan este modulo: hablan con el mediante un
socket Unix y ``SO_PEERCRED``. Aunque un agente ejecute codigo Python en su
propio proceso, no obtiene la clave, no puede registrar claves y no puede
firmar: la frontera es de proceso y de identidad del sistema operativo, no de
visibilidad de clases.

Modos
-----

``production``  exige identidades distintas (servicio, agentes, administrador),
                proveedor OIDC configurado y archivos protegidos.
``test``        permite simular identidad y compartir UID. El estado se declara
                ``isolation: not_enforced`` y nunca debe usarse en produccion.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import urllib.parse
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import audit_chain
import implementation_gate
import revocation_registry
import safe_fs
import validate

PROTOCOL_VERSION = 2
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_CONTENT_BYTES = 1024 * 1024
SOCKET_TIMEOUT = 10.0
ATTESTATION_PREFIX = "SPEC-GUARDIAN-AUTHORITY-ATTESTATION-V1"
ATTESTATION_TTL_SECONDS = 300
NONCE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CLIENT_OPERATIONS = ("status", "request_approval", "authorize", "evaluate", "verify_approval")
ADMIN_OPERATIONS = ("pending", "challenge", "approve", "revoke", "revoke_key", "reconcile", "audit_verify", "status")


class ConfigError(RuntimeError):
    """Configuracion de la autoridad invalida o insegura."""


class Denied(RuntimeError):
    """Solicitud denegada con motivo registrable."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def attestation_statement(nonce: str, service_uid: int, pid: int) -> bytes:
    """Declaracion firmada que acredita la identidad del servicio."""
    return f"{ATTESTATION_PREFIX}\n{nonce}\n{int(service_uid)}\n{int(pid)}".encode("utf-8")


def _sha256(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _oidc_placeholders(oidc: dict) -> bool:
    text = " ".join(str(value).lower() for value in oidc.values())
    markers = ("ejemplo", "example", "placeholder", "todo", "pending", "changeme", "idp.")
    if any(marker in text for marker in markers):
        return True
    issuer = str(oidc.get("issuer") or "")
    jwks_url = str(oidc.get("jwks_url") or "")
    try:
        issuer_parts = urllib.parse.urlparse(issuer)
        jwks_parts = urllib.parse.urlparse(jwks_url)
    except ValueError:
        return True
    return not (issuer_parts.scheme == "https" and issuer_parts.netloc and jwks_parts.scheme == "https" and jwks_parts.netloc)


def _is_link(path: Path) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


@dataclass(frozen=True)
class ClientGrant:
    uid: int
    agents: tuple
    delegates: dict

    def delegated(self, agent: str) -> tuple:
        return tuple(self.delegates.get(agent, ()))


@dataclass
class AuthorityConfig:
    """Configuracion fijada por el supervisor del servicio."""

    path: Path
    socket_path: Path
    socket_group_gid: int | None
    state_dir: Path
    projects: dict
    admin_uids: tuple
    clients: dict
    approver: str
    trusted_keys_file: Path
    revocations_dir: Path
    audit_log: Path
    signing_key_file: Path | None
    key_id: str
    issuer: str
    oidc: dict
    environment: str
    challenge_ttl: int
    require_distinct_uid: bool
    allow_simulated_identity: bool
    expected_approver_subject: str = ""
    service_uid: int = field(default_factory=os.getuid)

    # -- carga ------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | str) -> "AuthorityConfig":
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"configuracion inexistente: {config_path}")
        if _is_link(config_path):
            raise ConfigError("la configuracion no puede ser un enlace simbolico")
        info = os.lstat(config_path)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("la configuracion no es un archivo regular")
        if info.st_uid not in (0, os.getuid()):
            raise ConfigError("propietario de la configuracion no autorizado")
        if stat.S_IMODE(info.st_mode) & 0o007:
            raise ConfigError("la configuracion es legible por otros usuarios")
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ConfigError("configuracion ilegible o JSON invalido") from error
        if not isinstance(raw, dict):
            raise ConfigError("la configuracion debe ser un objeto JSON")

        def required(name: str):
            value = raw.get(name)
            if not value:
                raise ConfigError(f"campo de configuracion ausente: {name}")
            return value

        projects_raw = required("projects")
        if not isinstance(projects_raw, dict) or not projects_raw:
            raise ConfigError("projects debe declarar al menos un proyecto")
        projects = {}
        for name, root in projects_raw.items():
            root_path = Path(str(root))
            if not root_path.is_absolute():
                raise ConfigError(f"el proyecto {name} debe usar una ruta absoluta")
            projects[str(name)] = root_path

        clients_raw = raw.get("clients") or []
        if not isinstance(clients_raw, list):
            raise ConfigError("clients debe ser una lista")
        clients = {}
        for entry in clients_raw:
            if not isinstance(entry, dict):
                raise ConfigError("entrada de cliente invalida")
            uid = int(entry.get("uid", -1))
            agents = entry.get("agents") or []
            delegates = entry.get("delegates") or {}
            if uid < 0 or not isinstance(agents, list) or not agents:
                raise ConfigError("cada cliente necesita uid y agentes")
            if not isinstance(delegates, dict):
                raise ConfigError("delegates debe ser un objeto")
            clients[uid] = ClientGrant(
                uid=uid,
                agents=tuple(str(agent) for agent in agents),
                delegates={str(key): tuple(str(item) for item in value) for key, value in delegates.items()},
            )

        admin_uids = tuple(int(uid) for uid in (raw.get("admin_uids") or []))
        environment = str(raw.get("environment") or "production")
        if environment not in ("production", "test"):
            raise ConfigError("environment debe ser production o test")

        socket_path = Path(str(required("socket_path")))
        state_dir = Path(str(required("state_dir")))
        for name, value in (("socket_path", socket_path), ("state_dir", state_dir)):
            if not value.is_absolute():
                raise ConfigError(f"{name} debe ser una ruta absoluta")
        projects_resolved = list(projects.values())
        for name, value in (
            ("socket_path", socket_path),
            ("state_dir", state_dir),
            ("trusted_keys_file", Path(str(required("trusted_keys_file")))),
            ("revocations_dir", Path(str(required("revocations_dir")))),
            ("audit_log", Path(str(required("audit_log")))),
        ):
            for root in projects_resolved:
                if _inside(value, root):
                    raise ConfigError(f"{name} no puede estar dentro del workspace del agente")

        signing_key = raw.get("signing_key_file")
        return cls(
            path=config_path,
            socket_path=socket_path,
            socket_group_gid=int(raw["socket_group_gid"]) if raw.get("socket_group_gid") is not None else None,
            state_dir=state_dir,
            projects=projects,
            admin_uids=admin_uids,
            clients=clients,
            approver=str(required("approver")),
            trusted_keys_file=Path(str(required("trusted_keys_file"))),
            revocations_dir=Path(str(required("revocations_dir"))),
            audit_log=Path(str(required("audit_log"))),
            signing_key_file=Path(str(signing_key)) if signing_key else None,
            key_id=str(required("key_id")),
            issuer=str(required("issuer")),
            oidc=dict(raw.get("oidc") or {}),
            environment=environment,
            challenge_ttl=int(raw.get("challenge_ttl_seconds") or 180),
            require_distinct_uid=bool(raw.get("require_distinct_uid", True)),
            allow_simulated_identity=bool(raw.get("allow_simulated_identity", False)),
            expected_approver_subject=str((raw.get("oidc") or {}).get("expected_subject") or ""),
            service_uid=os.getuid(),
        )

    # -- consultas --------------------------------------------------------
    def project_root(self, name: str) -> Path:
        root = self.projects.get(str(name))
        if root is None:
            raise Denied(f"proyecto no autorizado: {name}")
        return root

    def is_admin(self, uid: int) -> bool:
        return uid in self.admin_uids

    def grant(self, uid: int) -> ClientGrant | None:
        return self.clients.get(uid)


# ---------------------------------------------------------------------------
# Preflight: comprobaciones que impiden arrancar una autoridad insegura
# ---------------------------------------------------------------------------


def _owner_and_mode_problems(path: Path, uid: int, *, allow_root: bool = True, reject_world: bool = True) -> list:
    problems: list = []
    try:
        info = os.lstat(path)
    except OSError:
        return [f"no existe: {path}"]
    if stat.S_ISLNK(info.st_mode):
        problems.append(f"es un enlace simbolico: {path}")
    owners = (0, uid) if allow_root else (uid,)
    if info.st_uid not in owners:
        problems.append(f"propietario no autorizado: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if reject_world and mode & 0o007:
        problems.append(f"permisos abiertos a otros usuarios: {path}")
    if stat.S_ISDIR(info.st_mode) and mode & 0o020:
        problems.append(f"directorio escribible por el grupo: {path}")
    if stat.S_ISREG(info.st_mode) and mode & 0o077:
        problems.append(f"archivo legible por grupo u otros: {path}")
    return problems


def preflight(config: AuthorityConfig) -> list:
    problems: list = []
    uid = config.service_uid
    if config.require_distinct_uid:
        if uid in config.clients:
            problems.append("el UID del servicio aparece como cliente de agente")
        if uid in config.admin_uids:
            problems.append("el UID del servicio aparece como administrador")
        if set(config.clients) & set(config.admin_uids):
            problems.append("un mismo UID no puede ser agente y administrador")
    if config.environment == "production":
        if not config.admin_uids:
            problems.append("produccion requiere al menos un administrador humano")
        if config.allow_simulated_identity:
            problems.append("produccion no puede permitir identidad simulada")
        if not all(str(config.oidc.get(key) or "").strip() for key in ("issuer", "audience", "jwks_url", "expected_subject")):
            problems.append("produccion requiere issuer, audience, jwks_url y expected_subject OIDC")
        if _oidc_placeholders(config.oidc):
            problems.append("OIDC contiene valores de ejemplo o pendientes")
        try:
            jwks = _load_jwks(str(config.oidc.get("jwks_url") or ""), str(config.oidc.get("ca_file") or "") or None)
            if not jwks:
                problems.append("JWKS no contiene claves RS256 utilizables")
        except Exception as error:
            problems.append(f"JWKS no verificable: {type(error).__name__}")
        if config.signing_key_file is None:
            problems.append("produccion requiere clave de firma")
        if config.socket_group_gid is None:
            problems.append("produccion requiere socket_group_gid (grupo de agentes)")
    for path in (config.trusted_keys_file, config.revocations_dir, config.state_dir, config.socket_path.parent, config.audit_log.parent):
        problems.extend(_owner_and_mode_problems(path, uid))
    if config.signing_key_file is not None:
        key_problems = _owner_and_mode_problems(config.signing_key_file, uid, allow_root=False)
        problems.extend(key_problems)
        for root in config.projects.values():
            if _inside(config.signing_key_file, root):
                problems.append("la clave de firma esta dentro del workspace")
    for name, root in config.projects.items():
        if not root.is_dir():
            problems.append(f"workspace inexistente para {name}: {root}")
        if _is_link(root):
            problems.append(f"workspace es un enlace simbolico: {name}")
        else:
            try:
                report = __import__("workspace_guard").verify(root, uid, list(config.clients))
                if config.environment == "production":
                    problems.extend([f"workspace NO PROTEGIDO ({name}): {item}" for item in report.problems[:10]])
            except Exception as error:
                problems.append(f"workspace no verificable ({name}): {type(error).__name__}")
    return problems


# ---------------------------------------------------------------------------
# Autoridad
# ---------------------------------------------------------------------------


class Authority:
    def __init__(self, config: AuthorityConfig) -> None:
        self.config = config
        self.lock = threading.RLock()
        self.key_store = approval_service.TrustedKeyStore.from_config_file(config.trusted_keys_file)
        if not self.key_store.configured:
            raise ConfigError(f"almacen de confianza no utilizable: {self.key_store.error}")
        self.signer = None
        if config.signing_key_file is not None:
            self.signer = approval_service.FileSignerBackend(config.signing_key_file, config.key_id, config.issuer)
        provider = None
        if all(config.oidc.get(key) for key in ("issuer", "audience", "jwks_url")):
            provider = approval_service.OIDCIdentityProvider(
                issuer=str(config.oidc["issuer"]),
                audience=str(config.oidc["audience"]),
                jwks_provider=lambda: _load_jwks(str(config.oidc["jwks_url"]), str(config.oidc.get("ca_file") or "") or None),
                max_auth_age_seconds=int(config.oidc.get("max_auth_age_seconds", 300)),
            )
        if provider is None and config.allow_simulated_identity and config.environment == "test":
            provider = _TestIdentityProvider(config.approver)
        self.service = approval_service.ApprovalService(
            provider=provider,
            signer=self.signer,
            key_store=self.key_store,
            environment=config.environment,
        )
        self.audit = audit_chain.AuditChain(config.audit_log)
        self.audit.initialize()
        audit_valid, audit_reason, _ = self.audit.verify()
        if not audit_valid:
            try:
                self.audit.mark_incomplete("AUDIT_CORRUPT", {"reason": audit_reason})
            except audit_chain.AuditError as error:
                raise ConfigError("auditoria no verificable; autoridad no puede iniciar") from error
        self._audit_unhealthy = not audit_valid
        self._audit_reconciliable = audit_valid or audit_reason == "audit log ausente despues de inicializar"
        self._attestation_nonces: dict = {}
        self._requests_dir = config.state_dir / "requests"
        self._approvals_dir = config.state_dir / "approvals"
        self._requests_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._approvals_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # -- estado -----------------------------------------------------------
    @property
    def isolation(self) -> str:
        if self.config.require_distinct_uid and self.config.service_uid not in self.config.clients and self.config.service_uid not in self.config.admin_uids:
            return "enforced"
        return "not_enforced"

    def status(self) -> dict:
        valid, reason, count = self.audit.verify()
        return {
            "protocol": PROTOCOL_VERSION,
            "environment": self.config.environment,
            "isolation": self.isolation,
            "signing_available": bool(self.signer and self.signer.available),
            "identity_provider": type(self.service.provider).__name__ if self.service.provider else None,
            "identity_provider_configured": bool(self.service.provider and getattr(self.service.provider, "configured", False)),
            "audit_blocked": self.audit.is_blocked() or not valid,
            "audit_state": self.audit.health_state(),
            "audit_block_reason": self.audit.block_reason() if self.audit.is_blocked() else None,
            "audit_chain": {"valid": valid, "reason": reason, "events": count},
            "clients": [{"uid": grant.uid, "agents": list(grant.agents)} for grant in self.config.clients.values()],
        }

    def _require_healthy_audit(self) -> None:
        valid, reason, _ = self.audit.verify()
        if not valid or (self.audit.is_blocked() and os.path.lexists(self.audit.init_path)):
            self._audit_unhealthy = True
            raise Denied(f"auditoria no saludable ({reason}); requiere reconciliacion")

    def attest(self, uid: int, payload: dict) -> dict:
        """Prueba de identidad del servicio para el cliente.

        La firma se hace con la misma clave Ed25519 de la autoridad sobre una
        declaracion con dominio propio (no es una aprobacion) que liga el nonce
        del cliente, el UID y el PID del servicio. Un socket falso puede imitar
        la forma de la respuesta, pero no producir la firma.
        """
        if self.config.grant(uid) is None and not self.config.is_admin(uid):
            raise Denied("UID no autorizado para atestacion")
        nonce = str(payload.get("nonce") or "")
        if not NONCE_PATTERN.match(nonce):
            raise Denied("nonce de atestacion invalido")
        if self.signer is None or not self.signer.available:
            raise Denied("firma no disponible para atestacion")
        now = time.monotonic()
        with self.lock:
            expired = [key for key, seen in self._attestation_nonces.items() if now - seen > ATTESTATION_TTL_SECONDS]
            for key in expired:
                self._attestation_nonces.pop(key, None)
            if nonce in self._attestation_nonces:
                raise Denied("nonce de atestacion reutilizado")
            self._attestation_nonces[nonce] = now
            # El PID firmado es el del proceso servidor, no el del cliente: es
            # lo que el cliente compara con el PID de SO_PEERCRED.
            pid = os.getpid()
            try:
                signature = self.signer.sign(attestation_statement(nonce, os.getuid(), pid))
                fingerprint = self.signer.public_key_sha256()
            except approval_service.SignerUnavailable as error:
                raise Denied("firma no disponible para atestacion") from error
        return {
            "service_uid": os.getuid(),
            "pid": pid,
            "nonce": nonce,
            "key_id": self.config.key_id,
            "public_key_sha256": fingerprint,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    # -- utilidades de almacenamiento -------------------------------------
    def _request_path(self, request_id: str) -> Path:
        if not request_id.startswith("REQ-") or "/" in request_id:
            raise Denied("identificador de solicitud invalido")
        return self._requests_dir / f"{request_id}.json"

    def _save_request(self, request: dict) -> None:
        payload = {"request": request, "integrity": _sha256(request)}
        audit_chain.atomic_json_write(self._request_path(str(request["request_id"])), payload, mode=0o600)

    def _load_request(self, request_id: str) -> dict:
        path = self._request_path(request_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise Denied("solicitud desconocida o ilegible") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
            raise Denied("solicitud corrupta")
        request = payload["request"]
        if str(payload.get("integrity") or "") != _sha256(request):
            raise Denied("la solicitud fue alterada despues de registrarse")
        return request

    def _approval_path(self, spec_id: str, version: str) -> Path:
        safe = validate.SPEC_ID_PATTERN.match(spec_id)
        if not safe:
            raise Denied("spec_id invalido")
        return self._approvals_dir / f"{spec_id}-{version}.json"

    def _save_bundle(self, spec_id: str, version: str, approval: dict, spec_path: str, project: str) -> None:
        bundle = {
            "approval": approval,
            "context": {"spec_path": spec_path, "project": project},
        }
        audit_chain.atomic_json_write(self._approval_path(spec_id, version), bundle, mode=0o600)

    def _load_bundle(self, spec_id: str, version: str) -> tuple:
        path = self._approval_path(spec_id, version)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise Denied("no hay autorizacion registrada para esa SPEC") from error
        approval = payload.get("approval")
        context = payload.get("context") or {}
        if not isinstance(approval, dict):
            raise Denied("autorizacion corrupta")
        return approval, str(context.get("spec_path") or ""), str(context.get("project") or "")

    def _registry(self, spec_id: str) -> revocation_registry.RevocationRegistry:
        return revocation_registry.RevocationRegistry.for_spec(
            spec_id,
            key_store=self.key_store,
            workspace_root=None,
            registry_dir=self.config.revocations_dir,
        )

    # -- identidad de agentes ---------------------------------------------
    def resolve_agent(self, uid: int, operation: dict) -> str:
        grant = self.config.grant(uid)
        if grant is None:
            raise Denied("UID de cliente no autorizado")
        agent = str(operation.get("agent") or "").strip()
        if not agent:
            raise Denied("identidad de agente ausente")
        chain = operation.get("delegation") or []
        if agent in grant.agents:
            if chain:
                raise Denied("un agente principal no puede declarar delegacion")
            return agent
        if not isinstance(chain, list) or not chain:
            raise Denied("agente no autorizado y sin cadena de delegacion")
        current = None
        for step in chain:
            if not isinstance(step, dict):
                raise Denied("cadena de delegacion invalida")
            origin = str(step.get("from") or "")
            target = str(step.get("to") or "")
            if current is None:
                if origin not in grant.agents:
                    raise Denied("la delegacion no parte de un agente autorizado")
                current = origin
            elif origin != current:
                raise Denied("cadena de delegacion rota")
            if target not in grant.delegated(current):
                raise Denied("delegacion no autorizada para el agente")
            current = target
        if current != agent:
            raise Denied("el agente final no coincide con la cadena de delegacion")
        return agent

    # -- operaciones de agente --------------------------------------------
    def request_approval(self, uid: int, payload: dict) -> dict:
        self._require_healthy_audit()
        grant = self.config.grant(uid)
        if grant is None:
            raise Denied("UID de cliente no autorizado")
        project = str(payload.get("project") or "")
        root = self.config.project_root(project)
        spec_rel = str(payload.get("spec") or "")
        try:
            parts = safe_fs.split_relative(spec_rel)
            root_fd = safe_fs.open_root(root)
            try:
                text = safe_fs.read_file(root_fd, "/".join(parts)).decode("utf-8")
            finally:
                os.close(root_fd)
        except (safe_fs.UnsafePathError, UnicodeDecodeError) as error:
            raise Denied(f"SPEC no legible en el workspace: {error}") from error

        problems = validate.document_problems(text, require_approved=True)
        if problems:
            raise Denied("documento no aprobable: " + "; ".join(problems[:4]))
        identifiers = validate.spec_identifiers(text)
        operations = [str(item) for item in (payload.get("operations") or [])]
        paths = [str(item) for item in (payload.get("paths") or [])]
        requirements = [str(item).upper() for item in (payload.get("requirements") or [])]
        tasks = [str(item).upper() for item in (payload.get("tasks") or [])]
        if not (operations and paths and requirements and tasks):
            raise Denied("alcance vacio no autoriza nada")
        unknown_operations = [item for item in operations if item not in implementation_gate.FILE_OPERATIONS]
        if unknown_operations:
            raise Denied("operacion no ejecutable por el gate: " + ", ".join(unknown_operations))
        for requirement in requirements:
            if requirement not in identifiers["requirements"]:
                raise Denied(f"el requisito {requirement} no existe en la SPEC")
        for task in tasks:
            if task not in identifiers["tasks"]:
                raise Denied(f"la tarea {task} no existe en la SPEC")
        for path in paths:
            safe_fs.split_relative(path)
        if len(set(operations)) != len(operations) or len(set(paths)) != len(paths):
            raise Denied("el alcance contiene duplicados")
        scope = str(payload.get("scope") or "").strip()
        if not scope:
            raise Denied("alcance sin descripcion")

        frontmatter = validate.parse_frontmatter(text)
        spec_id = str(frontmatter.get("spec_id") or "")
        version = str(frontmatter.get("version") or "")

        with self.lock:
            request = self.service.register_request(
                spec_id=spec_id,
                project=project,
                version=version,
                spec_text=text,
                expected_approver=self.config.approver,
                scope=scope,
                operations=operations,
                authorized_paths=paths,
                requirements=requirements,
                tasks=tasks,
                expires_at=payload.get("expires_at"),
            )
            if request is None:
                raise Denied("solicitud rechazada por el servicio de aprobacion")
            request["spec_path"] = "/".join(parts)
            request["agent"] = ", ".join(str(agent) for agent in grant.agents)
            request["scope_hash"] = _sha256(
                {
                    "project": project,
                    "spec_id": spec_id,
                    "version": version,
                    "operations": sorted(operations),
                    "paths": sorted(paths),
                    "requirements": sorted(requirements),
                    "tasks": sorted(tasks),
                    "scope": scope,
                }
            )
            self._save_request(request)
            self.audit.append(
                {
                    "stage": "request",
                    "request_id": request["request_id"],
                    "spec_id": spec_id,
                    "version": version,
                    "project": project,
                    "fingerprint": request["fingerprint"],
                    "scope_hash": request["scope_hash"],
                    "client_uid": uid,
                }
            )
        return {
            "request_id": request["request_id"],
            "spec_id": spec_id,
            "version": version,
            "fingerprint": request["fingerprint"],
            "scope_hash": request["scope_hash"],
            "scope": scope,
            "operations": operations,
            "paths": paths,
            "requirements": requirements,
            "tasks": tasks,
            "status": "PENDING_USER_APPROVAL",
        }

    def pending(self, uid: int) -> dict:
        requests = []
        for path in sorted(self._requests_dir.glob("REQ-*.json")):
            try:
                request = self._load_request(path.stem)
            except Denied:
                requests.append({"request_id": path.stem, "status": "CORRUPT"})
                continue
            if request.get("status") in (None, "PENDING_USER_APPROVAL"):
                requests.append(
                    {
                        "request_id": request["request_id"],
                        "spec_id": request.get("spec_id"),
                        "version": request.get("version"),
                        "project": request.get("project"),
                        "scope": request.get("scope"),
                        "operations": request.get("operations"),
                        "paths": request.get("authorized_paths"),
                        "requirements": request.get("requirements"),
                        "tasks": request.get("tasks"),
                        "fingerprint": request.get("fingerprint"),
                        "agent": request.get("agent"),
                        "status": "PENDING_USER_APPROVAL",
                    }
                )
        return {"requests": requests, "count": len(requests)}

    def challenge(self, uid: int, payload: dict) -> dict:
        self._require_healthy_audit()
        request_id = str(payload.get("request_id") or "")
        if self.audit.is_blocked() or not self.audit.verify()[0]:
            raise Denied("auditoria no saludable: desafio denegado")
        with self.lock:
            request = self._load_request(request_id)
            if request.get("status") not in (None, "PENDING_USER_APPROVAL"):
                raise Denied(f"la solicitud ya esta en estado {request.get('status')}")
            project = str(request.get("project") or "")
            root = self.config.project_root(project)
            try:
                root_fd = safe_fs.open_root(root)
                try:
                    spec_text = safe_fs.read_file(root_fd, str(request.get("spec_path") or "")).decode("utf-8")
                finally:
                    os.close(root_fd)
            except (safe_fs.UnsafePathError, UnicodeDecodeError) as error:
                raise Denied(f"no se pudo mostrar la SPEC: {error}") from error
            if hashlib.sha256(spec_text.encode("utf-8")).hexdigest() != str(request.get("fingerprint") or ""):
                raise Denied("la SPEC cambio despues de registrar la solicitud")
            token = secrets.token_urlsafe(32)
            request["challenge_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            request["challenge_expires_at"] = _iso(_now() + timedelta(seconds=self.config.challenge_ttl))
            request["challenge_used"] = False
            request["oidc_state"] = secrets.token_urlsafe(32)
            request["oidc_nonce"] = secrets.token_urlsafe(32)
            request["session_id"] = secrets.token_urlsafe(32)
            self._save_request(request)
            self.audit.append({"stage": "challenge", "request_id": request_id, "admin_uid": uid})
        return {
            "request_id": request_id,
            "challenge": token,
            "expires_at": request["challenge_expires_at"],
            "fingerprint": request["fingerprint"],
            "scope_hash": request["scope_hash"],
            "oidc_state": request["oidc_state"],
            "oidc_nonce": request["oidc_nonce"],
            "session_id": request["session_id"],
            "review": {
                "project": request.get("project"),
                "spec": request.get("spec_path"),
                "spec_id": request.get("spec_id"),
                "version": request.get("version"),
                "operations": request.get("operations"),
                "paths": request.get("authorized_paths"),
                "requirements": request.get("requirements"),
                "tasks": request.get("tasks"),
                "scope": request.get("scope"),
                "spec_sha256": request.get("fingerprint"),
                # El contenido se obtiene en paginas ligadas a esta huella.
                "spec_sha256": request.get("fingerprint"),
                "spec_length": len(spec_text),
                "review_complete": False,
                "review_page_size": 4000,
                "review_pages": (len(spec_text) + 3999) // 4000,
                "review_base_offset": 0,
                "preview_truncated": True,
            },
        }

    def spec_page(self, uid: int, payload: dict) -> dict:
        request_id = str(payload.get("request_id") or "")
        offset = payload.get("offset", 0)
        limit = payload.get("limit", 4000)
        if not isinstance(offset, int) or not isinstance(limit, int) or offset < 0 or limit < 1 or limit > 4000:
            raise Denied("paginacion de SPEC invalida")
        request = self._load_request(request_id)
        root = self.config.project_root(str(request.get("project") or ""))
        root_fd = safe_fs.open_root(root)
        try:
            text = safe_fs.read_file(root_fd, str(request.get("spec_path") or "")).decode("utf-8")
        finally:
            os.close(root_fd)
        fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if fingerprint != request.get("fingerprint") or fingerprint != payload.get("fingerprint"):
            raise Denied("la SPEC cambio o la pagina no corresponde a la huella de revision")
        page = text[offset:offset + limit]
        return {"request_id": request_id, "spec_id": request["spec_id"], "version": request["version"],
                "fingerprint": fingerprint, "offset": offset, "next_offset": offset + len(page),
                "complete": offset + len(page) >= len(text), "content": page}

    def approve(self, uid: int, payload: dict) -> dict:
        self._require_healthy_audit()
        request_id = str(payload.get("request_id") or "")
        if self.audit.is_blocked() or not self.audit.verify()[0]:
            raise Denied("auditoria no saludable: aprobacion denegada")
        token = str(payload.get("challenge") or "")
        if not token:
            raise Denied("desafio de aprobacion ausente")
        with self.lock:
            request = self._load_request(request_id)
            stored = str(request.get("challenge_hash") or "")
            if not secrets.compare_digest(str(payload.get("oidc_state") or ""), str(request.get("oidc_state") or "")):
                raise Denied("state OIDC ausente o no coincide con la solicitud")
            if not secrets.compare_digest(str(payload.get("session_id") or ""), str(request.get("session_id") or "")):
                raise Denied("sesion de aprobacion ausente o incorrecta")
            if not stored or hashlib.sha256(token.encode("utf-8")).hexdigest() != stored:
                raise Denied("desafio de aprobacion invalido")
            if request.get("challenge_used"):
                raise Denied("desafio de aprobacion ya utilizado")
            expires_at = approval_service._parse_iso(request.get("challenge_expires_at"))
            if expires_at is None or _now() > expires_at:
                raise Denied("desafio de aprobacion caducado")
            # El desafio se consume antes de firmar: un fallo posterior no lo reutiliza.
            request["challenge_used"] = True
            self._save_request(request)

            project = str(request.get("project") or "")
            root = self.config.project_root(project)
            try:
                root_fd = safe_fs.open_root(root)
                try:
                    current = safe_fs.read_file(root_fd, str(request.get("spec_path") or "")).decode("utf-8")
                finally:
                    os.close(root_fd)
            except (safe_fs.UnsafePathError, UnicodeDecodeError) as error:
                raise Denied(f"no se pudo releer la SPEC: {error}") from error
            current_fingerprint = hashlib.sha256(current.encode("utf-8")).hexdigest()
            if current_fingerprint != str(request.get("fingerprint") or ""):
                raise Denied("la SPEC cambio despues de registrar la solicitud")
            scope_hash = _sha256({"project": request["project"], "spec_id": request["spec_id"], "version": request["version"], "operations": sorted(request["operations"]), "paths": sorted(request["authorized_paths"]), "requirements": sorted(request["requirements"]), "tasks": sorted(request["tasks"]), "scope": request["scope"]})
            if scope_hash != request.get("scope_hash") or payload.get("scope_hash") != scope_hash:
                raise Denied("el alcance cambio despues de la revision")
            review_pages = max(1, (len(current) + 3999) // 4000)
            if payload.get("review_complete") is not True or payload.get("review_pages") != review_pages or payload.get("review_fingerprint") != current_fingerprint:
                raise Denied("revision completa de la SPEC requerida antes de aprobar")
            problems = validate.document_problems(current, require_approved=True)
            if problems:
                raise Denied("documento no aprobable: " + "; ".join(problems[:4]))

            if not self.service.import_request(request):
                raise Denied("solicitud no reconstruible por la autoridad")
            event = self._approval_event(payload)
            record = self.service.approve_request(request_id, event)
            if record is None:
                raise Denied("firma de aprobacion denegada")
            request["status"] = "APPROVED"
            request["authorization_event_id"] = record.get("authorization_event_id")
            self._save_request(request)
            self._save_bundle(
                str(request["spec_id"]),
                str(request["version"]),
                record,
                str(request.get("spec_path") or ""),
                project,
            )
            self.audit.append(
                {
                    "stage": "approval",
                    "request_id": request_id,
                    "spec_id": request.get("spec_id"),
                    "version": request.get("version"),
                    "authorization_event_id": record.get("authorization_event_id"),
                    "approver": record.get("approver"),
                    "key_id": record.get("key_id"),
                    "admin_uid": uid,
                }
            )
        return {"approval": record, "request_id": request_id}

    def _approval_event(self, payload: dict) -> dict:
        if self.config.environment == "test" and self.config.allow_simulated_identity:
            identity = payload.get("test_identity")
            if not isinstance(identity, dict) or identity.get("confirmed") is not True:
                raise Denied("identidad de prueba no confirmada")
            return {"type": "human_approval", "subject": str(identity.get("subject") or ""), "confirmed": True}
        token = payload.get("id_token")
        if not isinstance(token, str) or not token.strip():
            raise Denied("falta el token OIDC de la persona que aprueba")
        # Never treat an unverified token parse as authentication. The current
        # transport has no browser callback/session capable of binding state,
        # nonce and PKCE to a verified authorization-code response.
        raise Denied("SETUP INCOMPLETE: se requiere callback OIDC con Authorization Code + PKCE")

    def verify_approval(self, payload: dict) -> dict:
        spec_id = str(payload.get("spec_id") or "")
        version = str(payload.get("version") or "")
        approval, _, _ = self._load_bundle(spec_id, version)
        check = self._registry(spec_id).check(spec_id, version, str(approval.get("authorization_event_id") or ""))
        verified = self.service.verify(approval)
        return {
            "verified": verified,
            "identity_bound": approval_service.identity_is_bound(approval, self.key_store),
            "revocation": {"status": check.status, "revoked": check.revoked, "reason": check.reason},
        }

    def _operation_decision(self, uid: int, payload: dict, execute: bool) -> dict:
        audit_valid, audit_reason, _ = self.audit.verify()
        if self._audit_unhealthy or self.audit.is_blocked() or not audit_valid:
            raise Denied(f"auditoria no saludable: {audit_reason}; operaciones bloqueadas")
        operation = payload.get("operation")
        if not isinstance(operation, dict):
            raise Denied("contexto de operacion ausente")
        agent = self.resolve_agent(uid, operation)
        project = str(operation.get("project") or "")
        root = self.config.project_root(project)
        spec_id = str(operation.get("spec_id") or "")
        version = str(operation.get("version") or "")
        approval, spec_rel, bundle_project = self._load_bundle(spec_id, version)
        if bundle_project != project:
            raise Denied("la autorizacion pertenece a otro proyecto")
        content = payload.get("content")
        if content is not None and not isinstance(content, str):
            raise Denied("contenido no admitido")
        if content is not None and len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise Denied("contenido demasiado grande")

        context = {key: operation.get(key) for key in implementation_gate.REQUIRED_CONTEXT_FIELDS}
        context["agent"] = agent
        context["workspace_root"] = str(root)
        if content is not None:
            context["content"] = content

        gate = implementation_gate.ImplementationGate(
            approval=approval,
            spec_path=root / spec_rel,
            key_store=self.key_store,
            registry=self._registry(spec_id),
            audit_path=self.config.audit_log,
            workspace_root=root,
        )
        decision = gate.execute(context) if execute else gate.authorize(context)
        result = decision.as_dict()
        result["agent"] = agent
        return result

    def authorize(self, uid: int, payload: dict) -> dict:
        return self._operation_decision(uid, payload, execute=True)

    def evaluate(self, uid: int, payload: dict) -> dict:
        return self._operation_decision(uid, payload, execute=False)

    # -- operaciones de administracion ------------------------------------
    def revoke(self, uid: int, payload: dict) -> dict:
        self._require_healthy_audit()
        admin_identity = self._admin_identity(uid, payload)
        spec_id = str(payload.get("spec_id") or "")
        version = str(payload.get("version") or "")
        event_id = str(payload.get("authorization_event_id") or "")
        reason = str(payload.get("reason") or "").strip()
        if not (spec_id and version and event_id and reason):
            raise Denied("revocacion incompleta")
        entries = self._read_revocations(spec_id)
        admin_identity = self._admin_identity(uid, payload)
        entries.append(
            {
                "authorization_event_id": event_id,
                "spec_id": spec_id,
                "version": version,
                "revoked": True,
                "revoked_by": admin_identity,
                "revoked_at": _iso(_now()),
                "reason": reason,
            }
        )
        self._write_revocations(spec_id, entries)
        self.audit.append(
            {
                "stage": "revocation",
                "spec_id": spec_id,
                "version": version,
                "authorization_event_id": event_id,
                "revoked_by": self.config.approver,
                "reason": reason,
                "admin_uid": uid,
                "authenticated_identity": admin_identity,
            }
        )
        return {"revoked": True, "spec_id": spec_id, "entries": len(entries)}

    def _read_revocations(self, spec_id: str) -> list:
        path = self.config.revocations_dir / f"{spec_id}.json"
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise Denied("registro de revocaciones ilegible") from error
        entries = payload.get("revocations")
        if not isinstance(entries, list):
            raise Denied("registro de revocaciones corrupto")
        return entries

    def _write_revocations(self, spec_id: str, entries: list) -> None:
        if self.signer is None or not self.signer.available:
            raise Denied("firma no disponible para el registro de revocaciones")
        payload = revocation_registry.sign_registry(spec_id, entries, self.signer)
        audit_chain.atomic_json_write(self.config.revocations_dir / f"{spec_id}.json", payload, mode=0o600)

    def revoke_key(self, uid: int, payload: dict) -> dict:
        self._require_healthy_audit()
        admin_identity = self._admin_identity(uid, payload)
        admin_identity = self._admin_identity(uid, payload)
        key_id = str(payload.get("key_id") or "")
        reason = str(payload.get("reason") or "").strip()
        if not (key_id and reason):
            raise Denied("revocacion de clave incompleta")
        raw = json.loads(self.config.trusted_keys_file.read_text(encoding="utf-8"))
        keys = raw.get("keys") if isinstance(raw, dict) else None
        if not isinstance(keys, list):
            raise Denied("almacen de confianza corrupto")
        found = False
        for entry in keys:
            if str(entry.get("key_id") or "") == key_id:
                entry["revoked"] = True
                entry["revoked_at"] = _iso(_now())
                entry["revoked_reason"] = reason
                found = True
        if not found:
            raise Denied("clave desconocida")
        audit_chain.atomic_json_write(self.config.trusted_keys_file, raw, mode=0o600)
        # El almacen en memoria se reconstruye para que la revocacion surta efecto ya.
        self.key_store = approval_service.TrustedKeyStore.from_config_file(self.config.trusted_keys_file)
        self.service.key_store = self.key_store
        self.audit.append({"stage": "key_revoked", "key_id": key_id, "reason": reason, "admin_uid": uid, "authenticated_identity": admin_identity})
        return {"revoked": True, "key_id": key_id}

    def _admin_identity(self, uid: int, payload: dict) -> dict:
        if uid not in self.config.admin_uids:
            raise Denied("accion administrativa requiere UID administrador")
        event = self._approval_event(payload)
        identity = self.service.provider.authenticate(event) if self.service.provider and event.get("id_token") else None
        if identity is None or identity.subject != self.config.expected_approver_subject:
            raise Denied("reautenticacion OIDC del administrador requerida")
        return {"issuer": identity.issuer, "subject": identity.subject, "authenticated_at": identity.authenticated_at, "uid": uid}

    def reconcile(self, uid: int, payload: dict) -> dict:
        admin_identity = self._admin_identity(uid, payload)
        note = str(payload.get("note") or "").strip()
        if not note:
            raise Denied("la reconciliacion exige una nota")
        if not self._audit_reconciliable:
            raise Denied("cadena corrupta/inaccesible: no se puede reconciliar sin restaurar evidencia")
        if not self.audit.is_blocked():
            return {"reconciled": False, "reason": "no hay auditoria incompleta"}
        event = self.audit.clear_incomplete(str(admin_identity), note)
        self._audit_unhealthy = False
        return {"reconciled": True, "seq": event.get("seq")}

    def audit_verify(self, uid: int) -> dict:
        valid, reason, count = self.audit.verify()
        return {"valid": valid, "reason": reason, "events": count, "blocked": self.audit.is_blocked()}


class _TestIdentityProvider(approval_service.IdentityProvider):
    """Identidad simulada: solo se instancia con environment=test."""

    is_simulated = True
    configured = True

    def __init__(self, subject: str) -> None:
        self.subject = subject
        self.issuer = "https://idp.test"
        self.method = "simulated"

    def authenticate(self, approval_event: dict):
        if not isinstance(approval_event, dict):
            return None
        if approval_event.get("type") != "human_approval" or approval_event.get("confirmed") is not True:
            return None
        if str(approval_event.get("subject") or "") != self.subject:
            return None
        return approval_service.HumanIdentity(
            method="simulated",
            issuer=self.issuer,
            subject=self.subject,
            audience="spec-guardian",
            authenticated_at=_iso(_now() - timedelta(minutes=1)),
            expires_at=_iso(_now() + timedelta(minutes=30)),
        )


def _load_jwks(url: str, ca_file: str | None = None) -> dict:
    """Descarga JWKS del proveedor OIDC y lo convierte en PEM por ``kid``."""
    import ssl
    import urllib.request

    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    with urllib.request.urlopen(url, timeout=5, context=context) as response:
        payload = json.loads(response.read().decode("utf-8"))
    keys = {}
    for entry in payload.get("keys") or []:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
            continue
        if entry.get("alg") != "RS256" or not entry.get("kid"):
            continue
        kid = str(entry.get("kid") or "")
        try:
            modulus = int.from_bytes(base64.urlsafe_b64decode(entry["n"] + "=="), "big")
            exponent = int.from_bytes(base64.urlsafe_b64decode(entry["e"] + "=="), "big")
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            public = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            keys[kid] = public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (KeyError, ValueError):
            continue
    return keys


# ---------------------------------------------------------------------------
# Servidor
# ---------------------------------------------------------------------------


class AuthorityServer:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority
        self.config = authority.config
        self._stop = threading.Event()
        self._socket: socket.socket | None = None

    # -- sockets ----------------------------------------------------------
    def _bind(self) -> socket.socket:
        path = self.config.socket_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if _is_link(path):
                raise ConfigError("el socket de la autoridad es un enlace simbolico")
            path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        os.chmod(path, 0o660)
        # El grupo del socket es el de los clientes (agentes), no el del servicio:
        # el servicio solo necesita poder crear el socket en su directorio.
        if self.config.socket_group_gid is not None:
            try:
                os.chown(path, -1, int(self.config.socket_group_gid))
            except OSError as error:
                raise ConfigError(f"no se pudo asignar el grupo del socket: {error}") from error
        server.listen(16)
        server.settimeout(1.0)
        return server

    def serve_forever(self) -> None:
        self._socket = self._bind()
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = self._socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                thread = threading.Thread(target=self._serve_connection, args=(connection,), daemon=True)
                thread.start()
        finally:
            self._shutdown()

    def stop(self) -> None:
        self._stop.set()

    def _shutdown(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        try:
            self.config.socket_path.unlink()
        except OSError:
            pass

    # -- protocolo --------------------------------------------------------
    @staticmethod
    def _peer(connection: socket.socket) -> tuple:
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except (AttributeError, OSError) as error:
            raise Denied("credenciales del par no disponibles (SO_PEERCRED)") from error
        pid, uid, gid = struct.unpack("3i", raw)
        return pid, uid, gid

    def _handle(self, uid: int, request: dict) -> dict:
        method = str(request.get("method") or "")
        payload = request.get("payload") or {}
        if not isinstance(payload, dict):
            raise Denied("payload invalido")
        authority = self.authority
        if method == "attest":
            return {"ok": True, "result": authority.attest(uid, payload)}
        if method == "spec_page":
            if not authority.config.is_admin(uid):
                raise Denied("solo el administrador puede consultar la revision")
            return {"ok": True, "result": authority.spec_page(uid, payload)}
        if method in CLIENT_OPERATIONS:
            if method == "status":
                return {"ok": True, "result": authority.status()}
            if authority.config.grant(uid) is None and not authority.config.is_admin(uid):
                raise Denied("UID no autorizado")
            if method == "request_approval":
                return {"ok": True, "result": authority.request_approval(uid, payload)}
            if method == "authorize":
                return {"ok": True, "result": authority.authorize(uid, payload)}
            if method == "evaluate":
                return {"ok": True, "result": authority.evaluate(uid, payload)}
            if method == "verify_approval":
                return {"ok": True, "result": authority.verify_approval(payload)}
        if method == "spec_page":
            if not authority.config.is_admin(uid):
                raise Denied("solo el administrador puede consultar la revision")
            return {"ok": True, "result": authority.spec_page(uid, payload)}
        if method in ADMIN_OPERATIONS:
            if not authority.config.is_admin(uid):
                raise Denied("operacion administrativa: UID no autorizado")
            if method == "pending":
                return {"ok": True, "result": authority.pending(uid)}
            if method == "challenge":
                return {"ok": True, "result": authority.challenge(uid, payload)}
            if method == "approve":
                return {"ok": True, "result": authority.approve(uid, payload)}
            if method == "revoke":
                return {"ok": True, "result": authority.revoke(uid, payload)}
            if method == "revoke_key":
                return {"ok": True, "result": authority.revoke_key(uid, payload)}
            if method == "reconcile":
                return {"ok": True, "result": authority.reconcile(uid, payload)}
            if method == "audit_verify":
                return {"ok": True, "result": authority.audit_verify(uid)}
        raise Denied(f"metodo no admitido: {method}")

    @staticmethod
    def _read_message(stream) -> dict | None:
        line = stream.readline(MAX_MESSAGE_BYTES + 1)
        if not line or len(line) > MAX_MESSAGE_BYTES:
            return None
        try:
            message = json.loads(line)
        except ValueError as error:
            raise Denied("mensaje JSON invalido") from error
        if not isinstance(message, dict):
            raise Denied("el mensaje debe ser un objeto JSON")
        return message

    @staticmethod
    def _write_message(stream, response: dict) -> None:
        stream.write(json.dumps(response, sort_keys=True).encode("utf-8") + b"\n")
        stream.flush()

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(SOCKET_TIMEOUT)
            pid, uid, _ = self._peer(connection)
        except (Denied, OSError):
            try:
                connection.sendall(json.dumps({"ok": False, "error": "credenciales no verificables"}).encode() + b"\n")
            except OSError:
                pass
            connection.close()
            return
        try:
            with connection.makefile("rwb") as stream:
                # Primer mensaje: atestacion obligatoria. Sin ella no se procesa
                # ninguna operacion, ni siquiera ``status``.
                try:
                    hello = self._read_message(stream)
                    if hello is None:
                        self._write_message(stream, {"ok": False, "error": "mensaje vacio o demasiado grande"})
                        return
                    if str(hello.get("method") or "") != "attest":
                        raise Denied("se exige atestacion antes de cualquier peticion")
                    if int(hello.get("protocol") or 0) != PROTOCOL_VERSION:
                        raise Denied("version de protocolo no admitida")
                    self._write_message(stream, self._handle(uid, hello))
                except Denied as error:
                    self._write_message(stream, {"ok": False, "error": str(error)})
                    return

                # Segundo mensaje: la peticion real, en la misma conexion ya
                # autenticada por SO_PEERCRED y por la atestacion firmada.
                try:
                    request = self._read_message(stream)
                    if request is None:
                        self._write_message(stream, {"ok": False, "error": "peticion vacia o demasiado grande"})
                        return
                    if str(request.get("method") or "") == "attest":
                        raise Denied("atestacion duplicada en la conexion")
                    if int(request.get("protocol") or 0) != PROTOCOL_VERSION:
                        raise Denied("version de protocolo no admitida")
                    response = self._handle(uid, request)
                except Denied as error:
                    response = {"ok": False, "error": str(error)}
                self._write_message(stream, response)
        except (OSError, ValueError):
            pass
        finally:
            connection.close()


def _bootstrap(directory: Path) -> Path:
    """Crea una autoridad de pruebas aislada en ``directory`` (modo test)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    state = root / "state"
    keys = root / "keys"
    revocations = root / "revocations"
    run = root / "run"
    for path in (state, keys, revocations, run):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    key = Ed25519PrivateKey.generate()
    key_path = keys / "signing_key.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted = keys / "trusted_keys.json"
    trusted.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "KEY-TEST-001",
                        "issuer": "spec-guardian-authority",
                        "subject": "usuario",
                        "public_key_pem": public_pem.decode("ascii"),
                        "revoked": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    os.chmod(trusted, 0o600)
    uid = os.getuid()
    params = {
        "environment": "test",
        "socket_path": str(run / "authority.sock"),
        "state_dir": str(state),
        "projects": {},
        "admin_uids": [uid],
        "clients": [{"uid": uid, "agents": ["agente-1"], "delegates": {"agente-1": ["subagente-1"]}}],
        "approver": "usuario",
        "trusted_keys_file": str(trusted),
        "revocations_dir": str(revocations),
        "audit_log": str(state / "audit.jsonl"),
        "signing_key_file": str(key_path),
        "key_id": "KEY-TEST-001",
        "issuer": "spec-guardian-authority",
        "oidc": {},
        "challenge_ttl_seconds": 120,
        "require_distinct_uid": False,
        "allow_simulated_identity": True,
    }
    config_path = root / "authority.json"
    config_path.write_text(json.dumps(params, indent=2), encoding="utf-8")
    os.chmod(config_path, 0o600)
    # Configuracion del cliente equivalente a la que instala root en
    # /etc/spec-guardian/client.json: socket, UID/GID esperados y clave publica
    # pinnada. Sin estos datos el cliente no conecta.
    client_path = root / "client.json"
    client_path.write_text(
        json.dumps(
            {
                "version": 1,
                "socket_path": params["socket_path"],
                "expected_service_uid": uid,
                "socket_gid": os.getgid(),
                "authority_public_key_pem": public_pem.decode("ascii"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    os.chmod(client_path, 0o600)
    return config_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Servicio de autoridad de Spec-First Guardian.")
    parser.add_argument("--config", type=Path, help="Configuracion de la autoridad.")
    parser.add_argument("--check", action="store_true", help="Solo valida la configuracion y los permisos.")
    parser.add_argument("--bootstrap", type=Path, help="Crea una autoridad de pruebas en el directorio indicado.")
    parser.add_argument("--print-status", action="store_true", help="Muestra el estado y termina.")
    args = parser.parse_args(argv)

    if args.bootstrap:
        target = _bootstrap(args.bootstrap)
        print(json.dumps({"bootstrap": str(target)}, indent=2))
        return 0
    if not args.config:
        parser.error("--config es obligatorio")
    try:
        config = AuthorityConfig.load(args.config)
    except ConfigError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2
    problems = preflight(config)
    if problems:
        print(json.dumps({"ok": False, "problems": problems}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 2
    authority = Authority(config)
    if args.check or args.print_status:
        print(json.dumps(authority.status(), indent=2, ensure_ascii=False))
        return 0

    server = AuthorityServer(authority)

    def _stop(signum, frame):
        server.stop()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(json.dumps({"ok": True, "socket": str(config.socket_path), "isolation": authority.isolation}), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
