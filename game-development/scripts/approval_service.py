#!/usr/bin/env python3
"""Autoridad unica de aprobacion de Spec-First Guardian (SPEC-001).

Contrato de seguridad
---------------------

* Ninguna funcion publica acepta una clave privada. La firma solo puede
  realizarla un backend protegido (``FileSignerBackend``) que carga la clave
  desde un archivo fuera del workspace del agente y con permisos restrictivos.
* Ninguna funcion publica acepta una clave publica desde el registro bajo
  verificacion. La verificacion resuelve ``key_id`` exclusivamente en un
  ``TrustedKeyStore`` cargado desde configuracion del supervisor.
* Una firma no demuestra por si sola aprobacion humana: el registro debe
  contener una identidad autenticada por un proveedor externo, ligada a la
  clave de la autoridad y a la huella del contenido aprobado.
* Toda entrada invalida produce una denegacion controlada y registrada; no se
  propaga ninguna excepcion hacia el flujo de autorizacion.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNATURE_ALGORITHM = "Ed25519"
AUTHORIZATION_FORMAT_VERSION = "2.0.0"

FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SPEC_ID_PATTERN = re.compile(r"^SPEC-\d+$", re.IGNORECASE)

REQUIRED_APPROVAL_FIELDS = (
    "spec_id",
    "project",
    "version",
    "fingerprint",
    "approver",
    "issuer",
    "approved_at",
    "scope",
    "authorization_event_id",
    "key_id",
)

logger = logging.getLogger("spec_guardian.approval")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _string_list(value) -> list:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value if str(item or "").strip()]


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# Serializacion canonica
# ---------------------------------------------------------------------------


def canonical_payload(approval: dict) -> bytes:
    """Serializacion determinista del contenido completo de la autorizacion.

    Incluye identidad, alcance, listas de operaciones/rutas/requisitos/tareas,
    emisor, clave y version de formato. Cambiar cualquier campo firmado invalida
    la firma.
    """
    approval = approval if isinstance(approval, dict) else {}
    identity = approval.get("identity") if isinstance(approval.get("identity"), dict) else {}
    payload = {
        "spec_id": approval.get("spec_id"),
        "project": approval.get("project"),
        "version": approval.get("version"),
        "fingerprint": approval.get("fingerprint"),
        "approver": approval.get("approver"),
        "issuer": approval.get("issuer"),
        "identity": {
            "method": identity.get("method"),
            "issuer": identity.get("issuer"),
            "subject": identity.get("subject"),
            "audience": identity.get("audience"),
            "authenticated_at": identity.get("authenticated_at"),
        },
        "approved_at": approval.get("approved_at"),
        "expires_at": approval.get("expires_at"),
        "scope": approval.get("scope"),
        "operations": _string_list(approval.get("operations")),
        "authorized_paths": _string_list(approval.get("authorized_paths")),
        "requirements": _string_list(approval.get("requirements")),
        "tasks": _string_list(approval.get("tasks")),
        "authorization_event_id": approval.get("authorization_event_id"),
        "key_id": approval.get("key_id"),
        "authorization_format_version": approval.get("authorization_format_version"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_revocation_envelope(spec_id: str, revocations: list) -> bytes:
    payload = {"spec_id": str(spec_id or ""), "revocations": revocations if isinstance(revocations, list) else []}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Identidad humana
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HumanIdentity:
    """Identidad humana autenticada por un proveedor externo."""

    method: str
    issuer: str
    subject: str
    audience: str | None = None
    authenticated_at: str | None = None
    expires_at: str | None = None

    def valid_at(self, moment: datetime) -> bool:
        authenticated_at = _parse_iso(self.authenticated_at)
        if authenticated_at is None or authenticated_at > moment + timedelta(minutes=5):
            return False
        expires_at = _parse_iso(self.expires_at)
        if expires_at is not None and expires_at <= moment:
            return False
        return bool(self.subject and self.issuer and self.method)


class IdentityProvider:
    """Contrato de proveedor de identidad.

    ``is_simulated`` debe ser ``True`` solo en implementaciones de prueba; el
    servicio de aprobacion rechaza proveedores simulados fuera del entorno de
    test.
    """

    is_simulated = False
    configured = False

    def authenticate(self, approval_event: dict) -> HumanIdentity | None:  # pragma: no cover - contrato
        raise NotImplementedError


class OIDCIdentityProvider(IdentityProvider):
    """Proveedor OIDC/SigIL: valida un ID token firmado contra un emisor fijo.

    Requiere emisor, audiencia y al menos una clave de firma (``jwks`` o
    ``jwks_provider``). Sin esa configuracion el proveedor no esta operativo y
    toda aprobacion queda denegada.
    """

    is_simulated = False

    def __init__(self, issuer: str | None = None, audience: str | None = None, jwks: dict | None = None, jwks_provider=None, clock_skew_seconds: int = 60) -> None:
        self.issuer = str(issuer or "").strip()
        self.audience = str(audience or "").strip()
        self._jwks = {str(kid): pem for kid, pem in (jwks or {}).items()}
        self._jwks_provider = jwks_provider
        self.clock_skew_seconds = int(clock_skew_seconds)

    @property
    def configured(self) -> bool:
        return bool(self.issuer and self.audience and (self._jwks or self._jwks_provider is not None))

    def _key_for(self, kid) -> bytes | None:
        if kid is not None and str(kid) in self._jwks:
            return self._jwks[str(kid)]
        if self._jwks_provider is not None:
            try:
                keys = self._jwks_provider() or {}
            except Exception:
                return None
            if kid is not None:
                return keys.get(str(kid))
            if len(keys) == 1:
                return next(iter(keys.values()))
        return None

    def authenticate(self, approval_event: dict) -> HumanIdentity | None:
        if not self.configured:
            logger.warning("aprobacion denegada: proveedor OIDC no configurado")
            return None
        if not isinstance(approval_event, dict):
            return None
        token = approval_event.get("id_token")
        if not isinstance(token, str) or not token.strip():
            logger.warning("aprobacion denegada: evento sin id_token")
            return None
        try:
            import jwt

            header = jwt.get_unverified_header(token)
            key = self._key_for(header.get("kid"))
            if not key:
                logger.warning("aprobacion denegada: clave de firma OIDC desconocida")
                return None
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=self.clock_skew_seconds,
            )
        except Exception as error:  # token invalido, caducado, emisor o audiencia incorrectos
            logger.warning("aprobacion denegada: token OIDC invalido (%s)", type(error).__name__)
            return None
        return HumanIdentity(
            method="oidc",
            issuer=str(claims.get("iss") or ""),
            subject=str(claims.get("sub") or ""),
            audience=str(claims.get("aud") or "") or None,
            authenticated_at=_iso(datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)),
            expires_at=_iso(datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)),
        )


# ---------------------------------------------------------------------------
# Backend de firma protegido
# ---------------------------------------------------------------------------


class SignerUnavailable(RuntimeError):
    """El backend de firma no puede usarse (clave ausente, permisos o formato)."""


class SignerBackend:
    """Contrato de backend de firma. Nunca recibe material de clave del llamante."""

    key_id = ""
    issuer = ""

    @property
    def available(self) -> bool:  # pragma: no cover - contrato
        return False

    def sign(self, payload: bytes) -> bytes:  # pragma: no cover - contrato
        raise NotImplementedError


class FileSignerBackend(SignerBackend):
    """Firma con una clave Ed25519 almacenada en un archivo protegido.

    Verifica que la clave este fuera del workspace del agente y que sus permisos
    no permitan lectura por grupo u otros usuarios. Cualquier incumplimiento
    deja el backend no disponible y la aprobacion queda denegada.
    """

    def __init__(self, key_path: Path | str, key_id: str, issuer: str, workspace_root: Path | str | None = None) -> None:
        self.key_path = Path(key_path)
        self.key_id = str(key_id or "")
        self.issuer = str(issuer or "")
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None
        self._private_key: Ed25519PrivateKey | None = None
        self.error = ""
        self._load()

    def _load(self) -> None:
        if not self.key_id or not self.issuer:
            self.error = "key_id o emisor ausente"
            return
        try:
            resolved = self.key_path.resolve()
            info = resolved.stat()
        except OSError:
            self.error = "clave de firma inexistente"
            return
        if self.workspace_root is not None and _within(resolved, self.workspace_root):
            self.error = "clave de firma dentro del workspace del agente"
            return
        if stat.S_IMODE(info.st_mode) & 0o077:
            self.error = "permisos de clave de firma demasiado abiertos"
            return
        try:
            material = resolved.read_bytes()
            loaded = serialization.load_pem_private_key(material, password=None)
        except (OSError, ValueError, TypeError):
            self.error = "clave de firma ilegible o PEM invalido"
            return
        if not isinstance(loaded, Ed25519PrivateKey):
            self.error = "la clave de firma no es Ed25519"
            return
        self._private_key = loaded

    @property
    def available(self) -> bool:
        return self._private_key is not None

    def sign(self, payload: bytes) -> bytes:
        if self._private_key is None:
            raise SignerUnavailable(self.error or "firma no disponible")
        return self._private_key.sign(payload)


# ---------------------------------------------------------------------------
# Almacen de confianza
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    issuer: str
    subject: str
    public_key_pem: bytes
    revoked: bool = False


class TrustedKeyStore:
    """Claves publicas autorizadas, cargadas desde configuracion del supervisor.

    No expone registro publico: la unica via de alta es ``from_config_file``,
    que exige un archivo fuera del workspace con permisos restrictivos.
    """

    def __init__(self, keys: dict | None = None, source: Path | None = None, error: str | None = None, loaded: bool = False) -> None:
        self._keys: dict[str, TrustedKey] = dict(keys or {})
        self.source = source
        self.error = error
        # Solo una carga real desde archivo protegido marca el almacen como utilizable.
        # Construirlo a mano con claves o con una ruta arbitraria no lo habilita.
        self._loaded = bool(loaded)

    @property
    def configured(self) -> bool:
        return self._loaded and self.error is None and self.source is not None

    @classmethod
    def unconfigured(cls, reason: str = "almacen de confianza no configurado") -> "TrustedKeyStore":
        return cls({}, source=None, error=reason)

    @classmethod
    def from_config_file(cls, path: Path | str | None, workspace_root: Path | str | None = None) -> "TrustedKeyStore":
        if not path:
            return cls.unconfigured("no se configuro archivo de claves de confianza")
        config_path = Path(path)
        try:
            resolved = config_path.resolve()
            info = resolved.stat()
        except OSError:
            return cls.unconfigured("archivo de claves de confianza inexistente")
        if workspace_root is not None and _within(resolved, Path(workspace_root)):
            return cls({}, source=resolved, error="almacen de confianza dentro del workspace del agente")
        if stat.S_IMODE(info.st_mode) & 0o022:
            return cls({}, source=resolved, error="permisos del almacen de confianza permiten escritura ajena")
        try:
            data = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls({}, source=resolved, error="almacen de confianza ilegible o JSON invalido")
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            return cls({}, source=resolved, error="estructura del almacen de confianza invalida")
        keys: dict[str, TrustedKey] = {}
        for item in data["keys"]:
            if not isinstance(item, dict):
                return cls({}, source=resolved, error="entrada de clave invalida")
            key_id = str(item.get("key_id") or "").strip()
            issuer = str(item.get("issuer") or "").strip()
            subject = str(item.get("subject") or "").strip()
            pem = item.get("public_key_pem")
            if not key_id or not issuer or not subject or not isinstance(pem, str) or not pem.strip():
                return cls({}, source=resolved, error="entrada de clave incompleta")
            try:
                loaded = serialization.load_pem_public_key(pem.encode("utf-8"))
            except (ValueError, TypeError):
                return cls({}, source=resolved, error="clave publica PEM invalida")
            if not hasattr(loaded, "verify"):
                return cls({}, source=resolved, error="la clave publica no admite verificacion Ed25519")
            keys[key_id] = TrustedKey(
                key_id=key_id,
                issuer=issuer,
                subject=subject,
                public_key_pem=pem.encode("utf-8"),
                revoked=bool(item.get("revoked", False)),
            )
        return cls(keys, source=resolved, loaded=True)

    def entry(self, key_id: str) -> TrustedKey | None:
        return self._keys.get(str(key_id or ""))

    def issuer_for(self, key_id: str) -> str | None:
        key = self.entry(key_id)
        return key.issuer if key else None

    def known_key_ids(self) -> list:
        return sorted(self._keys.keys())


def _env_path(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def get_default_key_store(workspace_root: Path | str | None = None) -> TrustedKeyStore:
    """Carga el almacen de confianza configurado por el supervisor.

    El agente no puede declarar claves por parametro ni por variables con
    material criptografico: solo se acepta una ruta a configuracion protegida.

    Uso previsto: herramientas de **solo lectura** (validacion e informes). El
    camino de implementacion no usa esta funcion: la autoridad pasa su propio
    almacen cargado desde ``authority.json`` y nunca lee configuracion de
    confianza del entorno del agente.
    """
    root = workspace_root or _env_path("SPEC_GUARDIAN_WORKSPACE") or Path.cwd()
    return TrustedKeyStore.from_config_file(_env_path("SPEC_GUARDIAN_TRUSTED_KEYS"), workspace_root=root)


# ---------------------------------------------------------------------------
# Servicio de aprobacion
# ---------------------------------------------------------------------------


class ApprovalService:
    """Orquesta solicitud, confirmacion humana y firma de autorizaciones."""

    def __init__(self, provider: IdentityProvider | None = None, signer: SignerBackend | None = None, key_store: TrustedKeyStore | None = None, environment: str = "production") -> None:
        self.provider = provider
        self.signer = signer
        self.key_store = key_store if key_store is not None else TrustedKeyStore.unconfigured()
        self.environment = str(environment or "production")
        self._requests: dict[str, dict] = {}

    # -- estado -----------------------------------------------------------
    @property
    def signing_available(self) -> bool:
        if self.provider is None or not getattr(self.provider, "configured", False):
            return False
        if getattr(self.provider, "is_simulated", False) and self.environment == "production":
            return False
        if self.signer is None or not getattr(self.signer, "available", False):
            return False
        return True

    def _authenticate(self, approval_event: dict | None) -> HumanIdentity | None:
        if self.provider is None or not getattr(self.provider, "configured", False):
            logger.warning("aprobacion denegada: no hay proveedor de identidad configurado")
            return None
        if getattr(self.provider, "is_simulated", False) and self.environment == "production":
            logger.warning("aprobacion denegada: proveedor simulado en entorno de produccion")
            return None
        if not isinstance(approval_event, dict) or not approval_event:
            logger.warning("aprobacion denegada: sin evento de aprobacion")
            return None
        try:
            identity = self.provider.authenticate(approval_event)
        except Exception as error:
            logger.warning("aprobacion denegada: fallo del proveedor (%s)", type(error).__name__)
            return None
        if identity is None or not isinstance(identity, HumanIdentity):
            return None
        if not identity.valid_at(_now()):
            logger.warning("aprobacion denegada: identidad no vigente")
            return None
        return identity

    # -- solicitud --------------------------------------------------------
    def register_request(self, *, spec_id: str, project: str, version: str, spec_text: str, expected_approver: str, scope: str, operations: list, authorized_paths: list, requirements: list, tasks: list, expires_at: str | None = None) -> dict | None:
        """Registra una solicitud de aprobacion con la huella del contenido real."""
        if not isinstance(spec_text, str) or not spec_text.strip():
            return None
        if not SPEC_ID_PATTERN.match(str(spec_id or "")) or not str(project or "").strip() or not str(version or "").strip():
            return None
        if not str(expected_approver or "").strip() or not str(scope or "").strip():
            return None
        operations = _string_list(operations)
        authorized_paths = _string_list(authorized_paths)
        requirements = _string_list(requirements)
        tasks = _string_list(tasks)
        if not (operations and authorized_paths and requirements and tasks):
            logger.warning("solicitud rechazada: alcance vacio no autoriza nada")
            return None
        if expires_at is not None and _parse_iso(expires_at) is None:
            return None
        request = {
            "request_id": f"REQ-{uuid.uuid4().hex}",
            "spec_id": str(spec_id),
            "project": str(project),
            "version": str(version),
            "fingerprint": hashlib.sha256(spec_text.encode("utf-8")).hexdigest(),
            "expected_approver": str(expected_approver),
            "scope": str(scope),
            "operations": operations,
            "authorized_paths": authorized_paths,
            "requirements": requirements,
            "tasks": tasks,
            "expires_at": str(expires_at) if expires_at else None,
            "registered_at": _iso(_now()),
        }
        self._requests[request["request_id"]] = request
        return dict(request)

    def import_request(self, request: dict) -> bool:
        """Recupera una solicitud serializada para el proceso de aprobacion."""
        if not isinstance(request, dict):
            return False
        request_id = str(request.get("request_id") or "")
        required = ("spec_id", "project", "version", "fingerprint", "expected_approver", "scope")
        if not request_id or any(not str(request.get(field_name) or "").strip() for field_name in required):
            return False
        if not all(_string_list(request.get(field_name)) for field_name in ("operations", "authorized_paths", "requirements", "tasks")):
            return False
        self._requests[request_id] = dict(request)
        return True

    def approve_request(self, request_id: str, approval_event: dict, now: datetime | None = None) -> dict | None:
        """Procesa una aprobacion humana autenticada y firma la autorizacion."""
        request = self._requests.get(str(request_id or ""))
        if request is None:
            logger.warning("aprobacion denegada: solicitud desconocida")
            return None
        if not self.signing_available:
            logger.warning("aprobacion denegada: firma no disponible")
            return None
        identity = self._authenticate(approval_event)
        if identity is None:
            return None
        if identity.subject != request["expected_approver"]:
            logger.warning("aprobacion denegada: la identidad autenticada no es el aprobador esperado")
            return None
        moment = now or _now()
        record = {
            "spec_id": request["spec_id"],
            "project": request["project"],
            "version": request["version"],
            "fingerprint": request["fingerprint"],
            "approver": identity.subject,
            "issuer": self.signer.issuer,
            "identity": {
                "method": identity.method,
                "issuer": identity.issuer,
                "subject": identity.subject,
                "audience": identity.audience,
                "authenticated_at": identity.authenticated_at or _iso(moment),
            },
            "approved_at": _iso(moment),
            "expires_at": request["expires_at"],
            "scope": request["scope"],
            "operations": list(request["operations"]),
            "authorized_paths": list(request["authorized_paths"]),
            "requirements": list(request["requirements"]),
            "tasks": list(request["tasks"]),
            "authorization_event_id": f"EVT-{uuid.uuid4().hex}",
            "key_id": self.signer.key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "authorization_format_version": AUTHORIZATION_FORMAT_VERSION,
        }
        try:
            signature = self.signer.sign(canonical_payload(record))
        except Exception as error:
            logger.warning("aprobacion denegada: fallo de firma (%s)", type(error).__name__)
            return None
        record["signature"] = base64.b64encode(signature).decode("ascii")
        record["signed_at"] = _iso(moment)
        return record

    # -- verificacion -----------------------------------------------------
    def verify(self, approval: dict | None) -> bool:
        return verify_approval(approval, key_store=self.key_store)

    def trusted_issuer(self, key_id: str) -> str | None:
        return self.key_store.issuer_for(key_id)


# ---------------------------------------------------------------------------
# Verificacion
# ---------------------------------------------------------------------------


def _structural_problems(approval: dict) -> list:
    problems: list = []
    for field_name in REQUIRED_APPROVAL_FIELDS:
        if not str(approval.get(field_name) or "").strip():
            problems.append(f"campo obligatorio ausente: {field_name}")
    if approval.get("algorithm") != SIGNATURE_ALGORITHM:
        problems.append("algoritmo de firma no admitido")
    if approval.get("authorization_format_version") != AUTHORIZATION_FORMAT_VERSION:
        problems.append("version de formato de autorizacion no admitida")
    if not FINGERPRINT_PATTERN.match(str(approval.get("fingerprint") or "")):
        problems.append("huella de contenido invalida")
    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        problems.append("firma ausente")
    for list_field in ("operations", "authorized_paths", "requirements", "tasks"):
        if not _string_list(approval.get(list_field)):
            problems.append(f"alcance vacio en {list_field}")
    approved_at = _parse_iso(approval.get("approved_at"))
    if approved_at is None:
        problems.append("fecha de aprobacion invalida")
    return problems


def _key_problems(approval: dict, key_store: TrustedKeyStore | None) -> list:
    store = key_store if key_store is not None else get_default_key_store()
    if not store.configured:
        return [store.error or "almacen de confianza no configurado"]
    key = store.entry(str(approval.get("key_id") or ""))
    if key is None:
        return ["key_id desconocido para la autoridad de confianza"]
    if key.revoked:
        return ["clave de la autoridad revocada"]
    problems: list = []
    if str(approval.get("issuer") or "") != key.issuer:
        problems.append("el emisor declarado no coincide con la autoridad de la clave")
    if str(approval.get("approver") or "") != key.subject:
        problems.append("el aprobador no coincide con el sujeto autorizado para la clave")
    return problems


def verify_approval(approval: dict | None, key_store: TrustedKeyStore | None = None, now: datetime | None = None) -> bool:
    """Verifica firma, emisor, sujeto, vigencia e integridad del alcance.

    Los campos ``verified``, ``revoked``, ``signature_valid`` o ``public_key``
    del registro no se consultan: nunca son fuente de confianza.
    """
    if not isinstance(approval, dict):
        logger.warning("verificacion denegada: registro no es un objeto")
        return False
    problems = _structural_problems(approval)
    problems.extend(_key_problems(approval, key_store))
    if problems:
        logger.warning("verificacion denegada: %s", "; ".join(problems))
        return False
    store = key_store if key_store is not None else get_default_key_store()
    key = store.entry(str(approval["key_id"]))
    if key is None:
        return False
    try:
        signature = base64.b64decode(str(approval["signature"]).strip(), validate=True)
        if not signature:
            return False
        public_key = serialization.load_pem_public_key(key.public_key_pem)
        public_key.verify(signature, canonical_payload(approval))
    except (binascii.Error, ValueError, TypeError):
        logger.warning("verificacion denegada: firma o codificacion invalida")
        return False
    except InvalidSignature:
        logger.warning("verificacion denegada: la firma no corresponde al contenido firmado")
        return False
    except Exception:
        logger.warning("verificacion denegada: fallo criptografico")
        return False
    moment = now or _now()
    expires_at = _parse_iso(approval.get("expires_at"))
    if approval.get("expires_at") and expires_at is None:
        return False
    if expires_at is not None and moment > expires_at:
        logger.warning("verificacion denegada: autorizacion caducada")
        return False
    identity = approval.get("identity")
    if not isinstance(identity, dict):
        logger.warning("verificacion denegada: autorizacion sin identidad autenticada")
        return False
    if str(identity.get("subject") or "") != str(approval.get("approver") or ""):
        logger.warning("verificacion denegada: identidad no ligada al aprobador")
        return False
    if not str(identity.get("method") or "").strip() or not str(identity.get("issuer") or "").strip():
        logger.warning("verificacion denegada: identidad incompleta")
        return False
    authenticated_at = _parse_iso(identity.get("authenticated_at"))
    approved_at = _parse_iso(approval.get("approved_at"))
    if authenticated_at is None or approved_at is None:
        logger.warning("verificacion denegada: fechas de identidad invalidas")
        return False
    if authenticated_at > approved_at + timedelta(minutes=5):
        logger.warning("verificacion denegada: identidad posterior a la aprobacion")
        return False
    return True


def identity_is_bound(approval: dict | None, key_store: TrustedKeyStore | None = None) -> bool:
    """Comprueba que la identidad firmada pertenece al sujeto de la clave."""
    if not isinstance(approval, dict):
        return False
    store = key_store if key_store is not None else get_default_key_store()
    key = store.entry(str(approval.get("key_id") or ""))
    if key is None:
        return False
    identity = approval.get("identity")
    if not isinstance(identity, dict):
        return False
    return bool(
        str(identity.get("subject") or "") == key.subject
        and str(identity.get("subject") or "") == str(approval.get("approver") or "")
        and str(identity.get("issuer") or "").strip()
        and str(approval.get("issuer") or "") == key.issuer
    )
