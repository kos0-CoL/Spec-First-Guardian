#!/usr/bin/env python3
"""Cliente del agente para la autoridad de Spec-First Guardian.

Este modulo no importa la autoridad ni carga claves privadas: es la superficie
que un agente puede usar. La conexion no se configura con variables de entorno
ni con argumentos de linea de comandos, sino con un archivo protegido que
instala ``install_authority.sh`` como root (por defecto
``/etc/spec-guardian/client.json``).

Antes de enviar una sola peticion, el cliente:

1. comprueba que la configuracion es un archivo regular, absoluto, sin enlaces
   simbolicos, propiedad de root o del usuario del servicio y no escribible por
   el grupo ni por otros (puede ser legible: solo contiene la clave publica);
2. comprueba que el socket es un socket real (no un enlace), propiedad del UID
   del servicio, con el GID esperado y sin acceso para otros, dentro de un
   directorio que el agente no puede escribir;
3. obtiene las credenciales del par con ``SO_PEERCRED`` y exige que el UID sea
   exactamente el del servicio (nunca ``None``);
4. pide al servidor que firme un nonce aleatorio y verifica la firma con la
   clave publica Ed25519 pinnada en la configuracion protegida.

El punto 4 es lo que impide que un socket falso suplante a la autoridad: un
proceso del agente puede crear su propio socket y ejecutarse con su propio UID,
pero no tiene la clave privada de la autoridad y no puede producir la
atestacion. Cualquier comprobacion que no pueda realizarse termina en
denegacion.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL_VERSION = 2
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
DEFAULT_CLIENT_CONFIG = Path("/etc/spec-guardian/client.json")
ATTESTATION_PREFIX = "SPEC-GUARDIAN-AUTHORITY-ATTESTATION-V1"
NONCE_PATTERN_LENGTH = 64


class AuthorityUnavailable(RuntimeError):
    """La autoridad no esta disponible o no es la esperada."""


class AuthorityDenied(RuntimeError):
    """La autoridad denego la peticion."""


class AuthorityConfigError(AuthorityUnavailable):
    """La configuracion protegida del cliente falta o no es segura."""


def attestation_statement(nonce: str, service_uid: int, pid: int) -> bytes:
    """Declaracion exacta que el servidor firma y el cliente verifica."""
    return f"{ATTESTATION_PREFIX}\n{nonce}\n{int(service_uid)}\n{int(pid)}".encode("utf-8")


def _public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _load_public_key(material: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(str(material).encode("utf-8"))
    except (TypeError, ValueError) as error:
        raise AuthorityConfigError("clave publica de la autoridad ilegible") from error
    if not isinstance(key, Ed25519PublicKey):
        raise AuthorityConfigError("la clave publica de la autoridad no es Ed25519")
    return key


def _absolute(path_value) -> Path:
    try:
        path = Path(str(path_value))
    except (TypeError, ValueError) as error:
        raise AuthorityConfigError("ruta de configuracion invalida") from error
    if not path.is_absolute():
        raise AuthorityConfigError(f"la ruta debe ser absoluta: {path}")
    return path


def _check_directory(directory: Path, owners: tuple) -> None:
    try:
        info = os.lstat(directory)
    except OSError as error:
        raise AuthorityConfigError(f"directorio de configuracion inaccesible: {directory}") from error
    if stat.S_ISLNK(info.st_mode):
        raise AuthorityConfigError(f"el directorio no puede ser un enlace simbolico: {directory}")
    if not stat.S_ISDIR(info.st_mode):
        raise AuthorityConfigError(f"no es un directorio: {directory}")
    if info.st_uid not in owners:
        raise AuthorityConfigError(f"propietario del directorio no autorizado: {directory}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise AuthorityConfigError(f"el directorio es escribible por grupo u otros: {directory}")


@dataclass(frozen=True)
class ClientConfig:
    """Configuracion de conexion validada, escrita por el instalador."""

    socket_path: Path
    service_uid: int
    socket_gid: int
    public_key_pem: str
    source: Path | None = None

    def __post_init__(self) -> None:
        path = _absolute(self.socket_path)
        object.__setattr__(self, "socket_path", path)
        if isinstance(self.service_uid, bool) or not isinstance(self.service_uid, int):
            raise AuthorityConfigError("expected_service_uid debe ser un entero")
        if self.service_uid <= 0:
            raise AuthorityConfigError("expected_service_uid no puede ser root ni estar ausente")
        if isinstance(self.socket_gid, bool) or not isinstance(self.socket_gid, int) or self.socket_gid < 0:
            raise AuthorityConfigError("socket_gid debe ser un entero no negativo")
        _load_public_key(self.public_key_pem)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return _load_public_key(self.public_key_pem)

    @property
    def public_key_sha256(self) -> str:
        return _public_key_fingerprint(self.public_key)

    @classmethod
    def load(cls, path: Path | str = DEFAULT_CLIENT_CONFIG) -> "ClientConfig":
        """Carga y valida la configuracion protegida. Sin valores por defecto."""
        config_path = _absolute(path)
        try:
            info = os.lstat(config_path)
        except OSError as error:
            raise AuthorityConfigError(
                f"configuracion protegida ausente: {config_path}; ejecute install_authority.sh"
            ) from error
        if stat.S_ISLNK(info.st_mode):
            raise AuthorityConfigError("la configuracion no puede ser un enlace simbolico")
        if not stat.S_ISREG(info.st_mode):
            raise AuthorityConfigError("la configuracion no es un archivo regular")
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise AuthorityConfigError("configuracion ilegible o JSON invalido") from error
        if not isinstance(raw, dict):
            raise AuthorityConfigError("la configuracion debe ser un objeto JSON")
        if raw.get("version") not in (None, 1):
            raise AuthorityConfigError("version de configuracion no admitida")
        missing = [
            name
            for name in ("socket_path", "expected_service_uid", "socket_gid", "authority_public_key_pem")
            if raw.get(name) in (None, "")
        ]
        if missing:
            raise AuthorityConfigError("campos ausentes en la configuracion: " + ", ".join(missing))
        config = cls(
            socket_path=Path(str(raw["socket_path"])),
            service_uid=raw["expected_service_uid"],
            socket_gid=raw["socket_gid"],
            public_key_pem=str(raw["authority_public_key_pem"]),
            source=config_path,
        )
        # Propietario y permisos se comprueban despues de conocer el UID del
        # servicio: root instala el archivo y el servicio debe poder leerlo.
        owners = (0, config.service_uid)
        if info.st_uid not in owners:
            raise AuthorityConfigError("propietario de la configuracion no autorizado")
        mode = stat.S_IMODE(info.st_mode)
        # Solo datos publicos (socket y clave publica): puede ser legible, pero
        # nunca escribible por grupo ni por otros.
        if mode & 0o022:
            raise AuthorityConfigError("la configuracion es escribible por grupo u otros")
        _check_directory(config_path.parent, owners)
        return config


@dataclass
class AuthorityClient:
    """Cliente ligado a una configuracion ya validada."""

    config: ClientConfig
    timeout: float = 10.0

    # -- verificacion local ----------------------------------------------
    def _verify_socket(self) -> None:
        path = self.config.socket_path
        try:
            info = os.lstat(path)
        except OSError as error:
            raise AuthorityUnavailable(f"autoridad no disponible: {path}") from error
        if stat.S_ISLNK(info.st_mode):
            raise AuthorityUnavailable("el socket de la autoridad es un enlace simbolico")
        if not stat.S_ISSOCK(info.st_mode):
            raise AuthorityUnavailable("la ruta configurada no es un socket")
        if info.st_uid != self.config.service_uid:
            raise AuthorityUnavailable("el propietario del socket no es el UID del servicio esperado")
        if info.st_gid != self.config.socket_gid:
            raise AuthorityUnavailable("el GID del socket no coincide con el autorizado")
        if stat.S_IMODE(info.st_mode) & 0o007:
            raise AuthorityUnavailable("el socket es accesible por otros usuarios")
        _check_directory(path.parent, (0, self.config.service_uid))

    @staticmethod
    def _peer_credentials(connection) -> tuple:
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except (AttributeError, OSError) as error:
            raise AuthorityUnavailable("credenciales del par no disponibles (SO_PEERCRED)") from error
        pid, uid, gid = struct.unpack("3i", raw)
        return pid, uid, gid

    # -- protocolo --------------------------------------------------------
    @staticmethod
    def _send(stream, message: dict) -> None:
        stream.write(json.dumps(message).encode("utf-8") + b"\n")
        stream.flush()

    @staticmethod
    def _read(stream) -> dict:
        line = stream.readline(MAX_MESSAGE_BYTES + 1)
        if not line or len(line) > MAX_MESSAGE_BYTES:
            raise AuthorityUnavailable("respuesta vacia o demasiado grande")
        try:
            response = json.loads(line)
        except ValueError as error:
            raise AuthorityUnavailable("respuesta no es JSON") from error
        if not isinstance(response, dict):
            raise AuthorityUnavailable("respuesta invalida")
        return response

    def _verify_attestation(self, response: dict, nonce: str, peer_pid: int) -> None:
        if not response.get("ok"):
            raise AuthorityUnavailable(str(response.get("error") or "atestacion denegada"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise AuthorityUnavailable("atestacion invalida")
        if str(result.get("nonce") or "") != nonce:
            raise AuthorityUnavailable("la atestacion no corresponde al nonce enviado")
        if result.get("service_uid") != self.config.service_uid:
            raise AuthorityUnavailable("la atestacion declara otro UID de servicio")
        if result.get("pid") != peer_pid:
            raise AuthorityUnavailable("la atestacion no corresponde al proceso conectado")
        if str(result.get("public_key_sha256") or "") != self.config.public_key_sha256:
            raise AuthorityUnavailable("la autoridad no usa la clave publica pinnada")
        try:
            signature = base64.b64decode(str(result.get("signature") or ""), validate=True)
        except (binascii.Error, ValueError) as error:
            raise AuthorityUnavailable("firma de atestacion invalida") from error
        statement = attestation_statement(nonce, self.config.service_uid, peer_pid)
        try:
            self.config.public_key.verify(signature, statement)
        except InvalidSignature as error:
            raise AuthorityUnavailable("la firma de atestacion no es valida") from error

    def call(self, method: str, payload: dict | None = None) -> dict:
        self._verify_socket()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            try:
                connection.connect(str(self.config.socket_path))
            except (OSError, socket.timeout) as error:
                raise AuthorityUnavailable(f"autoridad no disponible: {error}") from error
            peer_pid, peer_uid, _ = self._peer_credentials(connection)
            if peer_uid != self.config.service_uid:
                raise AuthorityUnavailable("el servicio no se ejecuta con la identidad esperada")
            with connection.makefile("rwb") as stream:
                nonce = secrets.token_hex(NONCE_PATTERN_LENGTH // 2)
                self._send(stream, {"protocol": PROTOCOL_VERSION, "method": "attest", "payload": {"nonce": nonce}})
                self._verify_attestation(self._read(stream), nonce, peer_pid)
                self._send(
                    stream,
                    {"protocol": PROTOCOL_VERSION, "method": method, "payload": payload or {}},
                )
                response = self._read(stream)
        finally:
            connection.close()
        if not response.get("ok"):
            raise AuthorityDenied(str(response.get("error") or "denegado"))
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    # -- atajos -----------------------------------------------------------
    def status(self) -> dict:
        return self.call("status")

    def request_approval(self, **payload) -> dict:
        return self.call("request_approval", payload)

    def pending(self) -> dict:
        return self.call("pending")

    def challenge(self, request_id: str) -> dict:
        return self.call("challenge", {"request_id": request_id})

    def approve(self, request_id: str, challenge: str, *, id_token: str | None = None, test_identity: dict | None = None) -> dict:
        payload = {"request_id": request_id, "challenge": challenge}
        if id_token is not None:
            payload["id_token"] = id_token
        if test_identity is not None:
            payload["test_identity"] = test_identity
        return self.call("approve", payload)

    def revoke(self, **payload) -> dict:
        return self.call("revoke", payload)

    def revoke_key(self, key_id: str, reason: str) -> dict:
        return self.call("revoke_key", {"key_id": key_id, "reason": reason})

    def reconcile(self, note: str) -> dict:
        return self.call("reconcile", {"note": note})

    def audit_verify(self) -> dict:
        return self.call("audit_verify")

    def authorize(self, operation: dict, content: str | None = None) -> dict:
        payload: dict = {"operation": operation}
        if content is not None:
            payload["content"] = content
        return self.call("authorize", payload)

    def evaluate(self, operation: dict, content: str | None = None) -> dict:
        payload: dict = {"operation": operation}
        if content is not None:
            payload["content"] = content
        return self.call("evaluate", payload)


def client_from_protected_config(path: Path | str | None = None) -> AuthorityClient:
    """Cliente desde la configuracion instalada por root.

    No se consulta ninguna variable de entorno: el agente no puede redirigir el
    socket ni el UID esperado desde su propio proceso.
    """
    return AuthorityClient(ClientConfig.load(DEFAULT_CLIENT_CONFIG if path is None else path))
