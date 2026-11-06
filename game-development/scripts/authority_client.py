#!/usr/bin/env python3
"""Cliente del agente para la autoridad de Spec-First Guardian.

Este modulo no importa ``approval_service`` ni carga claves: es la superficie que
un agente puede usar. Cada llamada abre el socket Unix, verifica las
credenciales del servidor (``SO_PEERCRED``) y envia una unica peticion JSON.
"""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class AuthorityUnavailable(RuntimeError):
    """La autoridad no esta disponible o no es la esperada."""


class AuthorityDenied(RuntimeError):
    """La autoridad denego la peticion."""


@dataclass
class AuthorityClient:
    socket_path: Path | str
    expected_uid: int | None = None
    timeout: float = 10.0

    def _peer_uid(self, connection: socket.socket) -> int | None:
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except (AttributeError, OSError):
            return None
        return struct.unpack("3i", raw)[1]

    def call(self, method: str, payload: dict | None = None) -> dict:
        path = Path(self.socket_path)
        if not path.exists():
            raise AuthorityUnavailable(f"autoridad no disponible: {path}")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(path))
            peer_uid = self._peer_uid(connection)
            if self.expected_uid is not None and peer_uid != self.expected_uid:
                raise AuthorityUnavailable("el servicio no se ejecuta con la identidad esperada")
            request = {"protocol": PROTOCOL_VERSION, "method": method, "payload": payload or {}}
            connection.sendall(json.dumps(request).encode("utf-8") + b"\n")
            with connection.makefile("rb") as stream:
                line = stream.readline(MAX_MESSAGE_BYTES + 1)
            if not line or len(line) > MAX_MESSAGE_BYTES:
                raise AuthorityUnavailable("respuesta vacia o demasiado grande")
            try:
                response = json.loads(line)
            except ValueError as error:
                raise AuthorityUnavailable("respuesta no es JSON") from error
        except (OSError, socket.timeout) as error:
            raise AuthorityUnavailable(f"fallo de comunicacion con la autoridad: {error}") from error
        finally:
            connection.close()
        if not isinstance(response, dict):
            raise AuthorityUnavailable("respuesta invalida")
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


def client_from_environment(agent: str = "") -> AuthorityClient:
    """Construye el cliente con la configuracion dada por el supervisor."""
    import os

    socket_path = os.environ.get("SPEC_GUARDIAN_AUTHORITY_SOCKET", "").strip()
    if not socket_path:
        raise AuthorityUnavailable("SPEC_GUARDIAN_AUTHORITY_SOCKET no configurado")
    expected = os.environ.get("SPEC_GUARDIAN_AUTHORITY_UID", "").strip()
    return AuthorityClient(socket_path=Path(socket_path), expected_uid=int(expected) if expected.isdigit() else None)
