#!/usr/bin/env python3
"""Enforcement de operaciones (lado agente).

Este proceso **no** ejecuta escrituras ni carga claves: envia la operacion a la
autoridad por el socket Unix. ``evaluate`` pide una decision sin escribir;
``apply`` pide a la autoridad que ejecute la operacion autorizada. Si la
autoridad no esta disponible, la respuesta es denegar.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authority_client


def _denied(reason: str, operation: str = "") -> dict:
    return {
        "allowed": False,
        "executed": False,
        "operation": operation,
        "spec_id": None,
        "version": None,
        "path": None,
        "digest": None,
        "audit_complete": False,
        "reasons": [reason],
    }


def _load_context(value: str | None) -> dict | None:
    if not value:
        return None
    if value == "-":
        try:
            data = json.load(sys.stdin)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None
    path = Path(value)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _client(socket_path: str | None) -> authority_client.AuthorityClient:
    selected = (socket_path or os.environ.get("SPEC_GUARDIAN_AUTHORITY_SOCKET", "")).strip()
    if not selected:
        raise authority_client.AuthorityUnavailable("SPEC_GUARDIAN_AUTHORITY_SOCKET no configurado")
    expected = os.environ.get("SPEC_GUARDIAN_AUTHORITY_UID", "").strip()
    return authority_client.AuthorityClient(
        socket_path=Path(selected),
        expected_uid=int(expected) if expected.isdigit() else None,
    )


def _request(operation: str, context: dict, execute: bool, socket_path: str | None) -> dict:
    payload = dict(context)
    if operation and not payload.get("operation_type"):
        payload["operation_type"] = operation
    content = payload.get("content")
    try:
        client = _client(socket_path)
        if execute:
            return client.authorize(payload, content=content if isinstance(content, str) else None)
        return client.evaluate(payload, content=content if isinstance(content, str) else None)
    except authority_client.AuthorityUnavailable as error:
        return _denied(f"IMPLEMENTACION BLOQUEADA: {error}", operation)
    except authority_client.AuthorityDenied as error:
        return _denied(f"operacion denegada: {error}", operation)


def evaluate_write(operation: str, spec_path: Path | None = None, task_id: str = "", approval_path: Path | None = None, operation_context: dict | None = None, socket_path: str | None = None) -> dict:
    """Decision de la autoridad, sin escribir."""
    if not isinstance(operation_context, dict):
        return _denied("IMPLEMENTACION BLOQUEADA: OPERACION SIN CONTEXTO DE AUTORIZACION.", operation)
    context = dict(operation_context)
    if task_id and not context.get("task"):
        context["task"] = task_id
    return _request(operation, context, execute=False, socket_path=socket_path)


def apply_write(operation: str, spec_path: Path | None = None, approval_path: Path | None = None, operation_context: dict | None = None, socket_path: str | None = None) -> dict:
    """Solicita a la autoridad ejecutar la operacion autorizada."""
    if not isinstance(operation_context, dict):
        return _denied("IMPLEMENTACION BLOQUEADA: OPERACION SIN CONTEXTO DE AUTORIZACION.", operation)
    return _request(operation, dict(operation_context), execute=True, socket_path=socket_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solicita a la autoridad evaluar o aplicar una operacion (SPEC-001).")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for name, help_text in (("evaluate", "Pide una decision sin escribir."), ("apply", "Pide ejecutar la operacion autorizada.")):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("--context", required=True, help="Contexto de operacion (JSON) o '-' para stdin.")
        sub.add_argument("--socket", default=None, help="Socket de la autoridad (por defecto, variable de entorno).")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    context = _load_context(args.context)
    if context is None:
        decision = _denied("contexto de operacion ausente o ilegible")
    elif args.mode == "apply":
        decision = apply_write(str(context.get("operation_type") or ""), operation_context=context, socket_path=args.socket)
    else:
        decision = evaluate_write(str(context.get("operation_type") or ""), operation_context=context, socket_path=args.socket)
    print(json.dumps(decision, indent=2, ensure_ascii=False))
    return 0 if decision.get("allowed") and decision.get("audit_complete", True) else 1


if __name__ == "__main__":
    sys.exit(main())
