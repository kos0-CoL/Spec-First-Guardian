#!/usr/bin/env python3
"""CLI de la autoridad de aprobacion (uso exclusivo del lado humano/confiable).

Este proceso es el unico que conoce la ubicacion de la clave privada. Los
agentes no deben poder ejecutarlo ni leer su configuracion.

Flujo:
    approval_cli.py request --spec SPEC.md ... --out request.json
    approval_cli.py approve --request request.json --event event.json --out approval.json
    approval_cli.py verify --approval approval.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import validate

CONFIG_ENV = "SPEC_GUARDIAN_AUTHORITY_CONFIG"


def load_config(path: str | None) -> dict:
    configured = path or os.environ.get(CONFIG_ENV)
    if not configured:
        raise SystemExit("Falta --config o SPEC_GUARDIAN_AUTHORITY_CONFIG.")
    data = json.loads(Path(configured).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("Configuracion de autoridad invalida.")
    return data


def build_service(config: dict) -> approval_service.ApprovalService:
    authority = config.get("authority") or {}
    identity = config.get("identity") or {}
    signer = approval_service.FileSignerBackend(
        key_path=authority.get("private_key_file", ""),
        key_id=authority.get("key_id", ""),
        issuer=authority.get("issuer", ""),
        workspace_root=config.get("agent_workspace"),
    )
    if not signer.available:
        raise SystemExit(f"Backend de firma no disponible: {signer.error}")
    jwks: dict = {}
    jwks_file = identity.get("jwks_file")
    if jwks_file:
        jwks = {str(kid): pem for kid, pem in json.loads(Path(jwks_file).read_text(encoding="utf-8")).items()}
    provider = approval_service.OIDCIdentityProvider(issuer=identity.get("issuer"), audience=identity.get("audience"), jwks=jwks)
    if not provider.configured:
        raise SystemExit("Proveedor de identidad no configurado: emisor, audiencia y JWKS son obligatorios.")
    key_store = approval_service.TrustedKeyStore.from_config_file(config.get("trusted_keys_file"), workspace_root=config.get("agent_workspace"))
    if not key_store.configured:
        raise SystemExit(f"Almacen de confianza no disponible: {key_store.error}")
    return approval_service.ApprovalService(provider=provider, signer=signer, key_store=key_store, environment="production")


def _split(values) -> list:
    result: list = []
    for value in values or []:
        result.extend(item.strip() for item in str(value).split(",") if item.strip())
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Autoridad de aprobacion de Spec-First Guardian.")
    parser.add_argument("--config", default=None)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    request_parser = subparsers.add_parser("request", help="Registra una solicitud de aprobacion.")
    request_parser.add_argument("--spec", type=Path, required=True)
    request_parser.add_argument("--project", required=True)
    request_parser.add_argument("--scope", required=True)
    request_parser.add_argument("--operations", action="append", required=True)
    request_parser.add_argument("--paths", action="append", required=True)
    request_parser.add_argument("--requirements", action="append", required=True)
    request_parser.add_argument("--tasks", action="append", required=True)
    request_parser.add_argument("--approver", required=True)
    request_parser.add_argument("--expires-at", default=None)
    request_parser.add_argument("--out", type=Path, required=True)

    approve_parser = subparsers.add_parser("approve", help="Firma una solicitud con identidad autenticada.")
    approve_parser.add_argument("--request", type=Path, required=True)
    approve_parser.add_argument("--event", type=Path, required=True)
    approve_parser.add_argument("--out", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify", help="Verifica una autorizacion firmada.")
    verify_parser.add_argument("--approval", type=Path, required=True)

    args = parser.parse_args(argv)
    config = load_config(args.config)
    service = build_service(config)

    if args.mode == "request":
        text = args.spec.read_text(encoding="utf-8")
        frontmatter = validate.parse_frontmatter(text)
        request = service.register_request(
            spec_id=str(frontmatter.get("spec_id") or ""),
            project=args.project,
            version=str(frontmatter.get("version") or ""),
            spec_text=text,
            expected_approver=args.approver,
            scope=args.scope,
            operations=_split(args.operations),
            authorized_paths=_split(args.paths),
            requirements=_split(args.requirements),
            tasks=_split(args.tasks),
            expires_at=args.expires_at,
        )
        if request is None:
            print("Solicitud rechazada: alcance incompleto o datos invalidos.")
            return 1
        args.out.write_text(json.dumps(request, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Solicitud registrada: {request['request_id']}")
        return 0

    if args.mode == "approve":
        request = json.loads(args.request.read_text(encoding="utf-8"))
        event = json.loads(args.event.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or not isinstance(event, dict):
            print("Solicitud o evento invalidos.")
            return 1
        if not service.import_request(request):
            print("Solicitud invalida o incompleta.")
            return 1
        record = service.approve_request(str(request.get("request_id") or ""), event)
        if record is None:
            print("Aprobacion denegada: identidad no autenticada o firma no disponible.")
            return 1
        args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        print("Autorizacion firmada.")
        return 0

    approval = json.loads(args.approval.read_text(encoding="utf-8"))
    if not service.verify(approval):
        print("Autorizacion NO verificable.")
        return 1
    print(f"Autorizacion valida para {approval.get('spec_id')} v{approval.get('version')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
