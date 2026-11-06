#!/usr/bin/env python3
"""Consola de la autoridad de Spec-First Guardian.

Se ejecuta en el dominio de la autoridad (UID administrador distinto del UID de
los agentes). No importa claves ni verifica firmas localmente: toda operacion se
delega en el servicio de autoridad por el socket Unix.

Flujo:

1. El agente crea la solicitud con ``request``.
2. La persona administradora revisa con ``pending`` y obtiene un desafio de un
   solo uso con ``challenge``.
3. La persona confirma con ``approve`` y su token OIDC.
4. Cualquier operacion posterior se autoriza contra la aprobacion firmada.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authority_client


def _client(args) -> authority_client.AuthorityClient:
    # Sin variables de entorno ni argumentos: la configuracion la instala root
    # y el cliente verifica UID, socket y clave publica antes de enviar nada.
    return authority_client.client_from_protected_config()


def _print(payload: dict) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Consola de la autoridad (SPEC-001).")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Estado de la autoridad.")

    request = sub.add_parser("request", help="Registra una solicitud de aprobacion.")
    request.add_argument("--project", required=True)
    request.add_argument("--spec", required=True, help="Ruta de la SPEC relativa al proyecto.")
    request.add_argument("--scope", required=True)
    request.add_argument("--operations", nargs="+", required=True)
    request.add_argument("--paths", nargs="+", required=True)
    request.add_argument("--requirements", nargs="+", required=True)
    request.add_argument("--tasks", nargs="+", required=True)
    request.add_argument("--expires-at", default=None)

    sub.add_parser("pending", help="Lista solicitudes pendientes para revisar.")

    challenge = sub.add_parser("challenge", help="Emite un desafio de un solo uso.")
    challenge.add_argument("request_id")

    approve = sub.add_parser("approve", help="Aprueba con identidad autenticada.")
    approve.add_argument("request_id")
    approve.add_argument("--challenge", required=True)
    approve.add_argument("--id-token-file", default=None, help="Archivo con el ID token OIDC.")
    approve.add_argument("--test-identity", default=None, help="Solo entorno de pruebas: sujeto que confirma.")
    approve.add_argument("--confirm", action="store_true", help="Confirma explicitamente la aprobacion.")

    verify = sub.add_parser("verify", help="Verifica una aprobacion registrada.")
    verify.add_argument("--spec-id", required=True)
    verify.add_argument("--version", required=True)

    revoke = sub.add_parser("revoke", help="Revoca una autorizacion.")
    revoke.add_argument("--spec-id", required=True)
    revoke.add_argument("--version", required=True)
    revoke.add_argument("--event", required=True)
    revoke.add_argument("--reason", required=True)

    revoke_key = sub.add_parser("revoke-key", help="Revoca una clave de confianza.")
    revoke_key.add_argument("key_id")
    revoke_key.add_argument("--reason", required=True)

    reconcile = sub.add_parser("reconcile", help="Cierra una auditoria incompleta.")
    reconcile.add_argument("--note", required=True)

    sub.add_parser("audit-verify", help="Verifica la cadena de auditoria.")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        client = _client(args)
        if args.command == "status":
            _print(client.status())
        elif args.command == "request":
            _print(
                client.request_approval(
                    project=args.project,
                    spec=args.spec,
                    scope=args.scope,
                    operations=args.operations,
                    paths=args.paths,
                    requirements=args.requirements,
                    tasks=args.tasks,
                    expires_at=args.expires_at,
                )
            )
        elif args.command == "pending":
            _print(client.pending())
        elif args.command == "challenge":
            _print(client.challenge(args.request_id))
        elif args.command == "approve":
            if not args.confirm:
                print("La aprobacion exige confirmacion explicita (--confirm).", file=sys.stderr)
                return 2
            token = None
            if args.id_token_file:
                token = Path(args.id_token_file).read_text(encoding="utf-8").strip()
            identity = {"subject": args.test_identity, "confirmed": True} if args.test_identity else None
            _print(client.approve(args.request_id, args.challenge, id_token=token, test_identity=identity))
        elif args.command == "verify":
            _print(client.call("verify_approval", {"spec_id": args.spec_id, "version": args.version}))
        elif args.command == "revoke":
            _print(
                client.revoke(
                    spec_id=args.spec_id,
                    version=args.version,
                    authorization_event_id=args.event,
                    reason=args.reason,
                )
            )
        elif args.command == "revoke-key":
            _print(client.revoke_key(args.key_id, args.reason))
        elif args.command == "reconcile":
            _print(client.reconcile(args.note))
        elif args.command == "audit-verify":
            _print(client.audit_verify())
        return 0
    except authority_client.AuthorityDenied as error:
        print(json.dumps({"ok": False, "denied": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except authority_client.AuthorityUnavailable as error:
        print(json.dumps({"ok": False, "unavailable": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
