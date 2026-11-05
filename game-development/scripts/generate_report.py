#!/usr/bin/env python3
"""Genera un informe de cumplimiento a partir de una especificacion (SPEC-001)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate


def build_report(result: dict) -> str:
    implementation_allowed = bool(result.get("implementation_allowed"))
    document_valid = bool(result.get("document_valid"))
    requirements_valid = bool(result.get("requirements_valid"))
    approval_valid = bool(result.get("approval_valid"))
    approval_verified = bool(result.get("approval_verified"))

    if not document_valid:
        state = "DOCUMENTO_INVALIDO"
        block_reason = "El documento no supera la validacion documental."
    elif not requirements_valid:
        state = "REQUISITOS_INVALIDOS"
        block_reason = "El documento es valido pero los requisitos no son validos."
    elif not approval_valid:
        state = "APROBACION_NO_VALIDADA"
        block_reason = "La aprobacion no puede validarse: ausente, invalida, revocada, version o contenido modificados."
    elif not implementation_allowed:
        state = "IMPLEMENTACION_BLOQUEADA"
        block_reason = "La aprobacion no habilita la implementacion para la version vigente."

    lines = [
        "# Informe de Cumplimiento — Spec-First Guardian (SPEC-001)",
        "",
        f"- **Spec ID**: {result.get('spec_id') or 'N/A'}",
        f"- **Estado**: {result.get('status') or 'N/A'}",
        f"- **Version**: {result.get('version') or 'N/A'}",
        f"- **Aprobador**: {result.get('approver') or 'N/A'}",
        f"- **Fecha de aprobacion**: {result.get('approved_at') or 'N/A'}",
        "",
        "## Resultado de la validacion",
        "",
        f"- **Errores**: {len(result.get('errors') or [])}",
        f"- **Advertencias**: {len(result.get('warnings') or [])}",
        "",
        "## Resultado de la autorizacion",
        "",
        f"- **Estado de la SPEC**: {result.get('status') or 'N/A'}",
        f"- **Aprobacion humana verificada**: {'SI' if approval_verified else 'NO'}",
        f"- **Aprobacion valida**: {'SI' if approval_valid else 'NO'}",
        f"- **Implementacion permitida**: {'SI' if implementation_allowed else 'NO'}",
        "",
        "## Bloqueo de implementacion",
        "",
    ]
    if implementation_allowed:
        lines.append("La especificacion esta aprobada, valida y autorizada. Proceder a implementacion dentro del alcance aprobado.")
    else:
        lines.append(f"IMPLEMENTACION BLOQUEADA: {state}. {block_reason}")
        lines.append("La implementacion esta bloqueada.")
    lines.append("")
    return "\n".join(lines)


def build_block_report(task_id: str, agent: str, project: str, reason: str, spec_status: str, missing_requirements: list, allowed_actions: list, forbidden_actions: list, next_step: str) -> str:
    lines = [
        "# Informe de Bloqueo — SPEC-001",
        "",
        f"- **Tarea**: {task_id}",
        f"- **Agente responsable**: {agent}",
        f"- **Proyecto**: {project}",
        f"- **Motivo**: {reason}",
        f"- **Estado de la SPEC**: {spec_status}",
        f"- **Requisitos faltantes**: {', '.join(missing_requirements) if missing_requirements else 'Ninguno'}",
        f"- **Acciones permitidas**: {', '.join(allowed_actions) if allowed_actions else 'Ninguna'}",
        f"- **Acciones prohibidas**: {', '.join(forbidden_actions) if forbidden_actions else 'Ninguna'}",
        f"- **Próximo paso**: {next_step}",
        "",
        "El agente debe comunicar el bloqueo sin ocultarlo, minimizarlo ni intentar resolverlo mediante modificaciones no autorizadas.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Genera el informe de cumplimiento o de bloqueo de una SPEC.")
    parser.add_argument("spec", type=Path, nargs="?", help="Ruta al archivo de especificacion (Markdown).")
    parser.add_argument("--block", action="store_true", help="Genera un informe de bloqueo (formato SPEC-001 seccion 12).")
    parser.add_argument("--task-id", default="TASK-XXX")
    parser.add_argument("--agent", default="agente")
    parser.add_argument("--project", default="proyecto")
    parser.add_argument("--reason", default="Sin SPEC aprobada.")
    parser.add_argument("--spec-status", default="DRAFT")
    parser.add_argument("--missing-requirements", default="")
    parser.add_argument("--allowed", default="")
    parser.add_argument("--forbidden", default="")
    parser.add_argument("--next-step", default="Elaborar SPEC.")
    parser.add_argument("--approval", type=Path, default=None, help="Ruta al registro de aprobacion (JSON) verificable.")
    args = parser.parse_args(argv)

    approval = validate.load_approval(args.approval) if args.approval else None

    if args.block:
        spec_status = args.spec_status
        if args.spec is not None and args.spec.exists():
            result = validate.validate_spec(args.spec, approval=approval)
            spec_status = str(result.get("status") or args.spec_status)
        missing = [m.strip() for m in args.missing_requirements.split(",") if m.strip()]
        allowed = [a.strip() for a in args.allowed.split(",") if a.strip()]
        forbidden = [a.strip() for a in args.forbidden.split(",") if a.strip()]
        print(build_block_report(args.task_id, args.agent, args.project, args.reason, spec_status, missing, allowed, forbidden, args.next_step))
        return 0

    if args.spec is None or not args.spec.exists():
        print(f"No existe el archivo: {args.spec}")
        return 2

    result = validate.validate_spec(args.spec, approval=approval)
    report = build_report(result)
    print(report)
    if not result.get("implementation_allowed"):
        return 3 if result.get("valid") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
