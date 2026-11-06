#!/usr/bin/env python3
"""Validador de especificaciones para el Spec-First Guardian (SPEC-001).

Comprueba la estructura minima de una especificacion y su estado de aprobacion.

Uso:
    python scripts/validate.py <ruta-a-spec.md> [--json]

Codigos de salida:
    0  La especificacion es valida y, si aplica, la implementacion esta permitida.
    1  La especificacion es invalida.
    2  Error de uso o de lectura del archivo.
    3  La especificacion es valida pero la implementacion esta bloqueada (sin autorizacion verificable).
    5  Error interno.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

import yaml
from jsonschema import ValidationError
from jsonschema import validate as jsonschema_validate

import approval_service

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "assets" / "schemas" / "spec.schema.json"

ALLOWED_STATUSES = ("DRAFT", "UNDER_REVIEW", "PENDING_USER_APPROVAL", "APPROVED", "REJECTED", "SUPERSEDED", "ARCHIVED")
REQUIRED_SECTIONS = (
    "identificacion",
    "contexto",
    "objetivos",
    "fuera de alcance",
    "requisitos funcionales",
    "requisitos no funcionales",
    "diseno tecnico",
    "restricciones",
    "criterios de aceptacion",
    "estrategia de validacion",
    "riesgos y dependencias",
    "plan de implementacion",
    "aprobacion",
)
SPEC_ID_PATTERN = re.compile(r"^SPEC-\d+$", re.IGNORECASE)
FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL | re.IGNORECASE)
HEADING_PATTERN = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
LIST_ITEM_PATTERN = re.compile(r"^\s*(?:[-*]\s+|\d+[.)]\s+|\u2022|\u00b7)\s*(.+)$")


def normalize(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return ascii_text.lower().strip()


def parse_frontmatter(text: str) -> dict:
    match = FRONTMATTER_PATTERN.match(text)
    if not match:
        return {}
    data = yaml.safe_load(match.group(1)) or {}
    if not isinstance(data, dict):
        return {}
    return {str(key).lower(): value for key, value in data.items()}


def extract_headings(body: str) -> list:
    return HEADING_PATTERN.findall(body)


def section_has_content(body: str, name: str) -> bool:
    current = None
    content_lines = []
    for line in body.splitlines():
        if re.match(r"^#{1,6}\s", line):
            if current is not None and name in current and any(l.strip() for l in content_lines):
                return True
            parts = line.split(None, 1)
            current = normalize(parts[1]) if len(parts) > 1 else ""
            content_lines = []
        else:
            content_lines.append(line)
    if current is not None and name in current and any(l.strip() for l in content_lines):
        return True
    return False


def acceptance_criteria_count(body: str) -> int:
    current = None
    items = []
    count = 0
    capturing = False
    for line in body.splitlines():
        if re.match(r"^#{1,6}\s", line):
            if capturing:
                count = len(items)
                capturing = False
            parts = line.split(None, 1)
            current = normalize(parts[1]) if len(parts) > 1 else ""
            items = []
            capturing = current.startswith("criterios de aceptacion")
        else:
            if capturing:
                match = LIST_ITEM_PATTERN.match(line)
                if match:
                    items.append(match.group(1).strip())
    if capturing:
        count = len(items)
    return count


def load_approval(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def validate_metadata_with_schema(frontmatter: dict) -> list:
    errors: list = []
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    instance: dict = {}
    for key, value in (
        ("spec_id", frontmatter.get("spec_id")),
        ("title", frontmatter.get("title")),
        ("status", frontmatter.get("status")),
        ("version", frontmatter.get("version")),
        ("author", frontmatter.get("author")),
        ("created_at", frontmatter.get("created_at")),
        ("approver", frontmatter.get("approver")),
        ("approved_at", frontmatter.get("approved_at")),
    ):
        if value is not None:
            instance[key] = value
    try:
        jsonschema_validate(instance=instance, schema=schema)
    except ValidationError as error:
        errors.append(f"Metadatos no cumplen el esquema: {error.message}")
    return errors


def load_revocations(spec_id: str) -> list | None:
    """Carga el registro de revocaciones.

    Devuelve la lista de revocaciones cuando el registro es valido, una lista vacia
    cuando no existe revocaciones aplicables, o None cuando el registro esta
    ausente, corrupto, inaccesible o invalido. Ante cualquier error se debe denegar
    nuevas operaciones de implementacion.
    """
    path = Path(__file__).resolve().parent.parent / "specs" / "revocations" / f"{spec_id}.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or str(data.get("spec_id") or "") != str(spec_id or ""):
        return None
    entries = data.get("revocations")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        if not str(entry.get("authorization_event_id") or "") or not isinstance(entry.get("revoked"), bool):
            return None
    return entries


def revocation_blocks(spec_id: str, authorization_event_id: str) -> bool:
    """Indica si una autorizacion fue revocada. Ante error de registro deniega."""
    entries = load_revocations(spec_id) if spec_id else None
    if entries is None:
        return True
    for entry in entries:
        if str(entry.get("authorization_event_id") or "") == str(authorization_event_id or "") and entry.get("revoked") is True:
            return True
    return False


def is_safe_path(base_dir: Path, relative_path: str) -> bool:
    """Valida que una ruta de escritura este dentro del workspace y sin traversal."""
    try:
        base = base_dir.resolve()
        candidate = (base / str(relative_path or "")).resolve()
        candidate.relative_to(base)
        return True
    except Exception:
        return False


def validate_spec(path: Path, approval: dict | None = None, key_store=None, now: object = None) -> dict:
    errors: list = []
    warnings: list = []

    if not path.exists():
        return {"valid": False, "document_valid": False, "requirements_valid": False, "approval_valid": False, "implementation_allowed": False, "approval_verified": False, "spec_id": None, "status": None, "version": None, "approver": None, "approved_at": None, "errors": [f"No existe el archivo: {path}"], "warnings": []}

    text = path.read_text(encoding="utf-8")
    frontmatter = parse_frontmatter(text)
    body = FRONTMATTER_PATTERN.sub("", text, count=1).strip()

    spec_id = str(frontmatter.get("spec_id") or "")
    status = str(frontmatter.get("status") or "").upper()
    version = str(frontmatter.get("version") or "")
    approver = str(frontmatter.get("approver") or "")
    approved_at = str(frontmatter.get("approved_at") or "")

    errors.extend(validate_metadata_with_schema(frontmatter))

    if not spec_id or not SPEC_ID_PATTERN.match(spec_id):
        errors.append("El frontmatter debe definir un spec_id valido con formato SPEC-001 (por ejemplo SPEC-002).")

    if status not in ALLOWED_STATUSES:
        errors.append(f"Estado no valido: '{status}'. Valores permitidos: {', '.join(ALLOWED_STATUSES)}.")

    for section in REQUIRED_SECTIONS:
        if not section_has_content(body, section):
            errors.append(f"Falta o esta vacio la seccion requerida: '{section}'.")

    if status == "APPROVED" and acceptance_criteria_count(body) == 0:
        errors.append("La SPEC esta aprobada pero no define criterios de aceptacion verificables.")

    if status == "APPROVED":
        if not version:
            errors.append("La SPEC esta aprobada pero no registra version.")
        approval_approver = str((approval or {}).get("approver") or approver or "")
        approval_approved_at = str((approval or {}).get("approved_at") or approved_at or "")
        if not approval_approver:
            errors.append("La SPEC esta aprobada pero la autorizacion no registra un aprobador verificable.")
        if not approval_approved_at:
            warnings.append("La aprobacion no registra fecha.")

    document_valid = len(errors) == 0
    requirements_valid = document_valid and acceptance_criteria_count(body) > 0

    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
    approval_verified = bool(approval and approval_service.verify_approval(approval, key_store=key_store, now=now))
    revoked = bool(approval is not None and revocation_blocks(str(spec_id or ""), str(approval.get("authorization_event_id") or "")))
    approval_version = str((approval or {}).get("version") or version or "")
    approval_valid = bool(
        status == "APPROVED"
        and approval_verified
        and not revoked
        and not bool(approval.get("revoked", False))
        and bool(approval_version)
        and bool(approval_approver)
        and bool(approval_approved_at)
        and approval.get("fingerprint") == fingerprint
        and approval.get("spec_id") == spec_id
        and approval.get("version") == version
    )

    implementation_allowed = bool(document_valid and requirements_valid and approval_valid)

    result = {
        "valid": document_valid,
        "document_valid": document_valid,
        "requirements_valid": requirements_valid,
        "approval_valid": approval_valid,
        "implementation_allowed": implementation_allowed,
        "approval_verified": approval_verified,
        "spec_id": spec_id,
        "status": status or None,
        "version": version or None,
        "approver": approver or None,
        "approved_at": approved_at or None,
        "errors": errors,
        "warnings": warnings,
    }

    if not implementation_allowed:
        if not approval_verified:
            warnings.append("Implementacion bloqueada: falta aprobacion humana verificable para la version aprobada.")
        elif not requirements_valid:
            warnings.append("Implementacion bloqueada: la especificacion no define criterios de aceptacion verificables.")

    if status != "APPROVED":
        warnings.append("Estado actual: la implementacion esta bloqueada hasta que la SPEC sea aprobada.")

    return result


REQUIRED_OPERATION_FIELDS = ("agent", "project", "spec_id", "version", "requirement", "task", "operation_type", "path")


def authorize_operation(approval: dict | None, operation: dict, key_store=None) -> bool:
    """Comprueba si una operacion esta dentro del alcance de una autorizacion (SPEC-001).

    Toda operacion debe declarar agent, project, spec_id, version, requirement,
    task, operation_type y path. Los campos ausentes se rechazan sin completarse
    con valores de la autorizacion.
    """
    if not isinstance(operation, dict):
        return False
    if any(not str(operation.get(field) or "").strip() for field in REQUIRED_OPERATION_FIELDS):
        return False
    if not isinstance(approval, dict):
        return False
    if not approval:
        return False
    if not approval_service.verify_approval(approval, key_store=key_store):
        return False
    spec_id = str(operation.get("spec_id") or "")
    version = str(operation.get("version") or "")
    approval_spec_id = str(approval.get("spec_id") or "")
    approval_version = str(approval.get("version") or "")
    approval_project = str(approval.get("project") or "")
    operation_project = str(operation.get("project") or "")
    if not operation_project or operation_project != approval_project or spec_id != approval_spec_id or version != approval_version:
        return False
    if revocation_blocks(spec_id, str(approval.get("authorization_event_id") or "")):
        return False
    scope = str(approval.get("scope") or "")
    operations = [str(o) for o in (approval.get("operations") or [])]
    paths = [str(p) for p in (approval.get("authorized_paths") or [])]
    if scope and scope != "ALCANCE_TOTAL":
        if str(operation.get("operation_type") or "") not in operations:
            return False
        path = str(operation.get("path") or "")
        if not path or not any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths):
            return False
    tasks = [str(t) for t in (approval.get("tasks") or [])]
    task_id = str(operation.get("task") or operation.get("task_id") or "")
    if tasks and task_id not in tasks:
        return False
    requirements = [str(r) for r in (approval.get("requirements") or [])]
    requirement = str(operation.get("requirement") or "")
    if requirements and requirement not in requirements:
        return False
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Valida una especific para el Spec-First Guardian.")
    parser.add_argument("spec", type=Path, help="Ruta al archivo de especificacion (Markdown).")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON.")
    parser.add_argument("--approval", type=Path, default=None, help="Ruta al registro de aprobacion (JSON) verificable.")
    args = parser.parse_args(argv)

    if not args.spec.exists():
        print(f"No existe el archivo: {args.spec}")
        return 2

    approval = load_approval(args.approval) if args.approval else None
    key_store = approval_service.get_default_key_store()
    result = validate_spec(args.spec, approval=approval, key_store=key_store)

    if args.json:
        payload = {
            "valid": result["valid"],
            "document_valid": result["document_valid"],
            "requirements_valid": result["requirements_valid"],
            "approval_valid": result["approval_valid"],
            "implementation_allowed": result["implementation_allowed"],
            "approval_verified": result["approval_verified"],
            "spec_id": result["spec_id"],
            "status": result["status"],
            "version": result["version"],
            "approver": result["approver"],
            "errors": result["errors"],
            "warnings": result["warnings"],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Spec ID: {result['spec_id'] or 'N/A'}")
        print(f"Estado: {result['status'] or 'N/A'}")
        print(f"Version: {result['version'] or 'N/A'}")
        print(f"Aprobador: {result['approver'] or 'N/A'}")
        print(f"Aprobado el: {result['approved_at'] or 'N/A'}")
        print(f"Implementacion permitida: {'SI' if result['implementation_allowed'] else 'NO'}")
        if result["errors"]:
            print("Errores:")
            for error in result["errors"]:
                print(f"  - {error}")
        if result["warnings"]:
            print("Advertencias:")
            for warning in result["warnings"]:
                print(f"  - {warning}")
        print(f"Resultado: {'VALIDA' if result['valid'] else 'INVALIDA'}")

    if not result["valid"]:
        return 1
    if not result["implementation_allowed"]:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
