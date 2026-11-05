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


def validate_spec(path: Path, approval: dict | None = None) -> dict:
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
        if not approver:
            errors.append("La SPEC esta aprobada pero no registra el aprobador.")
        if not approved_at:
            warnings.append("La aprobacion no registra fecha.")

    document_valid = len(errors) == 0
    requirements_valid = document_valid and acceptance_criteria_count(body) > 0

    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
    approval_verified = bool(approval and approval_service.verify_approval(approval))
    approval_valid = bool(
        status == "APPROVED"
        and approval_verified
        and not bool(approval.get("revoked", False))
        and bool(version)
        and bool(approver)
        and bool(approved_at)
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
    result = validate_spec(args.spec, approval=approval)

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
