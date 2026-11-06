#!/usr/bin/env python3
"""Validador y motor de autorizacion del Spec-First Guardian (SPEC-001).

El modulo no implementa criptografia propia: delega la verificacion en
``approval_service`` y la comprobacion de revocaciones en
``revocation_registry``. Los resultados son independientes y una comprobacion que
no puede realizarse nunca autoriza implementacion.

Resultados
----------
``document_valid``          estructura, esquema y secciones de la SPEC.
``requirements_valid``      requisitos y criterios de aceptacion verificables.
``approval_valid``          firma, emisor, sujeto, vigencia e integridad.
``identity_valid``          identidad humana autenticada ligada a la clave.
``revocation_check_valid``  comprobacion de revocaciones realizada con exito.
``scope_valid``             alcance explicito y no vacio.
``implementation_allowed``  conjuncion de todo lo anterior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import ValidationError
from jsonschema import validate as jsonschema_validate

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import revocation_registry

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
    "trazabilidad",
    "aprobacion",
)
SPEC_ID_PATTERN = re.compile(r"^SPEC-\d+$", re.IGNORECASE)
FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL | re.IGNORECASE)
HEADING_PATTERN = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
LIST_ITEM_PATTERN = re.compile(r"^\s*(?:[-*]\s+|\d+[.)]\s+|\u2022|\u00b7)\s*(.+)$")
PENDING_MARKER_PATTERN = re.compile(r"\[[^\]\n]{1,120}\]")
PENDING_DATE_PATTERN = re.compile(r"\bYYYY-MM-DD\b")

REQUIRED_OPERATION_FIELDS = (
    "agent",
    "project",
    "spec_id",
    "version",
    "requirement",
    "task",
    "operation_type",
    "path",
    "workspace_root",
)


def normalize(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return ascii_text.lower().strip()


def parse_frontmatter(text: str) -> dict:
    match = FRONTMATTER_PATTERN.match(text)
    if not match:
        return {}
    try:
        data = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key).lower(): value for key, value in data.items()}


def extract_headings(body: str) -> list:
    return HEADING_PATTERN.findall(body)


def _section_lines(body: str, name: str) -> list:
    current = None
    captured: list = []
    for line in body.splitlines():
        if re.match(r"^#{1,6}\s", line):
            if current is not None and name in current:
                return captured
            parts = line.split(None, 1)
            current = normalize(parts[1]) if len(parts) > 1 else ""
            captured = []
        elif current is not None and name in current:
            captured.append(line)
    if current is not None and name in current:
        return captured
    return captured if current is not None else []


def section_has_content(body: str, name: str) -> bool:
    return any(line.strip() for line in _section_lines(body, name))


def acceptance_criteria_count(body: str) -> int:
    count = 0
    for line in _section_lines(body, "criterios de aceptacion"):
        if LIST_ITEM_PATTERN.match(line):
            count += 1
    return count


def requirement_count(body: str) -> int:
    count = 0
    for line in _section_lines(body, "requisitos funcionales"):
        if LIST_ITEM_PATTERN.match(line) and re.search(r"\bRF-\d+", line):
            count += 1
    return count


def pending_markers(text: str) -> list:
    """Devuelve marcadores de plantilla sin completar (incluye fechas guia)."""
    markers = [match.group(0) for match in PENDING_MARKER_PATTERN.finditer(text)]
    markers.extend(match.group(0) for match in PENDING_DATE_PATTERN.finditer(text))
    deduplicated: list = []
    for marker in markers:
        if marker not in deduplicated:
            deduplicated.append(marker)
    return deduplicated


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
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["No se pudo cargar el esquema de metadatos."]
    instance: dict = {}
    for key in ("spec_id", "title", "status", "version", "author", "created_at"):
        value = frontmatter.get(key)
        if value is not None:
            instance[key] = value
    try:
        jsonschema_validate(instance=instance, schema=schema)
    except ValidationError as error:
        errors.append(f"Metadatos no cumplen el esquema: {error.message}")
    return errors


def is_safe_path(base_dir: Path, relative_path: str) -> bool:
    """Comprueba que una escritura queda dentro del workspace sin symlinks."""
    raw = str(relative_path or "").strip()
    if not raw or "\x00" in raw or "\\" in raw or os.path.isabs(raw):
        return False
    try:
        base = Path(base_dir).resolve(strict=True)
    except OSError:
        return False
    pure = PurePosixPath(raw)
    if not pure.parts or any(part in ("..", ".", "") for part in pure.parts):
        return False
    current = base
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            return False
    try:
        candidate = base.joinpath(*pure.parts).resolve(strict=False)
        candidate.relative_to(base)
    except (ValueError, OSError):
        return False
    return True


def _path_authorized(path: str, authorized_paths: list) -> bool:
    try:
        target = PurePosixPath(path)
    except (TypeError, ValueError):
        return False
    for allowed in authorized_paths:
        raw = str(allowed or "").strip()
        if not raw or raw in (".", "/"):
            continue
        entry = PurePosixPath(raw)
        if target == entry or entry in target.parents:
            return True
    return False


def _list_contains(values, candidate: str) -> bool:
    return bool(values) and str(candidate or "") in [str(value) for value in values]


def _registry_check(registry, spec_id: str, version: str, authorization_event_id: str) -> revocation_registry.RevocationCheck:
    if registry is None:
        return revocation_registry.RevocationCheck(revocation_registry.STATUS_MISSING, "registro de revocaciones no configurado")
    try:
        return registry.check(spec_id, version, authorization_event_id)
    except Exception:
        return revocation_registry.RevocationCheck(revocation_registry.STATUS_UNVERIFIED, "fallo al consultar el registro de revocaciones")


def validate_spec(path: Path, approval: dict | None = None, key_store=None, registry=None, now=None, workspace_root=None) -> dict:
    """Valida una SPEC y calcula permisos con resultados independientes."""
    path = Path(path)
    store = key_store if key_store is not None else approval_service.get_default_key_store(workspace_root)
    result = {
        "valid": False,
        "document_valid": False,
        "requirements_valid": False,
        "approval_valid": False,
        "approval_verified": False,
        "identity_valid": False,
        "revocation_check_valid": False,
        "revoked": False,
        "scope_valid": False,
        "template_complete": False,
        "implementation_allowed": False,
        "spec_id": None,
        "status": None,
        "version": None,
        "approver": None,
        "approved_at": None,
        "errors": [],
        "warnings": [],
    }
    if not path.exists():
        result["errors"].append(f"No existe el archivo: {path}")
        return result

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        result["errors"].append("No se pudo leer la especificacion.")
        return result

    frontmatter = parse_frontmatter(text)
    body = FRONTMATTER_PATTERN.sub("", text, count=1).strip()
    spec_id = str(frontmatter.get("spec_id") or "")
    status = str(frontmatter.get("status") or "").upper()
    version = str(frontmatter.get("version") or "")
    result["spec_id"] = spec_id or None
    result["status"] = status or None
    result["version"] = version or None

    errors: list = list(validate_metadata_with_schema(frontmatter))
    warnings: list = []

    if not spec_id or not SPEC_ID_PATTERN.match(spec_id):
        errors.append("El frontmatter debe definir un spec_id valido con formato SPEC-001.")
    if status not in ALLOWED_STATUSES:
        errors.append(f"Estado no valido: '{status}'.")
    for section in REQUIRED_SECTIONS:
        if not section_has_content(body, section):
            errors.append(f"Falta o esta vacio la seccion requerida: '{section}'.")

    markers = pending_markers(text)
    result["template_complete"] = not markers
    if markers:
        errors.append("La plantilla contiene marcadores pendientes sin completar: " + ", ".join(markers[:6]))

    if status == "APPROVED" and not version:
        errors.append("La SPEC esta aprobada pero no registra version.")
    if status == "APPROVED" and acceptance_criteria_count(body) == 0:
        errors.append("La SPEC esta aprobada pero no define criterios de aceptacion verificables.")

    document_valid = not errors
    requirements_valid = bool(document_valid and acceptance_criteria_count(body) > 0 and requirement_count(body) > 0)
    if document_valid and not requirements_valid:
        warnings.append("La SPEC no declara requisitos funcionales y criterios de aceptacion verificables.")

    approval_verified = bool(approval and approval_service.verify_approval(approval, key_store=store, now=now))
    identity_valid = bool(approval_verified and approval_service.identity_is_bound(approval, store))
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()

    authorization_event_id = str((approval or {}).get("authorization_event_id") or "")
    check = _registry_check(registry, spec_id, version, authorization_event_id)
    revocation_check_valid = check.checked
    revoked = check.revoked

    operations = [str(item) for item in ((approval or {}).get("operations") or [])]
    authorized_paths = [str(item) for item in ((approval or {}).get("authorized_paths") or [])]
    requirements = [str(item) for item in ((approval or {}).get("requirements") or [])]
    tasks = [str(item) for item in ((approval or {}).get("tasks") or [])]
    scope = str((approval or {}).get("scope") or "").strip()
    scope_valid = bool(scope and operations and authorized_paths and requirements and tasks)

    approval_valid = bool(
        status == "APPROVED"
        and approval_verified
        and str((approval or {}).get("spec_id") or "") == spec_id
        and str((approval or {}).get("version") or "") == version
        and str((approval or {}).get("fingerprint") or "") == fingerprint
    )
    if approval is not None:
        result["approver"] = str(approval.get("approver") or "") or None
        result["approved_at"] = str(approval.get("approved_at") or "") or None

    implementation_allowed = bool(
        document_valid
        and requirements_valid
        and approval_valid
        and identity_valid
        and revocation_check_valid
        and not revoked
        and scope_valid
    )

    result.update(
        {
            "valid": document_valid,
            "document_valid": document_valid,
            "requirements_valid": requirements_valid,
            "approval_valid": approval_valid,
            "approval_verified": approval_verified,
            "identity_valid": identity_valid,
            "revocation_check_valid": revocation_check_valid,
            "revoked": revoked,
            "scope_valid": scope_valid,
            "implementation_allowed": implementation_allowed,
            "errors": errors,
            "warnings": warnings,
        }
    )

    if not approval_verified:
        warnings.append("Implementacion bloqueada: la aprobacion no puede verificarse con la autoridad de confianza.")
    elif not identity_valid:
        warnings.append("Implementacion bloqueada: la identidad humana no esta ligada a la clave.")
    if not revocation_check_valid:
        warnings.append(f"Implementacion bloqueada: revocaciones no comprobadas ({check.status}: {check.reason}).")
    elif revoked:
        warnings.append("Implementacion bloqueada: la autorizacion fue revocada.")
    if not scope_valid:
        warnings.append("Implementacion bloqueada: el alcance autorizado esta vacio o incompleto.")
    if status != "APPROVED":
        warnings.append("Estado actual: la implementacion esta bloqueada hasta que la SPEC sea aprobada.")
    return result


def authorize_operation(approval: dict | None, operation: dict, key_store=None, spec_path: Path | None = None, registry=None, workspace_root=None) -> bool:
    """Comprueba si una operacion concreta esta dentro del alcance autorizado.

    Requiere contexto completo; no completa campos ausentes y no trata
    ``ALCANCE_TOTAL`` como permiso universal. Las listas vacias no autorizan.
    """
    if not isinstance(operation, dict) or not isinstance(approval, dict) or not approval:
        return False
    if any(not str(operation.get(field_name) or "").strip() for field_name in REQUIRED_OPERATION_FIELDS):
        return False
    store = key_store if key_store is not None else approval_service.get_default_key_store(workspace_root)
    if not approval_service.verify_approval(approval, key_store=store):
        return False
    if not approval_service.identity_is_bound(approval, store):
        return False
    spec_id = str(operation.get("spec_id") or "")
    version = str(operation.get("version") or "")
    project = str(operation.get("project") or "")
    if spec_id != str(approval.get("spec_id") or "") or version != str(approval.get("version") or ""):
        return False
    if not project or project != str(approval.get("project") or ""):
        return False
    root = Path(str(operation.get("workspace_root") or ""))
    path = str(operation.get("path") or "")
    if not is_safe_path(root, path):
        return False
    check = _registry_check(registry, spec_id, version, str(approval.get("authorization_event_id") or ""))
    if not check.checked or check.revoked:
        return False
    if spec_path is None:
        return False
    try:
        current = Path(spec_path).read_text(encoding="utf-8")
    except OSError:
        return False
    if hashlib.sha256(current.encode("utf-8")).hexdigest() != str(approval.get("fingerprint") or ""):
        return False
    operations = approval.get("operations") or []
    authorized_paths = approval.get("authorized_paths") or []
    requirements = approval.get("requirements") or []
    tasks = approval.get("tasks") or []
    if not (operations and authorized_paths and requirements and tasks):
        return False
    if not _list_contains(operations, str(operation.get("operation_type") or "")):
        return False
    if not _list_contains(requirements, str(operation.get("requirement") or "")):
        return False
    if not _list_contains(tasks, str(operation.get("task") or "")):
        return False
    if not _path_authorized(path, authorized_paths):
        return False
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Valida una especificacion para el Spec-First Guardian.")
    parser.add_argument("spec", type=Path, help="Ruta al archivo de especificacion (Markdown).")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON.")
    parser.add_argument("--approval", type=Path, default=None, help="Ruta al registro de aprobacion firmado.")
    args = parser.parse_args(argv)

    if not args.spec.exists():
        print(f"No existe el archivo: {args.spec}")
        return 2

    approval = load_approval(args.approval) if args.approval else None
    workspace_root = _workspace_root_for(args.spec)
    key_store = approval_service.get_default_key_store(workspace_root)
    spec_id = str((approval or {}).get("spec_id") or "")
    registry = revocation_registry.RevocationRegistry.for_spec(spec_id, key_store=key_store, workspace_root=workspace_root) if spec_id else None
    result = validate_spec(args.spec, approval=approval, key_store=key_store, registry=registry, workspace_root=workspace_root)

    if args.json:
        payload = {key: result[key] for key in ("valid", "document_valid", "requirements_valid", "approval_valid", "approval_verified", "identity_valid", "revocation_check_valid", "revoked", "scope_valid", "template_complete", "implementation_allowed", "spec_id", "status", "version", "approver", "errors", "warnings")}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Spec ID: {result['spec_id'] or 'N/A'}")
        print(f"Estado: {result['status'] or 'N/A'}")
        print(f"Version: {result['version'] or 'N/A'}")
        print(f"Aprobador: {result['approver'] or 'N/A'}")
        for key, label in (
            ("document_valid", "Documento valido"),
            ("requirements_valid", "Requisitos validos"),
            ("approval_valid", "Aprobacion valida"),
            ("identity_valid", "Identidad humana verificada"),
            ("revocation_check_valid", "Revocaciones comprobadas"),
            ("scope_valid", "Alcance explicito"),
            ("implementation_allowed", "Implementacion permitida"),
        ):
            print(f"{label}: {'SI' if result[key] else 'NO'}")
        if result["errors"]:
            print("Errores:")
            for error in result["errors"]:
                print(f"  - {error}")
        if result["warnings"]:
            print("Advertencias:")
            for warning in result["warnings"]:
                print(f"  - {warning}")

    if not result["valid"]:
        return 1
    if not result["implementation_allowed"]:
        return 3
    return 0


def _workspace_root_for(spec_path: Path) -> Path:
    configured = os.environ.get("SPEC_GUARDIAN_WORKSPACE")
    if configured and configured.strip():
        return Path(configured.strip())
    resolved = Path(spec_path).resolve()
    for candidate in resolved.parents:
        if (candidate / ".git").exists():
            return candidate
    return resolved.parent


if __name__ == "__main__":
    sys.exit(main())
