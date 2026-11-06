#!/usr/bin/env python3
"""Verificacion y aplicacion del aislamiento del workspace por permisos POSIX.

Un workspace solo esta protegido si los agentes no pueden escribir en el:

* pertenece al usuario del servicio, no al usuario de los agentes;
* no tiene permisos de escritura para grupo ni para otros;
* no tiene ACL que concedan escritura;
* el UID del servicio es distinto de todos los UID de agentes.

Mientras esas condiciones no se cumplan, el estado se declara ``NO PROTEGIDO``.
Este modulo no puede cambiar de identidad: ``apply`` exige ejecutarse como root.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Report:
    root: str
    protected: bool
    same_uid: bool
    problems: list = field(default_factory=list)
    entries: int = 0

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "protected": self.protected,
            "same_uid": self.same_uid,
            "entries": self.entries,
            "problems": list(self.problems),
        }


def _acl_present(path: Path) -> bool:
    try:
        os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
        return True
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP, errno.EPERM):
            return False
        return True


def verify(root: Path | str, service_uid: int, agent_uids: list) -> Report:
    root_path = Path(root)
    report = Report(root=str(root_path), protected=False, same_uid=service_uid in set(agent_uids))
    if not agent_uids:
        report.problems.append("no se declararon identidades de agente: no se puede afirmar proteccion")
    if report.same_uid:
        report.problems.append("el servicio y los agentes comparten UID: los permisos no separan procesos")
    try:
        info = os.lstat(root_path)
    except OSError:
        report.problems.append("workspace inexistente")
        return report
    if stat.S_ISLNK(info.st_mode):
        report.problems.append("el workspace es un enlace simbolico")
        return report
    if not stat.S_ISDIR(info.st_mode):
        report.problems.append("el workspace no es un directorio")
        return report
    if info.st_uid != service_uid:
        report.problems.append("el workspace no pertenece al usuario del servicio")
    if stat.S_IMODE(info.st_mode) & 0o022:
        report.problems.append("el workspace es escribible por grupo u otros")

    for current, directories, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        for name in list(directories) + list(files):
            entry = current_path / name
            report.entries += 1
            try:
                entry_info = os.lstat(entry)
            except OSError:
                report.problems.append(f"no se pudo inspeccionar: {entry}")
                continue
            if stat.S_ISLNK(entry_info.st_mode):
                report.problems.append(f"enlace simbolico en el workspace: {entry}")
                continue
            if entry_info.st_uid != service_uid:
                report.problems.append(f"propietario distinto del servicio: {entry}")
            if stat.S_IMODE(entry_info.st_mode) & 0o022:
                report.problems.append(f"escribible por grupo u otros: {entry}")
            if _acl_present(entry):
                report.problems.append(f"ACL presente (requiere revision manual): {entry}")
            if len(report.problems) > 200:
                report.problems.append("demasiados problemas: revision interrumpida")
                report.protected = False
                return report
    report.protected = not report.problems and not report.same_uid
    return report


def protect(root: Path | str, service_uid: int, service_gid: int) -> Report:
    """Aplica propiedad y permisos de solo lectura para agentes. Requiere root."""
    if os.geteuid() != 0:
        raise PermissionError("aplicar proteccion exige ejecutar como root")
    root_path = Path(root)
    for current, directories, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        os.chown(current_path, service_uid, service_gid, follow_symlinks=False)
        os.chmod(current_path, 0o755)
        for name in files:
            entry = current_path / name
            if os.path.islink(entry):
                continue
            os.chown(entry, service_uid, service_gid, follow_symlinks=False)
            os.chmod(entry, 0o644)
    return verify(root_path, service_uid, [])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verifica el aislamiento del workspace por permisos.")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("verify", "protect"):
        command = sub.add_parser(name)
        command.add_argument("root", type=Path)
        command.add_argument("--service-uid", type=int, required=True)
        command.add_argument("--agent-uid", type=int, action="append", default=[])
        command.add_argument("--service-gid", type=int, default=None)
    args = parser.parse_args(argv)
    if args.mode == "protect":
        if args.service_gid is None:
            parser.error("--service-gid es obligatorio en protect")
        report = protect(args.root, args.service_uid, args.service_gid)
        report = verify(args.root, args.service_uid, args.agent_uid)
    else:
        report = verify(args.root, args.service_uid, args.agent_uid)
    payload = report.as_dict()
    payload["no_protegido"] = not report.protected
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if report.protected else 3


if __name__ == "__main__":
    sys.exit(main())
