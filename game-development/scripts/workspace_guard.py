#!/usr/bin/env python3
"""Fail-closed verification and application of Linux POSIX workspace isolation."""
from __future__ import annotations

import argparse
import errno
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

ACL_PRESENT = "ACL_PRESENT"
ACL_ABSENT = "ACL_ABSENT"
ACL_UNKNOWN = "ACL_UNKNOWN"
_NO_ACL = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}
_ACL_ABSENT_MOUNT_TYPES = {"overlay", "ext4", "xfs", "btrfs", "tmpfs", "proc", "sysfs", "devtmpfs"}


@dataclass
class Report:
    root: str
    protected: bool
    same_uid: bool
    problems: list = field(default_factory=list)
    entries: int = 0
    acl_states: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"root": self.root, "protected": self.protected, "same_uid": self.same_uid,
                "entries": self.entries, "problems": list(self.problems), "acl_states": dict(self.acl_states)}


def _mount_type(path: Path) -> str | None:
    """Return the Linux mount type for the longest matching mount point."""
    try:
        target = os.path.realpath(path)
        best = (-1, None)
        with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
            for line in mounts:
                left, right = line.rstrip().split(" - ", 1)
                fields = left.split()
                mountpoint = fields[4].replace("\\040", " ").replace("\\134", "\\")
                if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/"):
                    if len(mountpoint) > best[0]:
                        best = (len(mountpoint), right.split()[0])
        return best[1]
    except (OSError, ValueError, IndexError):
        return None


def _acl_present(path: Path, attribute: str = "system.posix_acl_access") -> str:
    try:
        os.getxattr(path, attribute, follow_symlinks=False)
        return ACL_PRESENT
    except OSError as error:
        if error.errno in _NO_ACL:
            return ACL_ABSENT
        if error.errno == errno.ENOTSUP and _mount_type(path) in _ACL_ABSENT_MOUNT_TYPES:
            return ACL_ABSENT
        return ACL_UNKNOWN


def _walk_paths(root: Path):
    yield root

    def on_walk_error(error):
        raise error

    for current, directories, files in os.walk(root, followlinks=False, onerror=on_walk_error):
        current_path = Path(current)
        for name in directories + files:
            yield current_path / name


def verify(root: Path | str, service_uid: int, agent_uids: list) -> Report:
    root_path = Path(root)
    report = Report(root=str(root_path), protected=False, same_uid=service_uid in set(agent_uids))
    if not agent_uids:
        report.problems.append("no se declararon identidades de agente: no se puede afirmar proteccion")
    if report.same_uid:
        report.problems.append("el servicio y los agentes comparten UID: los permisos no separan procesos")
    try:
        root_info = os.lstat(root_path)
    except OSError as error:
        report.problems.append(f"workspace no inspeccionable: {error}")
        return report
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        report.problems.append("la raiz del workspace debe ser un directorio real, no enlace")
        return report
    mount_type = _mount_type(root_path)
    report.acl_states["filesystem"] = mount_type or "UNKNOWN"
    if mount_type is None:
        report.problems.append("no se pudo verificar el sistema de archivos/montaje")
    try:
        for entry in _walk_paths(root_path):
            report.entries += 1
            try:
                info = os.lstat(entry)
            except OSError as error:
                report.problems.append(f"no se pudo inspeccionar {entry}: {error}")
                continue
            key = str(entry)
            if stat.S_ISLNK(info.st_mode):
                report.problems.append(f"enlace simbolico en workspace: {entry}")
                continue
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                report.problems.append(f"tipo de archivo no admitido: {entry}")
            if info.st_uid != service_uid:
                report.problems.append(f"propietario distinto del servicio/no pertenece al servicio: {entry}")
            if stat.S_IMODE(info.st_mode) & 0o022:
                report.problems.append(f"escribible por grupo/otros (permisos POSIX): {entry}")
            acl = _acl_present(entry)
            report.acl_states[key + ":access"] = acl
            if acl != ACL_ABSENT:
                report.problems.append(f"ACL de acceso {acl}: {entry}")
            if stat.S_ISDIR(info.st_mode):
                default_acl = _acl_present(entry, "system.posix_acl_default")
                report.acl_states[key + ":default"] = default_acl
                if default_acl != ACL_ABSENT:
                    report.problems.append(f"ACL predeterminada {default_acl}: {entry}")
            if len(report.problems) >= 500:
                report.problems.append("revision interrumpida por exceso de problemas")
                return report
    except OSError as error:
        report.problems.append(f"workspace no completamente inspeccionable: {error}")
    report.protected = not report.problems and bool(agent_uids) and service_uid not in set(agent_uids)
    return report


def protect(root: Path | str, service_uid: int, service_gid: int, agent_uids: list | None = None) -> Report:
    """Apply restrictive ownership/modes, remove ACLs where possible, then verify."""
    if os.geteuid() != 0:
        raise PermissionError("aplicar proteccion exige ejecutar como root")
    root_path = Path(root)
    root_info = os.lstat(root_path)
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("la raiz debe ser un directorio real, no enlace")
    paths = list(_walk_paths(root_path))
    for entry in paths:
        info = os.lstat(entry)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"no se modifica workspace que contiene enlaces: {entry}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError(f"tipo de archivo no admitido: {entry}")
    for entry in reversed(paths):
        info = os.lstat(entry)
        os.chown(entry, service_uid, service_gid, follow_symlinks=False)
        os.chmod(entry, 0o755 if stat.S_ISDIR(info.st_mode) else 0o644, follow_symlinks=False)
        for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
            if attribute.endswith("default") and not stat.S_ISDIR(info.st_mode):
                continue
            state = _acl_present(entry, attribute)
            if state == ACL_PRESENT:
                os.removexattr(entry, attribute, follow_symlinks=False)
            elif state == ACL_UNKNOWN:
                raise PermissionError(f"no se pudo verificar ACL {attribute} de {entry}")
    if not agent_uids or service_uid in set(agent_uids):
        raise PermissionError("workspace sigue NO PROTEGIDO: UID de servicio y agentes no separados")
    report = verify(root_path, service_uid, agent_uids or [])
    if not report.protected:
        raise PermissionError("workspace sigue NO PROTEGIDO: " + "; ".join(report.problems[:10]))
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verifica el aislamiento del workspace por permisos POSIX/ACL.")
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
        report = protect(args.root, args.service_uid, args.service_gid, args.agent_uid)
    else:
        report = verify(args.root, args.service_uid, args.agent_uid)
    payload = report.as_dict()
    payload["no_protegido"] = not report.protected
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if report.protected else 3


if __name__ == "__main__":
    sys.exit(main())
