#!/usr/bin/env python3
"""Operaciones de archivo ancladas a descriptores de directorio.

Resolver una ruta y escribirla despues deja una ventana TOCTOU: otro proceso
puede sustituir un directorio por un enlace simbolico entre la comprobacion y
la escritura. Este modulo elimina la re-resolucion: abre el workspace una vez y
desciende componente a componente con ``O_NOFOLLOW``/``O_DIRECTORY``, de modo
que cada operacion se ejecuta sobre el inodo ya validado mediante ``dir_fd``.

Las rutas se manejan siempre como relativas al workspace. Ninguna funcion
acepta rutas absolutas ni resuelve enlaces simbolicos.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import PurePosixPath

MAX_COMPONENT = 255
MAX_PATH_COMPONENTS = 64

FLAGS_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FLAGS_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
FLAGS_WRITE = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafePathError(ValueError):
    """La ruta no puede usarse de forma segura dentro del workspace."""


def split_relative(relative: str | os.PathLike | None) -> list[str]:
    """Valida y descompone una ruta relativa admisible."""
    raw = str(relative or "").strip()
    if not raw or "\x00" in raw or "\\" in raw:
        raise UnsafePathError("ruta vacia o con caracteres no admitidos")
    if os.path.isabs(raw):
        raise UnsafePathError("no se admiten rutas absolutas")
    # Comprobar los segmentos en crudo: PurePosixPath normaliza '//' y './'.
    if any(segment in ("", ".", "..") for segment in raw.split("/")):
        raise UnsafePathError("la ruta contiene segmentos no permitidos")
    pure = PurePosixPath(raw)
    parts = list(pure.parts)
    if not parts or len(parts) > MAX_PATH_COMPONENTS:
        raise UnsafePathError("ruta vacia o demasiado profunda")
    for part in parts:
        if part in (".", "..", "/", ""):
            raise UnsafePathError("la ruta contiene segmentos no permitidos")
        if len(part.encode("utf-8")) > MAX_COMPONENT:
            raise UnsafePathError("componente de ruta demasiado largo")
    return parts


def open_root(root: str | os.PathLike) -> int:
    """Abre el workspace como descriptor de directorio sin seguir enlaces."""
    try:
        info = os.lstat(root)
    except OSError as error:
        raise UnsafePathError("workspace inexistente") from error
    if stat.S_ISLNK(info.st_mode):
        raise UnsafePathError("el workspace es un enlace simbolico")
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("el workspace no es un directorio")
    try:
        return os.open(os.fspath(root), FLAGS_DIR)
    except OSError as error:
        raise UnsafePathError("no se pudo abrir el workspace") from error


def _open_parent(root_fd: int, parts: list[str]) -> int:
    """Desciende hasta el directorio padre anclando cada componente."""
    descriptor = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            siguiente = os.open(part, FLAGS_DIR, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = siguiente
    except OSError as error:
        os.close(descriptor)
        raise UnsafePathError("la ruta atraviesa un directorio no valido") from error
    return descriptor


def _stat_at(parent_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise UnsafePathError("el destino no existe") from error
    except OSError as error:
        raise UnsafePathError("no se pudo inspeccionar el destino") from error


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("escritura incompleta")
        view = view[written:]


def _fsync_dir(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError:
        # Algunos sistemas de archivos no permiten fsync de directorios.
        pass


def read_file(root_fd: int, relative: str, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    parts = split_relative(relative)
    parent = _open_parent(root_fd, parts)
    try:
        name = parts[-1]
        info = _stat_at(parent, name)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError("el destino no es un archivo regular")
        descriptor = os.open(name, FLAGS_READ, dir_fd=parent)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UnsafePathError("el archivo excede el tamano permitido")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def write_file(root_fd: int, relative: str, data: bytes, mode: str = "create") -> str:
    """Crea, modifica o sobrescribe dentro del workspace.

    ``create`` exige que el destino no exista; ``modify`` exige un archivo
    regular existente; ``overwrite`` admite ambos casos. Devuelve el SHA-256
    del contenido escrito.
    """
    if mode not in ("create", "modify", "overwrite"):
        raise ValueError(f"modo de escritura no admitido: {mode}")
    parts = split_relative(relative)
    parent = _open_parent(root_fd, parts)
    try:
        name = parts[-1]
        if mode == "create":
            descriptor = os.open(name, FLAGS_WRITE | os.O_CREAT | os.O_EXCL, 0o640, dir_fd=parent)
            try:
                _write_all(descriptor, data)
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor)
                try:
                    os.unlink(name, dir_fd=parent)
                except OSError:
                    pass
                raise
            os.close(descriptor)
            _fsync_dir(parent)
            return hashlib.sha256(data).hexdigest()

        exists = True
        try:
            info = _stat_at(parent, name)
        except UnsafePathError:
            if mode == "modify":
                raise
            exists = False
            info = None
        if exists and not stat.S_ISREG(info.st_mode):
            raise UnsafePathError("el destino no es un archivo regular")

        temporary = f".sg-{secrets.token_hex(8)}.tmp"
        descriptor = os.open(temporary, FLAGS_WRITE | os.O_CREAT | os.O_EXCL, 0o640, dir_fd=parent)
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            raise
        os.close(descriptor)
        try:
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        except OSError:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            raise
        _fsync_dir(parent)
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(parent)


def delete_file(root_fd: int, relative: str) -> None:
    parts = split_relative(relative)
    parent = _open_parent(root_fd, parts)
    try:
        name = parts[-1]
        info = _stat_at(parent, name)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError("el destino no es un archivo regular")
        os.unlink(name, dir_fd=parent)
        _fsync_dir(parent)
    finally:
        os.close(parent)
