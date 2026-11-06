# PLAN-ARCH-001 — Secuencia propuesta para SPEC-ARCH-001

**Estado:** DRAFT — no es autorización de implementación  
**Fecha:** 2026-11-06  
**Autor:** Buffy (plan preliminar para revisión humana)  
**Alcance:** orden de trabajo, dependencias, pruebas, checkpoints, rollback y evidencias.  
**Autoridad documental:** subordinado a `SPEC-ARCH-001-HARDENING.md`; no puede agregar requisitos ni modificar criterios de aceptación. Si hay discrepancia, la SPEC gobierna y el PLAN debe revisarse.  
**Dependencias:** aprobación explícita de SPEC-ARCH-001 y decisiones pendientes en §11; ARCH-001/ADR-001 aprobados o enmendados; entorno Linux aislado para verificaciones.  
**Trazabilidad:** no se inicia hasta aprobación. Mapeo de criterios: checkpoint K1→SA-001…003, K2→SA-006, K3→SA-004…005/SA-007, K4→SA-008…010, K5→SA-011…014.

## Reglas de planificación

- No ejecutar ahora. Fase 1 Framework Core es la única prioridad.
- Cada PR/unidad de cambio se limita a una SPEC/criterio aprobado y registra hash, diffs, pruebas y decisión humana.
- Ningún cambio de código puede preceder aprobación explícita del usuario y autorización técnica vigente.
- No retirar rutas legacy ni datos históricos en una fase automática.

## Orden de implementación propuesto

| Orden | Paquete de tareas | Archivos candidatos (no exclusividad) | Dependencias | Pruebas/evidencias | Checkpoint |
|---|---|---|---|---|---|
| 0 | Preparar expediente: confirmar hash aprobado de SPEC, registrar snapshot commit/clean, cerrar decisiones de usuario, threat model y estado/backup de datos; fijar estrategia storage/IdP/mounts | docs de ARCH/SPEC/ADR, inventario | aprobación humana SPEC+ADR y environment aislado | captura hashes, threat model aprobado, baseline test result, backup/restore drill | K0 — sin cambios funcionales si una pregunta bloquea diseño |
| 1 | Implementar modelo transaccional de solicitud/challenge/auth attempt/authorization separado de estados documentales; callback OIDC Authorization Code + PKCE/UI/session; persistir nonce/replay y CSRF/state; production gate no habilita hasta conformidad | `scripts/authority_service.py`, `approval_service.py`, `authority_client.py`, `approval_cli.py`, posible módulo storage/HTTP callback bajo decisión | K0, elección interfaz/almacenamiento; no usar id_token directo | OIDC local integration, callback error matrix, replay/restart/concurrency, auth subject match | K1 — SA-001…003 y SA-013; producción aún bloqueada si staging IdP pendiente |
| 2 | Diseñar y aplicar health protocol fail-stop, journal de eventos y latch process authority; hacer audit append/health/marker coordinados interproceso; reconcile autenticado | `scripts/audit_chain.py`, `implementation_gate.py`, `authority_service.py`, posiblemente store nuevo sólo tras SPEC | K0, K1 estado compartido; backup de audit | fault injection matrices log/marker/health/fsync/restart/nuevos gates; multiprocess append/recovery | K2 — SA-002 y SA-006; no habilitar nuevas operaciones en health desconocido |
| 3 | Separar SPEC/PLAN schema/templates/validator con lector legacy, migración explicit/no-op por defecto, hash/diff; definir confirmación humana UI completa vinculada a hashes | `templates/technical-specification.md`, template PLAN nueva, `scripts/validate.py`, `assets/schemas/spec.schema.json`, README/SKILL/instructions, tests/examples | K1 model reviewed, política legacy decidida | fixtures golden para SPEC-001, ejemplo viejo/nuevo, property schema, migración dry-run/reversibilidad, UI confirmation hash | K3 — SA-004…005, SA-007, SA-013 |
| 4 | Endurecer workspace: mount ID por entry, nested/bind mount policy, hardlink/type/symlink/ACL, race-aware traversal/protect; recibir entorno Linux aislado con cuentas reales | `scripts/workspace_guard.py`, `safe_fs.py`, `install_authority.sh`, `tests/test_safe_fs.py`, `tests/test_authority.py` | K0 decisión mount allowlist, image/namespace/UIDs reales | bind/nested mounts, nlink, hardlink escape, ACL unknown, concurrent tree mutation, actual UID separation; no host prod | K4a — SA-008 |
| 5 | Endurecer durabilidad write receipts y persistencia audit; distinguir operación aplicada/confirmada/indeterminada en broker/gate | `scripts/safe_fs.py`, `implementation_gate.py`, `authority_service.py`, `audit_chain.py`, tests | K2, K4a; filesystem target declared | inject fsync(file/dir), rename/unlink, short write, crash/restart, verify digest/inode, no success claim | K4b — SA-009 |
| 6 | Rediseñar installer `INSTALL/VERIFY/UPGRADE/RECONFIGURE`; no-op safe rerun; migrate config/backups; preservar custom keys/revocations/pins; test rollback | `scripts/install_authority.sh`, posible helper modules/docs | K0, K1/K2 storage/config API estabilizados; runner Ubuntu aislado root | snapshot/diff, modes, repeated runs, revoked key monotonicity, custom fields, uid/project changes, restore drill | K4c — SA-010 |
| 7 | Alinear docs y skills A/B/C, mover contenido a universal/domain en branch migratoria sin borrar legacy; construir contract conformance APIs/adapters | `SKILL.md`, README, `instructions/*`, referencias/templates, nuevo `skills/*`, tests contract | K3/K4; API stable | lint/docs test, phrase audit claims matrix, adapter conformance, proof of no bypass limited to declared deployment | K5 — SA-011…014 |
| 8 | End-to-end validation, runbook/release readiness, revisión independiente de seguridad y verificación no-prod | todo el Core, pruebas/CI, docs | K1–K5 completos | suite completa, OIDC staging tests, real UIDs, Linux filesystem matrix, restart/fault tests, installer reruns, independent review | K6 — Release gate: production sólo si SA-001…014 están evidenciados y autorizados |

## Responsables/roles

- Humano propietario: decisión de SPEC, aprobaciones de UI/instalación/reconciliación y cambios de alcance.
- Implementador: agente autorizado después de aprobación; no aprueba su trabajo ni amplía contratos.
- Revisor seguridad: inspecciona transiciones de confianza, concurrencia, filesystem, persistencia y threat model; independencia definida por usuario.
- Operador Linux de pruebas: aporta sandbox/VM, IdP de staging y UID/mount matrix; no operar host productivo.

## Puntos de control y evidencias

Cada paquete guarda: commit base, hash de SPEC/PLAN, diff, comandos y resultados exactos, ambiente, limitaciones/omisiones, hashes de fixtures/backup, transición de estados/authorization, y revisión humana. Resultado unitario no sustituye integración real.

## Rollback/recovery

- Antes de cambios storage/config: backup consistente y verificado con hash, ensayo restore en copia.
- Si se detecta corrupción o fallo post-side-effect: parar broker/authority, no revertir archivos automáticamente, preservar journal/log, clasificar `INDETERMINATE` y requerir reconciliación humana.
- Si migración documental/schema falla: preservar SPEC/PLAN originales; desactivar lector nuevo sólo si downgrade no interpreta distinto/acepta más; de otro modo mantener servicio en read-only/deny.
- Si installer upgrade falla: restaurar backup verificable de config/client pin/service unit, nunca regenerar una llave revocada; mantener Authority offline si integridad de pin/keys no puede demostrarse.
- Cualquier rollback de software conserva esquema y registros; no borrar evidence ni resetear health a `HEALTHY` sin reconciliación.

## Lo que el plan no decide

No fija fechas, proveedor, stack web, storage definitivo, semántica de legacy approval ni ejecución privilegiada; esas decisiones deben resolverse antes del task correspondiente y conservar los requisitos de la SPEC.