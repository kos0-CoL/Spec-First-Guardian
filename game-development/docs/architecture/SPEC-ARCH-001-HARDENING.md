---
spec_id: SPEC-ARCH-001
title: "Hardening de seguridad y contratos del Framework Core"
status: DRAFT
version: 0.1.0
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
---

# SPEC-ARCH-001 — Hardening de seguridad y contratos del Framework Core

**Estado:** DRAFT; no aprobada, no autoriza implementación.  
**Fecha:** 2026-11-06  
**Autor:** Buffy — propuesta técnica para decisión del usuario.  
**Alcance:** definir resultados verificables para cerrar riesgos P0/P1 del Framework Core y especificar interfaces; no convierte SFG en plataforma.  
**Autoridad documental:** ninguna aprobación se infiere de este documento o su frontmatter. Sólo aprobación humana explícita mediante mecanismo de autoridad ya validado autorizará implementación.  
**Dependencias:** ARCH-001.md, CURRENT-STATE-MAP.md, ADR-001.md, FINDINGS-ARCH-001.md. PLAN-ARCH-001.md es secuencia secundaria y no puede agregar requisitos/criterios.  
**Impacto:** authority_service, approval_service/client, implementation_gate, audit_chain, safe_fs, workspace_guard, install_authority.sh, validate/schema/templates, README/SKILL/instructions/tests. No cambios realizados en esta etapa.

## 1. Contexto y objetivos

La auditoría del commit `5f070594a07c289dcda03f8f76eac7e2241d1974` encontró que `Authority.approve()` persiste `status=APPROVED` y `challenge_used=True` antes de `_approval_event()` y firma; producción actualmente deniega por ausencia de callback verificado. `AuditChain` usa `_poisoned` por instancia además de archivos y `ImplementationGate` crea instancias nuevas; `safe_fs._fsync_dir()` ignora fallos; SPEC y PLAN están mezclados; página de revisión no prueba presentación ni consentimiento; `workspace_guard` inspecciona mount type raíz pero no individualiza mounts/hardlinks/races; instalador reescribe trust store.

Objetivos: mantener producción fail-closed hasta OIDC real; no permitir estado falsamente aprobado; salud de auditoría fail-stop incluso tras reinicio/nuevas instancias; demostrar acceso íntegro a documento/scope y confirmación humana ligada a hashes; separación SPEC/PLAN con compatibilidad; límites de filesystem y durabilidad explícitos; instalación no destructiva; contratos uniformes y claims de Skill veraces.

## 2. No objetivos

No implementar en esta misión; no habilitar producción actual; no añadir estados documentales oficiales; no autorizar agente a autoaprobar; no ampliar el set de operaciones gate; no proteger procesos/scripts/dependencias/migraciones sin enforcement OS; no crear SaaS, billing, marketplace, editor, modelo propio u orquestador; no afirmar compatibilidad Windows/macOS; no reemplazar registros históricos silenciosamente.

## 3. Glosario y estados

Siete estados documentales inmutables: `DRAFT`, `UNDER_REVIEW`, `PENDING_USER_APPROVAL`, `APPROVED`, `REJECTED`, `SUPERSEDED`, `ARCHIVED`.

Estados separados:
- Solicitud: `PENDING`, `CHALLENGE_ISSUED`, `AUTHENTICATING`, `AUTHENTICATED`, `AUTH_FAILED`, `EXPIRED`, `APPROVAL_COMMITTING`, `APPROVED`, `REJECTED`, `RECONCILIATION_REQUIRED` (estados de servicio, no documentales).
- Autenticación: `PENDING`, `SUCCEEDED`, `FAILED`, `EXPIRED`, `REPLAYED`.
- Autorización: `NOT_ISSUED`, `COMMITTING`, `ACTIVE`, `REVOKED`, `INDETERMINATE`.
- Audit health: `HEALTHY`, `AUDIT_INCOMPLETE`, `AUDIT_CORRUPT`, `AUDIT_UNAVAILABLE`, `RECONCILIATION_REQUIRED`.

`APPROVED` sólo se asigna a solicitud/registro de autorización tras el commit seguro completo; el estado documental seguirá sujeto a transición humana/documental explícita y no se cambia como efecto incidental.

## 4. Requisitos funcionales

### RF-001 — Commit transaccional de aprobación (P0)

La autoridad implementará un flujo de callback OIDC Authorization Code + PKCE con sesión server-side. Debe validar state ligado a sesión y solicitud, nonce, PKCE S256, issuer, audience, firma/JWKS y algoritmo permitido, exp/iat, auth_time reciente (también rechazar valores futuros fuera de skew), sub exacto del aprobador esperado y expiraciones. El callback no aceptará login basado en ID token entregado por Agent Runtime.

Orden lógico: crear y persistir desafío/sesión; recibir callback; verificar state/session/PKCE y token; comprobar identidad esperada; obtener confirmación humana en UI de Authority del contenido íntegro y alcance; releer SPEC y validar hash y estado; recalcular hash canónico de scope; consumir challenge/token atómicamente con compare-and-swap; firmar canonical authorization; persistir bundle y ledger de autorización; persistir evento de auditoría de commit; sólo entonces marcar solicitud/autorización `APPROVED`/`ACTIVE` y responder éxito. Los pasos persistentes requieren transacción equivalente o journal/idempotency con recuperación. Ningún camino considera una solicitud aprobada mientras alguno de los tres (bundle, autorización, audit commit) quede sin confirmar.

La semántica exacta de consumir challenge antes o después de autenticar debe asegurar ambos: fallo auth no genera approval falso y challenge exitoso/reutilizado no se consume más de una vez. Se permite challenge invalidado al fallar auth con estado explícito y nueva solicitud/desafío, no volverlo reutilizable. Código callback ausente/incompleto mantiene producción bloqueada (`SETUP_INCOMPLETE`).

Concurrencia: serializar por request en storage protegido; CAS de estado y token nonce/replay; una única transición `CHALLENGE_ISSUED → APPROVAL_COMMITTING`; dos procesos concurrentes producen un ganador; resultado ambiguo bloquea como `INDETERMINATE/RECONCILIATION_REQUIRED`, no repite firma ni concede dos autorizaciones.

### RF-002 — Consumo y replay durable (P0)

No usar sólo sets en memoria para garantizar one-time nonce/token; persistir identificadores/hashes consumidos junto a request/session con expiración y recuperación. ID token/código no se registra en logs. PKCE verifier y nonce no se exponen al agente; callback mantiene secretos server-side. Nonce se vincula a ID token; state a sesión; PKCE al authorization code.

### RF-003 — Revisión de SPEC y confirmación (P1)

La autoridad entrega el documento íntegro y alcance canónico/hash exacto a una interfaz bajo sesión humana autenticada; no delega el rendering/confirmación a booleanos de cliente agente. Actualización de SPEC o scope invalida review/session/challenge y obliga iniciar nueva revisión. Debe registrarse que el sistema entregó todas las partes/versiones/hash y recibió acto explícito del sujeto; no declarar que la persona leyó o comprendió.

`review_next_offset` prueba secuencia servida; `review_fingerprint` ata páginas a hash; `review_pages` cuenta; `review_complete` de cliente no es evidencia. Aprobación requiere confirmación originada en la sesión de UI de Authority y vinculada a `spec_sha256` + `scope_sha256` + challenge/session + subject + timestamp + event id.

### RF-004 — Separación SPEC/PLAN y compatibilidad histórica (P1)

SPEC define contexto, objetivos, fuera alcance, requisitos, restricciones, arquitectura/interfases, aceptación, riesgos, estrategia de validación y trazabilidad. PLAN define tareas, orden, archivos, dependencias, pruebas, responsables, checkpoints, rollback y evidencias. PLAN tiene referencia a spec id/version/hash; no puede introducir requisitos, cambiar prioridad/alcance ni acceptance criteria.

Adaptar `technical-specification.md` a SPEC y crear template PLAN; `validate.py` y `spec.schema.json` validan formatos versionados. El parser debe reconocer legacy con plan embebido sin migración automática y reportar `legacy_format`; registros históricos se preservan byte/hash y la política de validez de aprobación anterior se decide antes de activar nuevo enforcement. No eliminar ni rebajar requisitos de una SPEC antigua en silencio. Migración es nueva revisión documentada, original inmutable, diff y aprobación humana requerida si cambia contenido autorizado.

### RF-005 — Auditoría fail-stop mult instancia y reinicio (P0)

Implementar health state protegido compartido y verificable más un latch de emergencia en proceso Authority. Cada nueva solicitud de concesión lee health desde una fuente durable/coordinada bajo lock cross-process, verifica cadena, marker y configuración. Cada fallo de intención antes de operación deniega; fallo del resultado tras ejecución marca proceso en emergencia y requiere reconciliación. `_poisoned` no será única fuente.

Estados health exactos: `HEALTHY`, `AUDIT_INCOMPLETE`, `AUDIT_CORRUPT`, `AUDIT_UNAVAILABLE`, `RECONCILIATION_REQUIRED`. Mapeo fail-closed: cualquier ausencia/inconsistencia/JSON inválido/permisos/IO/fsync/error de lectura no aceptado como HEALTHY. Si falla audit log + marker + health/fs, process latch detiene concesiones en esa autoridad y devuelve error; reinicio realiza preflight, detecta evidencia de inicialización, no autocura ni elimina bloqueo. Si tras reinicio no puede determinar integridad, servicio no concede y requiere recuperación humana fuera de banda documentada.

Reconciliación exige UID admin + reauth humana válida + nota/evidencia; verifica/restaura evidencia, escribe evento de reconciliación durable y confirma salud después de ese evento. No limpiar log corrupto como si fuera reparación; auditoría corrupta/inaccesible requiere restore desde backup confiable más evento de recovery o permanece bloqueada.

### RF-006 — Orden de transacciones de Authority (P0)

Aprobación, revocación, rotación de clave, persistencia de autorización y auditoría requieren estado intermedio/journal recoverable. No anunciar éxito antes de persistencia. En failure post-side-effect, bloquear authority y devolver estado `INDETERMINATE`; nuevas operaciones no se conceden hasta recuperar.

### RF-007 — Workspace allowlist y verificación estable (P1)

Verificar cada directorio/archivo sin symlink, tipo regular/directorio permitido, owner/mode/ACL; detectar `st_nlink>1` para archivos regulares y rechazar por defecto hardlinks no autorizados; inspeccionar mount ID/type/source por path (mountinfo escapes), detectar bind mounts y mounts anidados. Política base propuesta: prohibir mountpoint debajo del workspace salvo mount explícitamente allowlisted por configuración immutable; validar cada entry e identidad de mount. No confiar sólo en filesystem raíz.

Detección de race: usar traversal fd-relative/no-follow, registrar dev/inode/mount id y volver a verificar antes/después; en `protect()` bloquear cambios concurrentes mediante ownership/namespace/capability controlada o abortar si snapshot cambia. Descriptor/dir traversal debe evitar seguir symlink. En caso de montaje no inspeccionable, ACL `ACL_UNKNOWN`, entry mutada, hardlink fuera de scope o tipo especial, `protected=false`; nunca continuar declarando protección parcial.

Mantener valores ACL exactos `ACL_PRESENT`, `ACL_ABSENT`, `ACL_UNKNOWN`; `ENOTSUP` no prueba ausencia salvo filesystem/mount policy explícita y verificada. Documentar herencia/default ACL por cada directorio.

### RF-008 — Durabilidad verificable de operaciones (P1)

`_fsync_dir` no ignora errores. `create_file`, `modify_file`, `overwrite_file`, `delete_file` deben distinguir operación solicitada, syscall aplicado, fsync archivo, fsync directorio, verificación de digest/inode y audit result durable. API devuelve estados (`NOT_EXECUTED`, `EXECUTED_NOT_DURABLE`, `DURABILITY_CONFIRMED`, `INDETERMINATE`) y evidencia apropiada; no devolver éxito durable cuando cualquier fsync relevante falle.

Si fsync de archivo falla antes de rename/create commit: intentar limpieza segura, registrar resultado/indeterminado. Si rename/unlink ocurrió y fsync directory falla, modificación podría existir pero persistencia sobre crash no está confirmada: mark audit incomplete, latch Authority, no nuevas autorizaciones, devolver indeterminate. `delete_file` no proporciona digest posterior del contenido; conservar identity/digest previo en intención y recibo. `modify_file`/overwrite usan temp+rename; cualquier cambio inode/hardlinks debe documentarse. La recuperación compara intent log, target digest/inode y snapshot; nunca repetir ciegamente operación no idempotente.

### RF-009 — Instalador idempotente y no destructivo (P1)

Comandos/modos `INSTALL`, `VERIFY`, `UPGRADE`, `RECONFIGURE` con preconditions:
- `INSTALL`: sólo destinos ausentes o inicialización declarada; crea llave/config atomizada, crea trust store inicial una sola vez; conflicto existente aborta y reporta.
- `VERIFY`: sólo lectura, no cambia archivos, usuarios, ACL, permisos, servicios ni claves; reporta diffs/failures.
- `UPGRADE`: valida versión/formato, backup/hash verificable, migración idempotente explícita; preserva custom fields/UID/proyectos/pins/revocaciones; requiere rollback documentado.
- `RECONFIGURE`: cambios de proyecto, UID, OIDC, socket, admin/client o pin se presentan como diff; requiere validación/autorización admin y plan de transición; no ejecuta automáticamente hasta confirmar.

Nunca regenerar trust store conocido, resetear revoked=true, sobrescribir configuración custom/client.json, perder revocations o rotar key silenciosamente. Rotación debe ser explícita: nueva clave/id, periodo trust coexistente controlado, nueva public pin distribuida autenticadamente, prueba, revocación de antigua y evidence. Cambios UID/proyecto requieren comprobar ownership de todo workspace/config/socket y no reusar autorización incompatible.

### RF-010 — Skill claims alineados (P1)

Documentar tres clases: A) operaciones intermediadas actualmente: sólo create/modify/overwrite/delete de archivos a través del gate (declarar deployment/prod caveats); B) operaciones bloqueadas por permisos/aislamiento OS sólo cuando prueba/estado verify confirma: escritura directa del agente al workspace; C) operaciones no protegidas: procesos/shell, scripts, instalación deps, migraciones, herramientas externas, Git y acciones de subagentes fuera del IPC, salvo que OS policy real lo impida. No afirmar que denegar petición del gate impide ejecución OS.

Migración futura conserva `game-development/SKILL.md` y knowledge útil a `skills/spec-first-guardian/SKILL.md` universal y `skills/domains/game-development/`, `web-development/`, `backend-development/`; no mover en fase de implementación sin aprobación. No duplicar reglas universales.

### RF-011 — APIs uniformes (P2)

Todos los adaptadores llaman los mismos contratos versionados. El servidor autentica peer, deriva UID/actor/contexto desde configuración confiable, ignora identidad/decisión/authorization flags del cliente, valida payload/schema/límites, scope y freshness; deniega en error. Versiones incompatibles se rechazan de forma explícita.

## 5. Interfaces públicas propuestas

| Contrato | Entrada | Salida | Errores/validación/permisos |
|---|---|---|---|
| Specification API | `Create/Validate/Get(spec_id, version, content, format_version)` | `validation_report`, `spec_hash`, official status, requirements/criteria identifiers | malformed, legacy, invalid schema, stale hash; lectura pública según ACL, escritura requiere Authority. El cliente no fija status de aprobación. |
| Approval API | `Begin(spec_id,version,spec_hash,scope,scope_hash,actor_context)`; callback `code,state`; `ConfirmReview(session_id, hashes)` | redirect/opaque session, auth state, signed approval receipt | unauthorized admin, state/nonce/PKCE mismatch, identity mismatch, replay, stale content, expired, commit indeterminate. Sólo usuario esperado a través de callback/UI; no bearer directo de agente. |
| Authority API | `RequestApproval`, `GetStatus`, `Revoke`, `Reconcile`, `VerifyAuthorization` | request ID, health state, authorization reference, event receipts | invalid peer/config, denied, unavailable, conflict, audit unhealthy. Admin routes requieren UID autorizado + reauth humana; agente sólo request/status permitidos. |
| Policy API | `Evaluate(authorization_ref, operation, fresh_spec_hash, scope_hash, revocation_snapshot)` | `ALLOW/DENY`, reason codes, policy version | missing/stale evidence, unknown policy, revoked, out-of-scope; sólo Authority puede llamar; valores cliente no son prueba. |
| Enforcement API | `Execute(op_id, operation, content digest/ref)` | receipt con `executed`, `durability`, digest, audit seq | unauthorized, audit failure, broker timeout, `INDETERMINATE`; intención durable primero; Agent no ejecuta directo vía API. |
| Workspace API | `ExecuteAuthorized(capability, root_id, operation, relative_path, payload)` | filesystem receipt, inode/digest/durability | traversal, mount/hardlink/symlink, ACL unknown, race, OS error. Capability emitida Authority; Broker deriva raíz confiable, no acepta absolute root de caller. |
| Audit API | `Append(event_id, event)`, `Health()`, `Verify()`, `Reconcile(admin_proof, evidence)` | durable seq/hash, health enum, chain verification | append/fsync/health corruption/unavailable; Reconcile sólo humano reautenticado, no borra cadena. Idempotencia por event_id. |
| Integration API | handshake `protocol_version/capabilities`; typed requests/result | canonical DTO + stable error codes | incompatible, denied, timeout ambiguous, unsupported capability; ningún adapter lleva signing key ni policy fork. |

## 6. Requisitos no funcionales y seguridad

- Seguridad: authorization decisions fail-closed; signer privado sólo Authority; un humano aprobador exacto; scope least privilege; logs no exponen token, PKCE verifier, secretos ni datos sensibles no necesarios.
- Integridad: hashing canónico versionado y determinista; define UTF-8/normalization/newline policy para SPEC; cambios invalidan aprobación.
- Disponibilidad: no sacrificar seguridad ante IdP/filesystem/audit outage; informe `UNAVAILABLE`/denied.
- Compatibilidad: Linux inicial; todas garantías específicas de Linux explícitas. No claims macOS/Windows sin tests/implementaciones.
- Observabilidad: códigos de estado y evidencia; no registros falsamente exitosos.

## 7. Criterios de aceptación verificables

- SA-001: ante callback inexistente o inválido (state, sesión, nonce, PKCE, firma, issuer, audience, subject, auth_time, expiración) no existe autorización activa ni estado APPROVED; producción reporta `SETUP_INCOMPLETE` y niega.
- SA-002: fault injection tras cada etapa de aprobación deja o autorización completamente durable/auditable o estado no activo bloqueado/indeterminado; reinicio no transforma intento parcial en aprobación.
- SA-003: dos approvals concurrentes del mismo challenge producen exactamente una autorización firmada/activa; token/code/challenge/nonce replay se deniega después de reinicio.
- SA-004: alteración de SPEC o scope entre presentación y commit invalida sesión; hashes confirmados exactos requeridos.
- SA-005: agente puede recibir contenido íntegro; sólo acción de sesión humana autenticada genera confirmación; no se afirma lectura/comprensión.
- SA-006: todas las combinaciones de falla audit log/marker/health/fsync/read/restart causan denegación de nuevas operaciones; ninguna instancia nueva autoriza con salud desconocida; recovery añade evidencia humana durable.
- SA-007: SPEC/PLAN legacy conserva bytes/hash e historial; validador reconoce compatibilidad y no migra silenciosamente; PLAN sólo puede mapear a requisitos aceptados existentes.
- SA-008: mount interno no allowlisted, bind mount, symlink, hardlink no permitido, archivo especial, ACL_UNKNOWN y race de tree ⇒ `protected=false`; no declarar protección de snapshot incompleto.
- SA-009: fsync file o directory falla en cada una de las cuatro operaciones ⇒ resultado no es `DURABILITY_CONFIRMED`; post-side-effect mantiene fail-stop hasta reconcile.
- SA-010: correr `INSTALL` sobre estado existente no altera trust keys/revocations/custom config/client pin; `VERIFY` es read-only; upgrade/reconfigure idempotente, diff y rollback demostrados.
- SA-011: la Skill distingue A/B/C y no afirma control sobre vías no bloqueadas; operación `execute_script`, instalación, migration, subagent fuera broker no se reporta protegida.
- SA-012: tests de conformidad prueban cada adaptador en uso de mismos Authorization/Policy/Enforcement contracts; no hay canal de bypass aprobado.
- SA-013: siete estados oficiales permanecen exactos; estado de auth/challenge/audit se almacena separado.
- SA-014: tests unitarios, fault injection, multiproceso/restart, integración OIDC de test realista, Linux multi-UID y test sobre filesystems/mounts objetivo se ejecutan y reportan; no sustituir resultados de ambiente real por mocks.

## 8. Estrategia de validación

1. Unit tests: máquinas de estado, hash canon, validators legacy/current, error codes.
2. Property/fault injection: exceptions/short writes/fsync/rename/dirfsync/atomic replace, marker/health/log simultaneous failure.
3. Multiprocess: challenge CAS, audit append/recovery, restart y gate instances nuevas.
4. OIDC integration con IdP de test y callback/PKCE reales en entorno aislado; luego staging IdP antes de declarar prod.
5. Linux integration con UIDs distintos y perms reales; mount namespace, bind/nested mounts, hardlinks, ACL, symlink races; filesystem matrix declarada.
6. Installer tests en VM/container no privilegio global: modes, snapshots de configuración y trusted keys, reruns, upgrade/reconfigure rollback.
7. Adapter conformance suite.
8. Toda verificación no ejecutada se reporta como omitida/bloqueada, nunca como pass.

## 9. Migración y compatibilidad

- Mantener API/protocol actual v2 durante ventana de compatibilidad; nuevo protocolo versionado (p.ej. v3) sólo tras contract review; no aceptar fallback inseguro.
- Leer SPEC legacy que incorpora plan, marcar formato, aceptar para lectura/revisión según política aprobada; migración genera SPEC+PLAN nuevos enlazados, conserva source immutable y diffs. Approval anterior no pasa automáticamente a contenido diferente.
- Revalidar todos los ejemplos/templates y los registros `specs/approvals`, `specs/revocations`; artefactos marcados legacy no se borran.
- Mantener Skill en rutas existentes con aviso de transición; luego migrar según plan aprobado y mantener redirect/docs por un release definido.
- Instalador puede necesitar conservar configuración legada: crear backups con hashes y procedimiento restauración antes de cambios.

## 10. Riesgos y dependencias

Dependencias: decisión de usuario sobre UX OIDC/callback (no código hasta aprobación), IdP y client config, tecnología de almacenamiento transaccional (filesystem journal SQLite u otro, decisión aún abierta), filesystem/mounts Linux objetivo, identidad/privilegios reales, lifecycle systemd, política legacy.

Riesgos: transacción distribuida audit+authorization+filesystem no es atomicidad real; usar journal/estados indeterminados. Rollback de escritura tras resultado audit fallido puede destruir evidencia o ser no seguro; no revertir automáticamente sin operación compensatoria auditable. Latch de proceso no garantiza bloqueo ante proceso Authority comprometido, por eso persistencia OS externa necesita ACL. La confirmación UI no demuestra atención mental. Comportamiento de fsync/mount varía por filesystem. Borrado/rewrite de archivos puede afectar hardlinks externos. Instalador root puede dañar host si se prueba fuera de entorno aislado.

## 11. Decisiones pendientes del usuario

1. ¿Aprobar la división lógica/procesos (Authority + Workspace Broker + audit subservicio interno) o requerir broker separado desde fase inicial?
2. ¿Política legacy: seguir aceptando aprobaciones históricas sólo si bytes exactos y keys/revocations vigentes, o bloquear implementation legacy hasta re-aprobación?
3. ¿Interfaz OIDC humana: servidor local/localhost callback, loopback browser, web UI propia u otro deployment? Debe evitar token directo desde CLI del agente.
4. ¿Almacenamiento transaccional de estado/audit: SQLite local con WAL/full sync, filesystem journal, o backend ya existente? Evidencia/failure semantics requerida.
5. ¿Mount policy estricta de rechazar todo mount interno, o lista allowlist administrada por operador?
6. ¿Operaciones en `INDETERMINATE`: reconciliación manual solamente, o compensación explícita firmada por humano?

## 12. Trazabilidad

- RF-001, RF-002 → SA-001, SA-002, SA-003.
- RF-003 → SA-004, SA-005.
- RF-004 → SA-007, SA-013.
- RF-005, RF-006 → SA-002, SA-006.
- RF-007 → SA-008.
- RF-008 → SA-009.
- RF-009 → SA-010.
- RF-010 → SA-011.
- RF-011 → SA-012.
- SA-014 transversal a RF-001…RF-011.

## 13. Fuera del PLAN

El documento no define fechas, prioridad de ejecución, asignaciones, comandos destructivos ni la autoridad para cambiar código. El plan independiente sólo secuenciará esta SPEC y no podrá agregar o alterar estos requisitos/criterios. Toda implementación requiere aprobación explícita de este texto/version/hash por el usuario.