# AUDIT-ETAPA-B-094F93D — Expediente reproducible de la Etapa B

**Estado:** DRAFT — expediente de auditoría; **no** constituye una aprobación de seguridad ni habilita producción.<br>
**Proyecto:** Spec-First Guardian<br>
**Commit auditado:** `094f93d065cbbedce7d9ff35aeb862db92422476`<br>
**Commit padre:** `5f070594a07c289dcda03f8f76eac7e2241d1974`<br>
**Rama:** `main`<br>
**Fecha de auditoría:** 2026-11-06<br>
**Entorno:** Linux, usuario UID 1000, Python 3.14.4, SQLite 3.46.1 (`threadsafety=3`).<br>
**Alcance:** evidencia del commit, análisis estático de `authority_store.py`, `authority_service.py`, `implementation_gate.py` y `safe_fs.py`, suite existente y pruebas adversas temporales sin modificar el repositorio.<br>
**Autoridad documental:** este expediente no modifica la SPEC, no corrige defectos y no autoriza OIDC, despliegue ni producción.

> **Advertencia:** los hallazgos P1 siguientes son bloqueantes para declarar terminada la Etapa B o para avanzar a implementación OIDC. Las pruebas unitarias en verde no demuestran las garantías de recuperación ni de durabilidad del filesystem.

---

## 1. Congelamiento del repositorio

Comandos ejecutados antes de inspeccionar:

```bash
git fetch origin
git rev-parse --verify '094f93d^{commit}'
git rev-parse --verify 'origin/main^{commit}'
git merge-base --is-ancestor 094f93d origin/main
git branch --show-current
git status --short --branch
```

Resultado:

| Comprobación | Resultado |
|---|---|
| SHA completo | `094f93d065cbbedce7d9ff35aeb862db92422476` |
| `origin/main` | `094f93d065cbbedce7d9ff35aeb862db92422476` |
| ¿`origin/main` contiene el commit? | Sí (`merge-base --is-ancestor` exit 0) |
| Rama actual | `main` |
| Working tree al inicio | Limpio, `main...origin/main` |
| Commits/push/merge/rebase durante la auditoría | Ninguno |

No se cambió de rama ni se alteraron archivos de producción, tests, SPEC o configuración. El único artefacto creado es este expediente, que queda sin seguimiento en Git.

---

## 2. Inventario de cambios

`git diff-tree --no-commit-id --name-status -r 094f93d`:

| Estado | Archivo |
|---|---|
| M | `game-development/README.md` |
| A | `game-development/docs/architecture/ADR-001.md` |
| A | `game-development/docs/architecture/ARCH-001.md` |
| A | `game-development/docs/architecture/CURRENT-STATE-MAP.md` |
| A | `game-development/docs/architecture/FINDINGS-ARCH-001.md` |
| A | `game-development/docs/architecture/IMPLEMENTATION-ARCH-001.md` |
| A | `game-development/docs/architecture/PLAN-ARCH-001.md` |
| A | `game-development/docs/architecture/SPEC-ARCH-001-HARDENING.md` |
| M | `game-development/instructions/authority.md` |
| M | `game-development/scripts/authority_service.py` |
| A | `game-development/scripts/authority_store.py` |
| M | `game-development/scripts/implementation_gate.py` |
| M | `game-development/scripts/install_authority.sh` |
| M | `game-development/tests/test_authority.py` |
| A | `game-development/tests/test_store.py` |

**Resumen:** 15 archivos, 2380 inserciones y 93 eliminaciones. No hay archivos eliminados.

### 2.1 Cambios en Authority

- `AuthorityConfig` incorpora `store_path` opcional, por defecto `state_dir/authority.sqlite3`, y `preflight` valida su ruta, directorio y permisos (`authority_service.py:151-160`, `226-260`, `337-349`).
- `Authority.__init__` abre el `SQLiteAuthorityStore` y ejecuta la migración histórica antes de inicializar la auditoría (`authority_service.py:402-419`).
- Solicitudes, desafíos, páginas de revisión e invalidaciones se guardan en el store. El evento de auditoría se escribe en la misma transacción que el cambio de solicitud (`authority_service.py:519-553`, `598-855`).
- `Authority.approve()` autentica y firma antes de llamar a `commit_approval`; el commit confirma grant, estado `APPROVED`, consumo del desafío, replay y evento `approval` en una transacción (`authority_service.py:856-948`; `authority_store.py:575-654`).
- `Authority._load_bundle` lee del store y conserva un fallback de sólo lectura a `state_dir/approvals` cuando no existe grant (`authority_service.py:533-553`).
- `audit_verify` informa también `health` (`authority_service.py:1153-1162`).
- El CLI incorpora `--migrate` y `--verify-storage` (`authority_service.py:1502-1545`).
- `implementation_gate.py` acepta un sink `audit=` inyectable y captura `AuditError` al marcar auditoría incompleta (`implementation_gate.py:115-182`).

### 2.2 Cambios en tests, fixtures, configuración y políticas

- **Tests modificados:** `tests/test_authority.py` cambia la lectura de la auditoría de JSONL a `audit.store.events()` (líneas 139-145), cambia la manipulación de solicitud de archivo JSON a `UPDATE requests` directo en SQLite (líneas 211-231) y añade la regresión `test_failed_authentication_does_not_consume_challenge_or_approve` (líneas 168-196).
- **Tests nuevos:** `tests/test_store.py`, 15 pruebas de WAL/FULL, permisos, corrupción, atomicidad, concurrencia, replay, cadena, salud y migración.
- **Fixtures:** `tests/support.py` no fue modificado. Los fixtures nuevos generan claves y almacenes temporales.
- **Configuración:** `install_authority.sh` añade `"store_path": f"{state}/authority.sqlite3"` (línea 182); no cambia usuarios, grupos, claves ni políticas de socket.
- **Políticas:** no se modificaron políticas de autorización, allowlists, UID, revocaciones ni la SPEC; los documentos de arquitectura son nuevos y no normativos salvo la SPEC existente.
- **Modificación de tests y defectos:** los cambios de tests son adaptaciones al nuevo almacén, no una ocultación de fallos. La nueva prueba de autenticación fallida, sin embargo, **fija como comportamiento esperado la reutilización del desafío**, lo que contradice RF-001 (ver AUD-01).

### 2.3 Secretos, claves y bases de datos

Comprobaciones realizadas:

```bash
git diff-tree --no-commit-id --name-only -r 094f93d | \
  grep -Ei '(^|/)(\.env|.*\.sqlite([0-9]*)?|.*\.db|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa|id_ed25519)(\.|$)'
git grep -nEI 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}' 094f93d -- game-development
```

Resultado: **sin coincidencias**. No se incorporaron bases SQLite reales, claves privadas, tokens, `.env` ni material de claves. `install_authority.sh` y los tests generan claves efímeras en tiempo de ejecución; no se versionan.

### 2.4 Diff completo

El diff completo de los archivos críticos se reproduce en el **Anexo A** de este expediente. Para verificarlo de forma independiente:

```bash
git show --format= --no-color 094f93d -- game-development/scripts/authority_store.py
git show --format= --no-color 094f93d -- game-development/scripts/authority_service.py
git show --format= --no-color 094f93d -- game-development/scripts/implementation_gate.py
git show --format= --no-color 094f93d -- game-development/scripts/install_authority.sh
git show --format= --no-color 094f93d -- game-development/tests/test_store.py
git show --format= --no-color 094f93d -- game-development/tests/test_authority.py
```

Hashes SHA-256 de los archivos en el commit:

| Archivo | SHA-256 |
|---|---|
| `scripts/authority_store.py` | `c87d4a626c89fef99304a2ab8494683ef1e41274bb5162c302d40bd7acc626a0` |
| `scripts/authority_service.py` | `05b8547522264344f19713f63fe77bd19b76a983d883acfeddab96f33a5e2d78` |
| `scripts/implementation_gate.py` | `a0841ffda65a9e167c15fb375e8b38fd5cb028124ce1a38a11dcfb915cc6a4bc` |
| `tests/test_store.py` | `681e06cc01384ccb27cea36d7a34420a9ced24451e3a6f8bdb50dff22974ab09` |
| `tests/test_authority.py` | `ecfbf959403edf6f8b1d839a4d5970fc186ad741587aafdb7b9ff2e76196f58e` |
| `docs/architecture/SPEC-ARCH-001-HARDENING.md` | `77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda` |

---

## 3. Arquitectura observada

La Etapa B mantiene una autoridad local y un único proceso de servicio, sin infraestructura distribuida:

```text
Cliente / agente
  └── socket Unix + SO_PEERCRED + atestación firmada
        └── Authority (servicio)
              ├── ApprovalService (identidad + firma Ed25519)
              ├── AuthorityStore (contrato)
              │     └── SQLiteAuthorityStore (WAL, FULL, transacciones)
              │           ├── requests
              │           ├── grants
              │           ├── audit_events (cadena seq/prev/hash)
              │           ├── replay
              │           ├── health
              │           └── meta (schema_version, legacy_migration)
              ├── ImplementationGate
              │     └── safe_fs (operaciones fd-relative, O_NOFOLLOW)
              └── RevocationRegistry / TrustedKeyStore
```

Flujo nominal:

1. `request_approval` registra la solicitud y su huella.
2. `challenge` emite token, `oidc_state`, `session_id` y páginas de revisión; persiste estado + evento.
3. `spec_page` entrega la SPEC completa por páginas ligadas a la huella y avanza `review_next_offset`.
4. `approve` valida state/sesión/token/expiración, relee la SPEC, recalcula `scope_hash`, exige revisión completa, autentica y firma.
5. `commit_approval` confirma en SQLite grant + estado `APPROVED` + consumo del desafío + replay + evento `approval`.
6. `authorize`/`evaluate` verifican aprobación, revocación, alcance, SPEC y estado de auditoría.
7. `ImplementationGate.execute` registra `intent`, ejecuta la operación de archivo y registra `result`.

La separación de la base es real: `AuthorityStore` no expone `sqlite3` a las capas superiores; la implementación concreta está en `SQLiteAuthorityStore`. `safe_fs` no depende de SQLite. El gate recibe el sink de auditoría del store.

---

## 4. Análisis de SQLite

Archivo principal: `game-development/scripts/authority_store.py` (970 líneas en el commit; SHA-256 anterior).

### 4.1 Inicialización y archivo

`SQLiteAuthorityStore.__init__` (`authority_store.py:177-184`) ejecuta `_prepare_file()` y `_initialize_schema()` antes de exponer el sink de auditoría.

`_prepare_file` (`authority_store.py:187-212`):

- exige rutas absolutas;
- crea el directorio padre con `mode=0o700`;
- usa `os.lstat` y rechaza directorio symlink o no-directorio;
- limita el propietario a `0` o al UID actual;
- rechaza directorio con permisos de grupo/otros (`0o077`);
- si el archivo existe, rechaza symlink o no-regular, propietario no autorizado y modo con `0o077`;
- si no existe, lo crea con `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW` y modo `0600`.

Limitación: el archivo se crea, pero **no se hace `fsync` del directorio padre** tras la creación; la creación de la entrada de directorio no queda cubierta por `synchronous=FULL` (AUD-11). `_restrict_sidecars` (`authority_store.py:290-297`) hace `chmod(0o600)` a `-wal`/`-shm`, pero no usa `lstat`/`O_NOFOLLOW` (AUD-12).

### 4.2 Conexión, WAL y sincronización

`_connect` (`authority_store.py:214-234`):

```python
sqlite3.connect(..., timeout=busy_timeout_ms / 1000.0, isolation_level=None, check_same_thread=False)
PRAGMA busy_timeout=...
PRAGMA journal_mode=WAL
PRAGMA synchronous=FULL
PRAGMA foreign_keys=ON
PRAGMA trusted_schema=OFF
```

- `PRAGMA journal_mode=WAL` se ejecuta en **cada** conexión y se rechaza si el modo resultante no es `wal` (`authority_store.py:224-227`).
- `PRAGMA synchronous=FULL` se ejecuta en cada conexión (`authority_store.py:228`); la API normaliza `2` a `"full"` (`authority_store.py:306-313`).
- `PRAGMA trusted_schema=OFF` reduce la superficie de esquema no confiable.
- Los errores de `sqlite3` marcan `_poisoned = True` y se convierten en `StoreError` (`authority_store.py:232-234`).

La prueba `test_uses_wal_and_full_synchronous` (`tests/test_store.py:90-93`) verifica WAL, `full` y modo `0600`.

### 4.3 Transacciones, commit y rollback

`_transaction` (`authority_store.py:237-251`):

```python
connection.execute("BEGIN IMMEDIATE")
yield connection
connection.execute("COMMIT")
# except BaseException:
#   ROLLBACK; si ROLLBACK falla, _poisoned = True
# finally: connection.close()
```

- `BEGIN IMMEDIATE` serializa escritores y evita upgrades de lock.
- Cualquier excepción, incluidas `StoreConflict`, `MigrationError` y `KeyboardInterrupt`, provoca rollback.
- El cierre de conexión ocurre siempre.
- Si `ROLLBACK` falla, el store se marca envenenado.

`commit_approval` (`authority_store.py:575-654`) realiza, dentro de una sola transacción:

1. lectura y verificación de integridad de la solicitud (593-600);
2. rechazo de desafío usado/`APPROVED` (601-602);
3. comparación de hash de desafío (603-604);
4. comprobación de expiración (605-607);
5. comprobación de `fingerprint`, `spec_id` y `version` del grant (608-613);
6. inserción de replay con PK única (614-621);
7. detección de grant existente distinto (622-628) o inserción del grant (629-641);
8. actualización de la solicitud a `APPROVED` y `challenge_used=True` (642-649);
9. `_append_event(..., allow_blocked=False)` (650).

Cualquier fallo revierte los nueve pasos. La prueba `test_failure_during_audit_rolls_back_state_and_grant` (`tests/test_store.py:121-142`) simula un fallo de auditoría y verifica que la solicitud sigue `PENDING_USER_APPROVAL`, sin grant y sin evento.

**No se observó un camino normal que persista `APPROVED` sin grant ni un grant sin evento `approval`.** El defecto de migración (AUD-04) permite un grant histórico sin evento, fuera del flujo normal.

### 4.4 Errores y salud

- `_append_event` (`authority_store.py:338-357`) verifica `health`, calcula `seq`, `prev` y hash, y rechaza eventos mayores que `MAX_EVENT_BYTES`.
- `mark_incomplete` (`authority_store.py:466-474`) escribe estado `AUDIT_INCOMPLETE` y evento `audit_incomplete` en una transacción, con `allow_blocked=True`.
- `clear_incomplete` (`authority_store.py:476-499`) verifica la cadena fuera de la transacción, escribe `reconciled`, y sólo después vuelve a `HEALTHY`.
- `audit_blocked`, `health_state` y `block_reason` (`authority_store.py:417-464`) consultan salud y cadena; los estados desconocidos o ilegibles se tratan como bloqueados.
- `_poisoned` es un latch por instancia; la salud persistida es la fuente entre instancias (`authority_store.py:177-184`, `417-464`).
- `verify_chain` (`authority_store.py:369-396`) comprueba `seq` consecutivo, `prev`, hash y cuerpo JSON. No comprueba un ancla externa (AUD-07).

### 4.5 Permisos, propietario y symlinks

| Control | Implementado | Demostrado | Observación |
|---|---|---|---|
| Directorio `0700` | Sí, al crear; rechaza permisos amplios | `test_group_readable_store_is_rejected` sólo cubre archivo; directorio se valida en `_prepare_file` | Si el directorio ya existe con `0755`, se rechaza |
| Archivo `0600` | Sí, creación y validación | `test_uses_wal_and_full_synchronous` | `0600` exacto en archivo |
| Propietario | `0` o UID actual | No hay prueba con UID distinto | No demuestra aislamiento multi-UID |
| Symlink principal | `lstat` + `O_NOFOLLOW` | No hay prueba dedicada | Cubierto parcialmente por la suite de cliente/socket, no por store |
| Symlink de sidecars | No | `chmod` sigue symlink | AUD-12 |
| Directorio symlink | Rechazado | No hay prueba dedicada | Código claro |

### 4.6 Esquema y restricciones

`_initialize_schema` (`authority_store.py:253-288`) crea tablas `STRICT`:

- `meta(key PRIMARY KEY, value NOT NULL)`;
- `requests(request_id PRIMARY KEY, document, integrity, status, updated_at)`;
- `grants(spec_id, version, document, context, authorization_event_id, created_at, PRIMARY KEY(spec_id, version))`;
- `audit_events(seq INTEGER PRIMARY KEY, at, prev, hash, event)`;
- `replay(scope, identifier, expires_at, created_at, PRIMARY KEY(scope, identifier))`;
- `health(id PRIMARY KEY CHECK(id=1), state, reason, updated_at)`.

No hay claves foráneas ni `CHECK` de estados/expiración; `requests.status` es una columna informativa y la autoridad usa el documento. `grants.document` no tiene un digest independiente; la integridad se apoya en la firma Ed25519 (AUD-13). `schema_version` se valida y sólo se admite la versión 1 (`authority_store.py:272-278`).

### 4.7 Concurrencia y recuperación

- **Concurrencia de aprobación:** `commit_approval` relee dentro de `BEGIN IMMEDIATE`; la PK de `requests` y `grants` y la unicidad de `replay` refuerzan el CAS. Prueba existente con 6 hilos (`tests/test_store.py:144-173`) y prueba adversa con 4 procesos reales (A-1): exactamente un `committed`, tres `conflict`, un evento `approval`.
- **Reinicio tras consumo:** prueba adversa B: nuevo store y servicio completo; `APPROVED`, `challenge_used=True`; segundo `approve` denegado por desafío ya utilizado.
- **Rollback SQLite:** prueba adversa K: proceso terminado con `os._exit(9)` dentro de una transacción antes de `COMMIT`; al reabrir, 0 eventos y cadena válida.
- **Recuperación tras caída del gate:** **no implementada**. Prueba adversa J: proceso terminado tras escribir el archivo y antes de `result`; al reabrir, cadena válida/`HEALTHY` con sólo `intent`. La autoridad completa también arranca `HEALTHY` (AUD-02).
- **Migración interrumpida:** prueba adversa D: fallo inyectado tras importar solicitudes/grants; rollback deja 0 solicitudes, 0 grants, `meta` sin migración y cadena válida.
- **Corrupción:** prueba existente `test_corrupt_store_fails_closed` (`tests/test_store.py:100-105`) y `test_chain_detects_tampering` (`202-212`); el store corrupto no abre.
- **Error de escritura:** prueba adversa C: base `0400`; `commit_approval` devuelve `StoreError`, la solicitud queda `PENDING_USER_APPROVAL` y 0 grants.
- **Truncación de cola:** prueba adversa M: borrar el último evento deja `valid=True`; no hay ancla externa (AUD-07).

---

## 5. Ciclo de aprobación

### 5.1 Reconstrucción paso a paso de `Authority.approve()`

Referencia: `authority_service.py:856-948`.

| Paso | Qué ocurre | Evidencia / resultado |
|---|---|---|
| 1. Identidad / UID | `AuthorityServer._handle` exige `is_admin(uid)` para `approve` y `challenge`; `approve` recibe el UID. | `authority_service.py:1325-1340`; `test_admin_operations_require_admin_uid` (`test_authority.py:300-305`) |
| 2. Validación de solicitud | `_load_request` exige prefijo `REQ-`, sin `/`, y `get_request` verifica digest. | `authority_service.py:525-531`; `authority_store.py:524-537` |
| 3. State/sesión | `compare_digest` de `oidc_state` y `session_id`; sin coincidencia, deniega. | `authority_service.py:867-870` |
| 4. Desafío | Compara SHA-256 del token con `challenge_hash`; rechaza usado/`APPROVED` y expirado. | `authority_service.py:871-879` |
| 5. Relectura de SPEC | Abre el workspace con `safe_fs`, lee la SPEC y compara `fingerprint`. Si cambió, invalida revisión. | `authority_service.py:881-894` |
| 6. Scope | Recalcula `scope_hash` y exige que coincida con la solicitud y el payload. | `authority_service.py:895-897` |
| 7. Revisión | Exige `review_next_offset == len(SPEC)`, `review_fingerprint`, `review_complete is True` y `review_pages` exactos; valida el documento. | `authority_service.py:898-908` |
| 8. Importación | `service.import_request(request)` carga la solicitud en memoria. | `authority_service.py:910-911` |
| 9. Autenticación y firma | `_approval_event` autentica (test) o deniega producción; `approve_request` verifica identidad, firma la autorización y devuelve `record`. | `authority_service.py:912-917`, `950-978`; `approval_service.py:594-645` |
| 10. Commit | `store.commit_approval` confirma grant, estado, replay y evento en una transacción. | `authority_service.py:918-942`; `authority_store.py:575-654` |
| 11. Respuesta | Sólo después del commit devuelve `{"approval": record, "request_id": ...}`. | `authority_service.py:948` |

### 5.2 Caminos peligrosos

| Pregunta | Resultado | Evidencia |
|---|---|---|
| ¿Se persiste `APPROVED` sin grant? | **No en el flujo normal.** El estado se actualiza dentro de la misma transacción que inserta el grant. | `authority_store.py:629-649`; `test_commit_persists_grant_state_and_event_together` (`test_store.py:108-119`) |
| ¿Se emite grant sin evento de auditoría? | **No en el flujo normal**; **sí en migración** de un grant sin evento `approval`. | `authority_store.py:722-749`, `820-846`, `899-922`; prueba F |
| ¿Se consume desafío sin completar aprobación? | **No en el flujo normal.** `challenge_used` se escribe en el commit; si el commit falla, rollback. | `authority_store.py:642-649`; `test_failure_during_audit...` |
| ¿Un error permite reutilizar el desafío? | **Sí.** Cualquier fallo antes del commit (autenticación, firma, scope, error SQLite) deja el desafío utilizable. La prueba nueva lo declara explícitamente. | `authority_service.py:910-917`; `test_authority.py:168-196`; SPEC RF-001:50 |
| ¿Dos procesos aprueban simultáneamente? | **No**: un commit gana; los demás reciben `StoreConflict`. Probado con 4 procesos reales. | `authority_store.py:592-654`; prueba A |
| ¿Reinicio después de consumir desafío? | **No permite reutilizarlo**: `APPROVED`/`challenge_used` persisten. | Prueba B / B2 (servicio completo) |
| ¿Fallo de autenticación genera `APPROVED`? | **No**: no hay escritura; la solicitud sigue `PENDING`. | `test_failed_authentication...` líneas 190-193 |

### 5.3 Hallazgo central: desafío reutilizable tras fallo de autenticación

La SPEC exige:

> “Se permite challenge invalidado al fallar auth con estado explícito y nueva solicitud/desafío, **no volverlo reutilizable**.” — `SPEC-ARCH-001-HARDENING.md:50`

La implementación autentica y firma **antes** de escribir (`authority_service.py:912-917`) y sólo marca `challenge_used=True` dentro de `commit_approval` (`authority_store.py:642`). Si `_approval_event` o `approve_request` fallan, no hay escritura y el desafío sigue siendo válido. La prueba `test_failed_authentication_does_not_consume_challenge_or_approve` no sólo lo permite: después del fallo vuelve a llamar a `approve` con **el mismo challenge** y espera éxito (`test_authority.py:194-196`).

Esto contradice RF-001 y SA-001/SA-003. No permite aprobar sin autenticación, pero elimina la semántica de un solo uso ante fallos y permite reintentos indefinidos sobre el mismo desafío mientras no expire. Se clasifica **P1** (viola un requisito P0, sin bypass directo de autenticación).

---

## 6. Migración histórica

### 6.1 Mecanismo

`SQLiteAuthorityStore.migrate_legacy` (`authority_store.py:680-750`) recibe directorios de solicitudes/aprobaciones y un `audit.jsonl`; calcula digests de fuentes, comprueba un registro previo y, si no coincide, lee todo y lo importa en una transacción.

Validaciones:

| Validación | Implementación | Evidencia |
|---|---|---|
| Hash/integridad de solicitud | `_read_legacy_requests` exige `integrity == sha256(request)` y `request_id == stem` (`authority_store.py:810-813`). | `test_corrupt_request_refuses_migration_without_changes` (`test_store.py:316-326`) |
| Firma de grant | `_read_legacy_grants` llama `verify_approval` si `key_store.configured` (`authority_store.py:840-842`). | `test_imports_verified_evidence...` (`test_store.py:291-302`) |
| Secuencia de cadena | `_read_legacy_events` exige `seq == index`, `prev` encadenado y hash (`authority_store.py:860-880`). | `test_tampered_legacy_chain_is_refused` (`test_store.py:328-334`) |
| Empalme con cadena existente | `_import_events` compara prefijo y exige `seq == current_count+1` y `prev == current_hash` (`authority_store.py:924-966`). | `test_chain_that_cannot_be_spliced_is_refused` (`test_store.py:336-342`) |
| Duplicados | `_import_request` y `_import_grant` comparan integridad/event id y rechazan conflicto (`authority_store.py:883-922`). | Pruebas de migración |
| Idempotencia | Compara `source_digests` y `status=="completed"`; segunda ejecución devuelve `already_migrated` (`authority_store.py:702-707`). | `test_migration_is_idempotent...` (`test_store.py:304-314`) |
| Rollback | Todo dentro de `_transaction`; fallo de `_import_events` revierte solicitudes/grants (`authority_store.py:722-749`). | Prueba D (fallo inyectado): 0/0, `migration=None` |
| Archivos originales | Sólo lectura; no se escribe, mueve ni elimina. | `test_imports_verified_evidence...` compara hashes antes/después |

### 6.2 Comportamiento ante fallos e interrupciones

- **Migración interrumpida:** la transacción revierte. Prueba D inyecta `MigrationError` después de importar solicitudes y grants y confirma 0 solicitudes, 0 grants, `meta` sin migración, cadena válida.
- **SQLite con datos parciales/contradictorios:** `_import_request`/`_import_grant` rechazan conflictos; `_import_events` rechaza cadenas no empalmables. Las pruebas existentes cubren solicitud corrupta, cadena alterada y cadena no empalmable.
- **Migración incompleta que permita arrancar Authority:** no se encontró un camino normal de importación parcial; la transacción es atómica. Sin embargo, **sí se puede arrancar con un grant importado sin evento `approval`** (AUD-04).
- **Concurrencia de migración:** el registro previo se consulta **fuera** de la transacción (`authority_store.py:702-707`) y no se vuelve a comprobar dentro. Dos migraciones concurrentes pueden ambas leer “sin registro”, y la segunda puede volver a escribir `meta` y añadir otro evento `storage_migration`. No se probó con dos procesos; se clasifica P2 (AUD-08).
- **TOCTOU de fuentes:** `_source_digest` se calcula antes de leer (`authority_store.py:699`); un cambio entre digest y lectura no se detecta en esa ejecución. El digest se registraría con el valor anterior. P3/P2.

### 6.3 Hallazgo: grant importado sin evento `approval`

`_read_legacy_grants` verifica firma, contexto y `authorization_event_id` no vacío, pero **no** comprueba que ese `authorization_event_id` aparezca en la cadena de auditoría importada ni que exista un evento `approval` con ese ID (`authority_store.py:820-846`). `_import_grant` inserta el grant sin correlación (`authority_store.py:899-922`). `_import_events` importa la cadena disponible, aunque no contenga `approval` (`authority_store.py:924-966`).

Prueba F:

- cadena legacy con `request` y `challenge`, sin `approval`;
- `migrate_legacy` devuelve `completed`;
- `get_grant("SPEC-001","1.0.0")` devuelve el grant;
- eventos resultantes: `request`, `challenge`, `storage_migration`.

Resultado: un grant histórico puede existir sin el evento de commit que RF-001/RF-006 exigen. La firma del grant sigue siendo válida y el registro de revocaciones sigue aplicando, pero la invariante “grant + evento de aprobación” no se cumple para datos migrados. **P1 (AUD-04).**

---

## 7. Auditoría de filesystem

### 7.1 Flujo del gate

`ImplementationGate.execute` (`implementation_gate.py:244-292`):

1. `authorize()` verifica auditoría, contexto, SPEC, registro de revocaciones y alcance.
2. `_record("intent", ...)` registra intención; si falla, deniega sin ejecutar (`246-251`).
3. Ejecuta `safe_fs.write_file`/`delete_file` (`262-275`).
4. Si la operación lanza `PathSafetyError`/`OSError`, registra `result` fallido y devuelve `allowed=False` (`276-289`).
5. Si la escritura termina, marca `executed=True` y registra `result` (`291-292`).
6. Si `result` no se puede registrar, `_mark_incomplete` marca `audit_complete=False` y llama a `audit.mark_incomplete` (`171-182`).

### 7.2 Fallos entre intención y resultado

| Escenario | Comportamiento | Evidencia |
|---|---|---|
| Falla la intención antes de escribir | Deniega; no escribe. | `implementation_gate.py:246-251`; `test_audit_failure_denies_operation` (`test_gate.py:107-115`) |
| Falla la escritura | Registra `result` fallido; devuelve `allowed=False`, `executed=False`. | `implementation_gate.py:276-289`; `test_create_existing_file_is_denied` (`test_gate.py:84-88`) |
| Éxito de escritura y fallo al registrar `result` | `executed=True`, `audit_complete=False`; marca `AUDIT_INCOMPLETE`; bloquea operaciones posteriores en esa instancia y en el store. | `implementation_gate.py:291-292`, `171-182`; `authority_store.py:466-474` |
| Proceso muere tras escribir y antes de `result` | **No hay marca**: al reiniciar la cadena sigue válida y `health=HEALTHY`; la autoridad concede nuevas operaciones. | Prueba J; `authority_service.py:405-419`; `authority_store.py:14-18` |

### 7.3 `INDETERMINATE` y durabilidad

El docstring del store afirma:

> “si la operacion fisica se ejecuta y su resultado no puede registrarse, el resultado es INDETERMINATE y la autoridad bloquea nuevas operaciones hasta reconciliar.” — `authority_store.py:14-18`

El README repite la idea (`README.md:200-203`). **La implementación no cumple esa afirmación:**

- no existe un estado durable `COMMITTING`/`INDETERMINATE` antes de la escritura;
- no hay un escaneo de arranque de intenciones sin resultado;
- una caída abrupta deja sólo `intent` y `health=HEALTHY` (prueba J y prueba de autoridad completa);
- el gate devuelve `executed=True` con `audit_complete=False` en el caso de fallo de `result`, no un estado `INDETERMINATE` explícito;
- `verify_store` no detecta esa intención huérfana.

Esto viola RF-006 y SA-009, y contradice la documentación de la Etapa B. **P1 (AUD-02).**

### 7.4 `fsync` de directorio

`safe_fs._fsync_dir` (`safe_fs.py:104-109`):

```python
try:
    os.fsync(descriptor)
except OSError:
    # Algunos sistemas de archivos no permiten fsync de directorios.
    pass
```

`write_file` llama `_fsync_dir(parent)` después de crear/renombrar (`safe_fs.py:165`, `200`); `delete_file` después de `unlink` (`safe_fs.py:215`). La prueba G hace que `fsync` de un descriptor de directorio lance `OSError`; `write_file` devuelve digest y el archivo existe. El error se silencia y la operación se reporta como exitosa.

Esto viola RF-008 (“`_fsync_dir` no ignora errores”) y SA-009. Es un defecto **preexistente** a `094f93d`, pero la Etapa B lo integra en el flujo de resultados y no lo corrige. **P1 (AUD-03).**

---

## 8. Pruebas ejecutadas

### 8.1 Suite oficial (sin modificar pruebas)

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Resultado real:

```text
Ran 129 tests in 35.168s

OK
DURATION=35.41 s
```

- 129 pruebas ejecutadas, 129 OK.
- Sin errores, fallos ni excepciones no controladas en la suite.
- No se modificaron tests para obtener este resultado.

### 8.2 Comprobaciones estáticas

| Comando | Resultado |
|---|---|
| `python3 -m py_compile scripts/authority_store.py scripts/authority_service.py scripts/implementation_gate.py scripts/safe_fs.py tests/test_store.py tests/test_authority.py` | OK |
| `bash -n scripts/install_authority.sh` | OK |
| `git diff --check 5f07059 094f93d` | **No limpio**: 78 líneas con trailing whitespace, todas en documentos Markdown del commit (frontmatter con dos espacios). No hay avisos en scripts ni tests. |
| `git show --check 094f93d` | Reporta los mismos trailing whitespace documentales. |

El `git diff --check` limpio del working tree no equivale a un commit limpio: los documentos nuevos tienen espacios finales intencionales o no normalizados. **P3 (AUD-16).**

### 8.3 Pruebas adversas realizadas

Todas se ejecutaron con `python3 - <<'PY'` sobre directorios temporales, sin escribir en el repositorio ni en datos reales. UID 1000.

| ID | Prueba | Resultado |
|---|---|---|
| A | 4 procesos reales (`fork`) compitiendo por `commit_approval` de la misma solicitud | `['committed','conflict','conflict','conflict']`; 1 evento `approval`; 1 grant |
| B | Nuevo store tras el commit; reintento con desafío consumido | `status=APPROVED`, `challenge_used=True`; reintento denegado (`desafio ... ya utilizado`) |
| B2 | Reinicio completo de `Authority` y servidor, mismo socket; reintento de `approve` | `status=HEALTHY`, solicitud `APPROVED`; reintento denegado |
| C | Base SQLite en modo `0400`; intento de commit | `StoreError: no se pudo confirmar la aprobacion`; solicitud `PENDING_USER_APPROVAL`; 0 grants |
| D | Migración con fallo inyectado en `_import_events` tras importar solicitudes/grants | `MigrationError`; 0 solicitudes, 0 grants, `migration=None`, cadena válida |
| E | Solicitud manipulada directamente en SQLite; `verify_store` | `valid=True`, `health=HEALTHY`, `requests=1`; `get_request` deniega por integridad |
| E2 | `health=AUDIT_INCOMPLETE`; `verify_store` | `valid=True`, `health=AUDIT_INCOMPLETE` |
| F | Cadena legacy sin evento `approval`; migración | Grant importado; eventos `request`, `challenge`, `storage_migration`; `status=completed` |
| G | `fsync` de directorio simulado con `OSError`; `write_file` | `write_accepted=True`; archivo existe; error silenciado |
| H | `intent` + escritura, sin `result`; nuevo store | Eventos `['intent']`; `valid=True`, `health=HEALTHY` |
| I | Store sin grant + archivo legacy colocado después del arranque; `_load_bundle` | Devuelve approval legacy; `audit_events=0` |
| J | Proceso hijo escribe archivo y termina con `os._exit(9)` antes de `result` | `exit=9`, archivo existe, eventos `['intent']`, `valid=True`, `health=HEALTHY` |
| K | Proceso hijo entra en transacción, inserta y termina con `os._exit(9)` antes de `COMMIT` | `exit=9`; 0 eventos; cadena válida (rollback SQLite) |
| L | Grant manipulado directamente en SQLite (`authorized_paths`) | `verify_store` `valid=True`/`HEALTHY`; `verify_approval` devuelve `False` por firma |
| M | Borrado del último evento de auditoría | Antes `valid=True` con 2 eventos; después `valid=True` con 1 evento, razón `cadena integra` |
| N | `Authority` completa con `intent` + archivo escrito, sin `result`, reinicio | `state=HEALTHY`, `audit_state=HEALTHY`, `valid=True`, eventos `['intent']` |

### 8.4 Pruebas adversas omitidas

No se ejecutaron, por requerir entorno, privilegios o instrumentación fuera del alcance:

- corte de energía real o `fsync` fallido en hardware/filesystem objetivo;
- IdP OIDC real, callback Authorization Code + PKCE, JWKS remoto y reloj real;
- dos UIDs Linux distintos con permisos reales y socket multi-UID;
- mounts anidados, bind mounts, hardlinks, ACL y carreras de árbol;
- systemd, reinicio del servicio instalado y instalador en VM;
- migraciones concurrentes con dos procesos;
- aprobación concurrente a través de dos servicios completos (la prueba A es a nivel de store, no de RPC);
- corrupción física del disco, disco lleno y recuperación desde backup.

Estas omisiones son evidencia faltante, no resultados positivos.

---

## 9. Hallazgos priorizados

### Resumen

| Severidad | Cantidad | IDs |
|---|---:|---|
| P0 | 0 | — |
| P1 | 5 | AUD-01, AUD-02, AUD-03, AUD-04, AUD-05 |
| P2 | 5 | AUD-06, AUD-07, AUD-08, AUD-09, AUD-10 |
| P3 | 7 | AUD-11, AUD-12, AUD-13, AUD-14, AUD-15, AUD-16, AUD-17 |

**No se demostró ningún P0.** No hay un camino normal que persista `APPROVED` sin grant, emita un grant sin evento en el flujo de aprobación, consuma un desafío sin aprobación o permita dos grants. Los P1 son defectos de semántica de desafío, recuperación, durabilidad y verificación de evidencia.

---

### AUD-01 — P1 — Desafío reutilizable tras fallo de autenticación

- **Archivos/líneas:** `authority_service.py:856-948` (especialmente `910-917`), `authority_store.py:642-649`, `tests/test_authority.py:168-196`, SPEC `SPEC-ARCH-001-HARDENING.md:50`.
- **Evidencia:** la suite incluye una prueba que, tras fallar `_approval_event`, verifica `challenge_used=False` y luego aprueba con **el mismo challenge** (`test_authority.py:191-196`). La prueba pasa en la suite de 129.
- **Escenario:** un intento de aprobación con identidad/state/sesión o firma inválida no consume el desafío. El mismo token puede reintentarse hasta que expire; un atacante con el token puede repetir intentos de autenticación, y un operador puede reutilizar una sesión de revisión fallida.
- **Impacto:** se pierde la semántica de un solo uso ante fallo; contradice RF-001 (“no volverlo reutilizable”) y SA-001/SA-003. No permite aprobar sin autenticación, por eso no se clasifica P0.
- **Requisito:** RF-001, SA-001, SA-003.
- **Prueba que lo demuestra:** `test_failed_authentication_does_not_consume_challenge_or_approve` (comportamiento esperado actual).
- **Recomendación:** en cualquier fallo de autenticación/firma/state/sesión, invalidar atómicamente el desafío (`AUTH_FAILED`/consumido) y exigir nueva solicitud/desafío, o rotar el token; agregar una prueba que espere denegación al reutilizar el mismo challenge. No volver a usar el test actual como contrato.

### AUD-02 — P1 — Caída tras la escritura deja la autoridad `HEALTHY` sin resultado

- **Archivos/líneas:** `implementation_gate.py:244-292` (`intent` en 246, escritura en 265-273, `result` en 291-292), `implementation_gate.py:171-182`, `authority_service.py:405-419`, `authority_store.py:14-18`.
- **Evidencia:** prueba J: proceso hijo escribe `x.py`, termina con `os._exit(9)` antes de `result`; al reabrir, eventos `['intent']`, `valid=True`, `health=HEALTHY`. Prueba N: la `Authority` completa arranca `state=HEALTHY`, `audit_state=HEALTHY`, `valid=True` con sólo `intent`.
- **Escenario:** el proceso muere entre la escritura física y el evento de resultado (caída, OOM, kill, corrupción de proceso). El archivo cambió, pero no hay marca de operación en curso ni de resultado; el arranque no escanea intenciones huérfanas.
- **Impacto:** una modificación autorizada queda fuera de la auditoría de resultado; la autoridad concede nuevas operaciones como si todo estuviera sano. Viola RF-006/SA-002/SA-009 y la afirmación de `INDETERMINATE` de `authority_store.py:14-18`.
- **Requisito:** RF-006, RF-005, SA-002, SA-006, SA-009.
- **Prueba que lo demuestra:** J y N; no hay prueba en el repositorio para este caso.
- **Recomendación:** persistir un estado `COMMITTING`/intención durable antes de la escritura, con operation id, ruta, digest previsto y timestamp; al arrancar, buscar intenciones sin `result` y marcar `INDETERMINATE`/`RECONCILIATION_REQUIRED` sin conceder operaciones; devolver `INDETERMINATE` en la API. No auto-reparar ni borrar el marker.

### AUD-03 — P1 — `_fsync_dir` ignora errores y la escritura se reporta exitosa

- **Archivos/líneas:** `safe_fs.py:104-109`, `safe_fs.py:165`, `safe_fs.py:200`, `safe_fs.py:215`, `implementation_gate.py:265-273`.
- **Evidencia:** prueba G: `os.fsync` de un descriptor de directorio lanza `OSError`; `write_file` devuelve digest y el archivo existe. El `except OSError: pass` silencia el fallo.
- **Escenario:** filesystem que no soporta `fsync` de directorio, error de I/O, disco lleno o fallo transitorio; la API reporta éxito y el gate registra `executed=True`.
- **Impacto:** una creación/rename/delete puede no ser durable ante crash aunque se reporte éxito; contradice RF-008 (“`_fsync_dir` no ignora errores”) y SA-009.
- **Requisito:** RF-008, SA-009.
- **Prueba que lo demuestra:** G; no hay prueba en el repositorio.
- **Recomendación:** propagar el error de `fsync` de directorio; devolver `EXECUTED_NOT_DURABLE`/`INDETERMINATE`, marcar auditoría incompleta y bloquear; probar con inyección de fallo en cada una de las cuatro operaciones. El defecto es preexistente, pero la Etapa B no lo cierra.

### AUD-04 — P1 — Migración importa grants sin evento `approval`

- **Archivos/líneas:** `authority_store.py:820-846`, `authority_store.py:899-922`, `authority_store.py:924-966`, `authority_store.py:722-749`.
- **Evidencia:** prueba F: cadena legacy con `request` y `challenge`, sin `approval`; `migrate_legacy` devuelve `completed`; `get_grant` devuelve el grant; eventos `request`, `challenge`, `storage_migration`.
- **Escenario:** evidencia histórica incompleta o manipulada (cadena sin evento de aprobación) se importa como grant válido; el grant tiene firma válida, pero no el evento de commit que lo justifica.
- **Impacto:** se rompe la invariante “grant + evento de aprobación” para datos migrados; `verify_store` sigue diciendo `valid=True`. No crea una firma nueva, pero debilita la trazabilidad y la recuperación.
- **Requisito:** RF-001, RF-006, SA-002.
- **Prueba que lo demuestra:** F; no hay prueba en el repositorio.
- **Recomendación:** correlacionar `authorization_event_id` con un evento `approval` de la cadena importada/DB y con `fingerprint`/`spec_id`/`version`; rechazar la migración o marcarla `MIGRATION_INCOMPLETE`/bloqueada si falta. Añadir prueba de grant sin evento y de evento con otro `authorization_event_id`.

### AUD-05 — P1 — `--verify-storage` declara `valid=True` con datos manipulados o salud bloqueada

- **Archivos/líneas:** `authority_store.py:656-677`, `authority_service.py:1502-1545`, `authority_store.py:369-396`.
- **Evidencia:** prueba E: solicitud manipulada en SQLite; `verify_store` devuelve `valid=True`, `health=HEALTHY`, `requests=1`; `get_request` sí detecta la manipulación. Prueba E2: `health=AUDIT_INCOMPLETE`; `verify_store` sigue `valid=True`. Prueba L: grant manipulado; `verify_store valid=True`; `verify_approval=False` por firma.
- **Escenario:** un operador o auditor ejecuta `--verify-storage` y acepta el store como íntegro aunque una solicitud/grant esté manipulado o la salud esté bloqueada. `valid` se calcula sólo con `verify_chain()`; no verifica digests de solicitudes, firmas de grants, estados ni migración.
- **Impacto:** falsa assurance de auditoría; no autoriza por sí mismo porque `get_request`/`verify_approval` rechazan al usar, pero puede impedir la recuperación y producir un informe engañoso.
- **Requisito:** RF-005, RF-006, SA-006, SA-014.
- **Prueba que lo demuestra:** E, E2, L; no hay prueba en el repositorio.
- **Recomendación:** separar `chain_valid`, `store_valid` y `health`; verificar cada solicitud (`integrity`), cada grant (firma con `TrustedKeyStore`, evento asociado), `meta`, migración y estados; que `ok` sea verdadero sólo si todo es válido y `health=HEALTHY`; añadir pruebas de manipulación de solicitud/grant y salud bloqueada.

### AUD-06 — P2 — Fallback legacy sirve grants fuera del store canónico

- **Archivos/líneas:** `authority_service.py:533-553`.
- **Evidencia:** prueba I: store vacío, archivo `approvals/SPEC-001-1.0.0.json` colocado después del arranque; `_load_bundle` devuelve el approval legacy; `audit_events=0`.
- **Escenario:** un archivo legacy válidamente firmado se coloca en `state_dir/approvals` después del arranque; se usa sin migración, sin evento `approval` y sin pasar por el store. La firma y la revocación siguen aplicando, pero el estado canónico y la auditoría no.
- **Impacto:** bypass del almacén canónico para grants históricos; un grant antiguo puede reaparecer si el archivo existe y el store no tiene grant. No permite falsificar firma; P2.
- **Requisito:** RF-006, SA-002.
- **Prueba:** I; no hay prueba en el repositorio.
- **Recomendación:** limitar el fallback a un modo legacy explícito y previo a la migración; si existe registro de migración, denegar toda lectura legacy; migrar y auditar antes de autorizar; probar store sin grant + archivo legacy.

### AUD-07 — P2 — Truncación de la cola de auditoría no detectable

- **Archivos/líneas:** `authority_store.py:369-396`.
- **Evidencia:** prueba M: 2 eventos, `valid=True`; borrar el último evento; `valid=True`, 1 evento, razón `cadena integra`.
- **Escenario:** eliminación del sufijo de eventos o restauración de una copia antigua; la cadena restante es internamente consistente.
- **Impacto:** no se detecta pérdida de eventos; la auditoría no demuestra que la cadena esté completa respecto de un estado externo. P2.
- **Requisito:** RF-005, SA-006.
- **Prueba:** M; no hay prueba en el repositorio.
- **Recomendación:** anclar el tip (`seq`/hash) en un almacén de confianza separado (config firmada, backup inmutable, checkpoint externo) y verificar el número de eventos; no confiar sólo en la cadena local.

### AUD-08 — P2 — Idempotencia de migración no atómica entre procesos

- **Archivos/líneas:** `authority_store.py:699-707` (lectura de registro y digests fuera de transacción), `722-746` (escritura de meta/evento).
- **Evidencia:** análisis estático; no se ejecutó prueba con dos migraciones concurrentes.
- **Escenario:** dos `--migrate` o dos arranques concurrentes leen “sin migración”; ambos importan y ambos escriben `storage_migration`; el segundo puede sobrescribir `meta` y dejar dos eventos.
- **Impacto:** ruido de auditoría, informe de migración no determinista; no corrupción de grants si las filas coinciden. P2.
- **Requisito:** RF-004, RF-006.
- **Prueba:** no ejecutada; evidencia faltante.
- **Recomendación:** recheck de `meta` y de la cadena dentro de `BEGIN IMMEDIATE`, o lock de archivo dedicado; usar un identificador de migración único; añadir prueba con dos procesos.

### AUD-09 — P2 — Replay durable sólo se aplica en el commit; OIDC/callback ausente

- **Archivos/líneas:** `approval_service.py:203-266` (sets en memoria `_consumed_nonces`/`_consumed_token_hashes`), `authority_service.py:918-942` (replay se inserta en `commit_approval`), `authority_service.py:950-978` (producción deniega).
- **Evidencia:** la tabla `replay` tiene PK y se inserta en el commit; la autenticación OIDC no consulta esa tabla. La prueba `test_replay_identifier_is_durable_and_unique` (`test_store.py:175-200`) sólo prueba el store, no el proveedor ni el reinicio. Producción sigue bloqueada.
- **Escenario:** replay de nonce/token tras reinicio; sin callback/PKCE no hay forma de demostrar la secuencia completa. La memoria del proveedor se pierde al reiniciar.
- **Impacto:** RF-002/SA-003 sólo parcialmente demostrados; no se puede declarar replay durable end-to-end. P2 (conocido como bloqueo de producción).
- **Requisito:** RF-001, RF-002, SA-003.
- **Prueba:** store replay; falta prueba de proveedor/reinicio y callback real.
- **Recomendación:** consultar/insertar replay durable antes de aceptar autenticación, persistir hash de token/nonce, y completar el callback Authorization Code + PKCE con sesión server-side; probar dos reinicios y replay.

### AUD-10 — P2 — Cobertura de pruebas insuficiente para SA-014

- **Archivos/líneas:** `tests/test_store.py:144-173` (hilos, no procesos), `tests/test_gate.py:107-115` (fallo de intención, no de resultado), suite completa.
- **Evidencia:** 129 tests OK; no hay pruebas de caída después de escribir, `fsync` de directorio, reinicio del servicio completo, migración interrumpida, multi-UID, mounts/hardlinks ni IdP real.
- **Impacto:** las garantías de recuperación/durabilidad no están cubiertas por la suite; los resultados en verde no equivalen a SA-014. P2.
- **Requisito:** SA-014.
- **Prueba:** suite; faltantes listadas en §8.4.
- **Recomendación:** agregar fault injection en cada etapa, pruebas multiproceso y de reinicio, inyección de errores SQLite/fsync, multi-UID/mounts y un IdP de prueba realista.

### AUD-11 — P3 — Creación del archivo SQLite sin `fsync` del directorio

- **Archivos/líneas:** `authority_store.py:187-212`.
- **Evidencia:** análisis estático; no hay `fsync` del directorio padre tras `os.open`/creación.
- **Escenario:** caída justo después de crear la base; la entrada de directorio puede no ser durable aunque `synchronous=FULL` proteja el contenido/WAL.
- **Impacto:** la base podría no existir tras crash; recuperación operativa. P3.
- **Requisito:** RF-005/RF-006 (durabilidad).
- **Recomendación:** `fsync` del directorio padre tras crear el archivo y documentar el límite; probar con filesystem real.

### AUD-12 — P3 — `_restrict_sidecars` sigue symlinks

- **Archivos/líneas:** `authority_store.py:290-297`.
- **Evidencia:** `os.chmod(candidate, 0o600)` sin `lstat`/`O_NOFOLLOW`.
- **Escenario:** un `-wal`/`-shm` symlink en el directorio del store; `chmod` puede actuar sobre el destino. El directorio `0700` reduce la exposición, pero el control no es simétrico con el archivo principal.
- **Impacto:** cambio de permisos fuera del store en un escenario de mismo UID/root. P3.
- **Requisito:** RF-005/SA-006 (integridad de almacenamiento).
- **Recomendación:** `lstat`, rechazar symlink/no-regular y abrir con `O_NOFOLLOW`; probar sidecar symlink.

### AUD-13 — P3 — Esquema sin `CHECK`/FK y grant sin digest independiente

- **Archivos/líneas:** `authority_store.py:253-267`, `authority_store.py:558-573`.
- **Evidencia:** tablas `STRICT` con PKs, pero sin `CHECK` de estados, expiraciones o `CHECK` de `health`; `get_grant` sólo compara `authorization_event_id`, no un digest del documento/contexto.
- **Escenario:** edición directa de un grant manteniendo el event id; la firma Ed25519 lo detecta en `verify_approval` (prueba L), pero `get_grant` por sí solo no.
- **Impacto:** integridad depende de la firma en la capa superior; no hay defensa en profundidad en el esquema. P3.
- **Requisito:** RF-006/SA-006.
- **Recomendación:** agregar `CHECK` de estados/formatos, un `integrity`/digest por grant y verificar contexto; mantener la firma como ancla.

### AUD-14 — P3 — Comentario obsoleto y comprobación duplicada en `approve`

- **Archivos/líneas:** `authority_service.py:873-880`.
- **Evidencia:** el comentario dice “El desafio se consume antes de firmar”, pero la firma ocurre en `910-917` y el consumo en `commit_approval` (`authority_store.py:642`); además `challenge_used` se comprueba dos veces (873-876).
- **Impacto:** confusión de mantenimiento y riesgo de que futuras modificaciones asuman una semántica que no existe; relacionado con AUD-01.
- **Requisito:** RF-001.
- **Recomendación:** corregir el comentario, eliminar la comprobación duplicada y documentar la semántica real (o cambiarla según AUD-01).

### AUD-15 — P3 — Documentación sobreestima `INDETERMINATE`

- **Archivos/líneas:** `README.md:200-203`, `authority_store.py:14-18`; contraste con `docs/architecture/IMPLEMENTATION-ARCH-001.md:83`.
- **Evidencia:** README/store dicen que el gate marca la operación como indeterminada y bloquea; el código sólo tiene `AUDIT_INCOMPLETE` cuando el `result` falla y no tiene estado durable para caída. El registro de implementación sí reconoce SA-009 “No cubierto”.
- **Impacto:** un auditor o lector puede asumir una garantía que no existe. P3 documental, pero relevante para la auditoría.
- **Recomendación:** alinear README/docstring con el comportamiento real; no declarar `INDETERMINATE` hasta implementarlo y probarlo.

### AUD-16 — P3 — `git diff --check` no limpio en el commit

- **Archivos/líneas:** documentos Markdown añadidos (frontmatter), 78 líneas.
- **Evidencia:** `git diff --check 5f07059 094f93d` reporta trailing whitespace; no hay avisos en scripts/tests.
- **Impacto:** higiene de diff; puede ser intencional (saltos Markdown con dos espacios), pero no cumple el chequeo. P3.
- **Recomendación:** normalizar o justificar los saltos; ejecutar `git diff --check` antes de commits de documentación.

### AUD-17 — P3 — Manejo de excepciones no uniforme en rutas de error

- **Archivos/líneas:** `authority_service.py:923-947` (captura `StoreConflict`/`StoreError`, no `AuditError`), `authority_service.py:1387-1407` (el servidor captura `Denied`, `OSError`, `ValueError`), `authority_store.py:676` (`json.loads` de `meta` sin captura).
- **Evidencia:** análisis estático; no se provocó una carrera de salud durante el commit.
- **Escenario:** `_append_event` lanza `AuditError` dentro de `commit_approval` por una carrera de salud o evento demasiado grande; el servidor no lo convierte en respuesta `Denied` y puede cerrar la conexión. `verify_store` con `meta` corrupto puede lanzar `ValueError` fuera del `except` del CLI.
- **Impacto:** fallo cerrado pero con respuesta indeterminada/traceback; operación de recuperación más difícil. P3.
- **Recomendación:** capturar `AuditError`/`StoreError` en `approve` y en el servidor, convertirlos en denegación explícita y registrar el estado; capturar `ValueError` de `meta` en `verify_store`.

---

## 10. Matriz de requisitos y evidencia

Estados: **Cumple**, **Parcial**, **No cumple**, **No verificable**.

| Requisito / criterio | Estado | Evidencia | Comentario |
|---|---|---|---|
| RF-001 commit transaccional | **Parcial** | `authority_store.py:575-654`; pruebas `108-142`; A/B2 | Normal atómico; fallo de auth deja challenge reutilizable (AUD-01); no `INDETERMINATE`; sin OIDC callback. |
| RF-002 consumo/replay durable | **Parcial** | `authority_store.py:614-621`; `tests/test_store.py:175-200`; `approval_service.py:203-266` | Replay en commit con PK; proveedor en memoria; sin callback/PKCE. |
| RF-003 revisión y confirmación humana | **No cumple** | `authority_service.py:798-855`, `898-908`; `test_authority.py:319-325` | Páginas y offsets server-side, pero no UI/sesión humana; `review_complete` sigue siendo un booleano del cliente. |
| RF-004 separación SPEC/PLAN | **No cumple** | No hay cambios; SPEC existente | Fuera de alcance de esta etapa. |
| RF-005 auditoría fail-stop/reinicio | **Parcial** | `authority_store.py:466-499`; `authority_service.py:405-419`; J/N | Salud y reconciliación; no escaneo de intents huérfanos; truncación no detectada (AUD-07). |
| RF-006 orden de transacciones | **Parcial** | `authority_store.py:575-654`; `implementation_gate.py:244-292`; J | Aprobación atómica; filesystem post-side-effect no bloquea tras crash; migración sin evento (AUD-04). |
| RF-007 workspace/mounts/hardlinks | **No cumple** | `safe_fs.py`; no hay mounts/hardlinks | Sólo symlink/O_NOFOLLOW; faltan mounts, bind, hardlinks, ACL y carreras. |
| RF-008 durabilidad de operaciones | **No cumple** | `safe_fs.py:104-109`, `165`, `200`, `215`; G | `_fsync_dir` ignora errores; sin estados `NOT_EXECUTED`/`EXECUTED_NOT_DURABLE`/`DURABILITY_CONFIRMED`/`INDETERMINATE`. |
| RF-009 instalador idempotente | **No cumple** | `install_authority.sh:182` | Sólo `store_path`; no modos `INSTALL/VERIFY/UPGRADE/RECONFIGURE`. |
| RF-010 Skill claims | **No cumple** | Sin cambios | Fuera de alcance. |
| RF-011 APIs uniformes | **No verificable** | Sin cambios de adaptadores | Fuera de alcance. |
| SA-001 callback/identidad | **Parcial** | `authority_service.py:950-978`; preflight | Producción deniega (`SETUP_INCOMPLETE`); falta callback/PKCE; challenge reutilizable (AUD-01). |
| SA-002 fault injection/reinicio | **Parcial** | D, K; J | Rollback SQLite/migración; caída post-escritura no bloquea (AUD-02). |
| SA-003 concurrencia/replay | **Parcial** | A, B, B2; `test_store.py:144-200` | Un grant entre 4 procesos y replay tras reinicio; proveedor/replay end-to-end no probado. |
| SA-004 SPEC/scope | **Parcial** | `authority_service.py:881-908`; `test_modified_spec...` | Relectura/hash/scope; sin UI humana. |
| SA-005 confirmación humana | **No cumple** | `test_authority.py:319-325`; `approve` | No hay UI/sesión; el cliente puede declarar `review_complete`. |
| SA-006 salud/reconciliación | **Parcial** | `authority_store.py:466-499`; `test_incomplete_audit...` | Reconciliación y bloqueo; no cubre truncación, intents huérfanos ni fallos de fsync. |
| SA-007 legacy SPEC/PLAN | **No cumple** | Sin cambios | Fuera de alcance. |
| SA-008 mounts/ACL | **No cumple** | `safe_fs.py` | Sin mounts/hardlinks/ACL. |
| SA-009 fsync/INDETERMINATE | **No cumple** | G, J, N | `fsync` silenciado; sin estado durable. |
| SA-010 instalador | **No cumple** | `install_authority.sh` | Sin modos/rollback. |
| SA-011 Skill | **No cumple** | Sin cambios | Fuera de alcance. |
| SA-012 adaptadores | **No verificable** | Sin cambios | Fuera de alcance. |
| SA-013 estados oficiales | **Cumple** | SPEC/validate; store separa auth/challenge/audit | No se modificaron los siete estados documentales. |
| SA-014 pruebas reales | **Parcial** | 129 OK; A-N | Sin IdP real, multi-UID, mounts, systemd, corte de energía; pruebas adversas limitadas. |

---

## 11. Limitaciones del expediente

- Las pruebas adversas se ejecutaron con UID 1000 y directorios temporales; no demuestran aislamiento entre UID ni mounts reales.
- No se provocó un corte de energía ni un fallo físico de disco; `os._exit(9)` y errores inyectados aproximan la interrupción, no la durabilidad del hardware.
- No se ejecutó un IdP real ni el callback Authorization Code + PKCE; producción sigue bloqueada por diseño.
- No se probaron dos servicios completos aprobando en paralelo; la concurrencia se probó a nivel de store y la aprobación completa en un solo servicio con reinicio.
- No se probó el instalador en VM/container ni systemd; no se probaron mounts/hardlinks/ACL.
- El expediente es DRAFT y no sustituye una revisión independiente de seguridad ni una prueba de penetración.
- La suite de 129 tests pasa, pero varias garantías P1 no tienen prueba en el repositorio; los resultados adversos se obtuvieron fuera de la suite y no se añadieron tests (prohibido por la misión).

---

## 12. Recomendación final

**Mantener bloqueada la producción y no avanzar a la implementación OIDC en esta etapa.**

La Etapa B logra lo que declara para el camino nominal: SQLite con WAL/FULL, transacción única de aprobación, un grant entre procesos concurrentes, replay durable en el commit, migración idempotente con rollback y preservación de originales. También es correcto el fail-closed ante corrupción, permisos y errores de escritura SQLite.

Pero la recuperación post-escritura y la semántica del desafío no están a la altura de RF-001/RF-006/SA-009:

1. **AUD-01** contradice RF-001 y está fijado por una prueba que declara correcto reutilizar el challenge tras fallo de auth.
2. **AUD-02** deja la autoridad `HEALTHY` tras una caída entre la escritura y el resultado.
3. **AUD-03** silencia errores de `fsync` de directorio.
4. **AUD-04** importa grants sin evento `approval`.
5. **AUD-05** hace que `--verify-storage` diga `valid=True` con datos manipulados o salud bloqueada.

Recomendación concreta:

- No declarar “Etapa B terminada” ni “producción ready”.
- Corregir AUD-01…AUD-05 antes de cualquier diseño OIDC que dependa de la semántica de challenge/commit; definir y probar el estado `INDETERMINATE` y el journal de intención.
- Mantener OIDC y producción bloqueados. El diseño de UX/callback puede discutirse como decisión documental no normativa, pero **no** debe implementarse hasta que los P1 estén resueltos y exista un contrato de recuperación probado.
- Añadir las pruebas de fault injection, proceso/reinicio, fsync, multi-UID y mounts que SA-014 exige; no sustituir ambiente real por mocks.

**Este expediente no es una aprobación de seguridad.**

---

## Anexo A — Diff completo de archivos críticos

Los siguientes bloques se generaron con `git show --format= --no-color 094f93d -- <archivo>` y son el diff completo del commit para cada archivo. El path mostrado es relativo a la raíz del repositorio (`game-development/...`).


### A.1 `scripts/authority_store.py` (nuevo)

```diff
diff --git a/game-development/scripts/authority_store.py b/game-development/scripts/authority_store.py
new file mode 100644
index 0000000..ee8b20c
--- /dev/null
+++ b/game-development/scripts/authority_store.py
@@ -0,0 +1,970 @@
+#!/usr/bin/env python3
+"""Almacen durable de la autoridad, con SQLite como backend inicial.
+
+Contrato
+--------
+``AuthorityStore`` desacopla a la autoridad de SQLite. ``SQLiteAuthorityStore``
+es la implementacion aprobada: usa WAL y ``synchronous=FULL``, y confirma en
+una sola transaccion el cambio de estado de la solicitud, la emision del grant
+y el evento de auditoria correspondiente. Ninguna capa superior importa
+``sqlite3``.
+
+Limite explicito
+----------------
+SQLite hace atomico el estado de la autoridad y su auditoria, pero no puede
+hacer atomica una escritura del sistema de archivos. El gate registra intencion
+y resultado en transacciones separadas; si la operacion fisica se ejecuta y su
+resultado no puede registrarse, el resultado es INDETERMINATE y la autoridad
+bloquea nuevas operaciones hasta reconciliar.
+
+Evidencia historica
+-------------------
+La migracion lee los archivos JSON/JSONL anteriores y los deja intactos. El
+resultado queda registrado en ``meta`` y como evento de auditoria, y puede
+verificarse de nuevo sin reimportar nada.
+"""
+
+from __future__ import annotations
+
+import contextlib
+import hashlib
+import json
+import os
+import sqlite3
+import stat
+import threading
+from datetime import datetime, timezone
+from pathlib import Path
+from typing import Iterable, Iterator
+
+import approval_service
+import audit_chain
+from audit_chain import GENESIS, AuditError
+
+SCHEMA_VERSION = 1
+LEGACY_MIGRATION_KEY = "legacy_migration"
+HEALTH_STATES = (
+    "HEALTHY",
+    "AUDIT_INCOMPLETE",
+    "AUDIT_CORRUPT",
+    "AUDIT_UNAVAILABLE",
+    "RECONCILIATION_REQUIRED",
+)
+
+
+class StoreError(RuntimeError):
+    """El almacen no es utilizable o no puede confirmar la operacion."""
+
+
+class StoreConflict(StoreError):
+    """La transicion pretendida choca con el estado ya confirmado."""
+
+
+class StoreNotFound(StoreConflict):
+    """No existe el registro solicitado; no implica corrupcion."""
+
+
+class MigrationError(StoreError):
+    """La migracion no puede verificar o reconciliar la evidencia historica."""
+
+
+def _now_iso() -> str:
+    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
+
+
+def _parse_iso(value) -> datetime | None:
+    if not value:
+        return None
+    try:
+        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
+    except ValueError:
+        return None
+    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)
+
+
+def _canonical(value) -> bytes:
+    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
+
+
+def _digest(value) -> str:
+    return hashlib.sha256(_canonical(value)).hexdigest()
+
+
+def _decode(encoded: str, field: str) -> dict:
+    try:
+        value = json.loads(encoded)
+    except (TypeError, ValueError) as error:
+        raise StoreError(f"{field} ilegible") from error
+    if not isinstance(value, dict):
+        raise StoreError(f"{field} no es un objeto")
+    return value
+
+
+class AuthorityStore:
+    """Contrato de persistencia de estado y auditoria.
+
+    ``audit`` expone la misma superficie que ``audit_chain.AuditChain`` para que
+    el gate pueda registrar intencion/resultado sin conocer el backend.
+    """
+
+    audit = None  # type: ignore[assignment]
+
+    def save_request(self, request: dict, event: dict | None = None) -> None:
+        raise NotImplementedError
+
+    def get_request(self, request_id: str) -> dict:
+        raise NotImplementedError
+
+    def list_requests(self) -> list[dict]:
+        raise NotImplementedError
+
+    def get_grant(self, spec_id: str, version: str) -> tuple[dict, dict]:
+        raise NotImplementedError
+
+    def commit_approval(
+        self,
+        *,
+        request_id: str,
+        challenge_hash: str,
+        record: dict,
+        context: dict,
+        audit_event: dict,
+        replay: Iterable[tuple[str, str, str]] = (),
+    ) -> int:
+        raise NotImplementedError
+
+    def events(self) -> list[dict]:
+        raise NotImplementedError
+
+    def verify_store(self) -> dict:
+        raise NotImplementedError
+
+
+class StoreAudit:
+    """Sink de auditoria sobre el almacen; satisface el uso de ``AuditChain``."""
+
+    def __init__(self, store: "SQLiteAuthorityStore") -> None:
+        self.store = store
+
+    def initialize(self) -> None:
+        self.store.initialize_audit()
+
+    def append(self, event: dict, *, allow_blocked: bool = False) -> dict:
+        return self.store.append_event(event, allow_blocked=allow_blocked)
+
+    def verify(self) -> tuple[bool, str, int]:
+        return self.store.verify_chain()
+
+    def is_blocked(self) -> bool:
+        return self.store.audit_blocked()
+
+    def health_state(self) -> str:
+        return self.store.health_state()
+
+    def block_reason(self) -> str:
+        return self.store.block_reason()
+
+    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
+        self.store.mark_incomplete(reason, detail)
+
+    def clear_incomplete(self, operator: str, note: str) -> dict:
+        return self.store.clear_incomplete(operator, note)
+
+
+class SQLiteAuthorityStore(AuthorityStore):
+    """Implementacion SQLite: WAL, sincronizacion completa y transacciones."""
+
+    def __init__(self, path: Path | str, *, busy_timeout_ms: int = 5000) -> None:
+        self.path = Path(path)
+        self.busy_timeout_ms = int(busy_timeout_ms)
+        self._lock = threading.RLock()
+        self._poisoned = False
+        self._prepare_file()
+        self._initialize_schema()
+        self.audit = StoreAudit(self)
+
+    # -- archivo y conexion ----------------------------------------------
+    def _prepare_file(self) -> None:
+        parent = self.path.parent
+        if not parent.is_absolute() or not self.path.is_absolute():
+            raise StoreError("la ruta del almacen debe ser absoluta")
+        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
+        try:
+            parent_info = os.lstat(parent)
+        except OSError as error:
+            raise StoreError("directorio del almacen inaccesible") from error
+        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
+            raise StoreError("el directorio del almacen no es un directorio real")
+        if parent_info.st_uid not in (0, os.getuid()):
+            raise StoreError("propietario del directorio del almacen no autorizado")
+        if stat.S_IMODE(parent_info.st_mode) & 0o077:
+            raise StoreError("directorio del almacen accesible por grupo u otros")
+        if os.path.lexists(self.path):
+            info = os.lstat(self.path)
+            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
+                raise StoreError("el almacen debe ser un archivo regular sin enlaces")
+            if info.st_uid not in (0, os.getuid()):
+                raise StoreError("propietario del almacen no autorizado")
+            if stat.S_IMODE(info.st_mode) & 0o077:
+                raise StoreError("el almacen es accesible por grupo u otros")
+        else:
+            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
+            os.close(descriptor)
+
+    def _connect(self) -> sqlite3.Connection:
+        try:
+            connection = sqlite3.connect(
+                str(self.path),
+                timeout=self.busy_timeout_ms / 1000.0,
+                isolation_level=None,
+                check_same_thread=False,
+            )
+            connection.row_factory = sqlite3.Row
+            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
+            mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
+            if mode != "wal":
+                connection.close()
+                raise StoreError(f"WAL no disponible (modo {mode})")
+            connection.execute("PRAGMA synchronous=FULL")
+            connection.execute("PRAGMA foreign_keys=ON")
+            connection.execute("PRAGMA trusted_schema=OFF")
+            return connection
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise StoreError(f"almacen no disponible: {type(error).__name__}") from error
+
+    @contextlib.contextmanager
+    def _transaction(self) -> Iterator[sqlite3.Connection]:
+        with self._lock:
+            connection = self._connect()
+            try:
+                connection.execute("BEGIN IMMEDIATE")
+                yield connection
+                connection.execute("COMMIT")
+            except BaseException:
+                try:
+                    connection.execute("ROLLBACK")
+                except sqlite3.Error:
+                    self._poisoned = True
+                raise
+            finally:
+                connection.close()
+
+    def _initialize_schema(self) -> None:
+        statements = (
+            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT",
+            "CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, document TEXT NOT NULL,"
+            " integrity TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT",
+            "CREATE TABLE IF NOT EXISTS grants (spec_id TEXT NOT NULL, version TEXT NOT NULL,"
+            " document TEXT NOT NULL, context TEXT NOT NULL, authorization_event_id TEXT NOT NULL,"
+            " created_at TEXT NOT NULL, PRIMARY KEY (spec_id, version)) STRICT",
+            "CREATE TABLE IF NOT EXISTS audit_events (seq INTEGER PRIMARY KEY, at TEXT NOT NULL,"
+            " prev TEXT NOT NULL, hash TEXT NOT NULL, event TEXT NOT NULL) STRICT",
+            "CREATE TABLE IF NOT EXISTS replay (scope TEXT NOT NULL, identifier TEXT NOT NULL,"
+            " expires_at TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scope, identifier)) STRICT",
+            "CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY CHECK (id = 1),"
+            " state TEXT NOT NULL, reason TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT",
+        )
+        try:
+            with self._transaction() as connection:
+                for statement in statements:
+                    connection.execute(statement)
+                row = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
+                if row is None:
+                    connection.execute(
+                        "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
+                    )
+                elif int(row["value"]) != SCHEMA_VERSION:
+                    raise StoreError("version de esquema no soportada")
+                health = connection.execute("SELECT state FROM health WHERE id=1").fetchone()
+                if health is None:
+                    connection.execute(
+                        "INSERT INTO health(id, state, reason, updated_at) VALUES(1, 'HEALTHY', '', ?)",
+                        (_now_iso(),),
+                    )
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise StoreError("no se pudo inicializar el almacen") from error
+        self._restrict_sidecars()
+
+    def _restrict_sidecars(self) -> None:
+        for suffix in ("-wal", "-shm"):
+            candidate = self.path.with_name(self.path.name + suffix)
+            try:
+                if os.path.lexists(candidate):
+                    os.chmod(candidate, 0o600)
+            except OSError:
+                raise StoreError("no se pudieron restringir los archivos auxiliares del almacen")
+
+    def journal_mode(self) -> str:
+        connection = self._connect()
+        try:
+            return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
+        finally:
+            connection.close()
+
+    def synchronous_mode(self) -> str:
+        connection = self._connect()
+        try:
+            value = str(connection.execute("PRAGMA synchronous").fetchone()[0]).lower()
+        finally:
+            connection.close()
+        return {"0": "off", "1": "normal", "2": "full", "3": "extra"}.get(value, value)
+
+    # -- auditoria --------------------------------------------------------
+    def initialize_audit(self) -> None:
+        with self._transaction() as connection:
+            health = connection.execute("SELECT state FROM health WHERE id=1").fetchone()
+            if health is None:
+                connection.execute(
+                    "INSERT INTO health(id, state, reason, updated_at) VALUES(1, 'HEALTHY', '', ?)",
+                    (_now_iso(),),
+                )
+
+    def _health_row(self, connection: sqlite3.Connection) -> sqlite3.Row:
+        row = connection.execute("SELECT state, reason FROM health WHERE id=1").fetchone()
+        if row is None:
+            raise StoreError("estado de salud ausente")
+        return row
+
+    def _set_health(self, connection: sqlite3.Connection, state: str, reason: str = "") -> None:
+        if state not in HEALTH_STATES:
+            raise StoreError("estado de salud desconocido")
+        connection.execute(
+            "UPDATE health SET state=?, reason=?, updated_at=? WHERE id=1",
+            (state, reason, _now_iso()),
+        )
+
+    def _append_event(self, connection: sqlite3.Connection, event: dict, *, allow_blocked: bool) -> dict:
+        if not isinstance(event, dict):
+            raise AuditError("evento de auditoria invalido")
+        health = self._health_row(connection)
+        if health["state"] != "HEALTHY" and not allow_blocked:
+            raise AuditError(f"auditoria bloqueada ({health['state']}) hasta reconciliacion")
+        last = connection.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
+        seq = int(last["seq"]) + 1 if last is not None else 1
+        previous = str(last["hash"]) if last is not None else GENESIS
+        at = _now_iso()
+        record = {"seq": seq, "at": at, "prev": previous, "event": event}
+        digest = hashlib.sha256(_canonical(record)).hexdigest()
+        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+        if len(encoded.encode("utf-8")) > audit_chain.MAX_EVENT_BYTES:
+            raise AuditError("evento de auditoria demasiado grande")
+        connection.execute(
+            "INSERT INTO audit_events(seq, at, prev, hash, event) VALUES(?,?,?,?,?)",
+            (seq, at, previous, digest, encoded),
+        )
+        return {**record, "hash": digest}
+
+    def append_event(self, event: dict, *, allow_blocked: bool = False) -> dict:
+        if self._poisoned:
+            raise AuditError("almacen marcado no disponible")
+        try:
+            with self._transaction() as connection:
+                return self._append_event(connection, event, allow_blocked=allow_blocked)
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise AuditError("no se pudo persistir el evento de auditoria") from error
+
+    def verify_chain(self) -> tuple[bool, str, int]:
+        try:
+            connection = self._connect()
+        except StoreError as error:
+            return False, str(error), 0
+        try:
+            rows = connection.execute("SELECT seq, at, prev, hash, event FROM audit_events ORDER BY seq").fetchall()
+        except sqlite3.Error as error:
+            return False, f"auditoria ilegible: {type(error).__name__}", 0
+        finally:
+            connection.close()
+        expected_previous = GENESIS
+        count = 0
+        for row in rows:
+            count += 1
+            if int(row["seq"]) != count:
+                return False, f"secuencia rota en el evento {count}", count - 1
+            if str(row["prev"]) != expected_previous:
+                return False, f"cadena rota en el evento {count}", count - 1
+            try:
+                event = json.loads(row["event"])
+            except (TypeError, ValueError):
+                return False, f"evento ilegible en la posicion {count}", count - 1
+            record = {"seq": int(row["seq"]), "at": str(row["at"]), "prev": str(row["prev"]), "event": event}
+            if hashlib.sha256(_canonical(record)).hexdigest() != str(row["hash"]):
+                return False, f"hash alterado en el evento {count}", count - 1
+            expected_previous = str(row["hash"])
+        return True, "cadena integra", count
+
+    def events(self) -> list[dict]:
+        connection = self._connect()
+        try:
+            rows = connection.execute("SELECT seq, at, prev, hash, event FROM audit_events ORDER BY seq").fetchall()
+        finally:
+            connection.close()
+        result = []
+        for row in rows:
+            result.append(
+                {
+                    "seq": int(row["seq"]),
+                    "at": str(row["at"]),
+                    "prev": str(row["prev"]),
+                    "hash": str(row["hash"]),
+                    "event": json.loads(row["event"]),
+                }
+            )
+        return result
+
+    def audit_blocked(self) -> bool:
+        if self._poisoned:
+            return True
+        try:
+            connection = self._connect()
+        except StoreError:
+            return True
+        try:
+            health = self._health_row(connection)
+        except (StoreError, sqlite3.Error):
+            return True
+        finally:
+            connection.close()
+        if health["state"] != "HEALTHY":
+            return True
+        valid, _, _ = self.verify_chain()
+        return not valid
+
+    def health_state(self) -> str:
+        if self._poisoned:
+            return "AUDIT_UNAVAILABLE"
+        try:
+            connection = self._connect()
+        except StoreError:
+            return "AUDIT_UNAVAILABLE"
+        try:
+            health = self._health_row(connection)
+        except (StoreError, sqlite3.Error):
+            return "AUDIT_UNAVAILABLE"
+        finally:
+            connection.close()
+        if health["state"] != "HEALTHY":
+            return str(health["state"])
+        valid, _, _ = self.verify_chain()
+        return "HEALTHY" if valid else "AUDIT_CORRUPT"
+
+    def block_reason(self) -> str:
+        try:
+            connection = self._connect()
+        except StoreError as error:
+            return str(error)
+        try:
+            health = self._health_row(connection)
+            return str(health["reason"] or health["state"] or "AUDIT_UNAVAILABLE")
+        except (StoreError, sqlite3.Error):
+            return "AUDIT_UNAVAILABLE"
+        finally:
+            connection.close()
+
+    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
+        try:
+            with self._transaction() as connection:
+                self._set_health(connection, "AUDIT_INCOMPLETE", str(reason or "AUDIT_INCOMPLETE"))
+                payload = {"at": _now_iso(), "reason": str(reason), "detail": dict(detail or {})}
+                self._append_event(connection, {"stage": "audit_incomplete", **payload}, allow_blocked=True)
+        except (sqlite3.Error, StoreError, AuditError) as error:
+            self._poisoned = True
+            raise AuditError("no se pudo persistir el bloqueo de auditoria") from error
+
+    def clear_incomplete(self, operator: str, note: str) -> dict:
+        valid, reason, _ = self.verify_chain()
+        if not valid:
+            raise AuditError(f"no se puede reconciliar una cadena invalida: {reason}")
+        try:
+            with self._transaction() as connection:
+                health = self._health_row(connection)
+                if health["state"] == "HEALTHY":
+                    raise AuditError("no hay auditoria incompleta")
+                record = self._append_event(
+                    connection,
+                    {
+                        "stage": "reconciled",
+                        "operator": str(operator or ""),
+                        "note": str(note or ""),
+                        "previous_block": str(health["reason"] or health["state"]),
+                    },
+                    allow_blocked=True,
+                )
+                self._set_health(connection, "HEALTHY", "")
+                return record
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise AuditError("no se pudo persistir la reconciliacion") from error
+
+    # -- solicitudes y grants --------------------------------------------
+    def save_request(self, request: dict, event: dict | None = None) -> None:
+        if not isinstance(request, dict) or not str(request.get("request_id") or ""):
+            raise DeniedRequest("solicitud invalida")
+        request_id = str(request["request_id"])
+        document = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+        integrity = _digest(request)
+        status = str(request.get("status") or "PENDING_USER_APPROVAL")
+        try:
+            with self._transaction() as connection:
+                connection.execute(
+                    "INSERT INTO requests(request_id, document, integrity, status, updated_at)"
+                    " VALUES(?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET"
+                    " document=excluded.document, integrity=excluded.integrity,"
+                    " status=excluded.status, updated_at=excluded.updated_at",
+                    (request_id, document, integrity, status, _now_iso()),
+                )
+                if event is not None:
+                    self._append_event(connection, event, allow_blocked=False)
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise StoreError("no se pudo persistir la solicitud") from error
+
+    def get_request(self, request_id: str) -> dict:
+        connection = self._connect()
+        try:
+            row = connection.execute(
+                "SELECT document, integrity FROM requests WHERE request_id=?", (str(request_id),)
+            ).fetchone()
+        finally:
+            connection.close()
+        if row is None:
+            raise StoreNotFound("solicitud desconocida o ilegible")
+        request = _decode(row["document"], "solicitud")
+        if _digest(request) != str(row["integrity"]):
+            raise StoreConflict("la solicitud fue alterada despues de registrarse")
+        return request
+
+    def list_requests(self) -> list[dict]:
+        connection = self._connect()
+        try:
+            rows = connection.execute("SELECT request_id, document, integrity FROM requests ORDER BY request_id").fetchall()
+        finally:
+            connection.close()
+        result = []
+        for row in rows:
+            try:
+                request = _decode(row["document"], "solicitud")
+            except StoreError:
+                result.append({"request_id": row["request_id"], "status": "CORRUPT"})
+                continue
+            if _digest(request) != str(row["integrity"]):
+                result.append({"request_id": row["request_id"], "status": "CORRUPT"})
+                continue
+            result.append(request)
+        return result
+
+    def get_grant(self, spec_id: str, version: str) -> tuple[dict, dict]:
+        connection = self._connect()
+        try:
+            row = connection.execute(
+                "SELECT document, context, authorization_event_id FROM grants WHERE spec_id=? AND version=?",
+                (str(spec_id), str(version)),
+            ).fetchone()
+        finally:
+            connection.close()
+        if row is None:
+            raise StoreNotFound("no hay autorizacion registrada para esa SPEC")
+        approval = _decode(row["document"], "autorizacion")
+        context = _decode(row["context"], "contexto de autorizacion")
+        if str(approval.get("authorization_event_id") or "") != str(row["authorization_event_id"]):
+            raise StoreConflict("autorizacion corrupta")
+        return approval, context
+
+    def commit_approval(
+        self,
+        *,
+        request_id: str,
+        challenge_hash: str,
+        record: dict,
+        context: dict,
+        audit_event: dict,
+        replay: Iterable[tuple[str, str, str]] = (),
+    ) -> int:
+        """Confirma estado, grant, replay y auditoria en una sola transaccion."""
+        document = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+        context_document = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+        event_id = str(record.get("authorization_event_id") or "")
+        if not event_id:
+            raise StoreConflict("autorizacion sin identificador de evento")
+        try:
+            with self._transaction() as connection:
+                row = connection.execute(
+                    "SELECT document, integrity FROM requests WHERE request_id=?", (str(request_id),)
+                ).fetchone()
+                if row is None:
+                    raise StoreConflict("solicitud desconocida")
+                request = _decode(row["document"], "solicitud")
+                if _digest(request) != str(row["integrity"]):
+                    raise StoreConflict("la solicitud fue alterada despues de registrarse")
+                if request.get("challenge_used") or request.get("status") == "APPROVED":
+                    raise StoreConflict("desafio de aprobacion ya utilizado")
+                if str(request.get("challenge_hash") or "") != str(challenge_hash):
+                    raise StoreConflict("desafio de aprobacion invalido")
+                challenge_expiry = _parse_iso(request.get("challenge_expires_at"))
+                if challenge_expiry is None or datetime.now(timezone.utc) > challenge_expiry:
+                    raise StoreConflict("desafio de aprobacion caducado")
+                if str(record.get("fingerprint") or "") != str(request.get("fingerprint") or ""):
+                    raise StoreConflict("la autorizacion no corresponde a la SPEC de la solicitud")
+                if (str(record.get("spec_id") or ""), str(record.get("version") or "")) != (
+                    str(request.get("spec_id") or ""), str(request.get("version") or "")
+                ):
+                    raise StoreConflict("la autorizacion no corresponde a la version solicitada")
+                for scope, identifier, expires_at in replay:
+                    try:
+                        connection.execute(
+                            "INSERT INTO replay(scope, identifier, expires_at, created_at) VALUES(?,?,?,?)",
+                            (str(scope), str(identifier), str(expires_at), _now_iso()),
+                        )
+                    except sqlite3.IntegrityError as error:
+                        raise StoreConflict("identificador de autenticacion ya utilizado") from error
+                existing = connection.execute(
+                    "SELECT authorization_event_id FROM grants WHERE spec_id=? AND version=?",
+                    (str(record.get("spec_id")), str(record.get("version"))),
+                ).fetchone()
+                if existing is not None:
+                    if str(existing["authorization_event_id"]) != event_id:
+                        raise StoreConflict("ya existe una autorizacion distinta para esa SPEC")
+                else:
+                    connection.execute(
+                        "INSERT INTO grants(spec_id, version, document, context, authorization_event_id, created_at)"
+                        " VALUES(?,?,?,?,?,?)",
+                        (
+                            str(record.get("spec_id")),
+                            str(record.get("version")),
+                            document,
+                            context_document,
+                            event_id,
+                            _now_iso(),
+                        ),
+                    )
+                request["challenge_used"] = True
+                request["status"] = "APPROVED"
+                request["authorization_event_id"] = event_id
+                encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+                connection.execute(
+                    "UPDATE requests SET document=?, integrity=?, status=?, updated_at=? WHERE request_id=?",
+                    (encoded, _digest(request), "APPROVED", _now_iso(), str(request_id)),
+                )
+                audit = self._append_event(connection, audit_event, allow_blocked=False)
+                return int(audit["seq"])
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise StoreError("no se pudo confirmar la aprobacion") from error
+
+    def verify_store(self) -> dict:
+        valid, reason, count = self.verify_chain()
+        result = {
+            "valid": valid,
+            "reason": reason,
+            "events": count,
+            "journal_mode": self.journal_mode(),
+            "synchronous": self.synchronous_mode(),
+            "health": self.health_state(),
+            "path": str(self.path),
+        }
+        connection = self._connect()
+        try:
+            migration = connection.execute("SELECT value FROM meta WHERE key=?", (LEGACY_MIGRATION_KEY,)).fetchone()
+            grants = connection.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
+            requests = connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
+        finally:
+            connection.close()
+        result["grants"] = int(grants)
+        result["requests"] = int(requests)
+        result["migration"] = json.loads(migration["value"]) if migration is not None else None
+        return result
+
+    # -- migracion historica ---------------------------------------------
+    def migrate_legacy(
+        self,
+        *,
+        requests_dir: Path | str | None = None,
+        approvals_dir: Path | str | None = None,
+        audit_log: Path | str | None = None,
+        key_store=None,
+    ) -> dict:
+        """Importa evidencia anterior verificada, sin modificar los originales.
+
+        Idempotente: con las mismas fuentes no reimporta. Si encuentra
+        conflictos, corrupcion o una cadena que no puede empalmarse, aborta sin
+        modificar el almacen.
+        """
+        sources = {
+            "requests": Path(requests_dir) if requests_dir is not None else None,
+            "approvals": Path(approvals_dir) if approvals_dir is not None else None,
+            "audit": Path(audit_log) if audit_log is not None else None,
+        }
+        digests = {name: self._source_digest(path) for name, path in sources.items()}
+        if all(value is None for value in digests.values()):
+            return self._empty_migration()
+        existing = self._migration_record()
+        if existing is not None and existing.get("source_digests") == digests and existing.get("status") == "completed":
+            valid, reason, count = self.verify_chain()
+            if not valid:
+                raise MigrationError(f"la migracion registrada no verifica: {reason}")
+            return {**existing, "already_migrated": True, "events": count}
+
+        requests = self._read_legacy_requests(sources["requests"])
+        grants = self._read_legacy_grants(sources["approvals"], key_store)
+        legacy_events = self._read_legacy_events(sources["audit"])
+        report = {
+            "status": "completed",
+            "migrated_at": _now_iso(),
+            "source_digests": digests,
+            "requests": len(requests),
+            "grants": len(grants),
+            "legacy_events": len(legacy_events),
+            "imported_events": 0,
+            "skipped_events": 0,
+        }
+        try:
+            with self._transaction() as connection:
+                for request in requests:
+                    self._import_request(connection, request)
+                for approval, context in grants:
+                    self._import_grant(connection, approval, context)
+                report["imported_events"], report["skipped_events"] = self._import_events(connection, legacy_events)
+                connection.execute(
+                    "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
+                    (LEGACY_MIGRATION_KEY, json.dumps(report, sort_keys=True, ensure_ascii=True)),
+                )
+                self._append_event(
+                    connection,
+                    {
+                        "stage": "storage_migration",
+                        "migrated_at": report["migrated_at"],
+                        "requests": report["requests"],
+                        "grants": report["grants"],
+                        "legacy_events": report["legacy_events"],
+                        "imported_events": report["imported_events"],
+                        "skipped_events": report["skipped_events"],
+                        "source_digests": digests,
+                    },
+                    allow_blocked=True,
+                )
+        except sqlite3.Error as error:
+            self._poisoned = True
+            raise MigrationError("no se pudo completar la migracion") from error
+        return report
+
+    @staticmethod
+    def _source_digest(path: Path | None) -> str | None:
+        if path is None or not os.path.lexists(path):
+            return None
+        if path.is_dir():
+            parts = []
+            for entry in sorted(path.glob("*")):
+                if entry.is_file() and not entry.is_symlink():
+                    parts.append({"name": entry.name, "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()})
+            return _digest(parts)
+        if path.is_file() and not path.is_symlink():
+            return hashlib.sha256(path.read_bytes()).hexdigest()
+        return None
+
+    @staticmethod
+    def _empty_migration() -> dict:
+        return {
+            "status": "nothing_to_migrate",
+            "valid": True,
+            "requests": 0,
+            "grants": 0,
+            "legacy_events": 0,
+            "imported_events": 0,
+            "skipped_events": 0,
+            "source_digests": {"requests": None, "approvals": None, "audit": None},
+        }
+
+    def _migration_record(self) -> dict | None:
+        connection = self._connect()
+        try:
+            row = connection.execute("SELECT value FROM meta WHERE key=?", (LEGACY_MIGRATION_KEY,)).fetchone()
+        finally:
+            connection.close()
+        if row is None:
+            return None
+        try:
+            value = json.loads(row["value"])
+        except ValueError as error:
+            raise MigrationError("registro de migracion ilegible") from error
+        return value if isinstance(value, dict) else None
+
+    @staticmethod
+    def _read_legacy_requests(directory: Path | None) -> list[dict]:
+        if directory is None or not directory.exists():
+            return []
+        if directory.is_symlink() or not directory.is_dir():
+            raise MigrationError("directorio de solicitudes legacy no verificable")
+        result = []
+        for path in sorted(directory.glob("REQ-*.json")):
+            if path.is_symlink() or not path.is_file():
+                raise MigrationError(f"solicitud legacy no verificable: {path.name}")
+            try:
+                payload = json.loads(path.read_text(encoding="utf-8"))
+            except (OSError, ValueError) as error:
+                raise MigrationError(f"solicitud legacy ilegible: {path.name}") from error
+            if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
+                raise MigrationError(f"solicitud legacy corrupta: {path.name}")
+            request = payload["request"]
+            if str(request.get("request_id") or "") != path.stem:
+                raise MigrationError(f"identificador de solicitud no coincide con el archivo: {path.name}")
+            if str(payload.get("integrity") or "") != _digest(request):
+                raise MigrationError(f"integridad de solicitud no verificable: {path.name}")
+            for field in ("spec_id", "project", "version", "fingerprint", "scope"):
+                if not str(request.get(field) or "").strip():
+                    raise MigrationError(f"solicitud legacy incompleta: {path.name}")
+            result.append(request)
+        return result
+
+    @staticmethod
+    def _read_legacy_grants(directory: Path | None, key_store) -> list[tuple[dict, dict]]:
+        if directory is None or not directory.exists():
+            return []
+        if directory.is_symlink() or not directory.is_dir():
+            raise MigrationError("directorio de autorizaciones legacy no verificable")
+        result = []
+        for path in sorted(directory.glob("*.json")):
+            if path.is_symlink() or not path.is_file():
+                raise MigrationError(f"autorizacion legacy no verificable: {path.name}")
+            try:
+                payload = json.loads(path.read_text(encoding="utf-8"))
+            except (OSError, ValueError) as error:
+                raise MigrationError(f"autorizacion legacy ilegible: {path.name}") from error
+            if not isinstance(payload, dict) or not isinstance(payload.get("approval"), dict):
+                raise MigrationError(f"autorizacion legacy corrupta: {path.name}")
+            approval = payload["approval"]
+            context = payload.get("context")
+            if not isinstance(context, dict) or not str(context.get("project") or ""):
+                raise MigrationError(f"contexto de autorizacion corrupto: {path.name}")
+            if key_store is not None and getattr(key_store, "configured", False):
+                if not approval_service.verify_approval(approval, key_store=key_store):
+                    raise MigrationError(f"firma de autorizacion no verificable: {path.name}")
+            if not str(approval.get("authorization_event_id") or ""):
+                raise MigrationError(f"autorizacion sin evento: {path.name}")
+            result.append((approval, {"spec_path": str(context.get("spec_path") or ""), "project": str(context.get("project"))}))
+        return result
+
+    @staticmethod
+    def _read_legacy_events(path: Path | None) -> list[dict]:
+        if path is None or not os.path.lexists(path):
+            return []
+        if path.is_symlink() or not path.is_file():
+            raise MigrationError("audit log legacy no verificable")
+        try:
+            raw_lines = path.read_text(encoding="utf-8").splitlines()
+        except OSError as error:
+            raise MigrationError("audit log legacy ilegible") from error
+        events = []
+        expected_previous = GENESIS
+        for index, raw in enumerate(raw_lines, start=1):
+            if not raw.strip():
+                raise MigrationError(f"linea vacia en audit log legacy ({index})")
+            try:
+                record = json.loads(raw)
+            except ValueError as error:
+                raise MigrationError(f"evento legacy ilegible en linea {index}") from error
+            if not isinstance(record, dict):
+                raise MigrationError(f"evento legacy invalido en linea {index}")
+            stored = str(record.get("hash") or "")
+            unsigned = {key: value for key, value in record.items() if key != "hash"}
+            if int(unsigned.get("seq") or -1) != index:
+                raise MigrationError(f"secuencia legacy rota en linea {index}")
+            if str(unsigned.get("prev") or "") != expected_previous:
+                raise MigrationError(f"cadena legacy rota en linea {index}")
+            if hashlib.sha256(_canonical(unsigned)).hexdigest() != stored:
+                raise MigrationError(f"hash legacy alterado en linea {index}")
+            if not isinstance(unsigned.get("event"), dict):
+                raise MigrationError(f"evento legacy sin cuerpo en linea {index}")
+            expected_previous = stored
+            events.append(unsigned | {"hash": stored})
+        return events
+
+    def _import_request(self, connection: sqlite3.Connection, request: dict) -> None:
+        document = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
+        integrity = _digest(request)
+        status = str(request.get("status") or "PENDING_USER_APPROVAL")
+        row = connection.execute(
+            "SELECT integrity FROM requests WHERE request_id=?", (str(request["request_id"]),)
+        ).fetchone()
+        if row is not None:
+            if str(row["integrity"]) != integrity:
+                raise MigrationError(f"solicitud en conflicto: {request['request_id']}")
+            return
+        connection.execute(
+            "INSERT INTO requests(request_id, document, integrity, status, updated_at) VALUES(?,?,?,?,?)",
+            (str(request["request_id"]), document, integrity, status, _now_iso()),
+        )
+
+    def _import_grant(self, connection: sqlite3.Connection, approval: dict, context: dict) -> None:
+        event_id = str(approval.get("authorization_event_id") or "")
+        row = connection.execute(
+            "SELECT authorization_event_id FROM grants WHERE spec_id=? AND version=?",
+            (str(approval.get("spec_id")), str(approval.get("version"))),
+        ).fetchone()
+        if row is not None:
+            if str(row["authorization_event_id"]) != event_id:
+                raise MigrationError(
+                    f"autorizacion en conflicto: {approval.get('spec_id')} {approval.get('version')}"
+                )
+            return
+        connection.execute(
+            "INSERT INTO grants(spec_id, version, document, context, authorization_event_id, created_at)"
+            " VALUES(?,?,?,?,?,?)",
+            (
+                str(approval.get("spec_id")),
+                str(approval.get("version")),
+                json.dumps(approval, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
+                json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
+                event_id,
+                _now_iso(),
+            ),
+        )
+
+    def _import_events(self, connection: sqlite3.Connection, events: list[dict]) -> tuple[int, int]:
+        if not events:
+            return 0, 0
+        last = connection.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
+        current_count = int(last["seq"]) if last is not None else 0
+        current_hash = str(last["hash"]) if last is not None else GENESIS
+        if current_count > 0:
+            stored = {
+                int(row["seq"]): str(row["hash"])
+                for row in connection.execute("SELECT seq, hash FROM audit_events").fetchall()
+            }
+            for record in events[:current_count]:
+                if stored.get(int(record["seq"])) != str(record.get("hash")):
+                    raise MigrationError("la cadena legacy no coincide con la cadena almacenada")
+            if stored.get(current_count) != current_hash:
+                raise MigrationError("cadena almacenada inconsistente")
+        imported = 0
+        skipped = 0
+        for record in events:
+            seq = int(record["seq"])
+            if seq <= current_count:
+                skipped += 1
+                continue
+            if seq != current_count + 1 or str(record.get("prev")) != current_hash:
+                raise MigrationError("la cadena legacy no puede empalmarse sin reescribir historia")
+            try:
+                event = record["event"]
+            except KeyError as error:
+                raise MigrationError("evento legacy sin cuerpo") from error
+            connection.execute(
+                "INSERT INTO audit_events(seq, at, prev, hash, event) VALUES(?,?,?,?,?)",
+                (
+                    seq,
+                    str(record.get("at")),
+                    current_hash,
+                    str(record["hash"]),
+                    json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
+                ),
+            )
+            current_count = seq
+            current_hash = str(record["hash"])
+            imported += 1
+        return imported, skipped
+
+
+class DeniedRequest(StoreError):
+    """La solicitud no tiene la forma minima exigida por el almacen."""
```

### A.2 `scripts/authority_service.py`

```diff
diff --git a/game-development/scripts/authority_service.py b/game-development/scripts/authority_service.py
index 85800e1..5628c9b 100644
--- a/game-development/scripts/authority_service.py
+++ b/game-development/scripts/authority_service.py
@@ -50,6 +50,7 @@ sys.path.insert(0, str(Path(__file__).resolve().parent))

 import approval_service
 import audit_chain
+import authority_store
 import implementation_gate
 import revocation_registry
 import safe_fs
@@ -150,6 +151,7 @@ class AuthorityConfig:
     trusted_keys_file: Path
     revocations_dir: Path
     audit_log: Path
+    store_path: Path
     signing_key_file: Path | None
     key_id: str
     issuer: str
@@ -226,6 +228,7 @@ class AuthorityConfig:

         socket_path = Path(str(required("socket_path")))
         state_dir = Path(str(required("state_dir")))
+        store_path = Path(str(raw.get("store_path") or (state_dir / "authority.sqlite3")))
         for name, value in (("socket_path", socket_path), ("state_dir", state_dir)):
             if not value.is_absolute():
                 raise ConfigError(f"{name} debe ser una ruta absoluta")
@@ -233,6 +236,7 @@ class AuthorityConfig:
         for name, value in (
             ("socket_path", socket_path),
             ("state_dir", state_dir),
+            ("store_path", store_path),
             ("trusted_keys_file", Path(str(required("trusted_keys_file")))),
             ("revocations_dir", Path(str(required("revocations_dir")))),
             ("audit_log", Path(str(required("audit_log")))),
@@ -254,6 +258,7 @@ class AuthorityConfig:
             trusted_keys_file=Path(str(required("trusted_keys_file"))),
             revocations_dir=Path(str(required("revocations_dir"))),
             audit_log=Path(str(required("audit_log"))),
+            store_path=store_path,
             signing_key_file=Path(str(signing_key)) if signing_key else None,
             key_id=str(required("key_id")),
             issuer=str(required("issuer")),
@@ -337,6 +342,11 @@ def preflight(config: AuthorityConfig) -> list:
             problems.append("produccion requiere socket_group_gid (grupo de agentes)")
     for path in (config.trusted_keys_file, config.revocations_dir, config.state_dir, config.socket_path.parent, config.audit_log.parent):
         problems.extend(_owner_and_mode_problems(path, uid))
+    if not config.store_path.is_absolute():
+        problems.append("store_path debe ser una ruta absoluta")
+    problems.extend(_owner_and_mode_problems(config.store_path.parent, uid))
+    if os.path.lexists(config.store_path):
+        problems.extend(_owner_and_mode_problems(config.store_path, uid))
     if config.signing_key_file is not None:
         key_problems = _owner_and_mode_problems(config.signing_key_file, uid, allow_root=False)
         problems.extend(key_problems)
@@ -389,7 +399,15 @@ class Authority:
             key_store=self.key_store,
             environment=config.environment,
         )
-        self.audit = audit_chain.AuditChain(config.audit_log)
+        self._attestation_nonces: dict = {}
+        self._legacy_requests_dir = config.state_dir / "requests"
+        self._legacy_approvals_dir = config.state_dir / "approvals"
+        try:
+            self.store = authority_store.SQLiteAuthorityStore(config.store_path)
+            self._migrate_legacy()
+        except (authority_store.StoreError, authority_store.MigrationError) as error:
+            raise ConfigError(f"almacen de autoridad no utilizable: {error}") from error
+        self.audit = self.store.audit
         self.audit.initialize()
         audit_valid, audit_reason, _ = self.audit.verify()
         if not audit_valid:
@@ -398,12 +416,23 @@ class Authority:
             except audit_chain.AuditError as error:
                 raise ConfigError("auditoria no verificable; autoridad no puede iniciar") from error
         self._audit_unhealthy = not audit_valid
-        self._audit_reconciliable = audit_valid or audit_reason == "audit log ausente despues de inicializar"
-        self._attestation_nonces: dict = {}
-        self._requests_dir = config.state_dir / "requests"
-        self._approvals_dir = config.state_dir / "approvals"
-        self._requests_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
-        self._approvals_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
+        self._audit_reconciliable = audit_valid
+
+    def _migrate_legacy(self) -> None:
+        """Importa evidencia JSON/JSONL anterior sin modificar los originales."""
+        legacy_present = (
+            self._legacy_requests_dir.exists()
+            or self._legacy_approvals_dir.exists()
+            or os.path.lexists(self.config.audit_log)
+        )
+        if not legacy_present:
+            return
+        self.store.migrate_legacy(
+            requests_dir=self._legacy_requests_dir if self._legacy_requests_dir.exists() else None,
+            approvals_dir=self._legacy_approvals_dir if self._legacy_approvals_dir.exists() else None,
+            audit_log=self.config.audit_log if os.path.lexists(self.config.audit_log) else None,
+            key_store=self.key_store,
+        )

     # -- estado -----------------------------------------------------------
     @property
@@ -487,49 +516,38 @@ class Authority:
         }

     # -- utilidades de almacenamiento -------------------------------------
-    def _request_path(self, request_id: str) -> Path:
-        if not request_id.startswith("REQ-") or "/" in request_id:
-            raise Denied("identificador de solicitud invalido")
-        return self._requests_dir / f"{request_id}.json"
-
-    def _save_request(self, request: dict) -> None:
-        payload = {"request": request, "integrity": _sha256(request)}
-        audit_chain.atomic_json_write(self._request_path(str(request["request_id"])), payload, mode=0o600)
+    def _save_request(self, request: dict, event: dict | None = None) -> None:
+        try:
+            self.store.save_request(request, event)
+        except authority_store.StoreError as error:
+            raise Denied(f"no se pudo persistir la solicitud: {error}") from error

     def _load_request(self, request_id: str) -> dict:
-        path = self._request_path(request_id)
+        if not request_id.startswith("REQ-") or "/" in request_id:
+            raise Denied("identificador de solicitud invalido")
         try:
-            payload = json.loads(path.read_text(encoding="utf-8"))
-        except (OSError, ValueError) as error:
-            raise Denied("solicitud desconocida o ilegible") from error
-        if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
-            raise Denied("solicitud corrupta")
-        request = payload["request"]
-        if str(payload.get("integrity") or "") != _sha256(request):
-            raise Denied("la solicitud fue alterada despues de registrarse")
-        return request
-
-    def _approval_path(self, spec_id: str, version: str) -> Path:
-        safe = validate.SPEC_ID_PATTERN.match(spec_id)
-        if not safe:
-            raise Denied("spec_id invalido")
-        return self._approvals_dir / f"{spec_id}-{version}.json"
-
-    def _save_bundle(self, spec_id: str, version: str, approval: dict, spec_path: str, project: str) -> None:
-        bundle = {
-            "approval": approval,
-            "context": {"spec_path": spec_path, "project": project},
-        }
-        audit_chain.atomic_json_write(self._approval_path(spec_id, version), bundle, mode=0o600)
+            return self.store.get_request(request_id)
+        except authority_store.StoreError as error:
+            raise Denied(str(error)) from error

     def _load_bundle(self, spec_id: str, version: str) -> tuple:
-        path = self._approval_path(spec_id, version)
+        if not validate.SPEC_ID_PATTERN.match(spec_id):
+            raise Denied("spec_id invalido")
+        try:
+            approval, context = self.store.get_grant(spec_id, version)
+            return approval, str(context.get("spec_path") or ""), str(context.get("project") or "")
+        except authority_store.StoreNotFound:
+            pass
+        except authority_store.StoreError as error:
+            raise Denied(f"autorizacion no verificable: {error}") from error
+        # Evidencia historica previa a la migracion: solo lectura, nunca escritura.
+        path = self._legacy_approvals_dir / f"{spec_id}-{version}.json"
         try:
             payload = json.loads(path.read_text(encoding="utf-8"))
         except (OSError, ValueError) as error:
             raise Denied("no hay autorizacion registrada para esa SPEC") from error
-        approval = payload.get("approval")
-        context = payload.get("context") or {}
+        approval = payload.get("approval") if isinstance(payload, dict) else None
+        context = (payload.get("context") if isinstance(payload, dict) else None) or {}
         if not isinstance(approval, dict):
             raise Denied("autorizacion corrupta")
         return approval, str(context.get("spec_path") or ""), str(context.get("project") or "")
@@ -656,8 +674,8 @@ class Authority:
                     "scope": scope,
                 }
             )
-            self._save_request(request)
-            self.audit.append(
+            self._save_request(
+                request,
                 {
                     "stage": "request",
                     "request_id": request["request_id"],
@@ -667,7 +685,7 @@ class Authority:
                     "fingerprint": request["fingerprint"],
                     "scope_hash": request["scope_hash"],
                     "client_uid": uid,
-                }
+                },
             )
         return {
             "request_id": request["request_id"],
@@ -685,11 +703,9 @@ class Authority:

     def pending(self, uid: int) -> dict:
         requests = []
-        for path in sorted(self._requests_dir.glob("REQ-*.json")):
-            try:
-                request = self._load_request(path.stem)
-            except Denied:
-                requests.append({"request_id": path.stem, "status": "CORRUPT"})
+        for request in self.store.list_requests():
+            if request.get("status") == "CORRUPT":
+                requests.append({"request_id": request.get("request_id"), "status": "CORRUPT"})
                 continue
             if request.get("status") in (None, "PENDING_USER_APPROVAL"):
                 requests.append(
@@ -740,8 +756,16 @@ class Authority:
             request["session_id"] = secrets.token_urlsafe(32)
             request["review_next_offset"] = 0
             request["review_fingerprint"] = ""
-            self._save_request(request)
-            self.audit.append({"stage": "challenge", "request_id": request_id, "admin_uid": uid})
+            self._save_request(
+                request,
+                {
+                    "stage": "challenge",
+                    "request_id": request_id,
+                    "spec_sha256": request.get("fingerprint"),
+                    "scope_sha256": request.get("scope_hash"),
+                    "admin_uid": uid,
+                },
+            )
         return {
             "request_id": request_id,
             "challenge": token,
@@ -798,7 +822,17 @@ class Authority:
             next_offset = offset + len(page)
             request["review_next_offset"] = next_offset
             request["review_fingerprint"] = fingerprint
-            self._save_request(request)
+            self._save_request(
+                request,
+                {
+                    "stage": "review_page",
+                    "request_id": request_id,
+                    "spec_sha256": fingerprint,
+                    "offset": offset,
+                    "next_offset": next_offset,
+                    "complete": next_offset == len(text),
+                },
+            )
             return {"request_id": request_id, "spec_id": request["spec_id"], "version": request["version"],
                     "fingerprint": fingerprint, "offset": offset, "next_offset": next_offset,
                     "complete": next_offset == len(text), "content": page}
@@ -810,7 +844,14 @@ class Authority:
         request["oidc_state"] = ""
         request["oidc_nonce"] = ""
         request["session_id"] = ""
-        self._save_request(request)
+        self._save_request(
+            request,
+            {
+                "stage": "review_invalidated",
+                "request_id": request.get("request_id"),
+                "spec_sha256": request.get("fingerprint"),
+            },
+        )

     def approve(self, uid: int, payload: dict) -> dict:
         self._require_healthy_audit()
@@ -868,35 +909,42 @@ class Authority:

             if not self.service.import_request(request):
                 raise Denied("solicitud no reconstruible por la autoridad")
-            request["challenge_used"] = True
-            request["status"] = "APPROVED"
-            self._save_request(request)
+            # Autenticacion y firma ocurren antes de cualquier escritura: si
+            # fallan, la solicitud y el desafio conservan su estado anterior.
             event = self._approval_event(payload, request)
             record = self.service.approve_request(request_id, event)
             if record is None:
                 raise Denied("firma de aprobacion denegada")
-            request["status"] = "APPROVED"
-            request["authorization_event_id"] = record.get("authorization_event_id")
-            self._save_request(request)
-            self._save_bundle(
-                str(request["spec_id"]),
-                str(request["version"]),
-                record,
-                str(request.get("spec_path") or ""),
-                project,
-            )
-            self.audit.append(
-                {
-                    "stage": "approval",
-                    "request_id": request_id,
-                    "spec_id": request.get("spec_id"),
-                    "version": request.get("version"),
-                    "authorization_event_id": record.get("authorization_event_id"),
-                    "approver": record.get("approver"),
-                    "key_id": record.get("key_id"),
-                    "admin_uid": uid,
-                }
-            )
+            replay = []
+            replay_expiry = str(request.get("challenge_expires_at") or _iso(_now() + timedelta(seconds=self.config.challenge_ttl)))
+            for scope, value in (("oidc_nonce", request.get("oidc_nonce")), ("session", request.get("session_id"))):
+                if value:
+                    replay.append((scope, hashlib.sha256(str(value).encode("utf-8")).hexdigest(), replay_expiry))
+            try:
+                self.store.commit_approval(
+                    request_id=request_id,
+                    challenge_hash=stored,
+                    record=record,
+                    context={"spec_path": str(request.get("spec_path") or ""), "project": project},
+                    audit_event={
+                        "stage": "approval",
+                        "request_id": request_id,
+                        "spec_id": request.get("spec_id"),
+                        "version": request.get("version"),
+                        "spec_sha256": request.get("fingerprint"),
+                        "scope_sha256": request.get("scope_hash"),
+                        "authorization_event_id": record.get("authorization_event_id"),
+                        "approver": record.get("approver"),
+                        "key_id": record.get("key_id"),
+                        "admin_uid": uid,
+                    },
+                    replay=replay,
+                )
+            except authority_store.StoreConflict as error:
+                raise Denied(f"aprobacion no confirmada: {error}") from error
+            except authority_store.StoreError as error:
+                self._audit_unhealthy = True
+                raise Denied(f"aprobacion no confirmada: {error}") from error
         return {"approval": record, "request_id": request_id}

     def _approval_event(self, payload: dict, request: dict | None = None) -> dict:
@@ -963,6 +1011,7 @@ class Authority:
             registry=self._registry(spec_id),
             audit_path=self.config.audit_log,
             workspace_root=root,
+            audit=self.audit,
         )
         decision = gate.execute(context) if execute else gate.authorize(context)
         result = decision.as_dict()
@@ -1103,7 +1152,13 @@ class Authority:

     def audit_verify(self, uid: int) -> dict:
         valid, reason, count = self.audit.verify()
-        return {"valid": valid, "reason": reason, "events": count, "blocked": self.audit.is_blocked()}
+        return {
+            "valid": valid,
+            "reason": reason,
+            "events": count,
+            "blocked": self.audit.is_blocked(),
+            "health": self.audit.health_state(),
+        }


 class _TestIdentityProvider(approval_service.IdentityProvider):
@@ -1450,6 +1505,8 @@ def main(argv=None) -> int:
     parser.add_argument("--check", action="store_true", help="Solo valida la configuracion y los permisos.")
     parser.add_argument("--bootstrap", type=Path, help="Crea una autoridad de pruebas en el directorio indicado.")
     parser.add_argument("--print-status", action="store_true", help="Muestra el estado y termina.")
+    parser.add_argument("--migrate", action="store_true", help="Importa evidencia JSON/JSONL anterior al almacen durable.")
+    parser.add_argument("--verify-storage", action="store_true", help="Verifica cadena, salud y migracion del almacen.")
     args = parser.parse_args(argv)

     if args.bootstrap:
@@ -1463,6 +1520,27 @@ def main(argv=None) -> int:
     except ConfigError as error:
         print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
         return 2
+    if args.migrate or args.verify_storage:
+        key_store = approval_service.TrustedKeyStore.from_config_file(config.trusted_keys_file)
+        if not key_store.configured:
+            print(json.dumps({"ok": False, "error": f"almacen de confianza no utilizable: {key_store.error}"}), file=sys.stderr)
+            return 2
+        try:
+            store = authority_store.SQLiteAuthorityStore(config.store_path)
+            if args.migrate:
+                result = store.migrate_legacy(
+                    requests_dir=config.state_dir / "requests" if (config.state_dir / "requests").exists() else None,
+                    approvals_dir=config.state_dir / "approvals" if (config.state_dir / "approvals").exists() else None,
+                    audit_log=config.audit_log if os.path.lexists(config.audit_log) else None,
+                    key_store=key_store,
+                )
+            else:
+                result = store.verify_store()
+        except (authority_store.StoreError, authority_store.MigrationError) as error:
+            print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
+            return 2
+        print(json.dumps({"ok": bool(result.get("valid", True)), "storage": result}, indent=2, ensure_ascii=False))
+        return 0 if result.get("valid", True) else 2
     problems = preflight(config)
     if problems:
         print(json.dumps({"ok": False, "problems": problems}, indent=2, ensure_ascii=False), file=sys.stderr)
```

### A.3 `scripts/implementation_gate.py`

```diff
diff --git a/game-development/scripts/implementation_gate.py b/game-development/scripts/implementation_gate.py
index 27c95f0..9b2b1a8 100644
--- a/game-development/scripts/implementation_gate.py
+++ b/game-development/scripts/implementation_gate.py
@@ -123,6 +123,7 @@ class ImplementationGate:
         registry=None,
         audit_path: Path | str | None = None,
         workspace_root: Path | str | None = None,
+        audit=None,
     ) -> None:
         self.approval = approval
         self.spec_path = Path(spec_path)
@@ -137,9 +138,11 @@ class ImplementationGate:
                 if spec_id
                 else None
             )
-        if audit_path is None:
-            raise PathSafetyError("el gate exige un audit log explicito")
-        self.audit = audit_chain.AuditChain(audit_path)
+        if audit is None:
+            if audit_path is None:
+                raise PathSafetyError("el gate exige un audit log explicito")
+            audit = audit_chain.AuditChain(audit_path)
+        self.audit = audit
         self._audit_unavailable = ""

     # -- auditoria --------------------------------------------------------
@@ -173,7 +176,7 @@ class ImplementationGate:
                 "fallo al registrar el resultado de la operacion",
                 {"operation": decision.operation, "path": decision.path, "detail": detail},
             )
-        except OSError as error:
+        except (OSError, audit_chain.AuditError) as error:
             # Cannot persist the marker: poison this gate instance so it cannot
             # continue granting permissions in this process.
             self._audit_unavailable = str(error)
```

### A.4 `scripts/install_authority.sh`

```diff
diff --git a/game-development/scripts/install_authority.sh b/game-development/scripts/install_authority.sh
index 551a974..6567817 100644
--- a/game-development/scripts/install_authority.sh
+++ b/game-development/scripts/install_authority.sh
@@ -179,6 +179,7 @@ config = {
     "socket_path": f"{run}/authority.sock",
     "socket_group_gid": int(agent_gid),
     "state_dir": state,
+    "store_path": f"{state}/authority.sqlite3",
     "projects": {"Spec-First-Guardian": project},
     "admin_uids": [int(admin_uid)],
     "clients": [{"uid": int(agent_uid), "agents": ["agente-1"], "delegates": {}}],
```

### A.5 `tests/test_store.py` (nuevo)

```diff
diff --git a/game-development/tests/test_store.py b/game-development/tests/test_store.py
new file mode 100644
index 0000000..9f6bade
--- /dev/null
+++ b/game-development/tests/test_store.py
@@ -0,0 +1,344 @@
+"""Pruebas del almacen durable: transacciones, cadena y migracion.
+
+Verifican el contrato de SPEC-ARCH-001 RF-001/RF-002/RF-005/RF-006 sin afirmar
+nada sobre aislamiento del sistema operativo ni sobre persistencia fisica real
+ante corte de energia.
+"""
+
+import hashlib
+import json
+import os
+import sqlite3
+import sys
+import threading
+import unittest
+from pathlib import Path
+from unittest import mock
+
+TESTS_DIR = Path(__file__).resolve().parent
+sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
+sys.path.insert(0, str(TESTS_DIR))
+
+import audit_chain  # noqa: E402
+import authority_store  # noqa: E402
+import support  # noqa: E402
+
+
+def canonical(value) -> bytes:
+    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
+
+
+def digest(value) -> str:
+    return hashlib.sha256(canonical(value)).hexdigest()
+
+
+def pending_request(record, request_id="REQ-" + "a" * 32, challenge="d" * 64):
+    return {
+        "request_id": request_id,
+        "spec_id": record["spec_id"],
+        "project": record["project"],
+        "version": record["version"],
+        "fingerprint": record["fingerprint"],
+        "expected_approver": "usuario",
+        "scope": "IMPLEMENTACION",
+        "operations": ["create_file"],
+        "authorized_paths": ["src/code.py"],
+        "requirements": ["RF-001"],
+        "tasks": ["TASK-001"],
+        "expires_at": None,
+        "registered_at": support.now_iso(),
+        "spec_path": "SPEC-001.md",
+        "scope_hash": "c" * 64,
+        "challenge_hash": hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
+        "challenge_expires_at": support.now_iso(30),
+        "challenge_used": False,
+        "oidc_state": "state",
+        "oidc_nonce": "nonce",
+        "session_id": "session",
+        "status": "PENDING_USER_APPROVAL",
+    }
+
+
+def signed_record(event_id="EVT-" + "e" * 32):
+    signer, public_pem, _ = support.make_signer()
+    store, _ = support.make_key_store(public_pem)
+    record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=store)
+    record["authorization_event_id"] = event_id
+    return record, store
+
+
+class TestSQLiteStore(unittest.TestCase):
+    def setUp(self):
+        self.directory = support.temp_dir("sg-store-")
+        self.path = self.directory / "authority.sqlite3"
+        self.store = authority_store.SQLiteAuthorityStore(self.path)
+
+    def commit(self, store=None, record=None, request_id="REQ-" + "a" * 32, request=None):
+        store = store or self.store
+        record = record or signed_record()[0]
+        request = request or pending_request(record, request_id)
+        store.save_request(request)
+        return store.commit_approval(
+            request_id=request_id,
+            challenge_hash=request["challenge_hash"],
+            record=record,
+            context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+            audit_event={"stage": "approval", "request_id": request_id},
+        )
+
+    # -- configuracion durable -------------------------------------------
+    def test_uses_wal_and_full_synchronous(self):
+        self.assertEqual(self.store.journal_mode(), "wal")
+        self.assertEqual(self.store.synchronous_mode(), "full")
+        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
+
+    def test_group_readable_store_is_rejected(self):
+        os.chmod(self.path, 0o640)
+        with self.assertRaises(authority_store.StoreError):
+            authority_store.SQLiteAuthorityStore(self.path)
+
+    def test_corrupt_store_fails_closed(self):
+        corrupt = self.directory / "corrupt.sqlite3"
+        corrupt.write_bytes(b"esto no es sqlite\n")
+        os.chmod(corrupt, 0o600)
+        with self.assertRaises(authority_store.StoreError):
+            authority_store.SQLiteAuthorityStore(corrupt)
+
+    # -- transaccion de aprobacion ---------------------------------------
+    def test_commit_persists_grant_state_and_event_together(self):
+        seq = self.commit()
+        request = self.store.get_request("REQ-" + "a" * 32)
+        approval, context = self.store.get_grant("SPEC-001", "1.0.0")
+        self.assertEqual(request["status"], "APPROVED")
+        self.assertTrue(request["challenge_used"])
+        self.assertEqual(approval["authorization_event_id"], request["authorization_event_id"])
+        self.assertEqual(context["project"], "Spec-First-Guardian")
+        events = self.store.events()
+        self.assertEqual(events[-1]["seq"], seq)
+        self.assertEqual(events[-1]["event"]["stage"], "approval")
+        self.assertTrue(self.store.verify_chain()[0])
+
+    def test_failure_during_audit_rolls_back_state_and_grant(self):
+        record = signed_record()[0]
+        request = pending_request(record)
+        self.store.save_request(request)
+        before = len(self.store.events())
+        with mock.patch.object(
+            self.store, "_append_event", side_effect=audit_chain.AuditError("fallo simulado")
+        ):
+            with self.assertRaises(audit_chain.AuditError):
+                self.store.commit_approval(
+                    request_id=request["request_id"],
+                    challenge_hash=request["challenge_hash"],
+                    record=record,
+                    context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+                    audit_event={"stage": "approval"},
+                )
+        stored = self.store.get_request(request["request_id"])
+        self.assertEqual(stored["status"], "PENDING_USER_APPROVAL")
+        self.assertFalse(stored["challenge_used"])
+        with self.assertRaises(authority_store.StoreConflict):
+            self.store.get_grant("SPEC-001", "1.0.0")
+        self.assertEqual(len(self.store.events()), before)
+
+    def test_concurrent_commits_produce_exactly_one_grant(self):
+        record = signed_record()[0]
+        request = pending_request(record)
+        self.store.save_request(request)
+        barrier = threading.Barrier(6)
+        outcomes = []
+
+        def worker():
+            store = authority_store.SQLiteAuthorityStore(self.path)
+            barrier.wait()
+            try:
+                store.commit_approval(
+                    request_id=request["request_id"],
+                    challenge_hash=request["challenge_hash"],
+                    record=record,
+                    context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+                    audit_event={"stage": "approval"},
+                )
+                outcomes.append("committed")
+            except authority_store.StoreConflict:
+                outcomes.append("conflict")
+
+        threads = [threading.Thread(target=worker) for _ in range(6)]
+        for thread in threads:
+            thread.start()
+        for thread in threads:
+            thread.join(timeout=10)
+        self.assertEqual(outcomes.count("committed"), 1, outcomes)
+        self.assertEqual(outcomes.count("conflict"), 5, outcomes)
+        self.assertEqual(sum(1 for event in self.store.events() if event["event"]["stage"] == "approval"), 1)
+
+    def test_replay_identifier_is_durable_and_unique(self):
+        record = signed_record(event_id="EVT-" + "1" * 32)[0]
+        request = pending_request(record)
+        self.store.save_request(request)
+        self.store.commit_approval(
+            request_id=request["request_id"],
+            challenge_hash=request["challenge_hash"],
+            record=record,
+            context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+            audit_event={"stage": "approval"},
+            replay=[("oidc_nonce", "f" * 64, support.now_iso(30))],
+        )
+        second_record = signed_record(event_id="EVT-" + "2" * 32)[0]
+        second = pending_request(second_record, request_id="REQ-" + "b" * 32)
+        self.store.save_request(second)
+        with self.assertRaises(authority_store.StoreConflict):
+            self.store.commit_approval(
+                request_id=second["request_id"],
+                challenge_hash=second["challenge_hash"],
+                record=second_record,
+                context={"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+                audit_event={"stage": "approval"},
+                replay=[("oidc_nonce", "f" * 64, support.now_iso(30))],
+            )
+        self.assertEqual(self.store.get_request(second["request_id"])["status"], "PENDING_USER_APPROVAL")
+
+    # -- integridad de la cadena -----------------------------------------
+    def test_chain_detects_tampering(self):
+        self.store.append_event({"stage": "one"})
+        self.store.append_event({"stage": "two"})
+        connection = sqlite3.connect(str(self.path))
+        try:
+            connection.execute("UPDATE audit_events SET event=? WHERE seq=1", ('{"stage":"alterado"}',))
+            connection.commit()
+        finally:
+            connection.close()
+        valid, reason, _ = self.store.verify_chain()
+        self.assertFalse(valid)
+        self.assertIn("hash", reason)
+
+    def test_unhealthy_store_blocks_events(self):
+        self.store.mark_incomplete("fallo simulado", {"op": "create_file"})
+        with self.assertRaises(audit_chain.AuditError):
+            self.store.append_event({"stage": "blocked"})
+        record = self.store.clear_incomplete("admin", "revisado")
+        self.assertEqual(record["event"]["stage"], "reconciled")
+        self.store.append_event({"stage": "allowed"})
+
+    def test_invalid_health_state_blocks(self):
+        connection = sqlite3.connect(str(self.path))
+        try:
+            connection.execute("UPDATE health SET state='DESCONOCIDO' WHERE id=1")
+            connection.commit()
+        finally:
+            connection.close()
+        self.assertTrue(self.store.audit_blocked())
+
+
+class TestLegacyMigration(unittest.TestCase):
+    def setUp(self):
+        self.root = support.temp_dir("sg-migrate-")
+        self.requests = self.root / "requests"
+        self.approvals = self.root / "approvals"
+        self.requests.mkdir()
+        self.approvals.mkdir()
+        self.audit_log = self.root / "audit.jsonl"
+
+        signer, public_pem, _ = support.make_signer()
+        self.store, _ = support.make_key_store(public_pem)
+        self.record, _ = support.approve(support.APPROVED_SPEC, signer=signer, store=self.store)
+
+        request = pending_request(self.record)
+        request_path = self.requests / f"{request['request_id']}.json"
+        request_path.write_text(
+            json.dumps({"request": request, "integrity": digest(request)}, indent=2), encoding="utf-8"
+        )
+        grant_path = self.approvals / "SPEC-001-1.0.0.json"
+        grant_path.write_text(
+            json.dumps(
+                {
+                    "approval": self.record,
+                    "context": {"spec_path": "SPEC-001.md", "project": "Spec-First-Guardian"},
+                },
+                indent=2,
+            ),
+            encoding="utf-8",
+        )
+        self._write_chain(
+            [
+                {"stage": "request", "request_id": request["request_id"]},
+                {"stage": "challenge", "request_id": request["request_id"]},
+                {"stage": "approval", "request_id": request["request_id"]},
+            ]
+        )
+        self.files = [request_path, grant_path, self.audit_log]
+        self.before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.files}
+
+    def _write_chain(self, events):
+        lines = []
+        previous = audit_chain.GENESIS
+        for index, event in enumerate(events, start=1):
+            record = {"seq": index, "at": support.now_iso(), "prev": previous, "event": event}
+            record["hash"] = hashlib.sha256(canonical(record)).hexdigest()
+            previous = record["hash"]
+            lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
+        self.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
+
+    def migrate(self, store=None):
+        store = store or authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        return store.migrate_legacy(
+            requests_dir=self.requests,
+            approvals_dir=self.approvals,
+            audit_log=self.audit_log,
+            key_store=self.store,
+        )
+
+    def test_imports_verified_evidence_and_preserves_originals(self):
+        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        result = self.migrate(store)
+        self.assertEqual(result["requests"], 1)
+        self.assertEqual(result["grants"], 1)
+        self.assertEqual(result["legacy_events"], 3)
+        self.assertEqual(result["imported_events"], 3)
+        self.assertTrue(store.verify_chain()[0])
+        approval, _ = store.get_grant("SPEC-001", "1.0.0")
+        self.assertEqual(approval["authorization_event_id"], self.record["authorization_event_id"])
+        for path in self.files:
+            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.before[path])
+
+    def test_migration_is_idempotent_and_records_result(self):
+        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        self.migrate(store)
+        events_after_first = len(store.events())
+        second = self.migrate(store)
+        self.assertTrue(second["already_migrated"])
+        self.assertEqual(len(store.events()), events_after_first)
+        verified = store.verify_store()
+        self.assertTrue(verified["valid"])
+        self.assertEqual(verified["migration"]["status"], "completed")
+        self.assertEqual(verified["grants"], 1)
+
+    def test_corrupt_request_refuses_migration_without_changes(self):
+        path = self.requests / ("REQ-" + "a" * 32 + ".json")
+        payload = json.loads(path.read_text(encoding="utf-8"))
+        payload["request"]["authorized_paths"] = ["src/otro.py"]
+        path.write_text(json.dumps(payload), encoding="utf-8")
+        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        with self.assertRaises(authority_store.MigrationError):
+            self.migrate(store)
+        self.assertFalse(any(event["event"]["stage"] == "storage_migration" for event in store.events()))
+        with self.assertRaises(authority_store.StoreConflict):
+            store.get_grant("SPEC-001", "1.0.0")
+
+    def test_tampered_legacy_chain_is_refused(self):
+        lines = self.audit_log.read_text(encoding="utf-8").splitlines()
+        lines[1] = lines[1].replace('"challenge"', '"alterado"')
+        self.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
+        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        with self.assertRaises(authority_store.MigrationError):
+            self.migrate(store)
+
+    def test_chain_that_cannot_be_spliced_is_refused(self):
+        store = authority_store.SQLiteAuthorityStore(self.root / "authority.sqlite3")
+        store.append_event({"stage": "nuevo"})
+        with self.assertRaises(authority_store.MigrationError):
+            self.migrate(store)
+
+
+if __name__ == "__main__":
+    unittest.main()
```

### A.6 `tests/test_authority.py`

```diff
diff --git a/game-development/tests/test_authority.py b/game-development/tests/test_authority.py
index 5569338..13a1395 100644
--- a/game-development/tests/test_authority.py
+++ b/game-development/tests/test_authority.py
@@ -141,10 +141,7 @@ class AuthorityTestCase(unittest.TestCase):
         self.ctx.client.authorize(self.operation(), content="x")
         valid, reason, count = self.ctx.authority.audit.verify()
         self.assertTrue(valid, reason)
-        stages = []
-        for line in (self.ctx.config.audit_log).read_text(encoding="utf-8").splitlines():
-            if line.strip():
-                stages.append(json.loads(line)["event"]["stage"])
+        stages = [record["event"]["stage"] for record in self.ctx.authority.audit.store.events()]
         for stage in ("request", "challenge", "approval", "intent", "result"):
             self.assertIn(stage, stages)

@@ -168,6 +165,36 @@ class AuthorityTestCase(unittest.TestCase):
         with self.assertRaises(authority_client.AuthorityDenied):
             self.ctx.client.challenge(request["request_id"])

+    def test_failed_authentication_does_not_consume_challenge_or_approve(self):
+        request = self.request()
+        challenge = self.ctx.client.challenge(request["request_id"])
+        offset = 0
+        reviewed_pages = 0
+        while offset < challenge["review"]["spec_length"]:
+            page = self.ctx.client.spec_page(request["request_id"], challenge["fingerprint"], offset)
+            offset = page["next_offset"]
+            reviewed_pages += 1
+        payload = {
+            "test_identity": {"subject": "usuario", "confirmed": True},
+            "scope_hash": challenge["scope_hash"],
+            "review_fingerprint": challenge["fingerprint"],
+            "review_pages": reviewed_pages,
+            "oidc_state": challenge["oidc_state"],
+            "session_id": challenge["session_id"],
+        }
+        with mock.patch.object(
+            self.ctx.authority, "_approval_event", side_effect=authority_service.Denied("SETUP INCOMPLETE")
+        ):
+            with self.assertRaises(authority_client.AuthorityDenied):
+                self.ctx.client.approve(request["request_id"], challenge["challenge"], **payload)
+        stored = self.ctx.authority.store.get_request(request["request_id"])
+        self.assertIn(stored.get("status"), (None, "PENDING_USER_APPROVAL"))
+        self.assertFalse(stored["challenge_used"])
+        self.assertFalse(any(item["event"]["stage"] == "approval" for item in self.ctx.authority.audit.store.events()))
+        # El desafio sigue siendo utilizable: la autenticacion es previa al commit.
+        approved = self.ctx.client.approve(request["request_id"], challenge["challenge"], **payload)
+        self.assertEqual(approved["approval"]["spec_id"], "SPEC-001")
+
     def test_wrong_challenge_is_denied(self):
         request = self.request()
         challenge = self.ctx.client.challenge(request["request_id"])
@@ -183,10 +210,22 @@ class AuthorityTestCase(unittest.TestCase):
     # -- integridad -------------------------------------------------------
     def test_tampered_stored_request_is_rejected(self):
         request = self.request()
-        path = self.ctx.authority._request_path(request["request_id"])
-        payload = json.loads(path.read_text(encoding="utf-8"))
-        payload["request"]["authorized_paths"] = ["src/otro.py"]
-        path.write_text(json.dumps(payload), encoding="utf-8")
+        import sqlite3
+
+        connection = sqlite3.connect(str(self.ctx.config.store_path))
+        try:
+            row = connection.execute(
+                "SELECT document FROM requests WHERE request_id=?", (request["request_id"],)
+            ).fetchone()
+            tampered = json.loads(row[0])
+            tampered["authorized_paths"] = ["src/otro.py"]
+            connection.execute(
+                "UPDATE requests SET document=? WHERE request_id=?",
+                (json.dumps(tampered, sort_keys=True, separators=(",", ":")), request["request_id"]),
+            )
+            connection.commit()
+        finally:
+            connection.close()
         # La integridad se comprueba al cargar: ni siquiera se emite desafio.
         with self.assertRaises(authority_client.AuthorityDenied):
             self.ctx.client.challenge(request["request_id"])
```
