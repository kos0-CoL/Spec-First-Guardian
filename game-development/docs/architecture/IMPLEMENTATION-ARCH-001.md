# IMPLEMENTATION-ARCH-001 — Registro de Etapa B (almacenamiento durable)

**Estado:** registro operativo; no modifica requisitos aprobados  
**Fecha:** 2026-11-06  
**Base:** commit `5f070594a07c289dcda03f8f76eac7e2241d1974`  
**SPEC de referencia:** `SPEC-ARCH-001-HARDENING.md`, versión 0.1.0, SHA-256 `77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda`.  
**PLAN de referencia:** `PLAN-ARCH-001.md`, SHA-256 `22a4d64f8710d194a0cdd12c49f3735231d860a58ff4ea348352406d7c028275`.

Este documento deja constancia de lo ejecutado. No es una nueva aprobación, no cambia la SPEC y no habilita producción.

## Decision aprobada por el usuario

SQLite local es el almacén canónico de estado de Authority y de auditoría, con estas condiciones: WAL y `synchronous=FULL`; permisos restrictivos; una única transacción para estado, grant y evento; cadena de hashes persistida en la misma transacción; migración verificable e idempotente; archivos históricos intactos; resultado de migración registrado y verificable; separación explícita del filesystem; denegación ante errores de escritura, integridad, sincronización o recuperación; y contrato de almacenamiento desacoplado.

## Implementado en esta etapa

### Contrato desacoplado

`scripts/authority_store.py` define `AuthorityStore`, `StoreAudit` y `StoreError`/`StoreConflict`/`MigrationError`. `Authority` depende del contrato; sólo la implementación conoce `sqlite3`. El gate recibe un sink de auditoría inyectado y conserva `audit_chain.AuditChain` para usos autónomos existentes.

### SQLite durable

`SQLiteAuthorityStore`:

- `BEGIN IMMEDIATE` por operación; WAL y `synchronous=FULL` verificados;
- archivo `0600` y directorio `0700`; rechaza symlinks, propietarios no autorizados y permisos de grupo/otros;
- esquema estricto con `requests`, `grants`, `audit_events`, `replay`, `health`, `meta`;
- eventos con `seq`, `at`, `prev`, `hash`, verificados al leer;
- estados de salud `HEALTHY`, `AUDIT_INCOMPLETE`, `AUDIT_CORRUPT`, `AUDIT_UNAVAILABLE`, `RECONCILIATION_REQUIRED`;
- cualquier estado desconocido, corrupción o error de apertura bloquea operaciones.

### Transacción de aprobación (RF-001/RF-002/RF-006)

`Authority.approve()` ahora autentica y firma **antes** de escribir. Después llama a `commit_approval`, que en una sola transacción:

1. relee la solicitud y verifica su integridad;
2. rechaza desafío usado, estado ya aprobado, hash distinto o desafío caducado;
3. comprueba que la huella, `spec_id` y versión del grant coinciden con la solicitud;
4. inserta identificadores de replay (`oidc_nonce`, `session`) con restricción única;
5. rechaza un grant distinto para la misma SPEC/versión;
6. inserta el grant;
7. actualiza la solicitud a `APPROVED` y marca el desafío consumido;
8. anexa el evento `approval` encadenado.

Cualquier fallo revierte los ocho pasos. Un fallo de autenticación no consume el desafío. La concurrencia produce un único grant.

### Migración verificable (RF-004, condición 3/4/5 del usuario)

`migrate_legacy`:

- verifica `integrity` de cada solicitud y que el ID coincida con el archivo;
- verifica la firma de cada grant con el almacén de confianza configurado;
- verifica secuencia, `prev` y hash de toda la cadena JSONL;
- rechaza duplicados en conflicto y cadenas que no puedan empalmarse sin reescribir historia;
- importa solicitudes, grants y eventos en una transacción;
- registra el informe en `meta` y como evento `storage_migration`;
- en una segunda ejecución con las mismas fuentes devuelve `already_migrated` sin reimportar;
- nunca escribe, mueve ni elimina los archivos originales.

La autoridad ejecuta la migración al arrancar si detecta evidencia anterior. Si la migración falla, no arranca.

### Operación

```bash
python scripts/authority_service.py --config /etc/spec-guardian/authority.json --verify-storage
python scripts/authority_service.py --config /etc/spec-guardian/authority.json --migrate
```

`--verify-storage` es de sólo lectura e informa cadena, salud, modo WAL, sincronización, grants, solicitudes y resultado de migración.

## Trazabilidad de criterios

| Criterio | Estado | Evidencia |
|---|---|---|
| SA-001 | Parcial | Callback OIDC ausente sigue denegando (`SETUP_INCOMPLETE`); ahora un fallo de autenticación no consume desafío ni persiste `APPROVED`. |
| SA-002 | Parcial | Rollback probado ante fallo del evento de auditoría; reinicio no convierte una aprobación parcial (no existe estado parcial). No se probó corte de energía. |
| SA-003 | Parcial | Concurrencia de 6 procesos lógicos produce un grant; replay durable por restricción única. Falta prueba con procesos OS reales y callback real. |
| SA-004 | No cubierto en esta etapa | Requiere interfaz de confirmación humana. La relectura de SPEC/hash ya existía y sigue. |
| SA-005 | No cubierto | No hay UI humana; sólo evidencia de páginas servidas. |
| SA-006 | Parcial | Salud durable en la misma base, bloqueo y reconciliación atómicos; no se probaron fallos simultáneos de disco ni reinicio del servicio real. |
| SA-007 | No cubierto | Separación SPEC/PLAN pendiente. |
| SA-008 | No cubierto | Workspace/mounts/hardlinks pendiente. |
| SA-009 | No cubierto | Durabilidad del filesystem e `INDETERMINATE` pendientes; el gate aún informa `executed` con `audit_complete=false`. |
| SA-010 | No cubierto | Modos del instalador pendientes; sólo se añadió `store_path` a la configuración generada. |
| SA-011 | No cubierto | Claims de Skill pendientes. |
| SA-012 | No cubierto | Conformidad de adaptadores pendiente. |
| SA-013 | Cubierto | Siete estados documentales intactos; estados de solicitud/auth/audit separados en el esquema. |
| SA-014 | Parcial | 129 pruebas unitarias pasan; sin IdP real, multi-UID, systemd, mounts ni fallo físico. |

## Pruebas ejecutadas

```text
python3 -m unittest discover -s tests -p 'test_*.py'
Ran 129 tests ... OK
```

Nuevas pruebas en `tests/test_store.py` (15): WAL/FULL, permisos, corrupción, commit atómico, rollback por fallo de auditoría, concurrencia con un único grant, replay durable, detección de manipulación, salud/reconciliación, migración verificada, idempotencia, solicitud corrupta, cadena alterada y cadena no empalmable.

Prueba de regresión añadida en `tests/test_authority.py`: un fallo de autenticación no consume el desafío ni crea aprobación; la aprobación posterior válida funciona.

Smoke del CLI ejecutado con configuración temporal: `--verify-storage` informa `wal`/`full`/cadena válida; `--migrate` sin evidencia devuelve `nothing_to_migrate`.

## No implementado / bloqueado

- Callback OIDC Authorization Code + PKCE, sesión de servidor y confirmación humana en UI (decisión de interfaz pendiente).
- `INDETERMINATE` explícito y durabilidad de las cuatro operaciones de archivo (RF-008).
- Mounts anidados/bind mounts, hardlinks y carreras de workspace (RF-007).
- Modos `INSTALL`/`VERIFY`/`UPGRADE`/`RECONFIGURE` del instalador (RF-009); sólo se agregó la ruta del almacén.
- Separación SPEC/PLAN y compatibilidad legacy documental (RF-004).
- Claims A/B/C de Skill y conformidad de adaptadores (RF-010/RF-011).

## Límites y riesgos residuales

- SQLite no hace atómica la escritura del filesystem; esa ventana sigue existiendo y se reporta, no se oculta.
- No hay prueba de corte de energía, corrupción física, ni recuperación desde backup.
- La base es local, sin réplica: su pérdida implica pérdida del estado posterior a la migración.
- Los archivos legacy son una foto histórica: tras migrar, el estado nuevo sólo vive en SQLite. Un rollback que borre la base perdería aprobaciones posteriores.
- La suite usa identidad simulada y UID compartido; no demuestra aislamiento OS.
- Producción permanece bloqueada por falta de callback OIDC/PKCE.

## Rollback

1. Detener la autoridad.
2. Conservar la base y sus `-wal`/`-shm` para recuperación; no borrar evidencia.
3. Si se requiere volver al código anterior, los archivos JSON/JSONL siguen intactos, pero no contienen el estado creado después de la migración.
4. Ante corrupción o resultado indeterminado: no reiniciar en caliente, preservar base/auditoría y exigir reconciliación humana.
