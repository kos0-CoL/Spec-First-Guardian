---
spec_id: SPEC-ARCH-002
title: "Remediación de hallazgos P1 de Etapa B"
status: DRAFT
version: 0.1.0
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
base_commit: "fbae472c17f0eee09d6f11043e47a6ff265e681b"
parent_spec: "SPEC-ARCH-001-HARDENING.md"
parent_spec_sha256: "77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda"
---

# SPEC-ARCH-002 — Remediación de hallazgos P1 de Etapa B

**Estado:** DRAFT; no aprobada, no autoriza implementación ni producción.<br>
**Fecha:** 2026-11-06<br>
**Autor:** Buffy — propuesta técnica para revisión humana.<br>
**Commit base examinado:** `fbae472c17f0eee09d6f11043e47a6ff265e681b`; el código auditado es el de `094f93d065cbbedce7d9ff35aeb862db92422476`.<br>
**Evidencia de origen:** `docs/audits/AUDIT-ETAPA-B-094F93D.md`.<br>
**SPEC de referencia:** `SPEC-ARCH-001-HARDENING.md`, versión 0.1.0, SHA-256 `77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda`.<br>
**Autoridad documental:** este documento no modifica la SPEC-ARCH-001, no corrige código, no cambia tests, configuración, instalador ni estados oficiales, y no habilita OIDC ni producción. Sólo una aprobación humana explícita de esta SPEC, versión y hash autorizará implementación.

> **Nota de autoridad:** la misión trata la SPEC-ARCH-001 como aprobada. El archivo de esa SPEC se autodeclara `DRAFT` y “no aprobada” en su frontmatter y encabezado. No resuelvo esa inconsistencia aquí: queda registrada como decisión pendiente **D-01**. Si la aprobación formal no existe, la cobertura de esta SPEC queda condicionada y no puede declararse conformidad.

## 1. Resumen ejecutivo

La auditoría de Etapa B identificó cinco hallazgos P1 y ningún P0 demostrado:

| ID | Defecto | Efecto observable |
|---|---|---|
| AUD-01 | El desafío no se invalida tras un fallo de autenticación/firma. | El mismo token puede reintentarse; la prueba actual incluso lo reutiliza con éxito después del fallo. |
| AUD-02 | No hay journal durable de la operación antes/después de la escritura. | Una caída entre el `intent` y el `result` deja el archivo modificado y la autoridad en `HEALTHY`. |
| AUD-03 | `_fsync_dir` silencia `OSError`. | Una escritura no durable se reporta como exitosa y el gate puede registrar `executed=True`. |
| AUD-04 | La migración importa grants sin exigir un evento `approval` correlacionado. | Un grant histórico puede quedar autorizable sin la evidencia de commit que lo justifica. |
| AUD-05 | `--verify-storage` sólo verifica la cadena. | Declara `valid=True` con solicitudes/grants manipulados o salud bloqueada. |

La corrección es acotada en alcance funcional, pero atraviesa almacenamiento, ciclo de aprobación, gate, filesystem, migración, CLI y compatibilidad. Las cinco correcciones deben cumplirse antes de declarar cerrada la Etapa B. Esta SPEC no implementa ninguna.

## 2. Contexto y evidencia

### 2.1 Baseline examinado

- El código actual conserva la estructura de Etapa B: Authority, `SQLiteAuthorityStore`, `ImplementationGate`, `safe_fs`, migración JSON/JSONL y CLI `--migrate`/`--verify-storage`.
- La suite registrada en la auditoría es de 129 pruebas OK; ese resultado no cubre los fallos de recuperación ni de durabilidad que originan estos P1.
- El commit actual agrega únicamente el expediente de auditoría; no cambia el código auditado.
- La corrección debe preservar los siete estados documentales oficiales de SPEC-ARCH-001 y no introducir estados documentales nuevos.

### 2.2 Evidencia por hallazgo

| Hallazgo | Evidencia en código actual | Evidencia adversa |
|---|---|---|
| AUD-01 | `authority_service.py:856-917` autentica/firma antes del commit; `authority_store.py:642-649` sólo marca `challenge_used` dentro de `commit_approval`; `tests/test_authority.py:168-196` fija la reutilización tras un fallo simulado. | Tras fallar `_approval_event`, el desafío sigue válido; la prueba usa `SETUP_INCOMPLETE`, que es configuración y no una autenticación real. El defecto se demuestra con una identidad no confirmada o un proveedor que deniegue. |
| AUD-02 | `implementation_gate.py:244-292` registra `intent`, escribe y luego `result`; `authority_service.py:405-419` no escanea intenciones huérfanas. | Proceso terminado con `os._exit(9)` tras escribir: sólo `intent`, archivo existente, `valid=True`, `health=HEALTHY`; Authority completa también arranca `HEALTHY`. |
| AUD-03 | `safe_fs.py:104-109` captura `OSError` y hace `pass`; `write_file`/`delete_file` llaman `_fsync_dir` en `165`, `200` y `215`. | `fsync` de directorio simulado con error: `write_file` devuelve digest y el archivo existe. |
| AUD-04 | `authority_store.py:820-846` verifica firma y evento no vacío; `899-922` inserta el grant; `924-966` importa eventos sin correlacionarlos. | Cadena legacy sin `approval`: migración `completed`, grant recuperable, eventos `request`, `challenge`, `storage_migration`. |
| AUD-05 | `authority_store.py:656-677` sólo llama `verify_chain()`; `authority_service.py:1502-1545` usa ese `valid` para el CLI. | Solicitud/grant manipulados o `health=AUDIT_INCOMPLETE`: `valid=True`; `get_request`/firma sí detectan el problema al usar. |

### 2.3 Contradicciones y requisitos insuficientes

1. **SPEC-ARCH-001 se declara DRAFT.** Su frontmatter dice `status: DRAFT` y su encabezado dice “no aprobada”. La misión la trata como aprobada. Es una decisión de autoridad documental, no una interpretación técnica. **D-01.**
2. **RF-001 usa dos fórmulas distintas para el desafío.** Permite “challenge invalidado al fallar auth” —lo que suena optativo— y a la vez exige “no volverlo reutilizable”. La segunda es obligatoria; la primera no define el disparador exacto ni cómo emitir uno nuevo. **D-02 y D-03.**
3. **La implementación declara el comportamiento contrario.** `IMPLEMENTATION-ARCH-001.md` afirma que “un fallo de autenticación no consume el desafío”, y la prueba lo consagra. Eso contradice RF-001 y el expediente de auditoría; no puede usarse como contrato.
4. **RF-006/RF-008 exigen `INDETERMINATE` y fail-stop, pero no definen el journal de operación ni el escaneo de arranque.** La documentación del store afirma una garantía que el código no implementa. Esta SPEC convierte el resultado en requisito verificable; AUD-15 queda como corrección documental posterior, fuera de alcance.
5. **RF-001/RF-006 exigen grant + evento de aprobación, pero la migración no explicita la correlación.** No se puede inferir por posición, nombre de archivo o `request_id`; hace falta una regla verificable. **D-04.**
6. **RF-005 exige verificar salud y cadena, pero no enumera la verificación de cada solicitud, grant, firma y correlación.** El `--verify-storage` actual interpreta “cadena válida” como “store válido”, lo que es insuficiente. **D-05.**
7. **La compatibilidad de registros históricos no está decidida.** Un grant firmado sin evento correlacionable es criptográficamente válido pero no satisface la invariante de aprobación. Rechazarlo puede bloquear historia legítima; aceptarlo debilita la trazabilidad. **D-04.**

## 3. Alcance

### 3.1 Incluido

- AUD-01: invalidación durable y de un solo uso del desafío después de un fallo de autenticación/firma, sin aprobación falsa.
- AUD-02: journal durable de operaciones, recuperación al arrancar, bloqueo por intención huérfana y reconciliación explícita.
- AUD-03: propagación de errores de `fsync` de archivo/directorio y resultado de durabilidad veraz.
- AUD-04: correlación obligatoria entre grant migrado y evento `approval`; rechazo fail-closed de evidencia no correlacionable.
- AUD-05: verificación integral del store y contrato veraz de `--verify-storage`.
- Pruebas unitarias, multiproceso, de reinicio y de inyección de fallos necesarias para demostrar lo anterior.
- Compatibilidad de esquema, CLI y registros existentes estrictamente en lo que estas correcciones exigen.

### 3.2 Excluido

- Implementar OIDC, callback Authorization Code + PKCE, UI humana, sesión de navegador o habilitar producción.
- Corregir AUD-06 a AUD-17, salvo la dependencia explícita que AUD-04 pueda tener con el fallback legacy; ese fallback no se modifica en esta misión.
- Añadir estados documentales oficiales, cambiar los siete estados existentes o redefinir la semántica de aprobación documental.
- Reescribir la arquitectura de Authority, el esquema de firmas, el algoritmo criptográfico o el modelo de permisos.
- Borrar, mover o reinterpretar silenciosamente datos históricos.
- Reparar automáticamente archivos, grants, auditoría o salud.
- Garantizar durabilidad ante corte de energía real sin pruebas en el filesystem objetivo.
- Añadir funcionalidad de plataforma, multi-tenant, red o servicio distribuido.

### 3.3 Supuestos

- Linux es la plataforma inicial; las garantías de `fsync` y permisos se limitan a filesystems y mounts declarados y probados.
- SQLite sigue siendo el backend inicial; otra implementación del contrato debe cumplir los mismos resultados.
- La autoridad es el único escritor autorizado del store y del journal; las pruebas multiproceso usan ese contrato.
- La aprobación humana y OIDC no forman parte de esta corrección; producción sigue bloqueada por `SETUP_INCOMPLETE`.
- Una operación de archivo y una escritura SQLite no son atómicas entre sí; la corrección debe hacer visible esa ambigüedad, no ocultarla.

## 4. Estados y vocabulario

### 4.1 Estados que no se modifican

Los siete estados documentales oficiales permanecen exactamente como en SPEC-ARCH-001: `DRAFT`, `UNDER_REVIEW`, `PENDING_USER_APPROVAL`, `APPROVED`, `REJECTED`, `SUPERSEDED`, `ARCHIVED`.

Esta SPEC reutiliza, sin crear estados oficiales nuevos:

- Estados de servicio ya definidos: `AUTH_FAILED`, `APPROVAL_COMMITTING`, `RECONCILIATION_REQUIRED`, entre otros.
- Estado de autorización ya definido: `INDETERMINATE`.
- Estados de salud ya definidos: `HEALTHY`, `AUDIT_INCOMPLETE`, `AUDIT_CORRUPT`, `AUDIT_UNAVAILABLE`, `RECONCILIATION_REQUIRED`.
- Resultados de durabilidad ya definidos en RF-008: `NOT_EXECUTED`, `EXECUTED_NOT_DURABLE`, `DURABILITY_CONFIRMED`, `INDETERMINATE`.

No se introduce un estado documental, de solicitud, de autenticación, de autorización o de salud nuevo. Los conceptos internos “intento de operación”, “resultado de operación” y “evidencia de reconciliación” son artefactos de journal, no estados oficiales.

### 4.2 Definiciones operativas

- **Desafío presentado:** solicitud de aprobación que incluye un token cuyo SHA-256 coincide con el `challenge_hash` almacenado.
- **Fallo de autenticación/firma:** identidad no verificable, `subject`/nonce/issuer/audience/exp/iat/auth_time/PKCE inválidos, error del proveedor, o firma no producida o no verificable. Un fallo de configuración previo a una tentativa autenticada (`SETUP_INCOMPLETE`, proveedor no configurado) no es un fallo de autenticación y no consume el desafío.
- **Intención durable:** registro persistido y confirmado antes de cualquier efecto en el filesystem.
- **Resultado durable:** registro persistido del efecto y de la durabilidad observada.
- **Intención huérfana:** intención durable sin resultado terminal correlacionado, tras reinicio o nueva instancia.
- **Operación resuelta:** intención huérfana acompañada por evidencia humana que determina si el target fue modificado; no implica reejecución.
- **Store válido:** todas las comprobaciones de RF-016 pasan y la salud es `HEALTHY`; no significa que la historia sea completa frente a un ancla externa (AUD-07 sigue abierto).

## 5. Requisitos funcionales

### RF-012 — Invalidación durable del desafío tras fallo de autenticación (AUD-01)

**Problema.** El desafío se consume sólo en el commit posterior a la firma. Un fallo de autenticación o firma deja el token reutilizable y no deja evidencia de la tentativa.

**Requisitos:**

- **RF-012.1** Un intento que presenta un desafío cuyo hash coincide con el almacenado DEBE ser de un solo uso para el éxito. Un mismo token no puede producir dos aprobaciones ni dos grants.
- **RF-012.2** Si falla la autenticación o la firma después de comprobar la posesión del desafío, el sistema DEBE impedir que ese token vuelva a ser aceptado. La solicitud NO DEBE quedar `APPROVED` y NO DEBE emitirse grant. Un fallo de configuración previo a una tentativa autenticada (`SETUP_INCOMPLETE` o proveedor no configurado) NO DEBE consumir el desafío.
- **RF-012.3** La invalidación y la evidencia del fallo DEBEN persistirse de forma durable y atómica respecto de la comprobación de uso. Si no pueden persistirse, la tentativa DEBE fallar cerrada: no hay aprobación, no se declara salud `HEALTHY` y la autoridad no concede nuevas operaciones hasta recuperar.
- **RF-012.4** Un intento con hash de desafío incorrecto, solicitud inexistente, token ausente o formato inválido NO DEBE consumir un desafío válido; no debe permitir que un tercero sin posesión del token agote desafíos ajenos.
- **RF-012.5** La invalidación DEBE usar una comprobación y actualización atómicas (compare-and-swap o equivalente). Si dos intentos compiten, como máximo uno puede consumir el desafío; el otro DEBE denegarse. Ningún resultado de la carrera puede ser `APPROVED` sin autenticación y commit completos.
- **RF-012.6** La autoridad PUEDE emitir un desafío nuevo para la misma solicitud sólo mediante una acción administrativa explícita, no automática, y sólo si la solicitud no está `APPROVED` y la SPEC/alcance no cambiaron. El token anterior DEBE quedar permanentemente inutilizable; emitir uno nuevo no revalida el anterior. La elección entre reemitir sobre la misma solicitud o exigir una solicitud nueva es **D-03**.
- **RF-012.7** Un fallo de commit con resultado ambiguo NO DEBE presentarse como éxito ni permitir un reintento ciego. Si no puede demostrarse que no hubo commit, el store/authority DEBE bloquearse como `INDETERMINATE`/`RECONCILIATION_REQUIRED` y requerir reconciliación.
- **RF-012.8** El fallo DEBE dejar evidencia consultable sin incluir el token, el código OIDC, el nonce ni secretos equivalentes. La evidencia debe permitir distinguir “no autenticado”, “desafío invalidado” y “aprobación confirmada”.

**Límite de alcance.** El mínimo obligatorio de RF-012.2 es el fallo de autenticación/firma. La extensión a fallos de `state`, sesión, scope o revisión posteriores a la prueba de posesión del desafío es una decisión de seguridad separada; no se presume aprobada. **D-02.**

**No cubierto por RF-012.** No se implementa el callback OIDC ni se acepta un token directo del agente. La producción sigue denegando por `SETUP_INCOMPLETE` hasta que exista el flujo aprobado de SPEC-ARCH-001.

### RF-013 — Journal durable de operaciones y recuperación de intenciones huérfanas (AUD-02)

**Problema.** El gate registra `intent` y `result` en transacciones separadas. Una caída entre ambos no deja marca durable; el arranque no detecta la intención huérfana y la autoridad queda `HEALTHY`.

**Requisitos:**

- **RF-013.1** Antes de cualquier efecto en el filesystem, la autoridad DEBE persistir una intención durable que identifique, como mínimo: operación, autorización, solicitud/contexto, proyecto/workspace, ruta relativa, tipo de operación, estado previo verificable (ausencia, digest e inode cuando exista), digest esperado del contenido cuando corresponda, timestamp e identidad de la instancia que ejecuta.
- **RF-013.2** Si la intención no puede persistirse y confirmarse, NO DEBE ejecutarse el efecto. La operación DEBE devolver denegación/`NOT_EXECUTED` y no debe dejar un archivo modificado.
- **RF-013.3** Después del efecto, la autoridad DEBE persistir un resultado terminal que registre si el efecto ocurrió, el digest/inode observable, la durabilidad y cualquier error. El resultado DEBE ser recuperable tras reinicio y correlacionable con la intención.
- **RF-013.4** Al abrir el store o arrancar cualquier instancia que pueda ejecutar operaciones, el sistema DEBE buscar intenciones sin resultado terminal. Si encuentra al menos una, NO DEBE declarar `HEALTHY`, NO DEBE conceder nuevas autorizaciones y DEBE marcar la salud con un estado existente de bloqueo (`AUDIT_INCOMPLETE` o `RECONCILIATION_REQUIRED`). No se autocura, no se borra la marca y no se reejecuta la operación.
- **RF-013.5** Una intención huérfana DEBE poder resolverse sólo con evidencia humana autenticada que indique si el target fue modificado y qué evidencia lo demuestra. La resolución DEBE registrar un evento durable ligado al identificador de la intención. La salud NO DEBE volver a `HEALTHY` mientras quede alguna intención sin resolver.
- **RF-013.6** El journal DEBE cubrir los puntos de caída: antes de la intención, después de la intención y antes del efecto, después del efecto y antes del resultado, y después del resultado y antes de responder. Los dos puntos intermedios deben terminar en bloqueo/reconciliación, no en salud sana.
- **RF-013.7** Dos gates o procesos que intenten registrar la misma operación DEBEN producir como máximo una intención ejecutable y un resultado terminal. Un duplicado DEBE denegarse o resolverse como conflicto; nunca dos efectos no idempotentes.
- **RF-013.8** Cualquier gate que ejecute operaciones DEBE usar un sink durable que soporte el journal y la consulta de intenciones huérfanas. Si el sink no puede demostrar esa capacidad, DEBE denegar las operaciones en lugar de degradar a `intent`/`result` sin recuperación.
- **RF-013.9** La API de resultado DEBE distinguir `executed`, `durability` y `audit_complete`; `allowed` por sí solo NO DEBE interpretarse como éxito durable. Un cliente que ignore los campos nuevos no debe recibir una afirmación de éxito no demostrada.

**Límite de alcance.** No se especifica aquí la tabla, archivo, transacción o algoritmo concreto del journal; esas son decisiones de implementación. Lo normativo es que la intención preceda al efecto, que el resultado sea durable y que una intención huérfana bloquee con reconciliación humana.

### RF-014 — Durabilidad verificable de las operaciones de archivo (AUD-03)

**Problema.** `_fsync_dir` ignora `OSError`; el gate puede reportar éxito y `executed=True` aunque la entrada de directorio no sea durable.

**Requisitos:**

- **RF-014.1** Ningún componente DEBE ignorar un error de `fsync` de archivo o de directorio. Un error DEBE propagarse como fallo de durabilidad y no puede convertirse en `DURABILITY_CONFIRMED`.
- **RF-014.2** Para `create_file`, `modify_file` y `overwrite_file`, la secuencia observable DEBE incluir sincronización del contenido y sincronización del directorio que hace visible el nombre. Para `delete_file`, DEBE incluir la eliminación y la sincronización del directorio; el recibo debe conservar el digest/inode previo porque ya no hay contenido posterior que hashear.
- **RF-014.3** Si el `fsync` de archivo falla antes de que el cambio sea visible, el sistema DEBE intentar una limpieza segura y devolver `NOT_EXECUTED` o `INDETERMINATE`. Si esa limpieza falla, NO DEBE declarar éxito; debe bloquear.
- **RF-014.4** Si el `fsync` de directorio falla después de un rename, create o unlink, el cambio puede existir pero su persistencia ante crash no está confirmada. El resultado DEBE ser `EXECUTED_NOT_DURABLE` o `INDETERMINATE`, `audit_complete=false`, y la autoridad DEBE bloquear nuevas operaciones hasta reconciliar.
- **RF-014.5** Un filesystem que no soporta `fsync` de directorio DEBE tratarse como no soportado/fail-closed, no como éxito silencioso. La matriz de filesystems soportados debe declararse y probarse; no se extrapola a otros.
- **RF-014.6** El recibo de operación DEBE incluir, como mínimo: `executed`, `data_synced`, `directory_synced`, `durability`, digest/inode observable y referencia de auditoría. La ausencia de un fsync obligatorio no puede compensarse con un digest correcto del contenido.
- **RF-014.7** La recuperación NO DEBE revertir automáticamente una escritura o borrado cuyo `fsync` falló. Debe conservar la evidencia y exigir reconciliación; un rollback no autorizado puede destruir evidencia o afectar hardlinks.

**Cobertura.** RF-008 y SA-009 ya exigen este resultado. La implementación actual no lo cumple; esta SPEC no agrega una garantía nueva, sino un criterio verificable y un contrato de recibo.

### RF-015 — Correlación obligatoria de grants históricos (AUD-04)

**Problema.** La migración verifica la firma del grant y que `authorization_event_id` no esté vacío, pero no que ese identificador corresponda a un evento `approval` de la cadena importada o existente. Un grant firmado puede quedar autorizable sin el evento que justifica su commit.

**Requisitos:**

- **RF-015.1** Para cada grant que se pretenda importar, la migración DEBE verificar que su `authorization_event_id` corresponde a un evento `approval` verificable en la cadena de auditoría que se importa o que ya existe en el store.
- **RF-015.2** La correlación DEBE comprobar, cuando los campos estén presentes, que `spec_id`, `version`, `fingerprint`, `scope_sha256`/alcance y el identificador de evento del grant coinciden con la solicitud y el evento. No se admite correlación inferida por posición, nombre de archivo, orden de importación o `request_id` no firmado.
- **RF-015.3** Si un grant no tiene evento correlacionable, tiene un evento de otra solicitud/versión o el evento no es verificable, la migración NO DEBE insertar ese grant ni registrar la migración como `completed`. La transacción completa DEBE revertirse y el CLI DEBE devolver un resultado de error no cero.
- **RF-015.4** La migración DEBE ser todo-o-nada para el conjunto importado: no puede dejar solicitudes, grants o eventos parciales, ni un registro `meta` que sugiera éxito. Los archivos originales DEBEN permanecer intactos en bytes.
- **RF-015.5** Una base ya migrada que contenga grants sin correlación DEBE ser detectada por la verificación de RF-016 y NO DEBE autorizar esos grants. El sistema no debe borrar ni “reparar” el grant automáticamente; debe bloquear y requerir la política humana de **D-04**.
- **RF-015.6** La migración de registros válidos debe seguir siendo idempotente y conservar la idempotencia existente; una segunda ejecución con las mismas fuentes no debe duplicar grants ni eventos.

**Límite de alcance.** La decisión de rechazar toda la migración, cuarentenar grants individuales o exigir re-aprobación histórica es **D-04**. Esta SPEC exige el resultado de seguridad mínimo: ningún grant no correlacionado puede quedar autorizable ni puede declararse migración exitosa.

### RF-016 — Verificación integral y veraz del almacén (AUD-05)

**Problema.** `verify_store` sólo verifica la cadena. Una solicitud o un grant manipulados, o una salud bloqueada, producen `valid=True`; el CLI puede reportar éxito falso.

**Requisitos:**

- **RF-016.1** `--verify-storage` DEBE verificar, como mínimo:
  - la cadena de auditoría (`seq`, `prev`, hash y cuerpo);
  - la salud y que su estado sea un valor conocido;
  - el esquema y `meta.schema_version`;
  - el registro de migración y su coherencia con los datos;
  - cada solicitud: decodificación, digest/integridad, identificador y estado permitido;
  - cada grant: decodificación, firma con el almacén de confianza, contexto y correlación con evento `approval`;
  - los identificadores de replay y sus expiraciones;
  - las intenciones de operación sin resultado terminal;
  - que no existan grants autorizables sin evento correlacionado.
- **RF-016.2** El resultado DEBE separar `chain_valid`, `store_valid`, `health` y `ok`. `ok`/`valid` sólo pueden ser verdaderos si todas las comprobaciones anteriores pasan y la salud es `HEALTHY`. `chain_valid` puede ser verdadero mientras `store_valid` es falso; no se debe confundir uno con otro.
- **RF-016.3** El CLI DEBE devolver exit code 0 sólo si `ok=true`. Cualquier store inválido, salud no `HEALTHY`, firma no verificable, grant huérfano, intención huérfana o error de lectura DEBE producir exit code no cero y un diagnóstico acotado.
- **RF-016.4** La verificación DEBE ser de sólo lectura lógica: no debe insertar, actualizar, borrar, migrar, reconciliar, reparar ni marcar salud. Si el store no existe, no puede abrirse o el almacén de confianza no está configurado, DEBE informar fallo cerrado; no debe crear un store nuevo ni asumir salud.
- **RF-016.5** El diagnóstico NO DEBE incluir tokens, códigos, nonces, claves privadas, contenido completo de grants ni datos sensibles innecesarios. Puede incluir identificadores, conteos, motivos y rutas relativas.
- **RF-016.6** La verificación DEBE ser reproducible sobre el mismo store y no debe modificar el resultado por el orden de las filas; los conteos y errores deben ser deterministas.
- **RF-016.7** La compatibilidad del campo `valid` debe ser fail-closed: los consumidores existentes que lo interpretan como “store íntegro” no deben recibir `true` cuando la salud está bloqueada o un registro no verifica. La forma exacta de conservar aliases y campos es **D-05**.

**Límite de alcance.** RF-016 no detecta truncación de la cola frente a un ancla externa (AUD-07), no verifica backups y no demuestra que el filesystem sea durable. Es una verificación del store local, no una prueba de historia completa.

## 6. Requisitos de seguridad

- **SR-001 — Fail-closed.** Cualquier duda de integridad, autenticación, durabilidad o recuperación debe denegar nuevas autorizaciones; nunca degradar a `HEALTHY` por conveniencia.
- **SR-002 — Sin éxito falso.** Ninguna API, CLI o evento puede declarar éxito, durabilidad o aprobación si falta una evidencia obligatoria. `allowed`, `executed`, `durability` y `audit_complete` no son intercambiables.
- **SR-003 — Evidencia durable y correlacionada.** Desafío, intención, resultado, grant y evento de aprobación deben poder correlacionarse por identificadores persistidos; una firma válida no sustituye la evidencia de commit.
- **SR-004 — Un solo uso y carrera segura.** El desafío y el grant se consumen una vez; la concurrencia no produce dos autorizaciones ni dos efectos.
- **SR-005 — Reconciliación humana.** Una intención huérfana o un resultado no durable sólo se resuelve con identidad administrativa reautenticada y evidencia; no se auto-repara.
- **SR-006 — Preservación de evidencia.** No se borran, reescriben ni reinterpretan silenciosamente registros históricos, archivos originales, WAL/SHM o eventos de fallo.
- **SR-007 — Mínima exposición.** Tokens, códigos, nonces, material de claves y contenido sensible no se registran en logs, errores, eventos ni salidas CLI.
- **SR-008 — Separación de estados.** Los estados documentales no se usan para representar fallos de autenticación, operación o almacenamiento; se usan los estados separados ya definidos.

## 7. Invariantes

- **INV-01** Los siete estados documentales oficiales no cambian.
- **INV-02** No existe `APPROVED` sin grant, evento `approval` y evidencia durable correlacionada en el flujo normal.
- **INV-03** Un desafío que sufrió fallo de autenticación/firma no puede reutilizarse para aprobar.
- **INV-04** No hay efecto en el filesystem sin intención durable previa.
- **INV-05** No se concede una nueva operación si existe una intención huérfana, una salud no `HEALTHY` o un resultado de durabilidad no confirmado.
- **INV-06** No se declara `DURABILITY_CONFIRMED` si falló cualquier fsync obligatorio.
- **INV-07** No se registra una migración `completed` con un grant no correlacionado.
- **INV-08** `verify-storage` sólo devuelve `ok=true` si todas las comprobaciones de RF-016 pasan y la salud es `HEALTHY`.
- **INV-09** La recuperación no reejecuta, revierte ni borra automáticamente una operación no idempotente.
- **INV-10** Los archivos históricos y la evidencia previa se preservan en bytes; una migración fallida no deja estado parcial.

## 8. Criterios de aceptación verificables

| ID | Criterio | Evidencia mínima |
|---|---|---|
| AC-012a | Tras un fallo real de autenticación/firma (identidad no confirmada o proveedor que deniega) con desafío válido, la solicitud no está `APPROVED`, no hay grant y el mismo desafío es rechazado al reintentar. Un `SETUP_INCOMPLETE` no consume el desafío. | Unitario + reinicio; evento de fallo durable; `approve` posterior con el mismo token denegado; prueba separada de `SETUP_INCOMPLETE` sin consumo. |
| AC-012b | Un desafío nuevo, emitido explícitamente tras la invalidación, funciona; el anterior sigue denegado. | Unitario + store nuevo; el token anterior no se revalida. |
| AC-012c | Dos intentos concurrentes con el mismo desafío producen como máximo un éxito; un fallo de autenticación no puede convivir con una aprobación. | Multiproceso con `fork`; exactamente 0 o 1 grant, nunca 2; sin `APPROVED` por el intento fallido. |
| AC-012d | Un intento con token incorrecto no consume el desafío válido. | Unitario; el token correcto sigue funcionando si no hubo fallo autenticado. |
| AC-013a | Si el proceso muere después de la intención y antes del resultado, al reiniciar no hay `HEALTHY`, no se conceden nuevas operaciones y no se reejecuta el efecto. | Subproceso con `os._exit(9)` en cada ventana; `valid=false`/salud bloqueada; archivo y journal preservados. |
| AC-013b | Una intención huérfana no puede limpiarse con una reconciliación genérica; exige evidencia ligada a la operación. | Intento de `reconcile` sin resolución: denegado; con evidencia: evento correlacionado y salud sólo entonces. |
| AC-013c | Una caída antes de la intención no deja efecto; una caída después del resultado conserva el resultado y no duplica la operación. | Matriz de puntos de caída; hashes y eventos antes/después. |
| AC-014a | Un fallo de `fsync` de directorio en `create_file`, `modify_file`, `overwrite_file` o `delete_file` no produce `DURABILITY_CONFIRMED` ni un éxito de API. | Inyección de `OSError` por operación; `EXECUTED_NOT_DURABLE`/`INDETERMINATE`; bloqueo. |
| AC-014b | Un fallo de `fsync` de archivo antes del rename no deja un target alterado; si la limpieza falla, el resultado es indeterminado y bloquea. | Inyección en archivo/temporal; target y temp inspeccionados; sin éxito. |
| AC-014c | Tras un fallo de durabilidad, un reinicio no devuelve `HEALTHY` ni permite operaciones sin reconciliación. | Store nuevo + Authority nueva; salud bloqueada persistente. |
| AC-015a | Una migración con grant sin evento `approval`, evento de otra solicitud o firma inválida no inserta grants ni registra `completed`; los originales no cambian. | Fixtures de migración; `MigrationError`; 0 grants; hashes de archivos iguales. |
| AC-015b | Una migración válida conserva grants, solicitudes, eventos e idempotencia, y una segunda ejecución no duplica. | Fixture válido; `already_migrated`; conteos y hashes. |
| AC-015c | Un store existente con grant no correlacionado no autoriza ese grant y `verify-storage` lo reporta. | Base manipulada/fixture; `get_grant` o autorización denegada; `ok=false`. |
| AC-016a | Solicitud manipulada, grant manipulado, firma inválida, evento faltante o salud bloqueada producen `ok=false`/`valid=false` y exit no cero. | Matriz de manipulación; `chain_valid` puede seguir true; `store_valid=false`. |
| AC-016b | Un store íntegro y saludable produce `ok=true`, `chain_valid=true`, `store_valid=true`, salud `HEALTHY`, exit 0, sin mutaciones. | Snapshot antes/después; SQLite trace o hash lógico; salida JSON. |
| AC-016c | Un store inexistente, inaccesible o sin trust store no se crea ni se declara válido. | CLI sobre ruta temporal; exit no cero; sin archivo nuevo. |
| AC-017 | No se introduce ningún estado oficial nuevo y los siete estados documentales siguen intactos. | Inspección de esquema/validadores + prueba de estados. |
| AC-018 | La corrección no implementa OIDC ni habilita producción; el camino de producción sigue denegando por `SETUP_INCOMPLETE`. | Prueba de estado/CLI; revisión de diff; sin callback/UI. |

## 9. Escenarios de fallo

| Escenario | Estado esperado | Prohibido |
|---|---|---|
| Fallo de autenticación/firma con token válido | Desafío invalidado, solicitud no aprobada, evento durable, autoridad sana si la invalidación se persistió. | Reutilizar el token; `APPROVED`; grant; alegar éxito. |
| Fallo de `state`/sesión/scope/revisión con token válido | Denegación; la política de consumo queda en D-02. | Aprobar sin autenticación o ignorar el fallo. |
| Caída antes de la intención | Sin efecto; al reiniciar no hay huérfana. | Crear archivo sin journal. |
| Caída después de la intención y antes del efecto | Intención huérfana; salud bloqueada; sin nuevas operaciones. | Reejecutar o borrar la intención automáticamente. |
| Caída después del efecto y antes del resultado | Intención huérfana; archivo puede existir; bloqueo y reconciliación. | Declarar `HEALTHY`; repetir la escritura; borrar el archivo. |
| `fsync` de archivo falla antes del rename | Limpieza segura o indeterminado; sin éxito. | `DURABILITY_CONFIRMED`; target alterado silenciosamente. |
| `fsync` de directorio falla después de rename/unlink | `EXECUTED_NOT_DURABLE`/`INDETERMINATE`; bloqueo. | Éxito; `allowed` interpretado como durable. |
| Disco lleno/IO error durante journal o resultado | Fallo cerrado; sin efecto si falta intención; bloqueo si el resultado es dudoso. | Continuar con salud sana o auto-reparar. |
| Migración con grant sin evento correlacionado | `MigrationError`; rollback; sin `completed`; originales intactos. | Insertar grant; marcar éxito; borrar fuente. |
| Store manipulado o salud bloqueada | `ok=false`; `store_valid=false`; exit no cero. | `valid=True`; `HEALTHY`; reparación automática. |
| Reinicio tras cualquier fallo anterior | Bloqueo persistente hasta reconciliación humana. | Reinicio “limpio” que borra la marca. |

## 10. Estrategia de recuperación

### 10.1 Principios

1. **Preservar antes de actuar:** detener la autoridad, conservar base, `-wal`, `-shm`, journal, archivos, logs y hashes. No borrar evidencia para “volver a intentar”.
2. **No auto-reparar:** ningún arranque debe convertir una intención huérfana, un grant no correlacionado o una salud bloqueada en `HEALTHY`.
3. **Reconciliación humana:** un administrador reautenticado debe aportar evidencia y una nota; la autoridad registra un evento durable y sólo después puede evaluar el desbloqueo.
4. **No repetir operaciones no idempotentes:** una escritura o borrado indeterminado no se reejecuta ni se revierte sin una decisión humana y una operación autorizada nueva.
5. **Verificar después:** tras la recuperación, `--verify-storage` debe pasar y la autoridad debe arrancar sin huérfanas.

### 10.2 Desafío invalidado (AUD-01)

- El token anterior permanece inutilizable para siempre.
- Se emite un desafío nuevo sólo por acción administrativa explícita y con state/session/nonce nuevos; el desafío anterior no se “resetea”.
- La solicitud puede seguir pendiente o registrar `AUTH_FAILED` según D-03; en ningún caso pasa a `APPROVED` sin un nuevo intento autenticado y un commit completo.
- Si la invalidación no pudo persistirse, la autoridad debe bloquearse, no continuar con un token potencialmente reutilizable.

### 10.3 Operación huérfana o no durable (AUD-02/AUD-03)

1. Detener la autoridad y preservar la evidencia.
2. Localizar la intención por `operation_id`; comparar target, digest/inode previo, existencia y journal.
3. Determinar si el efecto ocurrió. No inferir sólo por “no hay resultado”.
4. Si ocurrió, registrar la resolución como ejecutada; no repetir. Si no ocurrió, registrar la resolución como no ejecutada; una ejecución posterior requiere una operación autorizada nueva.
5. Si el resultado es ambiguo incluso con la evidencia, mantener `INDETERMINATE`/`RECONCILIATION_REQUIRED`; no desbloquear por comodidad.
6. Registrar reconciliación con identidad admin, reautenticación y nota; sólo entonces volver a `HEALTHY` si no quedan huérfanas.
7. Ejecutar `--verify-storage` y reiniciar; comprobar que no se repitió el efecto.

### 10.4 Migración fallida (AUD-04)

- La transacción se revierte completa; no se conserva un `meta` de éxito ni grants parciales.
- Los archivos originales permanecen intactos; se corrige la evidencia fuente o se aplica la política D-04.
- Se repite la migración sólo después de que la correlación sea verificable; la idempotencia debe impedir duplicados.
- Si la base ya contiene un grant no correlacionado, se bloquea su autorización y se decide entre re-aprobación, cuarentena o rechazo conforme a D-04.

### 10.5 Verificación fallida (AUD-05)

- `--verify-storage` no repara nada; informa `ok=false` y sale con error.
- Se preserva el store y se investiga el registro ofensor.
- La recuperación usa backup/restauración confiable o una remediación humana explícita, nunca un “clear health” genérico.
- Si la cadena es válida pero un grant no verifica, no se declara el store íntegro.

## 11. Compatibilidad histórica

- **Esquema actual:** `schema_version=1`. Cualquier tabla/columna nueva para journal, correlación o resultados exige una versión nueva y una migración explícita, idempotente y transaccional; no se debe abrir una base antigua como si ya tuviera la nueva estructura.
- **Datos existentes:** no se borran ni reescriben solicitudes, grants, eventos, `meta`, archivos legacy, WAL/SHM. Una migración fallida no deja cambios parciales.
- **Grants históricos:** la firma sigue siendo verificable, pero la autorización exige la correlación de RF-015. Un grant no correlacionado no se considera autorizable; la política de re-aprobación/cuarentena es D-04.
- **Registros de migración:** los registros `completed` existentes deben poder auditarse; si no cumplen la nueva verificación, se reportan como no válidos y no se “arreglan” silenciosamente.
- **CLI:** `valid` no puede seguir significando “sólo cadena” cuando se usa para decidir éxito. Se preservan los campos útiles, se agregan `chain_valid`, `store_valid` y `ok`, y el exit code pasa a ser fail-closed. La forma exacta es D-05.
- **Contrato de gate:** se agregan campos de durabilidad y journal; los clientes existentes que sólo miran `allowed` no deben interpretarlo como éxito durable. La compatibilidad de protocolo/versionado es D-05.
- **Instalador:** la ruta `store_path` existente se conserva. La corrección no exige cambiar usuarios, grupos, claves, socket ni configuración; sólo verificar que el instalador no invoque una verificación con semántica antigua. Cualquier cambio de instalador queda fuera de esta misión.
- **SPEC-ARCH-001:** no se modifica. Sus siete estados y requisitos siguen siendo el baseline; esta SPEC sólo aclara resultados para los P1.

## 12. Migraciones necesarias

1. **Esquema de store:** evaluar una versión 2 para journal/resultados y cualquier metadato de correlación. La migración debe ser forward-only, con backup verificado, transacción única, validación de `schema_version` y prueba de rollback operativo que preserve datos.
2. **Backfill de evidencia:** no se deben inventar eventos `approval` para grants históricos. Si una intención/resultado histórico no puede correlacionarse, se reporta y se bloquea; no se fabrica un resultado.
3. **Correlación legacy:** la migración existente debe verificar eventos antes de insertar grants y abortar todo el conjunto si falla; no se acepta una migración parcial.
4. **Salud:** una base migrada con huérfanas o grants no correlacionados debe quedar bloqueada, no `HEALTHY`; la migración no puede limpiar la salud.
5. **CLI/operación:** documentar la nueva semántica de `--verify-storage` y `--migrate`, incluyendo exit codes y campos de salida; no se requiere un comando nuevo para esta SPEC.
6. **Reversibilidad:** si se revierte el software, no se debe abrir la base nueva con un lector que ignore campos de seguridad y la declare válida. La política de downgrade debe ser explícita y fail-closed.

## 13. Pruebas obligatorias

### 13.1 Unitarias

- Invalidación de desafío tras un fallo real de autenticación/firma (identidad no confirmada o proveedor que deniega); no aprobación; token anterior rechazado; token nuevo aceptado; token incorrecto no consume. Un `SETUP_INCOMPLETE` se prueba por separado y no consume.
- Carrera lógica de dos intentos; CAS; exactamente un éxito como máximo.
- Journal: intención sin resultado, resultado sin intención (si se permite detectarlo), duplicado de operación, resolución humana.
- `safe_fs`: fallo de `fsync` de archivo y de directorio en las cuatro operaciones; limpieza; estados de durabilidad.
- Migración: grant sin evento, evento de otra solicitud, evento con campos divergentes, firma inválida, cadena válida, idempotencia, rollback.
- Verificación: solicitud manipulada, grant manipulado, firma inválida, evento faltante, salud bloqueada, migración inconsistente, store válido.
- Estados: los siete documentales intactos; ningún estado oficial nuevo.

### 13.2 Multiproceso y reinicio

- Dos o más procesos compitiendo por el mismo desafío: como máximo una aprobación; un fallo de autenticación no puede producir un grant.
- Procesos compitiendo por la misma intención: una sola ejecución; el resto conflicto/denegación.
- Caída con `os._exit(9)` antes de la intención, después de la intención, después del efecto y después del resultado; reinicio y verificación.
- Authority completa reiniciada con una intención huérfana: no `HEALTHY`, no nuevas operaciones, reconciliación obligatoria.
- Migración concurrente o repetida: no duplicar grants/eventos; AUD-08 sigue siendo P2 y no se declara resuelto por estas pruebas.

### 13.3 Inyección de fallos

- `OSError` en `fsync` de archivo y de directorio, por operación y por punto de la secuencia.
- Fallo de escritura/lectura SQLite, `AuditError`, fallo al persistir journal, fallo al persistir salud y fallo al persistir reconciliación.
- Rename/unlink fallido, limpieza fallida, archivo temporal residual, disco lleno simulado.
- Fallo de la verificación de firma/trust store durante `verify-storage`.
- Todos los fallos deben comprobar que no se declara éxito y que la salud permanece bloqueada cuando corresponde.

### 13.4 Integración y ambiente

- Linux con UID distintos cuando el entorno lo permita; no se extrapolan resultados de un UID compartido.
- Filesystem/mount declarados para la matriz de `fsync`; si no se puede probar, se reporta omitido, nunca pass.
- Reinicio del servicio completo con socket y configuración temporal; sin OIDC real.
- Pruebas de compatibilidad con una base v1 y con fixtures legacy; no usar bases reales.
- Suite existente completa: debe seguir pasando; las pruebas nuevas deben fallar en el código base y pasar con la corrección.

### 13.5 Evidencia y límites

- Guardar comandos, versiones, salida exacta, hashes de fixtures, estado de salud y limitaciones.
- No declarar durabilidad física demostrada por un mock de `fsync`; el mock demuestra manejo de errores, no hardware.
- No declarar OIDC, multi-UID, mounts o corte de energía probados si no se ejecutaron.
- No sustituir una prueba fallida por una omisión silenciosa.

## 14. Análisis de impacto

| Componente | Impacto previsto | Qué no se modifica ahora |
|---|---|---|
| Authority | Debe invalidar desafío, bloquear por huérfanas, verificar grants y exponer estado veraz. | No se implementa OIDC ni UI. |
| `SQLiteAuthorityStore` | Probable esquema v2/journal, CAS de desafío, correlación, verificación integral y migración. | No se toca el archivo en esta misión. |
| `ImplementationGate` | Intención durable, resultado, recuperación, contrato de durabilidad y reconciliación. | No se cambia el gate ahora. |
| `safe_fs` | Propagar errores de fsync y devolver evidencia de durabilidad; no limpiar silenciosamente. | No se cambia ahora. |
| Migración histórica | Correlación obligatoria, aborto todo-o-nada, grants no verificables bloqueados. | No se reescriben fuentes ni bases. |
| CLI | `--verify-storage` fail-closed, campos separados y exit code; `--migrate` reporta fallo. | No se ejecuta ni se cambia el CLI. |
| Instalador | Sin cambio funcional obligatorio; verificar que no dependa del `valid` ambiguo. | No se modifica. |
| Contratos/adaptadores | Nuevos campos de durabilidad/journal y semántica fail-closed; evaluar versión. | No se implementa adaptador. |
| Documentación | Corregir afirmaciones de `INDETERMINATE` y documentar recuperación; no reescribir SPEC-ARCH-001. | No se modifica documentación existente en esta misión. |
| Registros existentes | Preservar bytes; schema upgrade explícito; grants no correlacionados no autorizan. | No se migran datos ahora. |

## 15. Informe de trazabilidad

### 15.1 Cobertura de la SPEC-ARCH-001

| AUD | Requisito existente | Cobertura | Brecha que cubre esta SPEC |
|---|---|---|---|
| AUD-01 | RF-001 (P0), SA-001/SA-003 | Parcial; contradicción entre “se permite” y “no reutilizable”; sin disparador exacto. | RF-012, AC-012. |
| AUD-02 | RF-005, RF-006 (P0), RF-008, SA-002/SA-006/SA-009 | Cubierto en resultado, no implementado; sin journal/escaneo explícito. | RF-013, AC-013. |
| AUD-03 | RF-008 (P1), SA-009 | Cubierto explícitamente; implementación lo viola. | RF-014, AC-014. |
| AUD-04 | RF-001, RF-006 (P0), SA-002; RF-004 para compatibilidad | Invariante general, sin regla de migración correlacionada. | RF-015, AC-015. |
| AUD-05 | RF-005 (P0), SA-006/SA-014; Audit API `Verify()` | Parcial; no enumera verificación por registro. | RF-016, AC-016. |

### 15.2 Matriz AUD → RF → AC → prueba → decisión

| AUD | RF | AC | Pruebas | Decisión pendiente |
|---|---|---|---|---|
| AUD-01 | RF-012 | AC-012a…d | Unitarias, carrera, reinicio | D-02, D-03 |
| AUD-02 | RF-013 | AC-013a…c | Journal, crash, multiproceso, reinicio | D-06 |
| AUD-03 | RF-014 | AC-014a…c | Fault injection, cuatro operaciones, reinicio | D-05 (contrato de resultado) |
| AUD-04 | RF-015 | AC-015a…c | Migración, firmas, eventos, originales | D-04 |
| AUD-05 | RF-016 | AC-016a…c | Matriz de manipulación, CLI, read-only | D-05 |

### 15.3 Fuera de esta trazabilidad

- AUD-06 a AUD-17 no se corrigen aquí. En particular, AUD-06 (fallback legacy), AUD-07 (truncación sin ancla), AUD-08 (migración concurrente), AUD-09 (replay/OIDC) y AUD-15 (docs sobre `INDETERMINATE`) siguen abiertos o pendientes de su propia decisión.
- SA-014 no se declara cumplido por esta SPEC; sólo se definen las pruebas que la corrección debe aportar.
- La aprobación de SPEC-ARCH-001 no se infiere de este documento. **D-01.**

## 16. Riesgos residuales

1. **No hay atomicidad real entre SQLite y filesystem.** El journal reduce la ventana y hace visible la ambigüedad; no la elimina. Un crash puede requerir reconciliación humana.
2. **La durabilidad física no se demuestra con mocks.** La inyección de `fsync` prueba manejo de errores; el hardware/filesystem objetivo debe probarse aparte.
3. **La invalidación estricta del desafío puede ser un vector de denegación de servicio** si un tercero posee el token y provoca fallos. La extensión exacta a state/sesión/scope es D-02; el mínimo de autenticación/firma es obligatorio.
4. **Rechazar grants históricos sin evento correlacionable puede bloquear aprobaciones legítimas.** La política de re-aprobación/cuarentena es D-04; no se resuelve técnicamente.
5. **La verificación integral no detecta truncación de cola ni pérdida de un sufijo** sin ancla externa (AUD-07). Puede detectar inconsistencias internas y registros manipulados, no historia completa.
6. **El store local no tiene réplica.** La pérdida o corrupción física requiere backup/restauración; no se promete recuperación automática.
7. **La compatibilidad de clientes que interpretan `allowed` como éxito durable** requiere actualización de contrato; hasta entonces, el riesgo de falsa assurance persiste.
8. **Los estados oficiales no se amplían.** Cualquier necesidad de un estado nuevo debe justificarse y aprobarse por separado; no se introduce aquí.
9. **OIDC y producción siguen bloqueados.** Ninguna corrección de estos P1 habilita el flujo de aprobación humana real.
10. **Los P2/P3 siguen abiertos** y pueden afectar la garantía global aunque estos P1 se corrijan.

## 17. Decisiones pendientes de aprobación humana

| ID | Decisión | Opciones | Efecto | Bloquea |
|---|---|---|---|---|
| D-01 | Autoridad formal de SPEC-ARCH-001 | (a) aprobar/hash y actualizar su estado; (b) mantener DRAFT y no declarar cobertura. | Determina si existe baseline normativo. | Aprobación de esta SPEC. |
| D-02 | Disparador de invalidación | (a) sólo autenticación/firma; (b) todo fallo posterior a la prueba de posesión (state/sesión/scope/revisión), excluyendo `SETUP_INCOMPLETE`/configuración; (c) rotación automática. | Seguridad vs. fricción/DoS. | RF-012 completo. |
| D-03 | Reemisión del desafío | (a) nuevo desafío sobre la misma solicitud; (b) nueva solicitud obligatoria; (c) `AUTH_FAILED` + nueva solicitud. | UX y estado de la solicitud. | RF-012.5/RF-012.6. |
| D-04 | Grants históricos no correlacionados | (a) rechazar toda migración; (b) cuarentenar y bloquear; (c) exigir re-aprobación; (d) aceptar con marca legacy (no recomendada). | Disponibilidad histórica vs. trazabilidad. | RF-015/migración. |
| D-05 | Contrato de verificación y compatibilidad | (a) `valid` = store íntegro, `chain_valid` separado; (b) mantener `valid` de cadena y agregar `ok`; (c) nueva versión de protocolo. | Consumidores CLI/adaptadores. | RF-016/AC-016. |
| D-06 | Journal y recuperación | (a) journal en el store SQLite; (b) journal separado con atomicidad equivalente; (c) reutilizar eventos de auditoría enriquecidos. | Esquema, migración y recuperación. | RF-013. |
| D-07 | Datos existentes con huérfanas/no correlacionados | (a) bloquear arranque; (b) arrancar en modo sólo lectura; (c) cuarentena con operador. | Disponibilidad y recuperación. | Implementación. |
| D-08 | Alcance de P2/P3 | (a) estrictamente P1; (b) incluir AUD-06/AUD-15 por dependencia; (c) otro. | Evita ampliar la misión silenciosamente. | Plan final. |

Recomendación preliminar, sujeta a aprobación: D-02(a) como mínimo obligatorio y evaluar (b); D-03(a) con token anterior permanentemente muerto; D-04(b)/(c) antes que aceptar evidencia no correlacionada; D-05(a) por fail-closed; D-06(a) por atomicidad y menor superficie; D-07(a) para no servir datos dudosos; D-08(a) para mantener el alcance.

## 18. Condición de aprobación

Esta SPEC queda en **DRAFT**. No se implementa, no se modifica ningún componente y no se declara producción habilitada. La aprobación debe ser explícita sobre:

1. el texto, versión y hash de esta SPEC;
2. las decisiones D-01 a D-08 que correspondan;
3. el alcance estricto de los cinco P1, sin OIDC ni correcciones P2/P3 no autorizadas.

Hasta entonces, las garantías descritas son requisitos propuestos, no comportamiento demostrado.
