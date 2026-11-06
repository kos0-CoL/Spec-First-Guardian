---
spec_id: SPEC-ARCH-002
title: "Remediación de hallazgos P1 de Etapa B"
status: DRAFT
version: 0.2.1
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
base_commit: "d8a681c6226f89b123a2802b3aeb02b18f029368"
supersedes: "0.2.0 (DRAFT)"
parent_spec: "SPEC-ARCH-001-HARDENING.md"
parent_spec_sha256: "77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda"
decisions: "DECISIONS-ARCH-002-SECURITY-REMEDIATION.md"
---

# SPEC-ARCH-002 — Remediación de hallazgos P1 de Etapa B

**Estado:** DRAFT; no aprobada, no autoriza implementación ni producción.<br>
**Versión:** 0.2.1; revisión documental que sustituye al borrador 0.2.0.<br>
**Fecha:** 2026-11-06<br>
**Autor:** Buffy — propuesta técnica para revisión humana.<br>
**Baseline documental:** `d8a681c6226f89b123a2802b3aeb02b18f029368`; el código auditado es el de `094f93d065cbbedce7d9ff35aeb862db92422476`.<br>
**Evidencia de origen:** `docs/audits/AUDIT-ETAPA-B-094F93D.md`.<br>
**SPEC de referencia:** `SPEC-ARCH-001-HARDENING.md`, versión 0.1.0, SHA-256 `77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda`.<br>
**Registro de decisiones:** `DECISIONS-ARCH-002-SECURITY-REMEDIATION.md`; toda decisión abierta permanece `PENDING USER DECISION`.<br>
**Autoridad documental:** este documento no modifica la SPEC-ARCH-001, no corrige código, no cambia tests, configuración, instalador ni estados oficiales, y no habilita OIDC ni producción. Sólo una aprobación humana explícita de esta SPEC, versión y hash autorizará implementación.

> **Nota de autoridad:** no se encontró en el expediente examinado una aprobación formal de SPEC-ARCH-001: su archivo se autodeclara `DRAFT` y “no aprobada”. Esta SPEC **puede aprobarse explícitamente de forma condicional** aunque SPEC-ARCH-001 permanezca `DRAFT`; esa aprobación no aprueba la SPEC-ARCH-001 ni permite declarar conformidad normativa completa. Aprobar SPEC-ARCH-002, aprobar SPEC-ARCH-001 y declarar conformidad completa son actos distintos y requieren evidencia separada. La cuestión queda en **D-01**.

## 1. Resumen ejecutivo

La auditoría de Etapa B identificó cinco hallazgos P1 y ningún P0 demostrado:

| ID | Defecto | Efecto observable |
|---|---|---|
| AUD-01 | El desafío no se invalida tras un fallo de autenticación/firma. | El mismo token puede reintentarse; la prueba actual incluso lo reutiliza con éxito después del fallo. |
| AUD-02 | No hay journal durable de la operación antes/después de la escritura. | Una caída entre el `intent` y el `result` deja el archivo modificado y la autoridad en `HEALTHY`. |
| AUD-03 | `_fsync_dir` silencia `OSError`. | Una escritura no durable se reporta como exitosa y el gate puede registrar `executed=True`. |
| AUD-04 | La migración importa grants sin exigir un evento `approval` correlacionado. | Un grant histórico puede quedar autorizable sin la evidencia de commit que lo justifica. |
| AUD-05 | `--verify-storage` sólo verifica la cadena. | Declara `valid=True` con solicitudes/grants manipulados o salud bloqueada. |

La corrección es acotada en alcance funcional, pero atraviesa almacenamiento, ciclo de aprobación, gate, filesystem, migración, CLI y compatibilidad. Las cinco correcciones P1 deben implementarse, pero AUD-02 no se declarará completamente cerrado mientras no exista un mecanismo autorizado de resolución de intenciones huérfanas. Esta SPEC no implementa ninguna.

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
| AUD-04 | `authority_store.py:820-846` verifica firma y evento no vacío; `899-922` inserta el grant; `924-966` importa eventos sin correlacionarlos. Además, `authority_service.py:533-553` (`_load_bundle`) lee `approvals/{spec_id}-{version}.json` si el store no tiene el grant. | Cadena legacy sin `approval`: migración `completed`, grant recuperable, eventos `request`, `challenge`, `storage_migration`. El fallback puede devolver el mismo grant sin pasar por la correlación canónica. |
| AUD-05 | `authority_store.py:656-677` sólo llama `verify_chain()`; `authority_service.py:1502-1545` usa ese `valid` para el CLI. | Solicitud/grant manipulados o `health=AUDIT_INCOMPLETE`: `valid=True`; `get_request`/firma sí detectan el problema al usar. |

### 2.3 Contradicciones y requisitos insuficientes

1. **SPEC-ARCH-001 se declara DRAFT.** Su frontmatter dice `status: DRAFT` y su encabezado dice “no aprobada”. La misión la trata como referencia. Es una decisión de autoridad documental, no una interpretación técnica: D-01 distingue la aprobación condicional de SPEC-ARCH-002 de la aprobación de SPEC-ARCH-001 y de la conformidad normativa completa. **D-01.**
2. **RF-001 usa dos fórmulas distintas para el desafío.** Permite “challenge invalidado al fallar auth” —lo que suena optativo— y a la vez exige “no volverlo reutilizable”. La segunda es obligatoria; la primera no define el disparador exacto ni cómo emitir uno nuevo. **D-02 y D-03.**
3. **La implementación declara el comportamiento contrario.** `IMPLEMENTATION-ARCH-001.md` afirma que “un fallo de autenticación no consume el desafío”, y la prueba lo consagra. Eso contradice RF-001 y el expediente de auditoría; no puede usarse como contrato.
4. **RF-006/RF-008 exigen `INDETERMINATE` y fail-stop, pero no definen el journal de operación ni el escaneo de arranque.** La documentación del store afirma una garantía que el código no implementa. Esta SPEC convierte el resultado en requisito verificable; AUD-15 queda como corrección documental posterior, fuera de alcance.
5. **RF-001/RF-006 exigen grant + evento de aprobación, pero la migración no explicita la correlación.** No se puede inferir por posición, nombre de archivo o `request_id`; hace falta una regla verificable. **D-04.**
6. **RF-005 exige verificar salud y cadena, pero no enumera la verificación de cada solicitud, grant, firma y correlación.** El `--verify-storage` actual interpreta “cadena válida” como “store válido”, lo que es insuficiente. **D-05.**
7. **La compatibilidad de registros históricos no está decidida.** Un grant firmado sin evento correlacionable es criptográficamente válido pero no satisface la invariante de aprobación. Rechazarlo puede bloquear historia legítima; aceptarlo debilita la trazabilidad. **D-04.**
8. **El fallback legacy puede eludir la corrección de AUD-04.** La revisión independiente (OBS-01) comprobó que `_load_bundle` devuelve un approval desde el directorio histórico cuando el store no lo encuentra. La migración y el fallback son dos rutas de autorización distintas; cerrar sólo la migración no demuestra que un grant no correlacionado no pueda autorizar. La SPEC añade el requisito mínimo de paridad de verificación y pruebas negativas, sin absorber la remediación general de AUD-06. **D-04/D-08/OBS-01.**
9. **La reconciliación humana no está demostrada.** `reconcile` exige UID administrador y reautenticación, pero en producción `_approval_event` sigue denegando por `SETUP_INCOMPLETE`; la prueba existente usa identidad simulada. Además, `reconcile` sólo cierra una auditoría incompleta, no resuelve una operación huérfana. No se inventa un mecanismo nuevo: la resolución de huérfanas queda bloqueada hasta que exista uno autorizado. **OBS-03/D-07.**

## 3. Alcance

### 3.1 Incluido

- AUD-01: invalidación durable y de un solo uso del desafío después de un fallo de autenticación/firma, sin aprobación falsa.
- AUD-02: journal durable de operaciones, detección al arrancar, bloqueo persistente por intención huérfana, preservación de evidencia e inspección de sólo lectura. La resolución humana sólo puede existir si ya hay un mecanismo administrativo autorizado; esta misión no implementa ni inventa ese mecanismo y no declara AUD-02 completamente cerrado sin él.
- AUD-03: propagación de errores de `fsync` de archivo/directorio y resultado de durabilidad veraz.
- AUD-04: correlación obligatoria entre grant migrado y evento `approval`; rechazo fail-closed de evidencia no correlacionable.
- AUD-05: verificación integral del store y contrato veraz de `--verify-storage`.
- Pruebas unitarias, multiproceso, de reinicio y de inyección de fallos necesarias para demostrar lo anterior.
- Compatibilidad de esquema, CLI y registros existentes estrictamente en lo que estas correcciones exigen.

### 3.2 Excluido

- Implementar OIDC, callback Authorization Code + PKCE, UI humana, sesión de navegador o habilitar producción.
- Corregir AUD-06 a AUD-17, salvo el **ajuste mínimo anti-bypass** del fallback legacy directamente necesario para AUD-04 (RF-015.7–RF-015.9 y AC-015d). La remediación general de AUD-06, el rediseño del almacenamiento legacy y la eliminación completa del fallback quedan fuera de alcance.
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
- Existen al menos dos rutas de lectura de autorizaciones: el store canónico y el fallback de `approvals/{spec_id}-{version}.json`. Ambas deben satisfacer la misma verificación de seguridad; el fallback no es una excepción de política.
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
- **Rechazo definitivo de autenticación:** el proveedor o el verificador establece, sin ambigüedad, que la credencial o la identidad no es aceptable: firma/claims inválidos, `issuer`/`audience`/`subject`/nonce/exp/iat/auth_time incorrectos, replay, o denegación explícita del proveedor. Consume e invalida el desafío; no hay aprobación.
- **Rechazo definitivo de binding/revisión:** tras demostrar posesión del desafío, `state`, sesión, PKCE, fingerprint de revisión, scope o contenido no coinciden de forma concluyente. No es un fallo transitorio y nunca puede aprobar; **D-02 determina expresamente si se clasifica como rechazo definitivo y, por tanto, si consume el desafío**. Mientras D-02 esté pendiente no se presume esa clasificación.
- **Fallo transitorio del proveedor:** timeout, error de red, `5xx`, indisponibilidad o rate limit sin respuesta definitiva de identidad. No consume el desafío, no aprueba y debe auditarse; se permite reintento acotado dentro de la vigencia del desafío y con backoff.
- **Error de configuración:** `SETUP_INCOMPLETE`, proveedor no configurado, trust store ausente o callback no disponible. No es un rechazo de identidad, no consume el desafío y no aprueba.
- **Firma rechazada:** una firma producida que no verifica es un fallo definitivo de integridad: invalida el desafío y bloquea la aprobación. **No** se confunde con el firmante no disponible o un error interno antes de producir firma, que es técnico, no consume el desafío y no aprueba.
- **Commit indeterminado:** la autenticación/firma pudo completarse pero no puede demostrarse el estado del commit; se bloquea como `INDETERMINATE`/`RECONCILIATION_REQUIRED`, no se reintenta a ciegas y no se declara éxito.
- **Intención durable:** registro persistido y confirmado antes de cualquier efecto en el filesystem.
- **Resultado durable:** registro persistido del efecto y de la durabilidad observada.
- **Intención huérfana:** intención durable sin resultado terminal correlacionado, tras reinicio o nueva instancia.
- **Operación resuelta:** intención huérfana acompañada por evidencia humana que determina si el target fue modificado, sólo cuando existe un mecanismo administrativo autorizado; no implica reejecución ni se declara disponible por el hecho de definirla.
- **Store válido:** todas las comprobaciones de RF-016 pasan y la salud es `HEALTHY`; no significa que la historia sea completa frente a un ancla externa (AUD-07 sigue abierto).
- **Aprobación condicional de SPEC-ARCH-002:** autorización humana explícita del texto, versión y hash de esta SPEC con la condición documental de que D-01 sigue pendiente. Permite continuar la revisión y, tras cumplir las demás compuertas, la implementación autorizada; no aprueba SPEC-ARCH-001 ni acredita conformidad normativa completa.
- **Aprobación de SPEC-ARCH-001:** acto humano separado sobre el texto, versión y hash de la SPEC padre. No se infiere de aprobar SPEC-ARCH-002.
- **Conformidad normativa completa:** condición que exige que el baseline heredado esté formalmente aprobado y trazado. No puede declararse mientras D-01 permanezca pendiente.

## 5. Requisitos funcionales

### RF-012 — Invalidación durable del desafío tras fallo de autenticación (AUD-01)

**Problema.** El desafío se consume sólo en el commit posterior a la firma. Un fallo de autenticación o firma deja el token reutilizable y no deja evidencia de la tentativa.

**Requisitos:**

- **RF-012.1** Un intento que presenta un desafío cuyo hash coincide con el almacenado DEBE ser de un solo uso para el éxito. Un mismo token no puede producir dos aprobaciones ni dos grants.
- **RF-012.2** Un **rechazo definitivo de autenticación/firma** posterior a la posesión del desafío DEBE invalidarlo permanentemente y registrar evidencia durable. La solicitud NO DEBE quedar `APPROVED`, NO DEBE emitirse grant y el mismo token NO DEBE volver a aceptarse. Un fallo transitorio del proveedor, un error de configuración (`SETUP_INCOMPLETE`, proveedor no configurado), un error técnico anterior a la firma o el firmante no disponible NO son rechazos de identidad y NO DEBEN consumir el desafío.
- **RF-012.2a** La clasificación de una divergencia definitiva de `state`/sesión/PKCE/fingerprint/scope/revisión como **rechazo definitivo de binding** es una decisión de seguridad separada (**D-02**). Si D-02 la clasifica como rechazo definitivo, RF-012.2 se aplica también a esa clase y el token no puede reutilizarse. Si D-02 no la clasifica así, la divergencia sigue sin poder aprobar ni emitir grant, pero el consumo del desafío debe seguir la opción aprobada. En ningún caso se presume una opción mientras D-02 esté pendiente.
- **RF-012.3** La invalidación y la evidencia del fallo DEBEN persistirse de forma durable y atómica respecto de la comprobación de uso. Si no pueden persistirse, la tentativa DEBE fallar cerrada: no hay aprobación, no se declara salud `HEALTHY` y la autoridad no concede nuevas operaciones hasta recuperar.
- **RF-012.4** Un intento con hash de desafío incorrecto, solicitud inexistente, token ausente o formato inválido NO DEBE consumir un desafío válido; no debe permitir que un tercero sin posesión del token agote desafíos ajenos.
- **RF-012.5** La invalidación DEBE usar una comprobación y actualización atómicas (compare-and-swap o equivalente). Si dos intentos compiten, como máximo uno puede consumir el desafío; el otro DEBE denegarse. Ningún resultado de la carrera puede ser `APPROVED` sin autenticación y commit completos.
- **RF-012.6** La autoridad PUEDE emitir un desafío nuevo para la misma solicitud sólo mediante una acción administrativa explícita, no automática, y sólo si la solicitud no está `APPROVED` y la SPEC/alcance no cambiaron. El token anterior DEBE quedar permanentemente inutilizable; emitir uno nuevo no revalida el anterior. La elección entre reemitir sobre la misma solicitud o exigir una solicitud nueva es **D-03**.
- **RF-012.7** Un fallo de commit con resultado ambiguo NO DEBE presentarse como éxito ni permitir un reintento ciego. Si no puede demostrarse que no hubo commit, el store/authority DEBE bloquearse como `INDETERMINATE`/`RECONCILIATION_REQUIRED`; no se desbloquea sin resolución autorizada y, si ese mecanismo no existe, permanece bloqueado.
- **RF-012.8** El fallo DEBE dejar evidencia consultable sin incluir el token, el código OIDC, el nonce ni secretos equivalentes. La evidencia debe permitir distinguir, como mínimo, `authentication_rejected`, `binding_rejected` (si D-02 clasifica el binding como rechazo definitivo; en otro caso, `binding_mismatch`), `provider_unavailable`, `configuration_error`, `challenge_invalidated`, `challenge_expired` y `approval_confirmed`.
- **RF-012.9** Un fallo transitorio DEBE registrarse, aplicar backoff y limitar reintentos, pero NO DEBE invalidar automáticamente el desafío ni rotarlo. La solicitud permanece pendiente y sin aprobación. Si se agota la vigencia o el límite de reintentos, el desafío expira y se requiere una reemisión administrativa conforme a D-03; el resultado no se etiqueta como rechazo de identidad.
- **RF-012.10** El estado de la tentativa y la causa deben ser consultables sin secretos. Un error técnico nunca puede convertirse en `APPROVED`, aunque el proveedor haya podido autenticar: la aprobación sólo existe después de un commit completo y durable.
- **RF-012.11** Si la autenticación/firma tuvo éxito pero el commit es ambiguo, el desafío NO DEBE reutilizarse para un reintento ciego; la autoridad DEBE bloquearse como `INDETERMINATE`/`RECONCILIATION_REQUIRED` y preservar la evidencia.

**Tabla de decisión propuesta (sujeta a D-02).** Las filas marcadas «obligatorio» son el mínimo de esta SPEC; las demás dependen de una decisión que el usuario debe aprobar o rechazar. D-02 no puede debilitar el no-uso de un token incorrecto, la no aprobación ante errores, el CAS ni la prohibición de reutilizar cualquier supuesto que se clasifique como rechazo definitivo:

| Resultado observado | ¿Consume/invalida el desafío? | ¿Aprueba? | Estado/evidencia |
|---|---|---|---|
| Token ausente, hash incorrecto, formato no interpretable o solicitud inexistente | No; no hay posesión demostrada | No | `challenge_not_presented`/`bad_challenge`; no altera un desafío válido |
| Firma/claims/subject/nonce/issuer/audience/exp/iat/auth_time inválidos; replay; denegación explícita | Sí; rechazo definitivo (obligatorio) | No | `authentication_rejected`; desafío invalidado durablemente |
| `state`, sesión, PKCE, fingerprint, scope o revisión divergentes tras posesión | **Pendiente D-02:** si D-02 lo clasifica como rechazo definitivo, sí; si no, no se presume el consumo | No, en ninguna opción | `binding_rejected` si D-02-b; en otro caso, `binding_mismatch`; sin aprobación |
| Firma producida que no verifica | Sí; rechazo definitivo de integridad (obligatorio) | No | `signature_invalid`; salud/registro coherente |
| `SETUP_INCOMPLETE`, proveedor/callback/trust store no configurado | No | No | `configuration_error`; desafío intacto |
| Timeout, red, `5xx`, indisponibilidad o rate limit sin respuesta definitiva | No; backoff y límite de reintentos | No | `provider_unavailable`; desafío activo hasta expirar |
| Firmante no disponible o error interno antes de producir firma | No | No | `technical_error`; no se declara rechazo de identidad |
| Autenticación/firma correctas, commit ambiguo | Sí; no reutilizar (obligatorio) | No | `INDETERMINATE`/`RECONCILIATION_REQUIRED` |

**Transiciones internas del desafío.** Estos nombres describen el ciclo de vida del desafío; no son estados documentales, de solicitud, de autorización ni de salud, y pueden representarse con campos existentes. Las transiciones son normativas:

| Estado interno | Entrada | Salida permitida | Prohibición |
|---|---|---|---|
| `ACTIVE` | Desafío emitido, no usado | `AUTHENTICATING` por CAS; `EXPIRED` por TTL | No se usa para aprobar; no hay dos intentos simultáneos. |
| `AUTHENTICATING` | Intento con hash correcto y CAS ganador | `AUTHENTICATED` si auth/firma correctas; `ACTIVE` sólo por fallo transitorio/configuración/técnico, o si D-02 decide no consumir binding; `INVALIDATED` por rechazo definitivo | No aprobar; no emitir grant; no reutilizar el intento cuando sea definitivo. |
| `AUTHENTICATED` | Auth/firma correctas, pendiente de commit | `CONSUMED` sólo con commit completo y durable; `INDETERMINATE` si el commit es ambiguo; `INVALIDATED` si el commit se rechaza definitivamente | No reintentar a ciegas; no devolver el token a `ACTIVE`. |
| `CONSUMED` | Commit completo y durable | Terminal | No se reutiliza; no se reemite el mismo token. |
| `INVALIDATED` | Rechazo definitivo de auth/binding/firma o commit rechazado | Terminal; sólo un desafío nuevo puede sustituirlo (D-03) | No se resetea ni se revalida. |
| `EXPIRED` | TTL agotado | Terminal; reemisión administrativa (D-03) | No se usa para aprobar. |
| `INDETERMINATE` | Efecto/commit no demostrable | Sólo reconciliación autorizada; no es un estado de aprobación | No se reintenta, no se borra, no se declara éxito. |

**Límite de alcance.** El mínimo obligatorio es el rechazo definitivo de autenticación/firma. La clasificación de `state`/sesión/scope/revisión como rechazo definitivo de binding sigue pendiente de **D-02**: la recomendación es D-02-b, pero no se presenta como obligación aprobada. Por definición, cualquier supuesto que D-02 clasifique como rechazo definitivo nunca deja el desafío reutilizable. La rotación automática no se adopta: requiere autorización y no puede debilitar la propiedad de un solo uso. **D-02.**

**No cubierto por RF-012.** No se implementa el callback OIDC ni se acepta un token directo del agente. La producción sigue denegando por `SETUP_INCOMPLETE` hasta que exista el flujo aprobado de SPEC-ARCH-001.

### RF-013 — Journal durable de operaciones y recuperación de intenciones huérfanas (AUD-02)

**Problema.** El gate registra `intent` y `result` en transacciones separadas. Una caída entre ambos no deja marca durable; el arranque no detecta la intención huérfana y la autoridad queda `HEALTHY`.

**Requisitos:**

- **RF-013.1** Antes de cualquier efecto en el filesystem, la autoridad DEBE persistir una intención durable que identifique, como mínimo: operación, autorización, solicitud/contexto, proyecto/workspace, ruta relativa, tipo de operación, estado previo verificable (ausencia, digest e inode cuando exista), digest esperado del contenido cuando corresponda, timestamp e identidad de la instancia que ejecuta.
- **RF-013.2** Si la intención no puede persistirse y confirmarse, NO DEBE ejecutarse el efecto. La operación DEBE devolver denegación/`NOT_EXECUTED` y no debe dejar un archivo modificado.
- **RF-013.3** Después del efecto, la autoridad DEBE persistir un resultado terminal que registre si el efecto ocurrió, el digest/inode observable, la durabilidad y cualquier error. El resultado DEBE ser recuperable tras reinicio y correlacionable con la intención.
- **RF-013.4** Al abrir el store o arrancar cualquier instancia que pueda ejecutar operaciones, el sistema DEBE buscar intenciones sin resultado terminal. Si encuentra al menos una, NO DEBE declarar `HEALTHY`, NO DEBE conceder nuevas autorizaciones y DEBE marcar la salud con un estado existente de bloqueo (`AUDIT_INCOMPLETE` o `RECONCILIATION_REQUIRED`). No se autocura, no se borra la marca y no se reejecuta la operación.
- **RF-013.5** Cualquier resolución futura de una intención huérfana SÓLO PUEDE aceptarse con evidencia humana autenticada que indique si el target fue modificado y qué evidencia lo demuestra. Si existe un mecanismo autorizado, la resolución DEBE registrar un evento durable ligado al identificador de la intención. Si no existe, la operación permanece bloqueada conforme a RF-013.12; no se exige ni se simula un mecanismo. La salud NO DEBE volver a `HEALTHY` mientras quede alguna intención sin resolver.
- **RF-013.6** El journal DEBE cubrir los puntos de caída: antes de la intención, después de la intención y antes del efecto, después del efecto y antes del resultado, y después del resultado y antes de responder. Los dos puntos intermedios deben terminar en bloqueo/reconciliación, no en salud sana.
- **RF-013.7** Dos gates o procesos que intenten registrar la misma operación DEBEN producir como máximo una intención ejecutable y un resultado terminal. Un duplicado DEBE denegarse o resolverse como conflicto; nunca dos efectos no idempotentes.
- **RF-013.8** Cualquier gate que ejecute operaciones DEBE usar un sink durable que soporte el journal y la consulta de intenciones huérfanas. Si el sink no puede demostrar esa capacidad, DEBE denegar las operaciones en lugar de degradar a `intent`/`result` sin recuperación.
- **RF-013.9** La API de resultado DEBE distinguir `executed`, `durability` y `audit_complete`; `allowed` por sí solo NO DEBE interpretarse como éxito durable. Un cliente que ignore los campos nuevos no debe recibir una afirmación de éxito no demostrada.
- **RF-013.10** El journal y SQLite son dominios de persistencia distintos. La SPEC NO afirma atomicidad entre ambos: una operación cuyo efecto externo ocurrió pero cuyo resultado no pudo registrarse durablemente DEBE representarse como `INDETERMINATE`/`RECONCILIATION_REQUIRED`, nunca como éxito. La intención durable se confirma antes del efecto; el resultado se confirma después. Las ventanas entre ambos son parte del contrato, no un detalle oculto (recomendación D-06).
- **RF-013.11** La recuperación de una intención huérfana DEBE ser explícita y humana. Ningún proceso, reinicio, tarea de mantenimiento o agente puede resolverla, borrarla, revertirla ni reejecutarla automáticamente. La inspección de sólo lectura puede informar la anomalía, pero no la convierte en autorización.
- **RF-013.12** Si no existe un mecanismo administrativo autorizado que demuestre identidad humana reautenticada y aporte evidencia de la operación, la resolución permanece bloqueada. No se inventa un mecanismo alternativo ni se acepta una firma del propio agente. **OBS-03/D-07.**

**Límite de alcance.** No se especifica aquí la tabla, archivo, transacción o algoritmo concreto del journal; esas son decisiones de implementación (D-06). Lo normativo es que la intención preceda al efecto, que el resultado sea durable, que la falta de atomicidad se represente como ambigüedad y que una intención huérfana bloquee. La resolución sólo puede existir mediante un mecanismo administrativo autorizado; no se implementa uno en esta misión y AUD-02 no se declara completamente cerrado sin él.

### RF-014 — Durabilidad verificable de las operaciones de archivo (AUD-03)

**Problema.** `_fsync_dir` ignora `OSError`; el gate puede reportar éxito y `executed=True` aunque la entrada de directorio no sea durable.

**Requisitos:**

- **RF-014.1** Ningún componente DEBE ignorar un error de `fsync` de archivo o de directorio. Un error DEBE propagarse como fallo de durabilidad y no puede convertirse en `DURABILITY_CONFIRMED`.
- **RF-014.2** Para `create_file`, `modify_file` y `overwrite_file`, la secuencia observable DEBE incluir sincronización del contenido y sincronización del directorio que hace visible el nombre. Para `delete_file`, DEBE incluir la eliminación y la sincronización del directorio; el recibo debe conservar el digest/inode previo porque ya no hay contenido posterior que hashear.
- **RF-014.3** Si el `fsync` de archivo falla antes de que el cambio sea visible, el sistema DEBE intentar una limpieza segura y devolver `NOT_EXECUTED` o `INDETERMINATE`. Si esa limpieza falla, NO DEBE declarar éxito; debe bloquear.
- **RF-014.4** Si el `fsync` de directorio falla después de un rename, create o unlink, el cambio puede existir pero su persistencia ante crash no está confirmada. El resultado DEBE ser `EXECUTED_NOT_DURABLE` o `INDETERMINATE`, `audit_complete=false`, y la autoridad DEBE bloquear nuevas operaciones hasta reconciliar.
- **RF-014.5** Un filesystem que no soporta `fsync` de directorio DEBE tratarse como no soportado/fail-closed, no como éxito silencioso. La matriz de filesystems soportados debe declararse y probarse; no se extrapola a otros.
- **RF-014.6** El recibo de operación DEBE incluir, como mínimo: `executed`, `data_synced`, `directory_synced`, `durability`, digest/inode observable y referencia de auditoría. La ausencia de un fsync obligatorio no puede compensarse con un digest correcto del contenido.
- **RF-014.7** La recuperación NO DEBE revertir automáticamente una escritura o borrado cuyo `fsync` falló. Debe conservar la evidencia y exigir bloqueo/resolución autorizada si existe el mecanismo; si no existe, permanece bloqueada. Un rollback no autorizado puede destruir evidencia o afectar hardlinks.

**Cobertura.** RF-008 y SA-009 ya exigen este resultado. La implementación actual no lo cumple; esta SPEC no agrega una garantía nueva, sino un criterio verificable y un contrato de recibo.

### RF-015 — Correlación obligatoria de grants históricos (AUD-04)

**Problema.** La migración verifica la firma del grant y que `authorization_event_id` no esté vacío, pero no que ese identificador corresponda a un evento `approval` de la cadena importada o existente. Un grant firmado puede quedar autorizable sin el evento que justifica su commit.

**Requisitos:**

- **RF-015.1** Para cada grant que se pretenda importar, la migración DEBE verificar que su `authorization_event_id` corresponde a un evento `approval` verificable en la cadena de auditoría que se importa o que ya existe en el store.
- **RF-015.2** La correlación DEBE comprobar, cuando los campos estén presentes, que `spec_id`, `version`, `fingerprint`, `scope_sha256`/alcance y el identificador de evento del grant coinciden con la solicitud y el evento. No se admite correlación inferida por posición, nombre de archivo, orden de importación o `request_id` no firmado.
- **RF-015.3** Si un grant no tiene evento correlacionable, tiene un evento de otra solicitud/versión o el evento no es verificable, la migración NO DEBE insertarlo como activo ni registrar un `completed` incondicional. Según D-04, debe abortar toda la transacción o registrar el grant en cuarentena no autorizable con su fuente/hash; en ambos casos el CLI DEBE devolver un resultado no exitoso o `quarantined`, nunca un éxito integral.
- **RF-015.4** La migración DEBE ser todo-o-nada para los datos activos: no puede dejar solicitudes, grants o eventos activos parciales, ni un registro `meta` que sugiera éxito integral. Una cuarentena explícita, separada y no autorizable es la única excepción permitida si D-04 la autoriza. Los archivos originales DEBEN permanecer intactos en bytes.
- **RF-015.5** Una base ya migrada que contenga grants sin correlación DEBE ser detectada por la verificación de RF-016 y NO DEBE autorizar esos grants. El sistema no debe borrar ni “reparar” el grant automáticamente; debe bloquear y requerir la política humana de **D-04**.
- **RF-015.6** La migración de registros válidos debe seguir siendo idempotente y conservar la idempotencia existente; una segunda ejecución con las mismas fuentes no debe duplicar grants ni eventos.
- **RF-015.7** **Paridad de rutas (anti-bypass).** Toda ruta de autorización, incluida la compatibilidad legacy de `_load_bundle`/`approvals/*.json`, DEBE aplicar la misma verificación de firma, contexto, `authorization_event_id`↔evento `approval`, fingerprint/scope/versión y revocación que RF-015.1–RF-015.3. Ningún fallback puede devolver un grant no correlacionado, de otra solicitud o marcado como rechazado/cuarentenado. Una firma válida no sustituye el evento de aprobación.
- **RF-015.8** Si existe un registro de migración que marca un grant como rechazado o en cuarentena, ninguna ruta de lectura, incluido el fallback, puede usarlo para autorizar. El fallback DEBE ser de sólo lectura, no puede crear eventos ni migrar datos y no puede “reparar” la correlación.
- **RF-015.9** El fallback legacy sólo puede conservarse como compatibilidad de lectura si no elude RF-015.7. Su eliminación o rediseño general pertenece a AUD-06 y no se implementa aquí. La prueba negativa debe demostrar que un grant no correlacionado o cuarentenado no autoriza ni siquiera cuando el store canónico no lo contiene.

**Límite de alcance.** La decisión de rechazar toda la migración, cuarentenar grants individuales o exigir re-aprobación histórica es **D-04**. Esta SPEC exige el resultado de seguridad mínimo: ningún grant no correlacionado puede quedar autorizable ni puede declararse migración exitosa. El ajuste del fallback se limita a la paridad de verificación anterior; no absorbe la remediación completa de AUD-06.

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
- **RF-016.2** El resultado DEBE separar `chain_valid`, `store_valid`, `health` y `ok`, y DEBE publicar un contrato estable (propuesta sujeta a D-05):

| Campo | Significado | Regla |
|---|---|---|
| `chain_valid` | Integridad de la cadena de auditoría: secuencia, `prev`, hash y cuerpo. | Puede ser `true` con otros fallos; no implica store íntegro. |
| `store_valid` | Integridad estructural y semántica: esquema, `meta`, migración, solicitudes, grants/firmas, correlación, replay, revocación, journal/huérfanas y cuarentena. | `false` si falla cualquier comprobación de RF-016.1. |
| `health` | Estado de salud conocido: `HEALTHY`, `AUDIT_INCOMPLETE`, `AUDIT_CORRUPT`, `AUDIT_UNAVAILABLE` o `RECONCILIATION_REQUIRED`. | `UNKNOWN` o ausente se trata como no saludable. |
| `ok` | Resultado integral. | `true` sólo si `chain_valid && store_valid && health == "HEALTHY"` y no hay errores. |
| `valid` | Alias legacy de compatibilidad. | DEBE ser exactamente igual a `ok`; nunca significa “sólo cadena”. |
| `reason` / `chain_reason` | Motivo agregado y motivo específico de cadena. | No contienen secretos; pueden ser `null` si no aplica. |
| `checks` | Mapa de comprobaciones con `pass`, `fail`, `blocked` o `not_applicable`. | `not_applicable` no convierte un fallo en éxito. |
| `errors` | Lista determinista de errores con código, referencia y mensaje acotado. | Un solo error impide `ok=true`. |
| `counts` | Conteos de eventos, solicitudes, grants, grants en cuarentena, huérfanas y revocaciones. | Sólo informativo; no autoriza. |
| `migration` | Registro de migración y su estado. | Incompleto, fallido o ausente cuando se esperaba migración => `store_valid=false`. |
| `format_version` | Versión del contrato de verificación. | Permite a consumidores rechazar una versión desconocida. |

- **RF-016.3** El CLI DEBE devolver `0` sólo si `ok=true`. Cualquier store inválido, salud no `HEALTHY`, firma no verificable, grant no correlacionado o en cuarentena, intención huérfana, migración inconsistente o error de lectura/trust store DEBE producir `2` y un diagnóstico acotado. Un error de uso de la CLI puede usar el código convencional de `argparse`; no puede confundirse con `ok=true`.
- **RF-016.4** La verificación DEBE ser de sólo lectura lógica: no debe insertar, actualizar, borrar, migrar, reconciliar, reparar ni marcar salud. Si el store no existe, no puede abrirse o el almacén de confianza no está configurado, DEBE informar fallo cerrado; no debe crear un store nuevo ni asumir salud. La inspección de sólo lectura no es una vía de autorización.
- **RF-016.5** El diagnóstico NO DEBE incluir tokens, códigos, nonces, claves privadas, contenido completo de grants ni datos sensibles innecesarios. Puede incluir identificadores, conteos, motivos y rutas relativas.
- **RF-016.6** La verificación DEBE ser reproducible sobre el mismo store y no debe modificar el resultado por el orden de las filas; los conteos y errores deben ser deterministas.
- **RF-016.7** La compatibilidad del campo `valid` debe ser fail-closed: los consumidores existentes que lo interpretan como “store íntegro” no deben recibir `true` cuando la salud está bloqueada o un registro no verifica. `valid` DEBE ser alias de `ok`; conservar `valid` como “sólo cadena” queda prohibido. La forma exacta de conservar aliases y campos es **D-05**.
- **RF-016.8** La verificación NO DEBE crear, migrar, reconciliar ni modificar la base, el journal, los archivos legacy, WAL/SHM o la salud. Debe poder ejecutarse sobre una copia de sólo lectura y no debe convertir un store desconocido en uno vacío.

**Límite de alcance.** RF-016 no detecta truncación de la cola frente a un ancla externa (AUD-07), no verifica backups y no demuestra que el filesystem sea durable. Es una verificación del store local, no una prueba de historia completa. La forma física de los campos y la compatibilidad de adaptadores son D-05.

## 6. Requisitos de seguridad

- **SR-001 — Fail-closed.** Cualquier duda de integridad, autenticación, durabilidad o recuperación debe denegar nuevas autorizaciones; nunca degradar a `HEALTHY` por conveniencia.
- **SR-002 — Sin éxito falso.** Ninguna API, CLI o evento puede declarar éxito, durabilidad o aprobación si falta una evidencia obligatoria. `allowed`, `executed`, `durability` y `audit_complete` no son intercambiables.
- **SR-003 — Evidencia durable y correlacionada.** Desafío, intención, resultado, grant y evento de aprobación deben poder correlacionarse por identificadores persistidos; una firma válida no sustituye la evidencia de commit.
- **SR-004 — Un solo uso y carrera segura.** El desafío y el grant se consumen una vez; la concurrencia no produce dos autorizaciones ni dos efectos.
- **SR-005 — Reconciliación humana, cuando existe.** Una intención huérfana o un resultado no durable sólo puede resolverse con identidad administrativa reautenticada y evidencia mediante un mecanismo autorizado; si el mecanismo no existe, no se resuelve ni se auto-repara.
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
- **INV-11** Ninguna ruta de autorización, incluido el fallback legacy, puede devolver un grant que no satisfaga RF-015.1–RF-015.3; una ruta alternativa no puede eludir la correlación.
- **INV-12** Un fallo transitorio o de configuración nunca se convierte en rechazo de identidad, aprobación ni consumo permanente del desafío; un rechazo definitivo nunca deja el desafío reutilizable.
- **INV-13** `valid` es alias exacto de `ok`; `chain_valid=true` no implica store íntegro.
- **INV-14** La inspección de sólo lectura, el diagnóstico y la cuarentena no autorizan operaciones ni sustituyen una decisión humana.

## 8. Criterios de aceptación verificables

| ID | Criterio | Evidencia mínima |
|---|---|---|
| AC-012a | Tras un rechazo definitivo real de autenticación/firma (proveedor que deniega o firma producida no verificable) con desafío válido, la solicitud no está `APPROVED`, no hay grant, el fallo queda registrado y el mismo desafío es rechazado al reintentar, incluso tras reinicio. | Unitario + store nuevo; evento durable `authentication_rejected`/`signature_invalid`; `approve` posterior con el mismo token denegado. |
| AC-012b | Un desafío nuevo, emitido por acción administrativa explícita tras la invalidación, funciona; el anterior sigue denegado y la solicitud/alcance siguen sin aprobación automática. | Unitario + store nuevo; token anterior rechazado; evento `challenge_reissued`; scope/fingerprint sin cambios. |
| AC-012c | Dos intentos concurrentes con el mismo desafío producen como máximo un éxito; un fallo definitivo no puede convivir con una aprobación. | Multiproceso con `fork`; exactamente 0 o 1 grant, nunca 2; sin `APPROVED` por el intento fallido. |
| AC-012d | Un intento con token incorrecto no consume el desafío válido. | Unitario; el token correcto sigue funcionando si no hubo fallo autenticado. |
| AC-012e | Un timeout, error de red, `5xx`, indisponibilidad o rate limit sin respuesta definitiva no consume ni invalida el desafío, no aprueba, deja evidencia y permite un reintento acotado dentro de la vigencia. | Proveedor simulado que agota el tiempo/falla; el mismo desafío sigue activo; `SETUP_INCOMPLETE` separado; no hay grant ni `APPROVED`. |
| AC-012f | `SETUP_INCOMPLETE`/proveedor no configurado no consume el desafío ni se clasifica como rechazo de identidad. | Prueba de configuración; `challenge_used=false`; estado de setup; sin aprobación. |
| AC-012g | La prueba cubre la clasificación aprobada en D-02 para binding/revisión: si D-02-b, el rechazo definitivo invalida el desafío y no permite reutilizarlo; si otra opción, no se presume consumo, pero nunca hay aprobación ni grant. La prueba no puede marcarse PASS con D-02 pendiente. | Unitario por cada binding; decisión D-02 registrada con la alternativa elegida; evento/resultado coherente; sin `APPROVED` ni grant en ninguna opción. |
| AC-012h | El firmante no disponible antes de producir firma se trata como error técnico, no como rechazo de identidad: no aprueba, no consume el desafío y no se etiqueta `authentication_rejected`. | Inyección de error del firmante; desafío activo; sin grant; reintento permitido sólo si la política lo autoriza. |
| AC-013a | Si el proceso muere después de la intención y antes del resultado, al reiniciar no hay `HEALTHY`, no se conceden nuevas operaciones y no se reejecuta el efecto. | Subproceso con `os._exit(9)` en cada ventana; `valid=false`/salud bloqueada; archivo y journal preservados. |
| AC-013b | Sin un mecanismo administrativo autorizado, una intención huérfana permanece bloqueada: `reconcile` no la resuelve, no se borra, no se reejecuta y la salud no vuelve a `HEALTHY`. La inspección de sólo lectura y la preservación de evidencia sí funcionan. No se simula ni se exige un mecanismo inexistente. | Intento de `reconcile` genérico: no resuelve; snapshot/hash demuestra preservación; lectura de diagnóstico funciona; reinicio mantiene el bloqueo; ninguna firma de agente se acepta. |
| AC-013c | Una caída antes de la intención no deja efecto; una caída después del resultado conserva el resultado y no duplica la operación. | Matriz de puntos de caída; hashes y eventos antes/después. |
| AC-014a | Un fallo de `fsync` de directorio en `create_file`, `modify_file`, `overwrite_file` o `delete_file` no produce `DURABILITY_CONFIRMED` ni un éxito de API. | Inyección de `OSError` por operación; `EXECUTED_NOT_DURABLE`/`INDETERMINATE`; bloqueo. |
| AC-014b | Un fallo de `fsync` de archivo antes del rename no deja un target alterado; si la limpieza falla, el resultado es indeterminado y bloquea. | Inyección en archivo/temporal; target y temp inspeccionados; sin éxito. |
| AC-014c | Tras un fallo de durabilidad, un reinicio no devuelve `HEALTHY` ni permite operaciones sin reconciliación. | Store nuevo + Authority nueva; salud bloqueada persistente. |
| AC-015a | Una migración con grant sin evento `approval`, evento de otra solicitud, campos divergentes o firma inválida no inserta ese grant como activo ni registra un `completed` incondicional; según D-04, aborta o lo marca en cuarentena no autorizable, y los originales no cambian. | Fixtures de migración; `MigrationError` o estado `quarantined`; 0 grants activos; hashes de archivos iguales. |
| AC-015b | Una migración válida conserva grants, solicitudes, eventos e idempotencia, y una segunda ejecución no duplica. | Fixture válido; `already_migrated`; conteos y hashes. |
| AC-015c | Un store existente con grant no correlacionado no autoriza ese grant y `verify-storage` lo reporta. | Base manipulada/fixture; `get_grant` o autorización denegada; `ok=false`. |
| AC-015d | **Fallback anti-bypass:** con el store canónico sin el grant, un grant legacy no correlacionado, de otra solicitud o marcado rechazado/cuarentenado no autoriza por `_load_bundle`/`approvals/*.json`; la ruta devuelve denegación y no crea eventos. | Prueba negativa que coloca un archivo legacy y un store sin grant; `authorize`/`verify_approval` denegados; `ok=false`; original intacto. |
| AC-015e | Si D-04 elige cuarentena, los grants en cuarentena se preservan con su hash/fuente, no se insertan como activos, no autorizan y `verify-storage` los reporta; no se borran ni se “reparan”. | Fixture con grant no correlacionado; registro de cuarentena; `counts.quarantined_grants=1`; autorización denegada; bytes originales iguales. |
| AC-016a | Solicitud manipulada, grant manipulado, firma inválida, evento faltante, grant en cuarentena, intención huérfana, migración inconsistente o salud bloqueada producen `ok=false`/`valid=false` y exit `2`. | Matriz de manipulación; `chain_valid` puede seguir true; `store_valid=false`; `valid` igual a `ok`. |
| AC-016b | Un store íntegro y saludable produce `ok=true`, `chain_valid=true`, `store_valid=true`, `health=HEALTHY`, `valid=true`, exit 0, sin mutaciones. | Snapshot antes/después; hash lógico o traza SQLite; salida JSON completa. |
| AC-016c | Un store inexistente, inaccesible o sin trust store no se crea ni se declara válido; el resultado es fail-closed y no muta nada. | CLI sobre ruta temporal; exit 2; sin archivo nuevo; salida con error. |
| AC-016d | `valid` es alias exacto de `ok` y nunca refleja sólo la cadena; un consumidor que ignora `store_valid` no recibe `valid=true` ante un store inválido. | Caso con cadena válida y grant no correlacionado: `chain_valid=true`, `store_valid=false`, `ok=false`, `valid=false`, exit 2. |
| AC-017 | No se introduce ningún estado oficial nuevo y los siete estados documentales siguen exactamente intactos; la prueba verifica el conjunto y las transiciones permitidas, no sólo una lista textual. | **TST-09** `test_document_state_contract_is_unchanged` en `tests/test_state_contract.py`: compara el conjunto con los siete estados, comprueba que un estado desconocido es rechazado y que la SPEC-ARCH-001 no fue modificada; ejecutar antes/después del cambio. |
| AC-018 | La corrección no implementa OIDC ni habilita producción; el camino de producción sigue denegando por `SETUP_INCOMPLETE`; no se acepta un token directo como login. | Prueba de estado/CLI; revisión de diff; sin callback/UI; `SETUP_INCOMPLETE` sigue siendo el resultado de producción. |

## 9. Escenarios de fallo

| Escenario | Estado esperado | Prohibido |
|---|---|---|
| Rechazo definitivo de autenticación/firma con token válido | Desafío invalidado, solicitud no aprobada, evento durable, autoridad sana si la invalidación se persistió. | Reutilizar el token; `APPROVED`; grant; alegar éxito. |
| Fallo de `state`/sesión/scope/revisión con token válido | Rechazo definitivo de binding recomendado (D-02-b): desafío invalidado, sin aprobación. | Aprobar sin autenticación o ignorar el fallo. |
| `SETUP_INCOMPLETE`/configuración incompleta | No consume el desafío, no aprueba; sigue el bloqueo de producción. | Clasificarlo como rechazo de identidad; consumir el token. |
| Timeout/red/`5xx`/proveedor no disponible | No consume ni invalida; backoff y reintento acotado; sin aprobación. | Invalidación permanente automática; aprobar por error técnico. |
| Firmante no disponible antes de firmar | Error técnico, no rechazo de identidad; sin aprobación ni consumo. | Declarar firma rechazada; reutilizar para aprobar. |
| Caída antes de la intención | Sin efecto; al reiniciar no hay huérfana. | Crear archivo sin journal. |
| Caída después de la intención y antes del efecto | Intención huérfana; salud bloqueada; sin nuevas operaciones. | Reejecutar o borrar la intención automáticamente. |
| Caída después del efecto y antes del resultado | Intención huérfana; archivo puede existir; bloqueo y reconciliación. | Declarar `HEALTHY`; repetir la escritura; borrar el archivo. |
| `fsync` de archivo falla antes del rename | Limpieza segura o indeterminado; sin éxito. | `DURABILITY_CONFIRMED`; target alterado silenciosamente. |
| `fsync` de directorio falla después de rename/unlink | `EXECUTED_NOT_DURABLE`/`INDETERMINATE`; bloqueo. | Éxito; `allowed` interpretado como durable. |
| Disco lleno/IO error durante journal o resultado | Fallo cerrado; sin efecto si falta intención; bloqueo si el resultado es dudoso. | Continuar con salud sana o auto-reparar. |
| Migración con grant sin evento correlacionado | Rechazo o cuarentena no autorizable según D-04; sin grant activo; originales intactos. | Insertar grant; marcar `completed`; borrar fuente. |
| Fallback legacy con grant no correlacionado | Denegación; sin evento nuevo; no autoriza. | Devolver el grant sólo porque el store no lo tiene; inventar correlación. |
| Store manipulado o salud bloqueada | `ok=false`; `store_valid=false`; `valid=false`; exit 2. | `valid=True`; `HEALTHY`; reparación automática. |
| Reinicio tras cualquier fallo anterior | Bloqueo persistente; resolución sólo mediante mecanismo autorizado. Si no existe, el bloqueo permanece. | Reinicio “limpio” que borra la marca; simular una reconciliación. |

## 10. Estrategia de recuperación

### 10.1 Principios

1. **Preservar antes de actuar:** detener la autoridad, conservar base, `-wal`, `-shm`, journal, archivos, logs y hashes. No borrar evidencia para “volver a intentar”.
2. **No auto-reparar:** ningún arranque debe convertir una intención huérfana, un grant no correlacionado o una salud bloqueada en `HEALTHY`.
3. **Reconciliación humana, sólo si existe:** si ya existe un mecanismo administrativo autorizado, un administrador reautenticado debe aportar evidencia y una nota; la autoridad registra un evento durable y sólo después puede evaluar el desbloqueo. Si no existe, la operación permanece bloqueada; esta SPEC no lo implementa ni lo simula.
4. **No repetir operaciones no idempotentes:** una escritura o borrado indeterminado no se reejecuta ni se revierte sin una decisión humana y una operación autorizada nueva.
5. **Verificar después:** tras la recuperación, `--verify-storage` debe pasar y la autoridad debe arrancar sin huérfanas.

### 10.2 Desafío invalidado (AUD-01)

- El token anterior permanece inutilizable para siempre tras un rechazo definitivo; no se “resetea”.
- Se emite un desafío nuevo sólo por acción administrativa explícita y con state/session/nonce nuevos; la elección entre misma solicitud y solicitud nueva es D-03.
- La solicitud puede seguir pendiente o registrar `AUTH_FAILED` según D-03; en ningún caso pasa a `APPROVED` sin un nuevo intento autenticado y un commit completo.
- Un fallo transitorio no invalida el token; se registra, se aplica backoff y se permite reintento acotado. Si expira la vigencia, se requiere reemisión administrativa y el resultado no se llama rechazo de identidad.
- Si la invalidación no pudo persistirse, la autoridad debe bloquearse, no continuar con un token potencialmente reutilizable.
- `SETUP_INCOMPLETE` no se trata como intento de identidad: el desafío queda intacto y producción sigue bloqueada.

### 10.3 Operación huérfana o no durable (AUD-02/AUD-03)

1. Detener la autoridad y preservar la evidencia.
2. Localizar la intención por `operation_id`; comparar target, digest/inode previo, existencia y journal.
3. Determinar si el efecto ocurrió. No inferir sólo por “no hay resultado”.
4. Si existe un mecanismo autorizado y la evidencia demuestra que ocurrió, registrar la resolución como ejecutada; no repetir. Si no ocurrió, registrar la resolución como no ejecutada; una ejecución posterior requiere una operación autorizada nueva.
5. Si el resultado es ambiguo incluso con la evidencia, mantener `INDETERMINATE`/`RECONCILIATION_REQUIRED`; no desbloquear por comodidad.
6. Si existe el mecanismo autorizado, registrar reconciliación con identidad admin, reautenticación y nota; sólo entonces volver a `HEALTHY` si no quedan huérfanas. Si no existe, no se registra resolución ni se desbloquea.
7. Ejecutar `--verify-storage` y reiniciar; comprobar que no se repitió el efecto.

**Límite OBS-03.** El mecanismo existente `reconcile` exige UID administrador y reautenticación, pero en producción `_approval_event` sigue denegando por `SETUP_INCOMPLETE` y la prueba sólo usa identidad simulada. Además, `reconcile` limpia una auditoría incompleta; no resuelve por sí mismo una intención huérfana. Hasta que exista un mecanismo autorizado que ligue identidad humana, evidencia y operación, la resolución de huérfanas queda bloqueada. Un agente no puede reconciliar, aprobar ni firmar por sí mismo. **IMP-04 no implementa este mecanismo y AUD-02 no se declara completamente cerrado sin él.**

### 10.4 Migración fallida (AUD-04)

- La transacción se revierte completa; no se conserva un `meta` de éxito ni grants parciales.
- Los archivos originales permanecen intactos; se corrige la evidencia fuente o se aplica la política D-04.
- Se repite la migración sólo después de que la correlación sea verificable; la idempotencia debe impedir duplicados.
- Si la base ya contiene un grant no correlacionado, se bloquea su autorización y se decide entre re-aprobación, cuarentena o rechazo conforme a D-04.
- El fallback legacy no puede reintroducir un grant rechazado o cuarentenado: `_load_bundle` debe denegar cuando la correlación no verifica, aunque el archivo exista fuera del store. La eliminación general del fallback es AUD-06.

### 10.5 Verificación fallida (AUD-05)

- `--verify-storage` no repara nada; informa `ok=false` y sale con error.
- Se preserva el store y se investiga el registro ofensor.
- La recuperación usa backup/restauración confiable o una remediación humana explícita, nunca un “clear health” genérico.
- Si la cadena es válida pero un grant no verifica, no se declara el store íntegro.

## 11. Compatibilidad histórica

- **Esquema actual:** `schema_version=1`. Cualquier tabla/columna nueva para journal, correlación o resultados exige una versión nueva y una migración explícita, idempotente y transaccional; no se debe abrir una base antigua como si ya tuviera la nueva estructura.
- **Datos existentes:** no se borran ni reescriben solicitudes, grants, eventos, `meta`, archivos legacy, WAL/SHM. Una migración fallida no deja cambios parciales.
- **Grants históricos:** la firma sigue siendo verificable, pero la autorización exige la correlación de RF-015. Un grant no correlacionado no se considera autorizable; la política de re-aprobación/cuarentena es D-04.
- **Fallback legacy:** `_load_bundle` puede seguir leyendo el archivo histórico sólo como compatibilidad de lectura y sólo con paridad de verificación RF-015.7–RF-015.9. Si el grant falta en el store canónico, está en cuarentena, no tiene evento correlacionado o pertenece a otro contexto, la ruta debe denegar. No se convierte en una segunda fuente de autoridad. La eliminación/rediseño general es AUD-06.
- **Registros de migración:** los registros `completed` existentes deben poder auditarse; si no cumplen la nueva verificación, se reportan como no válidos y no se “arreglan” silenciosamente. Un registro que no distingue grants activos de cuarentenados no puede declararse íntegro.
- **CLI:** `valid` no puede seguir significando “sólo cadena” cuando se usa para decidir éxito. `valid` se convierte en alias de `ok`; se agregan `chain_valid`, `store_valid`, `checks`, `errors` y `format_version`, y el exit code es fail-closed (`0` sólo con `ok=true`, `2` en fallo). La forma exacta es D-05.
- **Contrato de gate:** se agregan campos de durabilidad y journal; los clientes existentes que sólo miran `allowed` no deben interpretarlo como éxito durable. La compatibilidad de protocolo/versionado es D-05.
- **Instalador:** la ruta `store_path` existente se conserva. La corrección no exige cambiar usuarios, grupos, claves, socket ni configuración; sólo verificar que el instalador no invoque una verificación con semántica antigua. Cualquier cambio de instalador queda fuera de esta misión.
- **SPEC-ARCH-001:** no se modifica. Sus siete estados y requisitos siguen siendo el baseline; esta SPEC sólo aclara resultados para los P1.

## 12. Migraciones necesarias

1. **Esquema de store:** la recomendación D-06 es una versión 2 con journal/resultados en el mismo store SQLite y metadatos de correlación/cuarentena. La migración debe ser forward-only, con backup verificado, transacción única, validación de `schema_version` y prueba de rollback operativo que preserve datos. La ubicación final sigue pendiente de D-06.
2. **Backfill de evidencia:** no se deben inventar eventos `approval` para grants históricos. Si una intención/resultado histórico no puede correlacionarse, se reporta y se bloquea o se cuarentena según D-04; no se fabrica un resultado.
3. **Correlación legacy:** la migración existente debe verificar eventos antes de insertar grants y no puede dejar un grant no correlacionado como activo. La elección entre aborto total y cuarentena es D-04; en ambos casos los originales se preservan.
4. **Salud:** una base migrada con huérfanas o grants no correlacionados debe quedar bloqueada, no `HEALTHY`; la migración no puede limpiar la salud.
5. **Fallback:** el ajuste mínimo debe aplicarse también a la lectura legacy; no se permite que un grant rechazado/cuarentenado vuelva por el archivo. La remediación completa de AUD-06 no se incluye.
6. **CLI/operación:** documentar la nueva semántica de `--verify-storage` y `--migrate`, incluyendo exit codes y campos de salida; no se requiere un comando nuevo para esta SPEC.
7. **Reversibilidad:** si se revierte el software, no se debe abrir la base nueva con un lector que ignore campos de seguridad y la declare válida. La política de downgrade debe ser explícita y fail-closed.

## 13. Pruebas obligatorias

### 13.1 Unitarias

- Invalidación de desafío tras un rechazo definitivo real (identidad/proveedor que deniega o firma producida no verificable); no aprobación; token anterior rechazado; token nuevo aceptado; token incorrecto no consume. `SETUP_INCOMPLETE`, timeout/red/`5xx`, firmante no disponible y binding divergente se prueban por separado con el resultado de la tabla RF-012.
- Carrera lógica de dos intentos; CAS; exactamente un éxito como máximo; un fallo definitivo no puede coexistir con una aprobación.
- Journal: intención sin resultado, resultado sin intención (si se permite detectarlo), duplicado de operación, resolución humana.
- `safe_fs`: fallo de `fsync` de archivo y de directorio en las cuatro operaciones; limpieza; estados de durabilidad.
- Migración: grant sin evento, evento de otra solicitud, evento con campos divergentes, firma inválida, cadena válida, idempotencia, rollback y cuarentena si D-04 la elige.
- Fallback: grant no correlacionado, de otra solicitud o cuarentenado presente sólo en `approvals/*.json`; `_load_bundle`/autorización denegados; sin eventos nuevos; original intacto.
- Verificación: solicitud manipulada, grant manipulado, firma inválida, evento faltante, salud bloqueada, migración inconsistente, grant en cuarentena, store válido; `valid == ok` y exit codes.
- Estados: los siete documentales intactos; ningún estado oficial nuevo; `test_document_state_contract_is_unchanged` (TST-09).
- Reconciliación: `reconcile` sin mecanismo autorizado no resuelve huérfanas; identidad simulada no se acepta como demostración de producción (OBS-03).

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
| `ImplementationGate` | Intención durable, resultado, detección de huérfanas, bloqueo persistente, preservación e inspección de sólo lectura. No implementa resolución humana. | No se cambia el gate ahora. |
| `safe_fs` | Propagar errores de fsync y devolver evidencia de durabilidad; no limpiar silenciosamente. | No se cambia ahora. |
| Migración histórica | Correlación obligatoria; aborto o cuarentena no autorizable según D-04; grants no verificables bloqueados. | No se reescriben fuentes ni bases. |
| Fallback legacy | Paridad de verificación RF-015.7–RF-015.9; no autoriza grants no correlacionados/cuarentenados. | No se elimina el fallback ni se resuelve AUD-06. |
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

La cobertura de esta tabla es **condicional**: no acredita la aprobación de SPEC-ARCH-001 ni permite declarar conformidad normativa completa. La aprobación condicional de SPEC-ARCH-002 no cambia el estado de SPEC-ARCH-001. **D-01.**

### 15.2 Matriz AUD → RF → AC → prueba → decisión

| AUD | RF | AC | Pruebas | Decisión pendiente |
|---|---|---|---|---|
| AUD-01 | RF-012 | AC-012a…h | Unitarias, transitorios, binding, carrera, reinicio | D-02, D-03 |
| AUD-02 | RF-013 | AC-013a…c | Journal, crash, multiproceso, reinicio | D-06, D-07 |
| AUD-03 | RF-014 | AC-014a…c | Fault injection, cuatro operaciones, reinicio | D-06 (durabilidad/journal) |
| AUD-04 | RF-015 | AC-015a…e | Migración, firmas, eventos, fallback, originales | D-04 |
| AUD-05 | RF-016 | AC-016a…d | Matriz de manipulación, CLI, read-only | D-05 |

### 15.3 Fuera de esta trazabilidad

- AUD-06 a AUD-17 no se corrigen aquí. En particular, AUD-06 (fallback legacy) queda cubierto sólo por el ajuste mínimo anti-bypass RF-015.7–RF-015.9; su eliminación/rediseño general sigue fuera de alcance. AUD-07 (truncación sin ancla), AUD-08 (migración concurrente), AUD-09 (replay/OIDC) y AUD-15 (docs sobre `INDETERMINATE`) siguen abiertos.
- **OBS-01** queda recogida en RF-015.7–RF-015.9 y AC-015d; **OBS-02** en RF-012.9–RF-012.10 y AC-012e/f/h; **OBS-03** en RF-013.11–RF-013.12 y §10.3; **OBS-04** en TST-09/AC-017 y en la corrección de dependencia IMP-03 del PLAN.
- **OBS-05** queda recogida en la Nota de autoridad, §4.2, §15.1 y §18; **OBS-06** en RF-012.2/2a, AC-012g y §17; **OBS-07** en §3.1, RF-013.5, §10.1/§10.3 y AC-013b; **OBS-08** en las compuertas y dependencias del PLAN.
- SA-014 no se declara cumplido por esta SPEC; sólo se definen las pruebas que la corrección debe aportar.
- La aprobación de SPEC-ARCH-001 no se infiere de este documento. **D-01.**

## 16. Riesgos residuales

1. **No hay atomicidad real entre SQLite y filesystem.** El journal reduce la ventana y hace visible la ambigüedad; no la elimina. Un crash puede requerir una resolución humana autorizada; si no existe mecanismo, el bloqueo permanece.
2. **La durabilidad física no se demuestra con mocks.** La inyección de `fsync` prueba manejo de errores; el hardware/filesystem objetivo debe probarse aparte.
3. **La invalidación estricta del desafío puede ser un vector de denegación de servicio** si un tercero posee el token y provoca fallos. La extensión exacta a state/sesión/scope es D-02; el mínimo de autenticación/firma es obligatorio.
4. **Rechazar grants históricos sin evento correlacionable puede bloquear aprobaciones legítimas.** La política de re-aprobación/cuarentena es D-04; no se resuelve técnicamente.
5. **La verificación integral no detecta truncación de cola ni pérdida de un sufijo** sin ancla externa (AUD-07). Puede detectar inconsistencias internas y registros manipulados, no historia completa.
6. **El store local no tiene réplica.** La pérdida o corrupción física requiere backup/restauración; no se promete recuperación automática.
7. **La compatibilidad de clientes que interpretan `allowed` como éxito durable** requiere actualización de contrato; hasta entonces, el riesgo de falsa assurance persiste.
8. **Los estados oficiales no se amplían.** Cualquier necesidad de un estado nuevo debe justificarse y aprobarse por separado; no se introduce aquí.
9. **OIDC y producción siguen bloqueados.** Ninguna corrección de estos P1 habilita el flujo de aprobación humana real.
10. **Los P2/P3 siguen abiertos** y pueden afectar la garantía global aunque estos P1 se corrijan.
11. **El fallback legacy sigue existiendo** como compatibilidad de lectura. La paridad de verificación cierra el bypass de AUD-04, pero no elimina la fuente alternativa ni resuelve AUD-06; una lectura fuera del store puede seguir siendo un riesgo de diseño.
12. **La reconciliación de huérfanas no tiene un mecanismo de producción demostrado.** Hasta que exista, el bloqueo puede ser operativamente permanente; no se debe simular una aprobación humana.
13. **La compatibilidad de `valid` exige migrar consumidores.** Aunque el alias sea fail-closed, un consumidor que no distinga `chain_valid` puede seguir interpretando mal un resultado parcial; D-05 debe aprobar el contrato y su versión.

## 17. Decisiones pendientes de aprobación humana

| ID | Decisión | Opciones | Efecto | Bloquea |
|---|---|---|---|---|
| D-01 | Autoridad formal de SPEC-ARCH-001 | (a) aprobar/hash y actualizar su estado; (b) mantener DRAFT y permitir aprobación condicional de esta SPEC sin declarar cobertura completa. | Determina si existe baseline normativo; no impide aprobar condicionalmente SPEC-ARCH-002. | Conformidad normativa completa, no la aprobación condicional de esta SPEC. |
| D-02 | Disparador de invalidación | (a) sólo autenticación/firma; (b) todo rechazo definitivo posterior a la posesión, incluido binding/revisión (recomendada); (c) rotación automática (no recomendada). | Seguridad vs. fricción/DoS; los fallos transitorios no invalidan; binding/revisión queda pendiente. | Clasificación de binding/revisión y AC-012g; no el mínimo obligatorio de auth/firma. |
| D-03 | Reemisión del desafío | (a) misma solicitud con desafío nuevo; (b) nueva solicitud obligatoria; (c) ambas con condiciones (recomendada: (a) por defecto, (b) si cambia alcance/expira). | UX, estado y auditoría. | RF-012.6. |
| D-04 | Grants históricos no correlacionados | (a) rechazar toda la migración; (b) cuarentenar y bloquear; (c) re-aprobación; (d) aceptar como legacy (no recomendada). | Disponibilidad histórica vs. trazabilidad. | RF-015/migración. |
| D-05 | Contrato de verificación y compatibilidad | (a) `valid=ok`, campos separados (recomendada); (b) `valid` de cadena + `ok` (no recomendada); (c) nueva versión de protocolo. | Consumidores CLI/adaptadores. | RF-016/AC-016. |
| D-06 | Journal y recuperación | (a) journal en el store SQLite; (b) journal separado; (c) eventos de auditoría enriquecidos. | Esquema, migración y recuperación; no hay atomicidad SQLite/filesystem. | RF-013. |
| D-07 | Datos existentes con anomalías | (a) bloquear autorizaciones y permitir sólo lectura/diagnóstico (recomendada); (b) bloqueo total; (c) cuarentena por registro. | Disponibilidad y recuperación. | Implementación. |
| D-08 | Alcance de P2/P3 | (a) P1 + ajuste mínimo anti-bypass (recomendada); (b) incluir AUD-06/AUD-15; (c) otro. | Evita ampliar la misión silenciosamente. | Plan final. |

Ninguna opción está aprobada. El análisis completo, alternativas, consecuencias y recomendaciones está en `DECISIONS-ARCH-002-SECURITY-REMEDIATION.md`; todas las decisiones permanecen `PENDING USER DECISION`.

## 18. Condición de aprobación

Esta SPEC queda en **DRAFT**. No se implementa, no se modifica ningún componente y no se declara producción habilitada. La aprobación debe ser explícita sobre:

1. el texto, versión y hash de esta SPEC;
2. las decisiones D-01 a D-08 que correspondan, con el estado registrado en `DECISIONS-ARCH-002-SECURITY-REMEDIATION.md`; D-01 no es requisito para la aprobación condicional de esta SPEC;
3. el alcance estricto de los cinco P1, más el ajuste mínimo anti-bypass del fallback, sin OIDC ni correcciones P2/P3 no autorizadas;
4. el contrato de verificación y exit codes de D-05, y la política de fallos transitorios de D-02.

La aprobación de esta SPEC puede ser **condicional** si D-01 sigue pendiente. Esa aprobación no aprueba SPEC-ARCH-001, no cambia su estado ni hash y no permite declarar conformidad normativa completa. Hasta que exista aprobación explícita, las garantías descritas son requisitos propuestos, no comportamiento demostrado.
