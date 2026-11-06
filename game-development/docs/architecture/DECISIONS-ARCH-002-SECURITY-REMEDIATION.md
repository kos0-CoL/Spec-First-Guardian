---
document_id: DECISIONS-ARCH-002
title: "Registro de decisiones de la remediación P1 de Etapa B"
status: DRAFT
version: 0.1.0
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
base_commit: "d8a681c6226f89b123a2802b3aeb02b18f029368"
spec: "SPEC-ARCH-002-SECURITY-REMEDIATION.md"
spec_version: "0.2.0"
spec_sha256: "b044327f56c9905ff9eddb97cbfbd9d8a600236904142e4534e34016c5f4de3e"
plan: "PLAN-ARCH-002-SECURITY-REMEDIATION.md"
---

# DECISIONS-ARCH-002 — Decisiones pendientes de la remediación P1

**Estado:** DRAFT; no aprobado, no autoriza implementación ni producción.<br>
**Fecha:** 2026-11-06<br>
**Autor:** Buffy — análisis para revisión humana.<br>
**SPEC de referencia:** `SPEC-ARCH-002-SECURITY-REMEDIATION.md`, versión 0.2.0, SHA-256 `b044327f56c9905ff9eddb97cbfbd9d8a600236904142e4534e34016c5f4de3e`.<br>
**Baseline documental:** `d8a681c6226f89b123a2802b3aeb02b18f029368`; código auditado `094f93d065cbbedce7d9ff35aeb862db92422476`.<br>
**Autoridad:** sólo el usuario puede aprobar una decisión. Este documento no cambia estados, no implementa, no firma y no convierte una recomendación en norma.

## 0. Estado y reglas de lectura

- **PENDING USER DECISION:** no hay autorización humana registrada. Es el estado de **todas** las decisiones D-01…D-08 en esta versión.
- **RECOMMENDED:** una recomendación técnica razonada, no aprobada. Se usa como campo interno, no como estado de la decisión.
- **RESOLVED WITH AUTHORIZATION:** sólo puede usarse después de una autorización humana explícita sobre el texto, versión, hash y alternativa. No se usa en este documento.
- Una recomendación no reduce la necesidad de autorización. Las opciones no recomendadas se conservan para que el usuario decida con información completa.
- Los requisitos y criterios afectados se refieren a `SPEC-ARCH-002`; la numeración de la SPEC-ARCH-001 se cita sólo como baseline condicional (D-01).

| ID | Tema | Estado | Recomendación | Bloquea |
|---|---|---|---|---|
| D-01 | Autoridad formal de SPEC-ARCH-001 | PENDING USER DECISION | Mantener cobertura condicional y no declarar aprobación | Aprobación de la SPEC-002 |
| D-02 | Clasificación de fallos y consumo del desafío | PENDING USER DECISION | Rechazo definitivo de auth/binding; transitorios no consumen | RF-012/AC-012 |
| D-03 | Reemisión del desafío | PENDING USER DECISION | Misma solicitud por defecto; nueva si cambia alcance/expira | RF-012.6 |
| D-04 | Grants históricos y fallback | PENDING USER DECISION | Cuarentena + bloqueo + re-aprobación; paridad de fallback | RF-015/MIG |
| D-05 | Contrato de verificación | PENDING USER DECISION | `valid=ok`; `chain_valid` separado; exit 0/2 | RF-016/AC-016 |
| D-06 | Journal y atomicidad | PENDING USER DECISION | Journal en SQLite; sin afirmar atomicidad con filesystem | RF-013 |
| D-07 | Datos existentes anómalos | PENDING USER DECISION | Bloqueo de autorización; lectura/diagnóstico seguro | Implementación |
| D-08 | Alcance | PENDING USER DECISION | AUD-01…AUD-05 + anti-bypass mínimo | Plan final |

## 1. D-01 — Autoridad formal de SPEC-ARCH-001

**Problema.** La misión presenta SPEC-ARCH-001 como referencia, pero el archivo examinado se autodeclara `DRAFT` y “no aprobada”. Sin una aprobación formal no puede afirmarse que todos sus requisitos sean baseline normativo de esta SPEC.

**Evidencia examinada.**

- `SPEC-ARCH-001-HARDENING.md` contiene `status: DRAFT` y el encabezado “DRAFT; no aprobada, no autoriza implementación”.
- El SHA-256 del archivo es `77f3afbb113df0a0a2c6b75755281a8305e85caa3e0cd0e68bc9694dc26c4cda`; un hash de archivo no es una aprobación.
- No se encontró en el expediente examinado un artefacto de aprobación explícito que indique versión, hash, alcance y autoridad humana.
- `IMPLEMENTATION-ARCH-001.md` registra una decisión aprobada sobre persistencia SQLite; no acredita la aprobación global de SPEC-ARCH-001.
- Los documentos `PLAN-ARCH-001.md`, `ARCH-001.md` y `ADR-001.md` también se declaran DRAFT/no normativos.

**Alternativas.**

1. **Aprobar formalmente SPEC-ARCH-001**: el usuario registra autorización explícita sobre versión y hash, y actualiza su estado por el procedimiento oficial. Esta misión no puede hacerlo.
2. **Mantener DRAFT y tratar la SPEC-002 como propuesta condicional** (recomendada): se usan los requisitos citados como referencia de trabajo, sin declarar que la SPEC-001 está aprobada ni que la cobertura es completa.
3. **Sustituir el baseline** por una nueva SPEC aprobada: obliga a rehacer la trazabilidad y no es necesario para esta revisión.

**Consecuencias funcionales.** La opción 2 permite revisar y aprobar SPEC-002 con una nota de condicionalidad; no impide implementar después si el usuario aprueba ambas. La opción 1 desbloquea la cobertura normativa, pero exige una decisión separada y no debe simularse.

**Consecuencias de seguridad.** Declarar aprobada una SPEC que no lo está crearía una falsa assurance sobre todas las invariantes heredadas. La cobertura condicional es más honesta y mantiene el fail-closed documental.

**Compatibilidad.** No se modifica SPEC-ARCH-001, sus estados ni su hash. La SPEC-002 puede citarla sin cambiar su contenido; si el usuario aprueba después, se registra el hash y se actualiza la referencia.

**Riesgos residuales.** La falta de baseline formal puede producir discrepancias entre requisitos heredados y la SPEC-002. La opción 2 deja abierta la pregunta de qué RF de SPEC-ARCH-001 son obligatorios; se mitiga citando sólo los que la misión y la auditoría identifican y manteniendo D-01 visible.

**Recomendación.** Opción 2: mantener D-01 pendiente, no modificar SPEC-ARCH-001 y no declarar cobertura normativa completa. Si el usuario afirma que existe aprobación, debe aportar el artefacto, versión y hash; una afirmación verbal en la misión no sustituye el registro.

**Decisión requerida.** El usuario debe elegir (1) aprobar formalmente la SPEC-001 con hash y alcance, o (2) mantenerla DRAFT y aceptar que la SPEC-002 es condicional. No se debe marcar RESOLVED sin el artefacto correspondiente.

**RF/AC afectados.** §15.1 y §15.3 de la SPEC; cobertura de todos los RF heredados; condición de aprobación §18. No cambia RF-012…RF-016.

## 2. D-02 — Invalidación de desafíos y clasificación de fallos

**Problema.** RF-012.2 originalmente usaba “fallo de autenticación/firma” para agrupar rechazo de identidad, errores transitorios, configuración, timeout y errores internos. Esa ambigüedad puede producir dos fallos opuestos: reutilización de un desafío tras un rechazo definitivo, o invalidación permanente por una caída temporal del proveedor.

**Clasificación propuesta.**

| Clase | Ejemplos | ¿Consume/invalida? | ¿Puede aprobar? |
|---|---|---|---|
| Sin posesión / token incorrecto | hash distinto, token ausente, formato no interpretable, solicitud inexistente | No | No |
| Rechazo definitivo de autenticación | firma/claims/subject/nonce/issuer/audience/exp/iat/auth_time inválidos, replay, denegación explícita | Sí, permanentemente | No |
| Rechazo definitivo de binding/revisión | `state`, sesión, PKCE, fingerprint, scope o revisión divergentes tras posesión | Sí, permanentemente (recomendado) | No |
| Firma producida no verificable | firma criptográficamente inválida o no corresponde al contenido | Sí, permanentemente | No |
| Error transitorio | timeout, red, `5xx`, indisponibilidad, rate limit sin respuesta definitiva | No; backoff y límite de reintentos | No |
| Error de configuración | `SETUP_INCOMPLETE`, proveedor/callback/trust store no configurado | No | No |
| Error técnico antes de firmar | firmante no disponible, error interno sin firma producida | No | No |
| Commit ambiguo | autenticación/firma correctas, resultado del commit desconocido | Sí; no reintento ciego; bloqueo | No |

**Alternativas.**

- **A. Sólo autenticación/firma invalida.** Reduce la fricción, pero permite reutilizar un token tras un fallo de `state`/sesión/scope que también es definitivo. No recomendada como política completa.
- **B. Todo rechazo definitivo posterior a la posesión invalida; transitorios/configuración no** (recomendada). Separa la naturaleza del fallo y evita tanto replay como DoS por indisponibilidad.
- **C. Rotación automática ante cualquier error.** Genera desafíos nuevos sin intervención, aumenta la superficie y puede convertir un fallo transitorio en una carrera; no recomendada.

**Consecuencias funcionales.** La opción B exige más transiciones y eventos, pero mantiene la aprobación humana en el centro. Un fallo transitorio no obliga a una nueva solicitud; un rechazo definitivo sí exige reemisión administrativa (D-03).

**Consecuencias de seguridad.** B elimina la reutilización tras rechazo real y evita que un atacante con el token fuerce una denegación permanente mediante timeouts. Un token robado sigue requiriendo autenticación; la invalidación definitiva reduce la ventana. La opción C puede facilitar denegación de servicio y no debe adoptarse sin análisis.

**Compatibilidad.** Los estados de servicio existentes (`AUTH_FAILED`, `APPROVAL_COMMITTING`, `RECONCILIATION_REQUIRED`) se reutilizan; no se introducen estados documentales nuevos. Los clientes deben distinguir `provider_unavailable` de `authentication_rejected`.

**Riesgos residuales.** Un tercero con el token puede provocar un rechazo definitivo y forzar reemisión; es el coste de no permitir replay. La indisponibilidad prolongada puede impedir aprobar hasta que expire el desafío; no se convierte en aprobación. El límite exacto de reintentos y backoff debe fijarse en la implementación aprobada.

**Recomendación.** Opción B. Los fallos transitorios no consumen; los rechazos definitivos de autenticación, binding, revisión y firma sí. `SETUP_INCOMPLETE` nunca consume. El commit ambiguo bloquea y no se reintenta.

**Decisión requerida.** El usuario debe aprobar la tabla de clasificación, en particular si los fallos de `state`/sesión/scope/revisión consumen (B) o no (A), y el límite de reintentos transitorios. Sin esta decisión, RF-012 no está cerrado.

**RF/AC afectados.** RF-012.1–RF-012.11; AC-012a–AC-012h; RF-012.9/AC-012e (transitorios); RF-012.10; riesgos §16.3.

## 3. D-03 — Reemisión del desafío

**Problema.** Tras invalidar un desafío, el sistema necesita un camino operativo para continuar sin reutilizar el token anterior ni aprobar automáticamente. No está definido si se reemite sobre la misma solicitud o se exige una solicitud nueva.

**Alternativas.**

- **A. Nueva solicitud obligatoria.** Máximo aislamiento y nueva revisión de alcance; coste alto y posible pérdida de continuidad.
- **B. Reemitir sobre la misma solicitud.** Conserva el contexto y la revisión si SPEC/alcance no cambiaron; exige invalidar el token anterior y crear state/session/nonce nuevos.
- **C. Ambas con condiciones** (recomendada): B por defecto si la solicitud sigue pendiente, la SPEC/alcance no cambiaron y no se agotó el límite; A si cambió el contenido/alcance, la solicitud expiró, está aprobada o se requiere una revisión nueva.

**Condiciones mínimas para B/C.**

- Acción administrativa explícita; ningún agente puede emitir, reemitir ni autorizar el desafío.
- El token anterior queda permanentemente inutilizable; no se “resetea”.
- Nueva identidad de desafío y nuevos `state`/sesión/nonce; no se reutilizan los anteriores.
- La solicitud no está `APPROVED`; no hay grant activo.
- La SPEC, versión, fingerprint, scope y contenido son los mismos; si cambian, se exige A.
- CAS/transacción: una sola reemisión gana; intentos concurrentes con el token anterior fallan.
- Auditoría: motivo, actor administrativo, identificador de desafío anterior/nuevo, sin token; no se registra el secreto.
- Límite de reemisiones y ventana de vigencia; no es un mecanismo de aprobación automática.

**Consecuencias funcionales.** B/C reduce fricción y mantiene la solicitud; A es más simple de auditar pero más costosa. La reemisión no cambia el estado documental ni aprueba.

**Consecuencias de seguridad.** La reemisión sobre la misma solicitud es segura sólo si el alcance está congelado y el token anterior muere. Si el alcance cambió y se reemite, se reutilizaría una revisión obsoleta; por eso A es obligatoria en ese caso. La reemisión debe impedir que un agente fabrique un desafío.

**Compatibilidad.** El estado de solicitud existente puede conservarse; no se añaden estados documentales. La API administrativa existente de `challenge` es el punto natural, pero su autorización debe verificarse en la implementación.

**Riesgos residuales.** Un administrador comprometido puede reemitir; la auditoría y el límite no eliminan esa autoridad. La reemisión repetida puede ser un vector de fricción; se limita y audita.

**Recomendación.** Opción C con B por defecto; A obligatoria si cambia SPEC/alcance/versión o la solicitud expiró. No permitir reemisión automática ni por agentes.

**Decisión requerida.** El usuario debe elegir A, B o C y confirmar las condiciones, el límite de reemisiones y quién es la autoridad administrativa.

**RF/AC afectados.** RF-012.6; AC-012b; §10.2; D-03 del PLAN (IMP-02).

## 4. D-04 — Grants históricos no correlacionados y bypass legacy

**Problema.** Un grant firmado sin evento `approval` correlacionado no satisface la invariante de autorización. La migración actual lo importa; además, el fallback `_load_bundle` puede devolverlo desde `approvals/{spec_id}-{version}.json` cuando el store no lo tiene. Cerrar sólo la migración no cierra el bypass.

**Evidencia del bypass.** `authority_service.py:533-553` captura `StoreNotFound`, lee el archivo legacy y devuelve `approval` sin verificar el evento `approval`, la correlación ni una cuarentena. `verify_approval` y `_operation_decision` usan ese resultado. El fallback no escribe, pero sí puede autorizar.

**Alternativas.**

- **A. Rechazar toda la migración si un grant no correlaciona.** Máxima integridad, pero un solo registro malo bloquea toda la historia y no distingue datos recuperables.
- **B. Cuarentena por grant + bloqueo de autorizaciones + re-aprobación humana** (recomendada). Preserva la evidencia, no inserta el grant como activo, marca la salud como `RECONCILIATION_REQUIRED` y exige una nueva aprobación humana; no se inventan eventos.
- **C. Exigir re-aprobación sin cuarentena.** Similar a B, pero puede perder la trazabilidad del registro original si no se conserva una referencia.
- **D. Aceptar el grant como legacy con una marca.** No recomendada: una marca no sustituye el evento de aprobación y mantiene autorizable un grant no correlacionado.

**Consecuencias funcionales.** B permite arrancar en modo de diagnóstico, pero no autorizar; el operador debe resolver cada grant. A es más simple pero puede impedir el servicio por un registro histórico. C puede ser operativamente más lenta si no se conserva el original.

**Consecuencias de seguridad.** B y C cumplen el mínimo: ningún grant no correlacionado autoriza. A también, pero su disponibilidad es menor. D viola AUD-04. La cuarentena debe ser no autorizable y no debe borrar el archivo ni la cadena original.

**Compatibilidad.** Los grants no correlacionados dejan de autorizar; es un cambio de comportamiento fail-closed. Los grants válidos y las solicitudes se preservan. No se altera la cadena histórica ni se fabrican eventos. El fallback se mantiene sólo con paridad de verificación; su eliminación general es AUD-06.

**Riesgos residuales.** La cuarentena puede bloquear aprobaciones legítimas hasta re-aprobación; es el coste de no aceptar evidencia insuficiente. La re-aprobación puede repetir una decisión histórica; debe registrar el vínculo con el grant original, no reescribirlo. El fallback sigue siendo una fuente alternativa; la paridad de verificación reduce el bypass, pero AUD-06 sigue abierto.

**Recomendación.** B + C: cuarentena no autorizable, salud bloqueada, preservación de originales y re-aprobación humana explícita. Añadir el guard de paridad en el fallback (RF-015.7–RF-015.9) y la prueba AC-015d. No aceptar D.

**Decisión requerida.** El usuario debe elegir la política (A/B/C/D), confirmar que la cuarentena bloquea autorizaciones y aprobar el alcance mínimo del fallback. Sin D-04 no se puede implementar MIG-02 ni cerrar AUD-04.

**RF/AC afectados.** RF-015.1–RF-015.9; AC-015a–AC-015e; RF-016.1 (detección); §10.4; §11; §12.3; MIG-02/MIG-03.

## 5. D-05 — Contrato de `--verify-storage`

**Problema.** El resultado actual usa `valid` para la validez de la cadena y lo presenta como validez del store. Un store con grants manipulados o salud bloqueada puede devolver `valid=True`. No hay contrato explícito de campos, exit codes ni comportamiento de sólo lectura.

**Alternativas.**

- **A. `valid` = resultado integral (`ok`); `chain_valid` separado; exit 0 sólo con `ok`** (recomendada). Fail-closed para consumidores antiguos.
- **B. Conservar `valid` como cadena y añadir `ok`.** Mantiene compatibilidad literal, pero permite que un consumidor antiguo interprete un store inválido como válido; no recomendada.
- **C. Nueva versión de protocolo con campos obligatorios.** Es compatible a largo plazo, pero exige actualizar todos los consumidores antes de usar la salida; puede ser parte de A mediante `format_version`.

**Contrato propuesto.**

| Campo | Semántica | Contribuye a `ok` |
|---|---|---|
| `chain_valid` | Cadena: secuencia, `prev`, hash, cuerpo. | Sí |
| `store_valid` | Esquema, meta, migración, solicitudes, grants/firmas, correlación, replay, revocación, journal/huérfanas, cuarentena. | Sí |
| `health` | Estado conocido; desconocido/ausente = no saludable. | Sí |
| `ok` | `chain_valid && store_valid && health=="HEALTHY"` y sin errores. | Es el resultado |
| `valid` | Alias exacto de `ok`. | Igual que `ok` |
| `checks` | `pass`/`fail`/`blocked`/`not_applicable` por comprobación. | Un fallo bloquea |
| `errors` | Lista determinista, sin secretos. | Cualquier error bloquea |
| `migration` | Registro y estado; incompleto/fallido = inválido. | Sí |
| `format_version` | Versión del contrato. | Desconocida = fallo |

**Exit codes.** `0` sólo con `ok=true`; `2` para store inválido, salud no sana, firma/correlación inválida, huérfana, migración inconsistente, error de lectura o trust store ausente. `argparse` puede usar su código de uso; nunca puede producir 0. No se introduce un código nuevo sin decisión.

**Sólo lectura.** La verificación no crea, migra, repara, reconcilia ni cambia salud. Si el store no existe o no se puede abrir, informa `ok=false`/error y no crea uno vacío. La inspección de sólo lectura no autoriza.

**Compatibilidad.** `valid` cambia de “cadena” a “integral”; es un cambio fail-closed intencional. Se documenta en `format_version` y en los adaptadores. Un consumidor que sólo mire `chain_valid` debe saber que no es suficiente.

**Riesgos residuales.** Un consumidor que ignore `ok`/`valid` puede seguir tomando decisiones incorrectas; la compatibilidad no puede obligar a un tercero a actualizarse. La verificación no detecta truncación de cola sin ancla (AUD-07).

**Recomendación.** A, con `format_version` y el contrato anterior. No conservar `valid` como cadena.

**Decisión requerida.** El usuario debe aprobar el contrato, el alias `valid=ok`, los exit codes 0/2 y la política de campos desconocidos.

**RF/AC afectados.** RF-016.1–RF-016.8; AC-016a–AC-016d; IMP-06/IMP-07; DOC-03.

## 6. D-06 — Ubicación y atomicidad del journal

**Problema.** AUD-02 demuestra que `intent` y `result` se escriben en transacciones separadas y que una caída deja un efecto sin resultado durable. La corrección necesita un journal recuperable. No existe atomicidad entre SQLite y el filesystem.

**Alternativas.**

- **A. Journal en el mismo store SQLite** (recomendada): tablas de intención/resultado, transacción local, consulta de huérfanas y salud en el mismo lugar. No elimina la ventana con el filesystem.
- **B. Journal separado con protocolo de recuperación.** Aísla el journal, pero añade otra fuente de verdad y más estados de corrupción.
- **C. Reutilizar eventos de auditoría enriquecidos.** Menos tablas, pero mezcla auditoría con estado operativo y dificulta CAS/consulta; no recomendada como mecanismo primario.

**Modelo recomendado (A).**

1. Persistir la intención en SQLite con `operation_id` único, contexto, preestado, digest esperado y timestamp; confirmar antes del efecto.
2. Ejecutar el efecto en el filesystem.
3. Persistir el resultado terminal con digest/inode observable, durabilidad y errores.
4. Si el proceso cae antes de 1: no hay efecto.
5. Si cae entre 1 y 2: intención sin efecto; huérfana; no reejecutar.
6. Si cae entre 2 y 3: efecto puede existir; resultado ausente; huérfana; `INDETERMINATE`.
7. Si cae después de 3: resultado durable; no repetir.

**Atomicidad.** No se afirma atomicidad SQLite↔filesystem. La representación correcta de la ventana 6 es `INDETERMINATE`/`RECONCILIATION_REQUIRED`, no éxito. La intención y el resultado son durables en SQLite; el efecto externo tiene su propia durabilidad.

**Concurrencia.** `operation_id` único y transacción `BEGIN IMMEDIATE`/CAS para que sólo una intención sea ejecutable. Un duplicado se deniega o se resuelve como conflicto; no se ejecutan dos efectos no idempotentes. La recuperación no debe reejecutar.

**Consecuencias.** A reduce fuentes de verdad y facilita la verificación, pero requiere esquema v2 y migración. B añade complejidad; C no ofrece CAS claro.

**Compatibilidad.** El esquema v2 exige migración explícita y una base antigua no puede abrirse como si tuviera journal. Los registros existentes se preservan; el journal nuevo no reinterpreta eventos históricos. Un lector viejo no debe declarar válida una base que no entiende.

**Riesgos residuales.** La ventana entre efecto y resultado sigue existiendo; el bloqueo y la reconciliación son obligatorios. La caída de energía real no se demuestra con mocks. La base SQLite y el filesystem pueden corromperse de forma independiente.

**Recomendación.** A, con el modelo anterior y sin promesa de atomicidad entre dominios.

**Decisión requerida.** El usuario debe aprobar la ubicación del journal, el esquema v2 y el tratamiento de la ventana indeterminada.

**RF/AC afectados.** RF-013.1–RF-013.12; RF-014 (durabilidad); AC-013a–AC-013c; IMP-01/IMP-04; MIG-01.

## 7. D-07 — Datos existentes con anomalías

**Problema.** El store puede contener operaciones huérfanas, grants no correlacionados, registros incompletos, cadenas inválidas, migraciones interrumpidas o salud inconsistente. No está definido qué puede hacer el servicio en cada contexto sin convertir la inspección en autorización.

**Matriz de comportamiento recomendada.**

| Contexto | Comportamiento | Prohibido |
|---|---|---|
| Arranque con anomalía | No declarar `HEALTHY`; no conceder autorizaciones; permitir estado de diagnóstico y lectura acotada. | Borrar, reparar, migrar o reconciliar automáticamente. |
| Nuevas escrituras | Denegar mientras exista anomalía bloqueante. | Escribir para “probar” o “limpiar”. |
| Autorización | Denegar el grant afectado; si la salud es no sana, denegar todas las nuevas autorizaciones. | Usar un grant en cuarentena o un fallback no verificado. |
| Inspección de sólo lectura | Permitida si no muta ni crea; informa `ok=false` y el motivo. | Convertir el resultado en aprobación. |
| Diagnóstico | Logs/eventos acotados, hashes y referencias; sin secretos. | Exponer tokens, claves o contenido sensible. |
| Reconciliación | Sólo con mecanismo autorizado, identidad humana reautenticada y evidencia; si no existe, bloqueada. | Aprobación/firma por agente; auto-reparación. |

**Alternativas.** (a) Bloqueo de autorizaciones + lectura/diagnóstico (recomendada); (b) bloqueo total del proceso, incluida la inspección; (c) cuarentena por registro con servicio parcial. (b) reduce disponibilidad y no mejora la seguridad; (c) puede dejar autorizaciones activas sobre datos dudosos si no se bloquea globalmente.

**Consecuencias de seguridad.** La opción (a) preserva evidencia y evita que la inspección se convierta en autorización. No se borra ni se “corrige” nada. La opción (c) debe demostrar que ninguna autorización usa datos dudosos; hasta entonces no se recomienda.

**Compatibilidad.** Los datos existentes se preservan; los grants no correlacionados quedan en cuarentena/no autorizables. La migración puede dejar la base en `RECONCILIATION_REQUIRED`; no se declara `completed` integral.

**Riesgos residuales.** El servicio puede quedar bloqueado indefinidamente si no hay mecanismo de reconciliación autorizado (OBS-03). La lectura de diagnóstico puede exponer metadatos; se acota.

**Recomendación.** (a), con bloqueo de autorizaciones, lectura/diagnóstico seguro y reconciliación sólo mediante mecanismo autorizado. No auto-reparar.

**Decisión requerida.** El usuario debe aprobar la matriz, el alcance de la lectura permitida y el bloqueo global frente al bloqueo por grant.

**RF/AC afectados.** RF-013.4–RF-013.5; RF-015.5; RF-016.4; AC-013a/AC-013b; AC-015c; §10.

## 8. D-08 — Alcance de la misión

**Problema.** AUD-06 describe el fallback legacy, pero AUD-04 no se cierra si el fallback sigue autorizando grants no correlacionados. Ampliar toda la misión a AUD-06 mezclaría una remediación P2 con los cinco P1.

**Alternativas.**

- **A. AUD-01…AUD-05 + ajuste mínimo anti-bypass** (recomendada): se corrige la correlación en migración y en toda ruta de autorización, incluido el fallback; no se rediseña el almacenamiento legacy.
- **B. Incluir AUD-06/AUD-15 completos**: mayor alcance, más riesgo y una misión distinta; requiere nueva planificación.
- **C. Dejar el fallback intacto**: no recomendada; mantiene el bypass de AUD-04.

**Qué se corrige.** AUD-01 (desafío), AUD-02 (journal), AUD-03 (fsync), AUD-04 (correlación + paridad de fallback), AUD-05 (verificación integral). Se añaden pruebas negativas del fallback y de estados.

**Qué se excluye.** OIDC/callback/UI, producción, rediseño general del fallback, eliminación de la fuente legacy, AUD-07 (truncación), AUD-08 (concurrencia de migración), AUD-09 (replay/OIDC), AUD-15 (documentación general de `INDETERMINATE`) y demás P2/P3. La documentación operativa necesaria para los P1 sí se incluye.

**Consecuencias funcionales.** La migración puede quedar en cuarentena/bloqueo en vez de completarse; el fallback legacy deja de servir grants no verificados. Algunos flujos históricos requerirán re-aprobación humana. No se añaden funciones de producto.

**Consecuencias de seguridad.** Se cierra la vía de AUD-04 que sobrevivía al corregir sólo la migración: ninguna ruta de autorización puede aceptar un grant no correlacionado o cuarentenado. No se elimina el riesgo general de AUD-06 ni se habilitan OIDC/producción.

**Cobertura exacta de AUD-06.** Cubierto aquí: la paridad de verificación del fallback para la correlación de AUD-04 y la denegación de grants rechazados/cuarentenados. Pendiente de AUD-06: eliminación/rediseño del almacenamiento legacy, otras rutas de compatibilidad, política general de migración y cualquier subhallazgo no relacionado con la correlación.

**Compatibilidad.** El cambio es fail-closed: los grants no correlacionados dejan de autorizar y el fallback sigue existiendo sólo como lectura verificada. No se reescriben registros ni se cambia la firma; los consumidores que esperaban el comportamiento permisivo deben actualizarse.

**Riesgos residuales.** El fallback sigue existiendo y puede ser una fuente alternativa; la paridad de verificación no elimina todos los riesgos de AUD-06. La deuda P2/P3 permanece y debe declararse.

**Recomendación.** A. El ajuste mínimo es la paridad de verificación y la denegación de grants rechazados/cuarentenados; no se absorbe AUD-06.

**Decisión requerida.** El usuario debe aprobar el límite y confirmar que el ajuste mínimo del fallback es aceptable.

**RF/AC afectados.** §3.1/§3.2; RF-015.7–RF-015.9; AC-015d; D-08 del PLAN.

## 9. Observaciones obligatorias

### OBS-01 — Fallback legacy

**Estado:** RESUELTO DOCUMENTALMENTE; implementación pendiente y no autorizada.

**Hallazgo.** `_load_bundle` (authority_service.py:533-553) lee `approvals/{spec_id}-{version}.json` cuando el store no encuentra el grant y devuelve el approval sin correlación. Por tanto, un grant no correlacionado puede seguir autorizando aunque la migración lo rechace.

**Respuesta.** RF-015.7 exige paridad de verificación en toda ruta; RF-015.8 prohíbe usar grants rechazados/cuarentenados desde el fallback; RF-015.9 limita el cambio a la paridad y deja AUD-06 fuera. AC-015d es la prueba negativa. El fallback no puede crear eventos, migrar ni reparar.

**Límite.** No se elimina el fallback ni se rediseña el almacenamiento legacy; eso sigue siendo AUD-06. La corrección de implementación no se ejecuta en esta misión.

### OBS-02 — Fallos transitorios del proveedor

**Estado:** RESUELTO DOCUMENTALMENTE, condicionado a D-02.

**Respuesta.** La tabla de RF-012 separa rechazo definitivo, transitorio, configuración, firma inválida, firmante no disponible y commit ambiguo. RF-012.9 exige backoff, límite de reintentos y no invalidación automática; AC-012e/f/h lo prueban. Un fallo transitorio nunca aprueba.

**Límite.** El número de reintentos, backoff y TTL debe aprobarse en D-02/implementación; no se fija aquí un valor arbitrario.

### OBS-03 — Reconciliación humana

**Estado:** PENDIENTE/BLOQUEADO.

**Hallazgo.** `authority_service.reconcile` exige UID administrador y `_admin_identity`; en producción `_approval_event` sigue denegando por `SETUP_INCOMPLETE`, y la prueba de reconciliación usa identidad simulada. Además, `reconcile` limpia una auditoría incompleta; no resuelve una intención huérfana ni aporta evidencia del target.

**Respuesta.** RF-013.11–RF-013.12 exigen un mecanismo autorizado con identidad humana reautenticada y evidencia; si no existe, la resolución permanece bloqueada. No se inventa un mecanismo ni se acepta una firma del agente. AC-013b prueba que `reconcile` genérico no resuelve la huérfana.

**Límite.** La reconciliación de operaciones huérfanas no puede implementarse hasta que el usuario autorice un mecanismo; el bloqueo es el resultado correcto, no un defecto a ocultar.

### OBS-04 — Trazabilidad del PLAN

**Estado:** RESUELTO DOCUMENTALMENTE.

**Respuesta.** IMP-03 (fsync/durabilidad) ya no depende de D-05; depende de IMP-01 y D-06. D-05 queda para IMP-06/IMP-07. AC-017 se vincula a TST-09 (`test_document_state_contract_is_unchanged`), que comprueba el conjunto exacto de siete estados, rechazo de un estado desconocido y ausencia de cambios en SPEC-ARCH-001. La matriz AUD→RF→AC→prueba está en la SPEC §15.2 y en el PLAN §5/§8.

**Límite.** TST-09 es una prueba planificada, no ejecutada en esta misión documental; no se declara PASS.

## 10. Matriz de decisiones y trazabilidad

| Decisión | RF | AC | Tarea del PLAN | Estado |
|---|---|---|---|---|
| D-01 | Cobertura heredada | §15.1/§18 | G0 | PENDING |
| D-02 | RF-012 | AC-012a–h | IMP-02/TST-01 | PENDING |
| D-03 | RF-012.6 | AC-012b | IMP-02/TST-01 | PENDING |
| D-04 | RF-015 | AC-015a–e | IMP-05/MIG-02/TST-04 | PENDING |
| D-05 | RF-016 | AC-016a–d | IMP-06/IMP-07/TST-05 | PENDING |
| D-06 | RF-013/RF-014 | AC-013a–c/AC-014a–c | IMP-01/IMP-04/MIG-01 | PENDING |
| D-07 | RF-013/RF-015 | AC-013/AC-015c | IMP-04/MIG-02 | PENDING |
| D-08 | RF-015.7–.9 | AC-015d | IMP-05/TST-04 | PENDING |

## 11. Riesgos residuales del registro

1. **D-01:** sin aprobación formal, la cobertura de la SPEC-001 es condicional y puede discutirse.
2. **D-04/OBS-01:** la paridad de verificación reduce el bypass, pero el fallback sigue siendo una fuente fuera del store; AUD-06 permanece.
3. **OBS-03:** no hay mecanismo de producción demostrado para reconciliar huérfanas; el bloqueo puede ser permanente.
4. **D-05:** consumidores que ignoran `ok`/`valid` pueden seguir interpretando mal la salida; la compatibilidad no es una garantía de uso correcto.
5. **D-06:** la atomicidad SQLite↔filesystem no existe; la ventana indeterminada requiere reconciliación humana.
6. **D-02:** la política estricta puede facilitar denegación de servicio si un tercero posee el token; es el coste de impedir replay.

## 12. Condición de cierre documental

Este registro queda en **DRAFT**. Ninguna decisión está aprobada. No se implementa, no se firma, no se modifica SPEC-ARCH-001 y no se declara producción habilitada. El usuario debe revisar las recomendaciones y emitir una autorización explícita por decisión, indicando la alternativa elegida y el hash de la SPEC-002 resultante.

Hasta entonces, las opciones descritas son propuestas y los estados de todas las D-01…D-08 son `PENDING USER DECISION`.
