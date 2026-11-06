---
plan_id: PLAN-ARCH-002
title: "Plan de remediación de hallazgos P1 de Etapa B"
status: DRAFT
version: 0.2.2
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
base_commit: "d8a681c6226f89b123a2802b3aeb02b18f029368"
supersedes: "0.2.1 (DRAFT)"
spec: "SPEC-ARCH-002-SECURITY-REMEDIATION.md"
spec_sha256: "6aa2b38674c50ff166ba0bd2d7a9e923df38420066f9f4903927b3e88cd5fec5"
decisions: "DECISIONS-ARCH-002-SECURITY-REMEDIATION.md"
---

# PLAN-ARCH-002 — Plan de remediación de hallazgos P1 de Etapa B

**Estado:** DRAFT; no aprobado, no autoriza implementación ni producción.<br>
**Versión:** 0.2.2; revisión documental que sustituye al borrador 0.2.1.<br>
**Fecha:** 2026-11-06<br>
**Autor:** Buffy — propuesta de secuencia para revisión humana.<br>
**SPEC de referencia:** `SPEC-ARCH-002-SECURITY-REMEDIATION.md`, versión 0.2.2, SHA-256 `6aa2b38674c50ff166ba0bd2d7a9e923df38420066f9f4903927b3e88cd5fec5`.<br>
**Registro de decisiones:** `DECISIONS-ARCH-002-SECURITY-REMEDIATION.md`; todas las decisiones permanecen pendientes.<br>
**Baseline documental:** `d8a681c6226f89b123a2802b3aeb02b18f029368`; código auditado en `094f93d065cbbedce7d9ff35aeb862db92422476`.<br>
**Autoridad documental:** este PLAN está subordinado a la SPEC-ARCH-002. No puede agregar requisitos, ampliar alcance, cambiar prioridades ni modificar criterios de aceptación. Si hay discrepancia, la SPEC gobierna y este PLAN debe corregirse.

> **No ejecutar ahora.** Este documento es una secuencia propuesta. No se modifican código, tests, scripts, configuración, SPEC-ARCH-001, OIDC ni datos en esta misión.

## 1. Reglas de planificación

- Ninguna tarea de implementación comienza sin aprobación explícita de la SPEC-ARCH-002 (texto, versión y hash). La aprobación puede ser condicional si D-01 sigue pendiente; D-01 no bloquea esa aprobación condicional, pero impide declarar conformidad normativa completa. Cada tarea depende además de las decisiones específicas indicadas en §2.1.1, no de todas las D-xx.
- Cada tarea debe mapear a un requisito RF-012…RF-016 y a un criterio AC-012…AC-018; una tarea sin trazabilidad no se ejecuta.
- Las pruebas de regresión deben demostrar el defecto en el commit base antes de aceptar la corrección. Una prueba que pasa con el código defectuoso no demuestra la corrección.
- No se relajan aserciones, no se omiten fallos y no se sustituyen pruebas de ambiente real por mocks.
- No se implementa OIDC, UI, callback ni habilitación de producción.
- No se corrigen AUD-06 a AUD-17 salvo el ajuste mínimo anti-bypass del fallback exigido por RF-015.7–RF-015.9; la remediación general de AUD-06, la truncación de cola y el rediseño del almacenamiento legacy no se incluyen silenciosamente.
- El fallback legacy sólo se toca para aplicar la misma verificación de correlación y denegar grants rechazados/cuarentenados; no se convierte en una segunda autoridad ni se elimina en esta misión.
- Los datos, archivos históricos, WAL/SHM, eventos y evidencia de fallos se preservan; no se borran para “limpiar” una prueba.
- Toda evidencia se registra con commit, hashes, comandos, versión de Python/SQLite, filesystem, resultados exactos y limitaciones.

## 2. Precondiciones y compuertas

### 2.1 Compuerta G0 — Autoridad global y alcance

G0 es una compuerta global de autoridad, no una exigencia de resolver todas las decisiones técnicas.

Antes de cualquier cambio:

- Aprobar explícitamente `SPEC-ARCH-002-SECURITY-REMEDIATION.md` con texto, versión y hash. La aprobación **puede ser condicional** si D-01 sigue pendiente: autoriza la revisión/implementación condicionada a las demás compuertas, pero no aprueba SPEC-ARCH-001 ni permite declarar conformidad normativa completa. **D-01 no bloquea esta aprobación condicional.**
- Confirmar el alcance AUD-01…AUD-05 más el ajuste mínimo anti-bypass del fallback. D-08 debe estar resuelta para fijar el alcance; no incluye la remediación general de AUD-06 ni P2/P3.
- Mantener las restricciones globales: no OIDC, no producción, no tokens directos de agentes, no ampliación de AUD-06 ni P2/P3.
- Verificar G1 antes de escribir código.

Sin G0 no se escribe código. Las tareas de análisis y fixtures pueden prepararse en rama aislada, pero no se integran. Una tarea sólo puede comenzar cuando estén resueltas **sus** decisiones específicas; las decisiones pendientes de otras tareas no bloquean tareas independientes.

#### 2.1.1 Decisiones específicas por tarea

| Decisión | Bloquea | No bloquea |
|---|---|---|
| D-01 | Declarar conformidad normativa completa o cobertura total de requisitos heredados. | La aprobación condicional de SPEC-ARCH-002 y las tareas P1 que no invoquen conformidad completa. |
| D-02 | La clasificación de binding/revisión, IMP-02, TST-01 y AC-012g en esa parte. | El mínimo obligatorio de autenticación/firma, el no-consumo de token incorrecto, el CAS y la prohibición de aprobar ante errores. |
| D-03 | La política de reemisión, IMP-02 y TST-01. | Las tareas que no emiten ni reemiten desafíos. |
| D-04 | IMP-05, MIG-02 y el cierre de AUD-04. | IMP-01/IMP-03 y el mínimo de no autorización de grants no correlacionados. |
| D-05 | IMP-06, IMP-07 y DOC-03. | IMP-03 y las tareas de durabilidad/journal. |
| D-06 | IMP-01, IMP-03, IMP-04 básico y MIG-01. | La documentación de límites y la detección conceptual. |
| D-07 | La política completa de tratamiento de anomalías, la clasificación operativa de estados, el alcance de lectura/diagnóstico y el cierre operativo de IMP-04. | La capacidad básica de IMP-04: journal durable, detección de intenciones huérfanas, bloqueo persistente, preservación de evidencia, inspección de sólo lectura y prohibición de reejecución automática. |
| D-08 | G0 y la delimitación del alcance de todas las tareas. | Ninguna tarea puede ampliar alcance por su cuenta. |

D-01 puede permanecer pendiente sin impedir G0 ni las tareas P1; sólo impide afirmar que la cobertura heredada es completa. Una tarea no comienza si están pendientes las decisiones que bloquean la capacidad concreta que va a ejecutar. En IMP-04, la capacidad básica puede comenzar con G0, G1, IMP-01, IMP-03 y D-06 resueltos; la capacidad condicionada no comienza sin D-07.

### 2.2 Compuerta G1 — Baseline reproducible

- Confirmar commit base, rama y working tree.
- Ejecutar la suite existente sin modificar tests y registrar el resultado.
- Congelar fixtures y hashes de bases/archivos legacy.
- Declarar el filesystem/mount y el entorno Linux de prueba.
- Crear backup verificable de cualquier store o dato que se use en migraciones; no usar datos reales.

### 2.3 Compuertas de seguridad

- **G2:** journal y salud demuestran bloqueo tras una intención huérfana.
- **G3:** desafío y durabilidad demuestran ausencia de éxito falso.
- **G4:** migración no deja grants no correlacionados.
- **G5:** `--verify-storage` es fail-closed y no repara.
- **G6:** validación independiente y matriz de aceptación completas.

## 3. Dependencias técnicas

```text
G0/G1
  └── IMP-01 (fundamento de store/journal/salud, D-06)
        ├── IMP-02 (AUD-01: desafío, D-02/D-03)
        ├── IMP-03 (AUD-03: fsync/durabilidad, D-06)
        │     └── IMP-04 básico (AUD-02: journal/detección/bloqueo/inspección, D-06)
        │           └── IMP-04 condicionado (política/cierre, además D-07)
        ├── IMP-05 (AUD-04: migración/correlación/fallback, D-04)
        └── IMP-06 (AUD-05: verificación integral, D-05)
              └── IMP-07 (CLI/adaptadores/compatibilidad, D-05)
                    └── VAL-01…VAL-06
```

Dependencias obligatorias:

- IMP-02, IMP-03 e IMP-05 comparten el contrato de store/salud de IMP-01; no se implementan antes de que exista una forma durable de registrar el fallo.
- IMP-04 básico depende de G0/G1, IMP-01, IMP-03 y D-06 para distinguir efecto aplicado de durabilidad confirmada; no depende de D-07. IMP-04 condicionado depende además de D-07 y del básico.
- IMP-06 depende de IMP-01, IMP-02, IMP-03, IMP-04 básico e IMP-05 porque la verificación integral debe comprobar journal, correlación, salud y resultados; la política/cierre de IMP-04 (D-07) no es requisito para iniciar la verificación básica, pero sin ella AUD-02 no se declara cerrado.
- IMP-07 depende de IMP-06 para fijar la semántica del CLI y de los adaptadores.
- **OBS-04:** IMP-03 no depende de D-05. Su dependencia real es IMP-01 + D-06 (journal/durabilidad). D-05 sólo entra en IMP-06/IMP-07.
- **OBS-08:** G0 no exige resolver D-01 ni todas las D-xx. D-01 sólo bloquea la declaración de conformidad completa; cada tarea respeta su fila de §2.1.1. Ninguna decisión pendiente autoriza a relajar una restricción global.
- **OBS-10:** IMP-04 separa la capacidad básica (journal, detección, bloqueo, preservación, inspección y no reejecución), que no depende de D-07, de la capacidad condicionada (política completa, clasificación operativa, alcance de lectura/diagnóstico y cierre), que no se ejecuta sin D-07. La básica sigue exigiendo G0/G1, IMP-01, IMP-03 y D-06.
- Las pruebas TST-01…TST-09 se escriben junto con cada tarea, pero la validación VAL-01…VAL-06 se ejecuta al final. TST-09 es la prueba documental de AC-017.

## 4. Tareas de implementación

| ID | Tarea | Depende | Requisitos | Archivos candidatos (no exclusivos) | Salida |
|---|---|---|---|---|---|
| IMP-01 | Fundamento durable: versión de esquema, journal de operaciones, consulta de huérfanas, CAS de desafío y primitivas de salud. No implementa resolución humana. | G0/G1, D-06 | RF-012, RF-013, RF-016 | `scripts/authority_store.py`, posible módulo de journal, tests de store | Esquema y APIs internas versionadas; migración v1→v2; sin cambiar todavía el flujo de aprobación. |
| IMP-02 | Invalidación del desafío tras rechazo definitivo de autenticación/firma; CAS y evento durable; política de binding según D-02; reemisión explícita; no aprobación falsa. | IMP-01, D-02/D-03 | RF-012 | `scripts/authority_service.py`, `scripts/authority_store.py`, tests de autoridad | Camino de fallo definitivo sin reutilización; binding según la decisión aprobada; token nuevo sólo por acción admin; concurrencia segura. |
| IMP-03 | Propagación de errores de fsync de archivo/directorio; estados `NOT_EXECUTED`, `EXECUTED_NOT_DURABLE`, `DURABILITY_CONFIRMED`, `INDETERMINATE`; recibo de durabilidad. | IMP-01, D-06 | RF-014 | `scripts/safe_fs.py`, `scripts/implementation_gate.py`, tests de fs | Ningún `fsync` silenciado; resultado veraz por operación; no depende del contrato CLI de D-05. |
| IMP-04 | **Básico:** journal durable en el gate, intención antes del efecto, resultado después, detección al arrancar, bloqueo persistente, preservación de evidencia, inspección de sólo lectura y prohibición de reejecución; no implementa ni simula reconciliación humana. **Condicionado a D-07:** política completa de tratamiento de anomalías, clasificación operativa de estados, alcance de lectura/diagnóstico y cierre operativo. | G0/G1, IMP-01, IMP-03, D-06; D-07 sólo para la parte condicionada | RF-013, RF-014 | `scripts/implementation_gate.py`, `scripts/authority_service.py`, `scripts/authority_store.py`, tests de gate | Básico: caída entre intención y resultado deja bloqueo persistente; la huérfana no se resuelve, borra ni reejecuta. Condicionado: política y cierre operativo sólo con D-07. |
| IMP-05 | Migración con correlación grant↔evento `approval`; aborto o cuarentena no autorizable según D-04; guard de paridad en `_load_bundle`/fallback; grants históricos no autorizables si no verifican. | IMP-01, D-04 | RF-015 | `scripts/authority_store.py`, `scripts/authority_service.py`, CLI de migración, tests de migración y fallback | Migración válida idempotente; fallo sin cambios parciales; originales intactos; fallback no autoriza grants no correlacionados/cuarentenados. |
| IMP-06 | Verificación integral del store: cadena, salud, esquema, migración, solicitudes, grants/firmas, correlación, replay, cuarentena y huérfanas; salida separada y fail-closed. | IMP-01, IMP-02, IMP-03, IMP-04 básico, IMP-05, D-05 | RF-016 | `scripts/authority_store.py`, `scripts/authority_service.py`, tests de verificación | `ok`/`valid` veraces; `chain_valid` separado; exit code 0/2; sin mutaciones. |
| IMP-07 | Adaptación del CLI y contratos de adaptadores a la semántica fail-closed y a los nuevos campos; no habilitar OIDC. | IMP-06, D-05 | RF-012…RF-016 | `scripts/authority_service.py`, `scripts/enforce.py`, `scripts/authority_client.py`, docs de contrato | Clientes y operadores reciben estados veraces; compatibilidad documentada. |

### 4.1 Restricciones de implementación (no son requisitos nuevos)

- IMP-01 se planifica conforme a la alternativa A recomendada de D-06: journal y resultados en el mismo store SQLite. D-06 sigue pendiente; no se adopta un journal separado ni eventos enriquecidos como mecanismo primario sin revisar y aprobar otra alternativa. La estructura física concreta (tablas, índices y migración) no se prescribe aquí; RF-013 y D-06 gobiernan su implementación.
- IMP-02 no debe confundir “token incorrecto” con “token válido que falló autenticación”; RF-012.4 es obligatorio.
- IMP-03 no debe revertir automáticamente una operación ya visible; RF-014.7.
- IMP-04 básico no depende de D-07: sólo implementa journal, detección, bloqueo persistente, preservación de evidencia, inspección de sólo lectura y prohibición de reejecución. IMP-04 condicionado no se ejecuta sin D-07 e incluye política completa, clasificación operativa, alcance de lectura/diagnóstico y cierre. Ninguna parte implementa, inventa ni simula una resolución administrativa de huérfanas; la resolución requiere un mecanismo autorizado que no existe en esta misión. RF-013.11–RF-013.12, AC-013b.
- IMP-05 no debe inventar eventos ni aceptar correlación por posición; RF-015.2. Debe probar el fallback tanto con grant ausente en el store como con grant en cuarentena; RF-015.7–RF-015.9.
- IMP-06 no debe marcar salud ni migrar durante la verificación; RF-016.4.

## 5. Tareas de prueba

| ID | Cobertura | Casos mínimos | Requisitos | Compuerta |
|---|---|---|---|---|
| TST-01 | Desafío | Fallo real de auth/firma (identidad no confirmada/proveedor); no `APPROVED`; token anterior rechazado; token nuevo aceptado; token incorrecto no consume; `SETUP_INCOMPLETE` no consume; timeout/red/`5xx` no consume; firmante no disponible no consume; binding/revisión se prueba según la opción D-02 aprobada (sin marcarla PASS si D-02 está pendiente); carrera de dos intentos. | RF-012, AC-012 | G3 |
| TST-02 | Journal | Fallo antes de intención; intención sin efecto; efecto sin resultado; resultado durable; huérfana al reiniciar; `reconcile` no resuelve sin mecanismo; inspección de sólo lectura; preservación de evidencia; duplicado. | RF-013, AC-013 | G2 |
| TST-03 | Durabilidad | Inyección de `OSError` en fsync de archivo/directorio para las cuatro operaciones; rename/unlink fallido; limpieza fallida. | RF-014, AC-014 | G3 |
| TST-04 | Migración y fallback | Grant sin evento; evento de otra solicitud; campos divergentes; firma inválida; cadena válida; idempotencia; originales intactos; rollback/cuarentena; fallback con grant no correlacionado/cuarentenado no autoriza. | RF-015, AC-015 | G4 |
| TST-05 | Verificación | Solicitud/grant manipulados; firma inválida; evento faltante; salud bloqueada; migración inconsistente; cuarentena; store válido; read-only; `valid==ok`; exit 0/2. | RF-016, AC-016 | G5 |
| TST-06 | Concurrencia y reinicio | Procesos reales; desafío único; intención única; Authority completa reiniciada; bloqueo persistente. | RF-012, RF-013, AC-012, AC-013 | G2/G3 |
| TST-07 | Regresión | Suite existente completa; pruebas nuevas fallan en base y pasan con corrección; no cambios de tests para ocultar fallos. | AC-012…AC-018 | G6 |
| TST-08 | Ambiente y límites | Linux/UID/filesystem disponibles; pruebas omitidas declaradas; sin OIDC real; sin declarar corte de energía probado. | SA-014/AC-018 | G6 |
| TST-09 | Contrato documental de estados | `test_document_state_contract_is_unchanged`: conjunto exacto de los siete estados, rechazo de un estado desconocido, SPEC-ARCH-001 no modificada; ejecutar antes/después. | AC-017 | G6 |

Reglas de pruebas:

- Cada caso debe tener un control negativo: el código base debe fallar el criterio, o la prueba debe demostrar que el criterio no se cumple antes de la corrección.
- Las pruebas de `fsync` con mocks demuestran manejo de errores, no durabilidad física. Se etiquetan como tales.
- Las pruebas de caída usan subprocesos reales y `os._exit(9)`; no simulan el crash con una excepción ordinaria.
- Las pruebas de concurrencia usan procesos, no sólo hilos, para el desafío y la intención.
- Las pruebas de migración comparan hashes de los archivos originales antes y después.
- Las pruebas de verificación no deben escribir ni reparar el store; se comprueba con snapshot/hash lógico y, si aplica, trazas SQLite.

## 6. Tareas de migración

| ID | Tarea | Depende | Requisitos | Evidencia |
|---|---|---|---|---|
| MIG-01 | Diseñar y probar la migración de esquema v1→v2 (o equivalente) para journal/correlación, con backup, transacción, idempotencia y validación de versión. | IMP-01, D-06 | RF-013, RF-015, RF-016 | Base v1 copiada; upgrade exitoso; segunda ejecución sin cambios; rollback documentado. |
| MIG-02 | Implementar la política D-04 para grants históricos: rechazo/cuarentena/re-aprobación; no fabricar eventos ni aceptar correlación inferida. | IMP-05, D-04 | RF-015 | Fixtures con y sin evento; resultados y hashes; decisión humana registrada. |
| MIG-03 | Probar rollback y recuperación: migración fallida no deja grants/eventos/meta parciales; originales intactos; base nueva no se declara válida con lector viejo. | MIG-01/MIG-02 | RF-015, RF-016 | Fallo inyectado; 0 cambios; backup restaurado; `verify-storage` no repara. |

La migración no se ejecuta sobre datos reales en esta fase. Cualquier cambio de esquema requiere backup verificado y una prueba de restauración en copia.

## 7. Tareas de documentación

| ID | Tarea | Depende | Requisitos | Salida |
|---|---|---|---|---|
| DOC-01 | Documentar el comportamiento nuevo de desafío, journal, durabilidad, migración y verificación; alinear afirmaciones afectadas, sin declarar cerrado AUD-15 ni ampliar a P3. | IMP-02…IMP-06 | RF-012…RF-016 | README/instrucciones/docstrings coherentes; sin tocar SPEC-ARCH-001. |
| DOC-02 | Runbook limitado: detectar y preservar evidencia, mantener el bloqueo, definir inspecciones de sólo lectura permitidas, negar reejecución y explicar que no se puede resolver una huérfana sin un mecanismo administrativo autorizado. Debe indicar la condición futura que habilitaría esa resolución, sin implementarla. | IMP-04/MIG-03 | RF-013, RF-014 | Procedimiento operativo con límites, bloqueo y rollback; sin promesa de reconciliación. |
| DOC-03 | Contrato CLI/adaptadores: campos, exit codes, compatibilidad y semántica de `valid`/`ok`/`durability`. | IMP-06/IMP-07, D-05 | RF-016 | Documento de contrato y ejemplos de salida. |
| DOC-04 | Informe de trazabilidad final: AUD→RF→AC→prueba→evidencia y omisiones. | VAL-01…VAL-06 | AC-012…AC-018 | Informe reproducible adjunto al cierre. |

DOC-01 no debe convertir AUD-06 a AUD-17 en parte del alcance; sólo documenta lo corregido y lo que sigue abierto.

## 8. Tareas de validación

| ID | Validación | Depende | Criterio | Evidencia |
|---|---|---|---|---|
| VAL-01 | Matriz de aceptación AC-012…AC-018, incluida AC-017/TST-09. | TST-01…TST-06, TST-09 | Cada AC tiene evidencia pass/blocked/omitted; AC-017 no se cierra sólo por inspección textual. | Tabla con comando, resultado y artefacto. |
| VAL-02 | Matriz de fallos: auth, journal, fsync, SQLite, migración, verificación y reinicio. | TST-01…TST-06 | Ningún fallo produce éxito falso ni salud sana indebida. | Logs y estados antes/después. |
| VAL-03 | Multiproceso, crash y reinicio real. | TST-06 | Un desafío/una intención como máximo; bloqueo persistente. | PID, exit codes, eventos, archivos. |
| VAL-04 | Ambiente Linux/UID/filesystem. | TST-08 | Resultados declarados por entorno; omitidos no se cuentan como pass. | Matriz de entorno. |
| VAL-05 | Revisión independiente de seguridad. | VAL-01…VAL-04 | Hallazgos clasificados; P0/P1 nuevos bloquean cierre. | Informe de revisión. |
| VAL-06 | No OIDC/no producción. | IMP-07 | `SETUP_INCOMPLETE` sigue vigente; no callback/UI. | Salida de estado y diff revisado. |

## 9. Orden de ejecución propuesto

| Fase | Trabajo | Salida | Compuerta |
|---|---|---|---|
| F0 | G0/G1: aprobaciones, baseline, fixtures, backup y entorno. | Expediente de inicio. | K0 |
| F1 | IMP-01 + TST-02/TST-05 parciales: fundamento de store/journal/salud y migración de esquema. | Esquema versionado, APIs, tests de base. | K1 |
| F2 | IMP-02 + TST-01/TST-06: desafío de un solo uso y carrera. | Camino AUD-01 corregido. | K2 |
| F3 | IMP-03 + TST-03: fsync y recibos de durabilidad. | Camino AUD-03 corregido. | K3 |
| F4a | IMP-04 básico + TST-02/TST-06: journal, detección de huérfanas, bloqueo persistente, preservación e inspección. | AUD-02 mitigado en la capacidad básica; resolución humana pendiente. | K4a |
| F4b | IMP-04 condicionado, sólo con D-07: política completa de anomalías, clasificación operativa, alcance de lectura/diagnóstico y cierre. | Cierre operativo de AUD-02 o bloqueo declarado. | K4b |
| F5 | IMP-05 + MIG-01/MIG-02/TST-04: correlación y migración. | Camino AUD-04 corregido. | K5 |
| F6 | IMP-06 + TST-05: verificación integral y CLI. | Camino AUD-05 corregido. | K6 |
| F7 | IMP-07 + DOC-01…DOC-03: compatibilidad, adaptadores y runbook. | Contrato y documentación. | K7 |
| F8 | VAL-01…VAL-06 + DOC-04: validación final e informe. | Evidencia de cierre o bloqueo. | K8 |

Las fases F2 y F3 pueden ejecutarse en paralelo sólo si comparten el contrato de IMP-01 y no modifican los mismos puntos de estado sin coordinación. F4a no comienza sin F3; F4b no comienza sin F4a y D-07. F6 no comienza sin F2, F4a y F5; F4b es necesaria para el cierre operativo de AUD-02, no para iniciar la verificación básica. F8 no declara cierre operativo de AUD-02 sin F4b.

## 10. Checkpoints y evidencias

Cada checkpoint debe registrar:

- SHA del commit base y del commit de trabajo.
- Hash de SPEC-ARCH-002 y de la SPEC-ARCH-001 usada como baseline.
- Diff revisado y archivos tocados.
- Comandos exactos y salida completa de pruebas.
- Versión de Python, SQLite, Linux, filesystem/mount y UID.
- Fixtures/hashes de bases y archivos legacy.
- Estados de salud, eventos, recibos de durabilidad y exit codes.
- Pruebas omitidas, bloqueadas o no concluyentes, con motivo.
- Decisiones específicas aplicadas y su registro; K4a no requiere D-07 y K4b sí; D-01 puede seguir pendiente si el checkpoint no declara conformidad normativa completa.

Un checkpoint no se cierra por “la suite pasó”; requiere que el criterio específico y su control negativo estén demostrados. K4a certifica journal, detección, bloqueo persistente, preservación e inspección de sólo lectura sin D-07. K4b sólo se abre con D-07 y certifica la política completa, la clasificación operativa, el alcance de lectura/diagnóstico y el cierre operativo.

## 11. Rollback y conservación

- **Código:** revertir el cambio de código no debe borrar la base, el journal, los eventos de fallo ni los datos históricos.
- **Esquema:** no se permite un downgrade que abra una base nueva y la declare válida ignorando campos de seguridad. Si el lector anterior no puede interpretar el esquema, debe negarse a operar.
- **Migración:** antes de migrar, backup verificado y restauración probada en copia. Un fallo deja la base original intacta; no se reintenta sobre datos parciales.
- **Journal:** las intenciones y resultados se preservan; no se borran para “desbloquear”. La inspección es de sólo lectura; si no existe un mecanismo administrativo autorizado, la huérfana permanece bloqueada y no se simula reconciliación.
- **Salud:** no se resetea a `HEALTHY` sin evidencia y evento de reconciliación emitido por un mecanismo autorizado; si no existe, no se desbloquea.
- **Archivos del workspace:** no se revierten automáticamente; una operación indeterminada sólo puede resolverse mediante un mecanismo autorizado con evidencia humana. Si no existe, permanece bloqueada.
- **Documentación:** los documentos nuevos son DRAFT hasta aprobación; un rollback documental no borra el expediente de auditoría.

## 12. Fuera de alcance del PLAN

- Implementar OIDC, callback, PKCE, UI o sesión de navegador.
- Habilitar producción o declarar SA-001…SA-014 cumplidos en bloque.
- Corregir AUD-06 a AUD-17 sin decisión D-08; el único ajuste permitido es la paridad anti-bypass de RF-015.7–RF-015.9.
- Reescribir SPEC-ARCH-001 o cambiar sus estados.
- Cambiar la arquitectura de permisos, criptografía o transporte.
- Reparar datos históricos sin política aprobada.
- Implementar, inventar o simular un mecanismo de reconciliación humana de huérfanas; DOC-02 sólo documenta el bloqueo y la condición futura.
- Añadir nuevas funciones de producto, plataforma o multi-tenant.

## 13. Condición de inicio

Este PLAN no se ejecuta hasta que el usuario apruebe explícitamente:

1. `SPEC-ARCH-002-SECURITY-REMEDIATION.md`, versión 0.2.2 y hash `6aa2b38674c50ff166ba0bd2d7a9e923df38420066f9f4903927b3e88cd5fec5`;
2. las decisiones específicas de §2.1.1 aplicables a cada tarea; D-01 puede seguir pendiente si la aprobación de la SPEC es explícitamente condicional;
3. el alcance estricto de los cinco P1 más el ajuste mínimo anti-bypass del fallback;
4. la exclusión de OIDC, producción y correcciones P2/P3 no autorizadas, incluida la remediación general de AUD-06.

La aprobación condicional de SPEC-ARCH-002 no es aprobación de SPEC-ARCH-001 ni permite declarar conformidad normativa completa. Hasta que exista esa aprobación y se cumplan las compuertas, este PLAN es sólo una propuesta y no autoriza cambios.
