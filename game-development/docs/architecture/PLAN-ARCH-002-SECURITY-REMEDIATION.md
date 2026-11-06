---
plan_id: PLAN-ARCH-002
title: "Plan de remediación de hallazgos P1 de Etapa B"
status: DRAFT
version: 0.1.0
author: "Buffy — borrador para revisión humana"
created_at: "2026-11-06"
base_commit: "fbae472c17f0eee09d6f11043e47a6ff265e681b"
spec: "SPEC-ARCH-002-SECURITY-REMEDIATION.md"
spec_sha256: "307acb063db7ff9568ad2c2e89cff005caa746b0599aebc03358fb635b9710d9"
---

# PLAN-ARCH-002 — Plan de remediación de hallazgos P1 de Etapa B

**Estado:** DRAFT; no aprobado, no autoriza implementación ni producción.<br>
**Fecha:** 2026-11-06<br>
**Autor:** Buffy — propuesta de secuencia para revisión humana.<br>
**SPEC de referencia:** `SPEC-ARCH-002-SECURITY-REMEDIATION.md`, versión 0.1.0, SHA-256 `307acb063db7ff9568ad2c2e89cff005caa746b0599aebc03358fb635b9710d9`.<br>
**Base examinada:** `fbae472c17f0eee09d6f11043e47a6ff265e681b`; código auditado en `094f93d065cbbedce7d9ff35aeb862db92422476`.<br>
**Autoridad documental:** este PLAN está subordinado a la SPEC-ARCH-002. No puede agregar requisitos, ampliar alcance, cambiar prioridades ni modificar criterios de aceptación. Si hay discrepancia, la SPEC gobierna y este PLAN debe corregirse.

> **No ejecutar ahora.** Este documento es una secuencia propuesta. No se modifican código, tests, scripts, configuración, SPEC-ARCH-001, OIDC ni datos en esta misión.

## 1. Reglas de planificación

- Ninguna tarea de implementación comienza sin aprobación explícita de la SPEC-ARCH-002 (texto, versión y hash) y de las decisiones D-01 a D-08 que correspondan.
- Cada tarea debe mapear a un requisito RF-012…RF-016 y a un criterio AC-012…AC-018; una tarea sin trazabilidad no se ejecuta.
- Las pruebas de regresión deben demostrar el defecto en el commit base antes de aceptar la corrección. Una prueba que pasa con el código defectuoso no demuestra la corrección.
- No se relajan aserciones, no se omiten fallos y no se sustituyen pruebas de ambiente real por mocks.
- No se implementa OIDC, UI, callback ni habilitación de producción.
- No se corrigen AUD-06 a AUD-17 salvo decisión D-08; en particular, el fallback legacy y la truncación de cola no se incluyen silenciosamente.
- Los datos, archivos históricos, WAL/SHM, eventos y evidencia de fallos se preservan; no se borran para “limpiar” una prueba.
- Toda evidencia se registra con commit, hashes, comandos, versión de Python/SQLite, filesystem, resultados exactos y limitaciones.

## 2. Precondiciones y compuertas

### 2.1 Compuerta G0 — Autoridad y decisiones

Antes de cualquier cambio:

- Aprobar o rechazar la SPEC-ARCH-002 y registrar su SHA-256.
- Resolver D-01: aprobación formal/hash de SPEC-ARCH-001; el archivo se declara DRAFT.
- Resolver D-02 y D-03: disparador de invalidación y forma de reemisión del desafío.
- Resolver D-04: política de grants históricos no correlacionados.
- Resolver D-05: contrato de `--verify-storage`, `valid`/`ok` y compatibilidad de adaptadores.
- Resolver D-06: ubicación y atomicidad del journal.
- Resolver D-07: comportamiento ante datos existentes con huérfanas/no correlacionados.
- Resolver D-08: confirmar que el alcance es estrictamente P1.

Sin G0 no se escribe código. Las tareas de análisis y fixtures pueden prepararse en rama aislada, pero no se integran.

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
  └── IMP-01 (fundamento de store/journal/salud)
        ├── IMP-02 (AUD-01: desafío)
        ├── IMP-03 (AUD-03: fsync/durabilidad)
        │     └── IMP-04 (AUD-02: gate/recovery)
        ├── IMP-05 (AUD-04: migración/correlación)
        └── IMP-06 (AUD-05: verificación integral)
              └── IMP-07 (CLI/adaptadores/compatibilidad)
                    └── VAL-01…VAL-06
```

Dependencias obligatorias:

- IMP-02, IMP-03 e IMP-05 comparten el contrato de store/salud de IMP-01; no se implementan antes de que exista una forma durable de registrar el fallo.
- IMP-04 depende de IMP-03 para distinguir efecto aplicado de durabilidad confirmada.
- IMP-06 depende de IMP-01 a IMP-05 porque la verificación integral debe comprobar journal, correlación, salud y resultados.
- IMP-07 depende de IMP-06 para fijar la semántica del CLI y de los adaptadores.
- Las pruebas TST-01…TST-08 se escriben junto con cada tarea, pero la validación VAL-01…VAL-06 se ejecuta al final.

## 4. Tareas de implementación

| ID | Tarea | Depende | Requisitos | Archivos candidatos (no exclusivos) | Salida |
|---|---|---|---|---|---|
| IMP-01 | Fundamento durable: versión de esquema, journal de operaciones, consulta de huérfanas, CAS de desafío y primitivas de salud/reconciliación. | G0/G1, D-06 | RF-012, RF-013, RF-016 | `scripts/authority_store.py`, posible módulo de journal, tests de store | Esquema y APIs internas versionadas; migración v1→v2; sin cambiar todavía el flujo de aprobación. |
| IMP-02 | Invalidación del desafío tras fallo de autenticación/firma; CAS y evento durable; reemisión explícita; no aprobación falsa. | IMP-01, D-02/D-03 | RF-012 | `scripts/authority_service.py`, `scripts/authority_store.py`, tests de autoridad | Camino de fallo sin reutilización; token nuevo sólo por acción admin; concurrencia segura. |
| IMP-03 | Propagación de errores de fsync de archivo/directorio; estados `NOT_EXECUTED`, `EXECUTED_NOT_DURABLE`, `DURABILITY_CONFIRMED`, `INDETERMINATE`; recibo de durabilidad. | IMP-01, D-05 | RF-014 | `scripts/safe_fs.py`, `scripts/implementation_gate.py`, tests de fs | Ningún `fsync` silenciado; resultado veraz por operación. |
| IMP-04 | Journal en el gate: intención antes del efecto, resultado después, detección al arrancar, bloqueo por huérfana y reconciliación ligada a la operación. | IMP-01, IMP-03, D-06 | RF-013, RF-014 | `scripts/implementation_gate.py`, `scripts/authority_service.py`, `scripts/authority_store.py`, tests de gate | Caída entre intención y resultado deja bloqueo persistente; no reejecución automática. |
| IMP-05 | Migración con correlación grant↔evento `approval`; aborto todo-o-nada; grants históricos no autorizables si no verifican. | IMP-01, D-04 | RF-015 | `scripts/authority_store.py`, `scripts/authority_service.py`, CLI de migración, tests de migración | Migración válida idempotente; fallo sin cambios parciales; originales intactos. |
| IMP-06 | Verificación integral del store: cadena, salud, esquema, migración, solicitudes, grants/firmas, correlación, replay y huérfanas; salida separada y fail-closed. | IMP-01…IMP-05, D-05 | RF-016 | `scripts/authority_store.py`, `scripts/authority_service.py`, tests de verificación | `ok`/`valid` veraces; `chain_valid` separado; exit code correcto. |
| IMP-07 | Adaptación del CLI y contratos de adaptadores a la semántica fail-closed y a los nuevos campos; no habilitar OIDC. | IMP-06, D-05 | RF-012…RF-016 | `scripts/authority_service.py`, `scripts/enforce.py`, `scripts/authority_client.py`, docs de contrato | Clientes y operadores reciben estados veraces; compatibilidad documentada. |

### 4.1 Restricciones de implementación (no son requisitos nuevos)

- IMP-01 puede elegir tabla de journal, eventos enriquecidos o journal separado, pero debe cumplir RF-013 y D-06; no se prescribe aquí la estructura física.
- IMP-02 no debe confundir “token incorrecto” con “token válido que falló autenticación”; RF-012.4 es obligatorio.
- IMP-03 no debe revertir automáticamente una operación ya visible; RF-014.7.
- IMP-05 no debe inventar eventos ni aceptar correlación por posición; RF-015.2.
- IMP-06 no debe marcar salud ni migrar durante la verificación; RF-016.4.

## 5. Tareas de prueba

| ID | Cobertura | Casos mínimos | Requisitos | Compuerta |
|---|---|---|---|---|
| TST-01 | Desafío | Fallo real de auth/firma (identidad no confirmada/proveedor); no `APPROVED`; token anterior rechazado; token nuevo aceptado; token incorrecto no consume; `SETUP_INCOMPLETE` no consume; carrera de dos intentos. | RF-012, AC-012 | G3 |
| TST-02 | Journal | Fallo antes de intención; intención sin efecto; efecto sin resultado; resultado durable; huérfana al reiniciar; resolución humana; duplicado. | RF-013, AC-013 | G2 |
| TST-03 | Durabilidad | Inyección de `OSError` en fsync de archivo/directorio para las cuatro operaciones; rename/unlink fallido; limpieza fallida. | RF-014, AC-014 | G3 |
| TST-04 | Migración | Grant sin evento; evento de otra solicitud; campos divergentes; firma inválida; cadena válida; idempotencia; originales intactos; rollback. | RF-015, AC-015 | G4 |
| TST-05 | Verificación | Solicitud/grant manipulados; firma inválida; evento faltante; salud bloqueada; migración inconsistente; store válido; read-only. | RF-016, AC-016 | G5 |
| TST-06 | Concurrencia y reinicio | Procesos reales; desafío único; intención única; Authority completa reiniciada; bloqueo persistente. | RF-012, RF-013, AC-012, AC-013 | G2/G3 |
| TST-07 | Regresión | Suite existente completa; pruebas nuevas fallan en base y pasan con corrección; no cambios de tests para ocultar fallos. | AC-012…AC-018 | G6 |
| TST-08 | Ambiente y límites | Linux/UID/filesystem disponibles; pruebas omitidas declaradas; sin OIDC real; sin declarar corte de energía probado. | SA-014/AC-018 | G6 |

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
| DOC-02 | Runbook de recuperación: preservar evidencia, resolver huérfanas, reconciliar con reautenticación, no reejecutar, verificar y reiniciar. | IMP-04/MIG-03 | RF-013, RF-014 | Procedimiento operativo con límites y rollback. |
| DOC-03 | Contrato CLI/adaptadores: campos, exit codes, compatibilidad y semántica de `valid`/`ok`/`durability`. | IMP-06/IMP-07, D-05 | RF-016 | Documento de contrato y ejemplos de salida. |
| DOC-04 | Informe de trazabilidad final: AUD→RF→AC→prueba→evidencia y omisiones. | VAL-01…VAL-06 | AC-012…AC-018 | Informe reproducible adjunto al cierre. |

DOC-01 no debe convertir AUD-06 a AUD-17 en parte del alcance; sólo documenta lo corregido y lo que sigue abierto.

## 8. Tareas de validación

| ID | Validación | Depende | Criterio | Evidencia |
|---|---|---|---|---|
| VAL-01 | Matriz de aceptación AC-012…AC-018. | TST-01…TST-06 | Cada AC tiene evidencia pass/blocked/omitted. | Tabla con comando, resultado y artefacto. |
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
| F4 | IMP-04 + TST-02/TST-06: journal, huérfanas, reconciliación. | Camino AUD-02 corregido. | K4 |
| F5 | IMP-05 + MIG-01/MIG-02/TST-04: correlación y migración. | Camino AUD-04 corregido. | K5 |
| F6 | IMP-06 + TST-05: verificación integral y CLI. | Camino AUD-05 corregido. | K6 |
| F7 | IMP-07 + DOC-01…DOC-03: compatibilidad, adaptadores y runbook. | Contrato y documentación. | K7 |
| F8 | VAL-01…VAL-06 + DOC-04: validación final e informe. | Evidencia de cierre o bloqueo. | K8 |

Las fases F2 y F3 pueden ejecutarse en paralelo sólo si comparten el contrato de IMP-01 y no modifican los mismos puntos de estado sin coordinación. F4 no comienza sin F3. F6 no comienza sin F2, F4 y F5.

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
- Decisión humana aplicada (D-01…D-08) y su registro.

Un checkpoint no se cierra por “la suite pasó”; requiere que el criterio específico y su control negativo estén demostrados.

## 11. Rollback y conservación

- **Código:** revertir el cambio de código no debe borrar la base, el journal, los eventos de fallo ni los datos históricos.
- **Esquema:** no se permite un downgrade que abra una base nueva y la declare válida ignorando campos de seguridad. Si el lector anterior no puede interpretar el esquema, debe negarse a operar.
- **Migración:** antes de migrar, backup verificado y restauración probada en copia. Un fallo deja la base original intacta; no se reintenta sobre datos parciales.
- **Journal:** las intenciones y resultados se preservan; no se borran para “desbloquear”. La recuperación usa reconciliación, no limpieza.
- **Salud:** no se resetea a `HEALTHY` sin evidencia y evento de reconciliación.
- **Archivos del workspace:** no se revierten automáticamente; una operación indeterminada se resuelve con evidencia humana.
- **Documentación:** los documentos nuevos son DRAFT hasta aprobación; un rollback documental no borra el expediente de auditoría.

## 12. Fuera de alcance del PLAN

- Implementar OIDC, callback, PKCE, UI o sesión de navegador.
- Habilitar producción o declarar SA-001…SA-014 cumplidos en bloque.
- Corregir AUD-06 a AUD-17 sin decisión D-08.
- Reescribir SPEC-ARCH-001 o cambiar sus estados.
- Cambiar la arquitectura de permisos, criptografía o transporte.
- Reparar datos históricos sin política aprobada.
- Añadir nuevas funciones de producto, plataforma o multi-tenant.

## 13. Condición de inicio

Este PLAN no se ejecuta hasta que el usuario apruebe explícitamente:

1. `SPEC-ARCH-002-SECURITY-REMEDIATION.md`, versión 0.1.0 y hash `307acb063db7ff9568ad2c2e89cff005caa746b0599aebc03358fb635b9710d9`;
2. las decisiones D-01 a D-08 aplicables;
3. el alcance estricto de los cinco P1;
4. la exclusión de OIDC, producción y correcciones P2/P3 no autorizadas.

Hasta entonces, este PLAN es sólo una propuesta y no autoriza cambios.
