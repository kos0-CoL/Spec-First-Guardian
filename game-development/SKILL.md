---
name: spec-first-guardian
description: |
  Guardián obligatorio de especificación (SPEC-001 — Spec-First Guardian).
  Impide iniciar, modificar o extender implementaciones sin una especificación
  técnica o funcional previamente creada, validada y aprobada explícitamente por
  el usuario. Activar este flujo antes de cualquier tarea de desarrollo, bug fix,
  refactorización, integración o creación de funcionalidad.
---

# Spec-First Guardian — SPEC-001

## Propósito

Establecer un mecanismo obligatorio que impida iniciar, modificar o extender
implementaciones de software sin una especificación técnica o funcional
previamente creada, validada y aprobada explícitamente por el usuario.

## Principio fundamental

**NINGUNA implementación sin una SPEC aprobada explícitamente por el usuario.**

La ausencia de especificación, su estado incompleto, su falta de aprobación o
cualquier duda sobre su alcance implica bloqueo de implementación.

No existen excepciones automáticas por simplicidad, urgencia, bajo riesgo
aparente, líneas reducidas, recomendación de otro agente, ni aprobación del
orquestador o de un agente especializado.

## Flujo obligatorio de trabajo

| Etapa | Nombre | Acción clave |
|---|---|---|
| 1 | Recepción de solicitud | Análisis de lectura e investigación |
| 2 | Comprobación de SPEC | Clasificar estado de la SPEC |
| 3 | Elaboración de SPEC | Documentar la especificación |
| 4 | Validación | Verificar calidad y completitud |
| 5 | Aprobación humana | Esperar aprobación explícita del usuario |
| 6 | Implementación autorizada | Implementar bajo alcance aprobado |

Cada etapa está detallada en `instructions/workflow.md`.

## Reglas críticas

- No escribir ni modificar código hasta que la SPEC esté en estado `APPROVED`.
- Las desviaciones de la SPEC aprobada deben registrarse y justificarse.
- El silencio, la falta de respuesta o la aprobación de agentes no equivalen a
  aprobación humana.
- El orquestador aplica un control técnico de enforcement antes de conceder
  permisos de escritura; si falla alguna comprobación obligatoria, se rechaza.
- Las operaciones de escritura protegidas (código, configuración, generación,
  scripts, dependencias, migraciones, Git, escrituras indirectas) están sujetas
  al control.
- Si el sistema no puede comprobar la autorización, debe denegar.
- Las restricciones se propagan a toda la cadena de delegación de subagentes.

## Estructura

- `references/` — Conocimiento de apoyo: diseño de juego, arquitectura, rendimiento, buenas prácticas.
- `instructions/` — Reglas, flujo de trabajo y estándares de calidad.
- `templates/` — Plantillas: documento de diseño, especificación técnica, reporte de bug.
- `scripts/` — Validación automática y generación de informes.
- `examples/` — Ejemplos de especificaciones.
- `assets/` — Esquemas (`schemas/`) y diagramas (`diagrams/`).

## Autoridad de aprobación

Una única autoridad: `scripts/approval_service.py` (Ed25519 + identidad humana +
almacén de confianza externo). No existe firma HMAC, clave por defecto ni
aprobación generada por el agente. La firma solo la produce el backend protegido
de la autoridad; la verificación solo acepta claves del almacén configurado por el
supervisor. Sin esa configuración, la implementación se deniega.

La aprobación vive en un registro externo firmado: identidad autenticada, huella
del contenido, alcance, vigencia y revocaciones. El documento nunca es fuente de
confianza de la aprobación.

## Comandos

```bash
python scripts/validate.py <ruta-a-spec.md> [--approval <registro.json>] [--json]
python scripts/generate_report.py <ruta-a-spec.md> [--approval <registro.json>]
python scripts/enforce.py evaluate --context operacion.json
python scripts/enforce.py apply    --context operacion.json
```

El agente debe solicitar cada escritura al Implementation Gate con contexto
completo (proyecto, agente, SPEC, versión, requisito, tarea, operación, ruta y
workspace). Sin contexto completo la operación se deniega.

## Enforcement real

El gate ejecuta `create_file`, `modify_file`, `overwrite_file` y `delete_file`
tras verificar firma, identidad, revocaciones, alcance, ruta y hash de la SPEC.
Las escrituras directas del agente, procesos externos, dependencias y migraciones
fuera del gate **no** están protegidas: requieren aislamiento del sistema
operativo. Ver `instructions/enforcement.md`.
