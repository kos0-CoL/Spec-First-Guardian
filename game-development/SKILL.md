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

## Autoridad de aprobación (dominio separado)

La autoridad es un **servicio independiente** (`scripts/authority_service.py`)
que corre con otro UID y habla por un socket Unix. Es el único proceso que tiene
la clave privada Ed25519, el almacén de claves de confianza, el registro de
revocaciones y la capacidad de escribir en el workspace.

El agente no importa claves ni firma: solicita. La autoridad verifica el UID del
par con `SO_PEERCRED`, exige identidad humana OIDC, emite un desafío de un solo
uso ligado a la solicitud, la huella y el alcance, y solo entonces firma.

No existe HMAC, clave por defecto, aprobación del agente ni registro de claves
por el agente. Sin autoridad disponible o sin firma verificable, se deniega.

## Comandos

```bash
export SPEC_GUARDIAN_AUTHORITY_SOCKET=/run/spec-guardian/authority.sock

python scripts/validate.py <ruta-a-spec.md> [--approval <registro.json>] [--json]
python scripts/generate_report.py <ruta-a-spec.md> [--approval <registro.json>]

python scripts/approval_cli.py status
python scripts/approval_cli.py request --project P --spec SPEC.md --scope S \
  --operations create_file --paths src/x.py --requirements RF-001 --tasks TASK-001
python scripts/approval_cli.py pending
python scripts/approval_cli.py challenge REQ-...
python scripts/approval_cli.py approve REQ-... --challenge ... --id-token-file token.txt --confirm

python scripts/enforce.py evaluate --context operacion.json
python scripts/enforce.py apply    --context operacion.json
```

El agente debe solicitar cada escritura con contexto completo (proyecto, agente,
SPEC, versión, requisito, tarea, operación, ruta y workspace). Sin contexto
completo la operación se deniega.

## Enforcement real

La autoridad ejecuta `create_file`, `modify_file`, `overwrite_file` y
`delete_file` sobre descriptores de directorio (`dir_fd`, `O_NOFOLLOW`), tras
verificar firma, identidad, revocaciones, alcance, correspondencia con la SPEC,
ruta y huella. Registra intención y resultado; si falta el cierre, bloquea nuevas
operaciones.

Las escrituras directas del agente, procesos externos, dependencias y migraciones
fuera del protocolo **no** están protegidas por el sistema: requieren aislamiento
del sistema operativo y un workspace sin permisos de escritura para el agente.
Ver `instructions/enforcement.md` y `instructions/authority.md`.
