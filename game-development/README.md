# Spec-First Guardian (SPEC-001)

Skill obligatoria de gobernanza del desarrollo asistido por inteligencia artificial.

## Propósito

**NINGUNA implementación sin una SPEC aprobada explícitamente por el usuario.**

La aprobación siempre corresponde al usuario humano. Ningún agente, subagente u
orquestador puede sustituirla.

## Instalación y requisitos

- Python 3.
- Acceso a los scripts del skill.

## Estructura

- `SKILL.md` — Entrada de la skill.
- `instructions/` — Reglas, flujo de trabajo, estándares y contrato de enforcement.
- `templates/` — Plantillas: especificación técnica, documento de diseño, reporte de bug.
- `scripts/` — Validador y generador de informes.
- `examples/` — Especificaciones de ejemplo.
- `assets/` — Esquemas y diagramas.
- `references/` — Conocimiento de apoyo.
- `specs/` — Especificaciones del proyecto y registros de aprobación.

## Uso

```bash
python scripts/validate.py <ruta-a-spec.md> [--approval <registro.json>]
python scripts/generate_report.py <ruta-a-spec.md> [--approval <registro.json>]
python scripts/generate_report.py --block --task-id TASK-001 --reason "Sin SPEC."
```

## Flujo

1. Recepción de solicitud.
2. Comprobación de SPEC.
3. Elaboración de SPEC.
4. Validación.
5. Aprobación humana.
6. Implementación autorizada.

## Aprobación humana

La aprobación efectiva requiere un registro verificable externo a la SPEC. Sin
registro verificable, la implementación debe denegarse.

## Limitaciones

- El validador documental no sustituye el control técnico de enforcement.
- La integración con orquestadores requiere adaptadores que implementen el contrato.

## Seguridad

Denegación por defecto. Sin autorización verificable: denegar.
