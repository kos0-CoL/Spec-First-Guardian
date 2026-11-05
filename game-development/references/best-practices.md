# Buenas Prácticas — SPEC-001

Recomendaciones para redactar especificaciones claras y mantenibles.

## Principios

- Especificaciones atómicas: una SPEC por cambio de alcance.
- Requisitos testables: formulados de forma verificable.
- Versionado: toda aprobación implica versión.
- Trazabilidad: cada tarea de desarrollo se asocia a un requisito.
- Actualización: una SPEC desactualizada debe revalidarse.

## Estados de una SPEC

La única máquina de estados permitida es:

- `DRAFT`
- `UNDER_REVIEW`
- `PENDING_USER_APPROVAL`
- `APPROVED`
- `REJECTED`
- `SUPERSEDED`
- `ARCHIVED`

La transición a `APPROVED` requiere aprobación humana verificable.

## Mantenimiento

Ante cambios de requisitos se debe elaborar una nueva versión de la SPEC.
