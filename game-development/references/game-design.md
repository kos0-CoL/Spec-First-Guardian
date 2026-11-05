# Referencia de Diseño de Juego — SPEC-001

Apoyo para redactar requisitos de diseño de juego dentro de una especificación.

## Propósito

Asegurar que las especificaciones de juego capturen el diseño de forma completa
y verificable antes de pasar a la implementación técnica.

## Elementos que toda SPEC de juego debe describir

1. **Visión**: propósito del juego y experiencia deseada.
2. **Mecánicas centrales**: reglas, controles, sistemas principales.
3. **Sistemas**: progresión, inventario, combate, puzzles, economía, etc.
4. **Balance**: curva de dificultad, tuning de valores.
5. **Feedback**: señales visuales, auditivas y de UI para cada acción.
6. **UX**: flujos principales, tutorialización, accesibilidad.

## Criterios medibles

- Las mecánicas se expresan en comportamientos observables.
- El balance define valores objetivo (p. ej. rango de dificultad por fase).
- Se definen métricas de éxito (retención, completitud, puntuación).

## Anti-patrones

- Describir soluciones de implementación en lugar de comportamientos.
- Dejar tuning numérico ambiguo.
- Omitir criterios de aceptación de la experiencia de juego.
