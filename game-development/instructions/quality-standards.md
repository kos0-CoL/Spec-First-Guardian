# Estándares de Calidad de la SPEC — SPEC-001

Checklist aplicable en la Etapa 4 — Validación, antes de presentar la SPEC.

## Checklist obligatorio

- [ ] Claridad de los objetivos.
- [ ] Completitud de requisitos.
- [ ] Coherencia interna.
- [ ] Compatibilidad con la arquitectura existente.
- [ ] Dependencias identificadas.
- [ ] Restricciones definidas.
- [ ] Riesgos identificados.
- [ ] Criterios de aceptación definidos.
- [ ] Estrategia de pruebas definida.
- [ ] Ausencia de requisitos ambiguos que afecten la implementación.

## Criterios de aceptación

- Deben existir y ser verificables.
- Deben cubrir los requisitos principales del alcance.

## Ambigüedad

Si existe algún requisito ambiguo que afecte la implementación, la SPEC debe
corregirse antes de presentarse para aprobación.

## Uso del validador

```bash
python scripts/validate.py <ruta-a-spec.md>
```
