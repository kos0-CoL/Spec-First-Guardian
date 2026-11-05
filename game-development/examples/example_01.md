---
spec_id: SPEC-101
status: APPROVED
version: 1.0.0
author: equipo-dev
approver: usuario
approved_at: 2026-10-01
---

# SPEC-101 — Añadir mecánica de dash

## Identificación

- ID: SPEC-101
- Nombre: Mecánica de dash
- Versión: 1.0.0
- Proyecto: juego
- Estado: APPROVED
- Fecha de creación: 2026-09-28

## Contexto

- Problema: el jugador no puede evadir riesgos.
- Situación actual: sin mecánica de dash.
- Motivación: necesidad de agilidad.

## Objetivos

- Resultado esperado: dash implementado.
- Alcance funcional: dash con colisión.
- Alcance técnico: integración con movimiento.

## Fuera de alcance

- Inventario de dashes.

## Requisitos funcionales

- RF-001: el dash dura 0.2 s.

## Requisitos no funcionales

- Rendimiento: sin impacto perceptible.

## Diseño técnico

- Arquitectura: módulo de jugador.
- Componentes: movimiento, input.
- Interfaces: input del jugador.
- Dependencias: sistema de colisiones.
- Flujo: input → dash → cooldown.

## Restricciones

- Tecnologías permitidas: motor de juego actual.
- Prohibidas: ninguna adicional.
- Compatibilidad: versiones actuales del motor.
- Reglas globales: control de implementación activo.

## Criterios de aceptación

- El dash dura 0.2 s.
- Cooldown de 0.8 s.
- Colisión con obstáculos causa daño.

## Estrategia de validación

- Pruebas unitarias, de integración, funcionales y de regresión.

## Riesgos y dependencias

- Riesgo: colisión. Dependencia: sistema de colisiones.

## Plan de implementación

- Tareas: diseño, implementación, pruebas.

## Aprobación

- Versión presentada: 1.0.0
- Estado: APPROVED
- Registro: usuario, 2026-10-01.
