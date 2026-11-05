---
spec_id: SPEC-001
status: APPROVED
version: 1.0.0
author: codebuff
approver: usuario
approved_at: 2026-11-05
---

# SPEC-001 — Spec-First Guardian

## Identificación

- ID: SPEC-001
- Nombre: Spec-First Guardian
- Versión: 1.0.0
- Proyecto: skill
- Estado: APPROVED
- Fecha de creación: 2026-10-05
- Fecha de aprobación: 2026-11-05

## Contexto

- Problema: ausencia de marco obligatorio de especificación.
- Situación actual: desarrollo improvisado.
- Motivación: evitar implementaciones sin SPEC.

## Objetivos

- Resultado esperado: flujo spec-first obligatorio.
- Alcance funcional: guardianía transversal.
- Alcance técnico: documentación, validador, enforcement.

## Fuera de alcance

- No sustituye políticas globales de seguridad.

## Requisitos funcionales

- RF-001: bloqueo de implementación sin SPEC aprobada.

## Requisitos no funcionales

- Rendimiento: evaluación inmediata.

## Diseño técnico

- Arquitectura: skill con módulos.
- Componentes: instrucciones, validador, reportes.
- Interfaces: comandos CLI.
- Dependencias: Python.
- Flujo: solicitud → spec → validación → aprobación → implementación.

## Restricciones

- Tecnologías permitidas: Python.
- Prohibidas: ninguna adicional.
- Compatibilidad: versiones actuales.
- Reglas globales: seguridad global prevalece.

## Criterios de aceptación

- SA-01: Un agente sin SPEC no puede escribir código.
- SA-02: Una SPEC en estado DRAFT no habilita implementación.
- SA-03: Una SPEC validada pero no aprobada no habilita implementación.
- SA-04: La aprobación del orquestador no sustituye la del usuario.
- SA-05: Una aprobación explícita habilita únicamente el alcance autorizado.
- SA-06: Una modificación posterior de la SPEC requiere nueva aprobación para los cambios introducidos.
- SA-07: Un subagente no puede eludir el bloqueo.
- SA-08: Una herramienta alternativa de escritura tampoco puede eludirlo.
- SA-09: Un bloqueo localizado no impide continuar trabajos independientes autorizados.
- SA-10: La revocación bloquea nuevas operaciones de implementación.
- SA-11: Los intentos rechazados quedan registrados.
- SA-12: Los agentes pueden continuar realizando análisis e investigación sin modificar el proyecto.

## Estrategia de validación

- Pruebas unitarias, integración, funcionales y de regresión.

## Riesgos y dependencias

- Riesgo: cumplimiento. Dependencia: orquestador.

## Plan de implementación

- Tareas: documentación, validador, enforcement, pruebas.

## Aprobación

- Versión presentada: 1.0.0
- Estado: APPROVED
- Registro: usuario, 2026-11-05.
