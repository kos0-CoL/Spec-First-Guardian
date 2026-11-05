# Flujo de Trabajo Obligatorio — SPEC-001

Detalle operativo de las 6 etapas.

## Etapa 1 — Recepción de solicitud

1. Identificar el objetivo solicitado.
2. Determinar el proyecto afectado.
3. Identificar los componentes potencialmente involucrados.
4. Buscar especificaciones existentes.
5. Comprobar su estado y versión.
6. Identificar requisitos relacionados.

**Acciones permitidas**: solo análisis de lectura e investigación.

**Criterio de salida**: objetivo y contexto claros.

## Etapa 2 — Comprobación de SPEC

Clasificar la situación:

- SPEC inexistente.
- SPEC existente y aplicable.
- SPEC incompleta.
- SPEC desactualizada.
- SPEC contradictoria.
- SPEC aprobada pero fuera de alcance.
- SPEC aprobada y aplicable.

**Acción**: si no existe una SPEC válida, iniciar la elaboración (Etapa 3).

## Etapa 3 — Elaboración de SPEC

El agente puede:

- Investigar alternativas.
- Examinar el código existente en modo lectura.
- Analizar dependencias.
- Identificar riesgos.
- Diseñar arquitectura.
- Proponer soluciones.
- Definir requisitos funcionales y técnicos.
- Elaborar criterios de aceptación.
- Identificar pruebas necesarias.

**Prohibición**: no ejecutar modificaciones de código durante esta etapa.

## Etapa 4 — Validación

Antes de presentar la SPEC al usuario, comprobar:

- Claridad de los objetivos.
- Completitud de requisitos.
- Coherencia interna.
- Compatibilidad con la arquitectura existente.
- Dependencias.
- Restricciones.
- Riesgos.
- Criterios de aceptación.
- Estrategia de pruebas.
- Ausencia de requisitos ambiguos que afecten la implementación.

Si encuentra problemas, corregir la propuesta antes de presentarla.

## Etapa 5 — Aprobación humana

Presentar la SPEC al usuario.

El usuario podrá:

- Aprobarla.
- Rechazarla.
- Solicitar modificaciones.
- Solicitar aclaraciones.
- Dejarla pendiente.

**Ninguna otra vía equivale a aprobación humana.**

La transición a `APPROVED` solo puede realizarse mediante una acción explícita del usuario.

Estados permitidos: `DRAFT`, `UNDER_REVIEW`, `PENDING_USER_APPROVAL`, `APPROVED`, `REJECTED`, `SUPERSEDED`, `ARCHIVED`, con transiciones controladas entre ellos.

## Etapa 6 — Implementación autorizada

Una vez aprobada:

1. Registrar la versión aprobada.
2. Registrar quién la aprobó y cuándo.
3. Asociar las tareas de desarrollo a sus requisitos.
4. Habilitar los permisos de implementación correspondientes.
5. Verificar que cada modificación respete la SPEC.
6. Registrar desviaciones.
7. Ejecutar las pruebas definidas.
8. Entregar un informe de cumplimiento.

**La autorización solamente cubre el alcance de la versión aprobada.**

## Control de implementación (Enforcement)

Antes de habilitar una operación de escritura, el orquestador debe verificar:

1. Existencia de una SPEC.
2. Identificador único de SPEC.
3. Versión de SPEC.
4. Estado `approved`.
5. Aprobación registrada por el usuario.
6. Correspondencia entre la tarea y el alcance aprobado.
7. Ausencia de bloqueos.
8. Vigencia de la autorización.

Si alguna comprobación falla, la operación debe rechazarse.

## Límites de las operaciones de lectura

Se permiten operaciones de inspección que no modifiquen el proyecto:
lectura de archivos, inspección de estructura, historial, análisis estático sin
escritura, consultas de dependencias, lectura de logs.

La ejecución de pruebas, compilaciones y herramientas que generen archivos o
modifiquen estados debe tratarse según sus permisos y efectos reales.No se considera automáticamente una operación de lectura.
