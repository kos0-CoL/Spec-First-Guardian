# Reglas del Spec-First Guardian — SPEC-001

## Reglas duras

1. **Ninguna implementación sin SPEC aprobada explícitamente por el usuario.**
2. Si la SPEC no existe, está incompleta, no está aprobada o hay duda sobre su
   alcance, se debe bloquear la implementación.
3. No improvisar ni interpretar requisitos no documentados.
4. No ampliar el alcance sin una nueva SPEC aprobada.
5. No modificar código bajo el argumento de que es una mejora menor.
6. Toda desviación de la SPEC aprobada debe registrarse con justificación.
7. La aprobación del orquestador o de un agente especializado no sustituye la
   aprobación humana.

## Estados y transiciones

- `draft` → `validated` → `approved` → (implementación).
- `rejected` o ausencia de aprobación: sin implementación.

## Bloqueos

Ante cualquier duda razonable sobre el cumplimiento de estas reglas, el agente
debe detener la tarea y solicitar clarificación al usuario.

## Control de implementación (Enforcement) — SPEC-001 §5

El orquestador debe aplicar un control técnico antes de conceder permisos de escritura o ejecución de operaciones de implementación.

### Comprobaciones obligatorias antes de habilitar escritura

1. Existencia de una SPEC.
2. Identificador único de SPEC.
3. Versión de SPEC.
4. Estado `APPROVED`.
5. Aprobación registrada por el usuario.
6. Correspondencia entre la tarea y el alcance aprobado.
7. Ausencia de bloqueos globales o del proyecto.
8. Vigencia de la autorización.

Si alguna comprobación falla, la operación debe rechazarse.

### Operaciones protegidas

Creación, edición y eliminación de código; modificación de configuraciones; generación de código; ejecución de scripts; instalación/actualización de dependencias; migraciones de bases de datos; operaciones de Git que alteren el estado; escrituras indirectas de subagentes. No alcanza con bloquear una herramienta si otra permite la misma modificación.

### Denegación por defecto

Si el sistema no puede comprobar la autorización, debe denegar. No asumir permiso por fallos del sistema, pérdida de conexión, información incompleta, estado desconocido, errores del orquestador o versión de SPEC desconocida.

### Protección de subagentes

Todo agente delegado hereda las restricciones globales. Ningún agente puede crear otro agente para eludir el bloqueo, delegar una implementación no autorizada, usar herramientas alternativas para escribir o solicitar a otro agente realizar una operación prohibida. Las restricciones se propagan por toda la cadena de delegación.

### Integridad de la autorización

La aprobación debe estar vinculada a una versión específica de la SPEC. Si se modifica la SPEC tras aprobarla: nueva versión, pendiente de aprobación, bloqueo de operaciones dependientes, y la aprobación anterior no se transfiere automáticamente. Las tareas dentro del alcance de la versión previamente aprobada pueden mantenerse autorizadas si no dependen de los cambios pendientes.

## Gestión de estados (SPEC-001 §7)

Estados permitidos: `DRAFT`, `UNDER_REVIEW`, `PENDING_USER_APPROVAL`, `APPROVED`,
`REJECTED`, `SUPERSEDED`, `ARCHIVED`.

Transiciones controladas:

- `DRAFT` → `UNDER_REVIEW`
- `UNDER_REVIEW` → `DRAFT` o `PENDING_USER_APPROVAL`
- `PENDING_USER_APPROVAL` → `APPROVED`, `REJECTED` o `DRAFT`
- `APPROVED` → `SUPERSEDED` o `ARCHIVED`
- `REJECTED` → `DRAFT` o `ARCHIVED`
- `SUPERSEDED` → `ARCHIVED`

La transición a `APPROVED` solo puede realizarse mediante una acción explícita del usuario.

## Registro de aprobación (SPEC-001 §8)

Cada aprobación debe registrar: ID de SPEC, número de versión, identidad del usuario aprobador, fecha y hora, huella digital del contenido aprobado, alcance autorizado e identificador de la sesión o evento de aprobación.

Una aprobación debe ser verificable y no puede ser creada por un agente.

## Revocación de aprobación (SPEC-001 §9)

Al revocarla: se bloquean nuevas operaciones de implementación asociadas; se detienen las operaciones pendientes que dependan de esa autorización; se preservan los archivos y cambios ya realizados; se registra el motivo, si el usuario lo proporciona; se informa el estado del trabajo; no se realizan reversiones automáticas sin autorización.

La revocación no equivale a eliminar el historial.

## Gestión de bloqueos y conflictos (SPEC-001 §11)

### Bloqueo localizado

Cuando una tarea no tiene una SPEC aprobada:

- Se bloquea esa tarea.
- Se identifican sus dependencias.
- Se informa al orquestador.
- Se buscan actividades independientes previamente autorizadas.

El bloqueo de una tarea no debe paralizar automáticamente todo el proyecto.

### Trabajo paralelo

Se permite continuar tareas independientes cuando:

- Tienen su propia SPEC aprobada.
- No dependen del trabajo bloqueado.
- No requieren modificar componentes fuera de su autorización.
- No generan conflictos con las restricciones globales.

### Conflictos entre especificaciones

Cuando dos SPEC presentan contradicciones:

1. Identificar los requisitos conflictivos.
2. Evaluar los componentes afectados.
3. Detener las operaciones que dependan de esos requisitos.
4. Informar al orquestador.
5. Presentar alternativas al usuario.
6. Esperar decisión humana cuando implique cambiar requisitos o alcance.

El orquestador puede analizar y recomendar, pero no resolver unilateralmente conflictos de requisitos.

### Emergencias

No existe una excepción automática para implementar ante una emergencia.

El agente puede:

- Analizar el incidente.
- Identificar el problema.
- Proponer una SPEC de emergencia.
- Evaluar alternativas.
- Preparar un plan de contención.

La implementación sigue requiriendo aprobación explícita del usuario.

## Comunicación y reportes (SPEC-001 §12)

Todo bloqueo debe generar un informe que contenga:

- Identificador de tarea.
- Agente responsable.
- Proyecto afectado.
- Motivo del bloqueo.
- Estado de la SPEC.
- Requisitos faltantes.
- Acciones permitidas.
- Acciones prohibidas.
- Próximo paso necesario.

El agente debe comunicar el bloqueo sin ocultarlo, minimizarlo ni intentar resolverlo mediante modificaciones no autorizadas.

## Auditoría y trazabilidad (SPEC-001 §13)

El sistema debe registrar: solicitudes recibidas, búsquedas de SPEC, validaciones realizadas, propuestas creadas, versiones presentadas, aprobaciones y rechazos, intentos de implementación bloqueados, permisos concedidos, cambios ejecutados, desviaciones detectadas y revocaciones.

Los registros deben permitir reconstruir qué autorización habilitó cada modificación.

## Seguridad y precedencia (SPEC-001 §14)

Esta Skill se integra con la política global de AOXIM.

Las restricciones globales de seguridad siempre prevalecen.

Ninguna SPEC aprobada puede autorizar:

- Acciones prohibidas por políticas globales.
- Acceso no autorizado a recursos.
- Exposición de secretos.
- Modificaciones fuera de los permisos concedidos.

Una aprobación humana no elimina las restricciones de seguridad.

## Criterios de aceptación de la Skill (SPEC-001 §15)

La Skill se considerará funcional cuando supere, como mínimo, estas pruebas:

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

## Condición de finalización (SPEC-001 §16)

La Skill no se considera completamente implementada por el simple hecho de disponer de su archivo SKILL.md.

Debe existir: documentación de la Skill, reglas de gobernanza, plantillas de SPEC, validador de especificaciones, mecanismo técnico de enforcement, integración con el orquestador, propagación de restricciones a subagentes, pruebas automatizadas de los controles y evidencia de que no existen vías de escritura que eluden la política.

Hasta que esos componentes estén implementados y validados, la política debe permanecer documentada como obligatoria, pero no debe afirmarse que su cumplimiento técnico está garantizado.
