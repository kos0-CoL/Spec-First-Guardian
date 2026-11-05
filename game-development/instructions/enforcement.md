# Contrato de Enforcement — SPEC-001

Interfaz desacoplada para el control técnico de operaciones de escritura.

## Responsabilidades

1. Verificación de autorización: comprobar identificación, evento y vigencia.
2. Comprobación de alcance: asegurar que la operación está dentro de la versión aprobada.
3. Comprobación de permisos: evaluar la cadena de delegación y herramientas permitidas.
4. Interceptación de operaciones: detener antes de ejecutar escrituras protegidas.
5. Registro de intentos bloqueados: dejar evidencia del rechazo.
6. Propagación de restricciones a subagentes: heredar el bloqueo por toda la cadena.

## Interfaz propuesta

Entrada: operación (tipo, recursos, alcance solicitado) + contexto (spec_id, version, usuario, evento de autorización).

Salida: permitido / denegado + motivo + referencia de la autorización.

## Adaptadores

- Orquestador principal.
- Agente de línea de comandos.
- Subagente.
- Herramienta alternativa de escritura.

Cada adaptador implementa la interfaz sin conocer el detalle del validador.

## Denegación por defecto

Si falla la verificación de autorización, la escritura debe rechazarse.

No se asume permiso por errores del sistema, pérdida de conexión, información
incompleta, estado desconocido o versión de SPEC desconocida.

## Separación de responsabilidades

1. Skill documental.
2. Validador de especificaciones.
3. Contrato de autorización.
4. Adaptador de integración.
5. Enforcement efectivo.

## Implementacion actual

El modulo `scripts/enforce.py` expone la evaluacion:

```bash
python scripts/enforce.py <operacion> <ruta-a-spec.md> --task-id TASK-001 --approval <registro.json>
```

## Registro

Todo intento denegado debe quedar registrado con tarea, agente, motivo, estado de
la SPEC y acción intentada.
