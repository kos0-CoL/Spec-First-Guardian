# Contrato de Enforcement — SPEC-001

Interfaz obligatoria para el control técnico de operaciones de escritura.

## Cadena de control

```
AGENTE
  → IMPLEMENTATION GATE        (implementation_gate.py)
  → MOTOR DE AUTORIZACIÓN      (validate.authorize_operation)
  → SERVICIO DE APROBACIÓN    (approval_service.verify_approval)
  → REGISTRO DE REVOCACIONES  (revocation_registry)
  → VALIDACIÓN DE ALCANCE Y RUTA
  → ESCRITURA EJECUTADA
```

El gate **ejecuta** la operación autorizada; no se limita a devolver una decisión.

## Operaciones controladas

`create_file`, `modify_file`, `overwrite_file`, `delete_file`.

Controles aplicados:

1. Contexto completo obligatorio: `agent`, `project`, `spec_id`, `version`,
   `requirement`, `task`, `operation_type`, `path`, `workspace_root`.
2. Firma Ed25519 verificada contra el almacén de confianza.
3. Identidad humana autenticada ligada al sujeto de la clave.
4. Revocaciones comprobadas en registro firmado y protegido.
5. Proyecto, versión, requisito, tarea y operación dentro de las listas autorizadas.
6. Ruta relativa, sin traversal, sin rutas absolutas, sin symlinks, dentro del workspace.
7. Hash SHA-256 de la SPEC igual al firmado.
8. Escritura atómica y audit log obligatorio (si no se puede auditar, se deniega).

## Operaciones NO protegidas por el gate

- Escrituras directas del agente con acceso al sistema de archivos.
- Ejecución de scripts o procesos externos.
- Instalación de dependencias y migraciones.
- Cambios de configuración fuera del gate.
- Operaciones de subagentes con su propio acceso al filesystem.

Estas vías requieren aislamiento del sistema operativo (usuario sin permisos de
escritura, contenedor, montaje de solo lectura o servicio intermediario). El gate
por sí solo no las bloquea y no se declara protección universal.

## Denegación por defecto

Sin contexto completo, sin autorización verificable, con revocaciones no
comprobadas o con cualquier error de lectura: denegar.

## Registro

Cada decisión (permitida o denegada) se escribe en el audit log con hora,
contexto de operación y motivo. Si el registro falla, la operación se deniega.

## Adaptadores

Orquestador, CLI y subagentes deben invocar `enforce.py apply` (o
`ImplementationGate.execute`) y no escribir directamente. Un adaptador que
escriba por su cuenta queda fuera del control y debe declararse como tal.
