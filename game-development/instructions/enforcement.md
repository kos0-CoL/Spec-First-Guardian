# Contrato de enforcement — SPEC-001

## Cadena de control

```
AGENTE (UID agente)
  │  socket Unix + SO_PEERCRED + atestación firmada
  ▼
AUTORIDAD (UID servicio)          ← dominio B, único con la clave
  → auditoría: intención
  → Implementation Gate
      → motor de autorización (firma, identidad, revocación, alcance, huella)
      → safe_fs (dir_fd, O_NOFOLLOW, escritura atómica)
  → auditoría: resultado
  ▼
WORKSPACE (propiedad del servicio, sin escritura para el agente)
```

El agente no ejecuta la escritura: la pide. La autoridad impone el workspace, la
identidad del agente y el alcance; no acepta ninguno de esos datos como prueba.

## Controles por operación

1. UID del par autorizado (`SO_PEERCRED`, obligatorio) y atestación firmada con
   la clave pública pinnada en `/etc/spec-guardian/client.json`; un UID
   desconocido, un socket falso o una firma no verificable no pueden pedir nada.
2. Identidad de agente resuelta por UID, no por lo que declare el cliente.
3. Cadena de delegación para subagentes: cada salto debe estar configurado y el
   agente final debe coincidir con el último eslabón.
4. Contexto completo: agente, proyecto, SPEC, versión, requisito, tarea,
   operación, ruta y workspace.
5. Firma Ed25519 verificada contra el almacén de confianza del servicio.
6. Identidad humana autenticada ligada al sujeto de la clave.
7. Revocaciones comprobadas en registro firmado gestionado por la autoridad.
8. Proyecto, versión, requisito, tarea y tipo de operación dentro del alcance.
9. Requisito y tarea existen realmente en la SPEC aprobada.
10. Documento válido: secciones, estado `APPROVED`, criterios y requisitos.
11. Huella SHA-256 del documento leído en el momento de la operación.
12. Ruta relativa, sin traversal ni enlaces; escritura sobre descriptores ya
    abiertos, sin re-resolución (TOCTOU).
13. Auditoría de intención antes de escribir y de resultado después.

## Operaciones ejecutadas

`create_file`, `modify_file`, `overwrite_file`, `delete_file`.

`create` exige que no exista; `modify` que exista y sea regular; `overwrite`
admite ambos; `delete` solo archivos regulares. Todo dentro del workspace, con
permisos 0640 y fsync del archivo y del directorio.

## Operaciones NO cubiertas

- Ejecución de scripts y procesos externos.
- Instalación de dependencias.
- Migraciones de datos.
- Cambios de configuración fuera del protocolo.
- Operaciones de subagentes que no pasen por la autoridad.

El gate las **deniega** si se le piden, pero no puede impedir que un agente con
acceso al sistema operativo las realice por otra vía. Se declaran `NO PROTEGIDO`
hasta que el workspace sea de solo lectura para el UID del agente y los procesos
estén restringidos por el sistema operativo o un contenedor.

## Auditoría

- Cadena de hashes: alterar, borrar o insertar una línea rompe la verificación.
- Intención previa: si no se puede registrar, la operación se deniega.
- Resultado posterior: si falla, se crea un marcador de auditoría incompleta y
  **se bloquean nuevas operaciones** hasta reconciliar (`approval_cli.py
  reconcile`).
- El marcador y el log son propiedad del servicio; el agente no puede escribirlos.

## Denegación por defecto

Sin contexto, sin autorización verificable, con revocaciones no comprobadas, con
auditoría bloqueada o ante cualquier error de lectura: denegar.
