# Spec-First Guardian (SPEC-001)

Skill obligatoria de gobernanza del desarrollo asistido por inteligencia artificial.

## Propósito

**NINGUNA implementación sin una SPEC aprobada explícitamente por el usuario.**

La aprobación siempre corresponde a un usuario humano autenticado. Ningún agente,
subagente u orquestador puede sustituirla, firmarla ni registrarla.

## Arquitectura de aprobación (única)

Existe **una sola** autoridad de aprobación:

| Componente | Responsabilidad |
|---|---|
| `scripts/approval_service.py` | Identidad humana, firma Ed25519 con backend protegido, verificación contra almacén de confianza. |
| `scripts/revocation_registry.py` | Registro de revocaciones firmado, fuera del workspace, con estados diferenciados. |
| `scripts/validate.py` | Validación documental, de requisitos, criptográfica, de identidad, de revocación y de alcance. Resultados independientes. |
| `scripts/implementation_gate.py` | Intermediario real de escritura: autoriza y ejecuta. |
| `scripts/enforce.py` | CLI de decisión (`evaluate`) y ejecución (`apply`). |
| `scripts/approval_cli.py` | CLI de la autoridad: registra solicitudes, firma aprobaciones y verifica. |

No hay HMAC, ni clave por defecto, ni firma local de autorizaciones. La única
criptografía de autorización es Ed25519 con clave pública resuelta en un almacén
de confianza externo.

## Flujo

1. El agente redacta la SPEC (plantilla `templates/technical-specification.md`).
2. La autoridad registra la solicitud con la huella del contenido y el alcance exacto.
3. El usuario se autentica ante el proveedor de identidad y confirma.
4. La autoridad firma la autorización (identidad + huella + alcance + vigencia).
5. El agente solicita operaciones al Implementation Gate con contexto completo.
6. El gate verifica firma, identidad, revocaciones, alcance, ruta y hash de la SPEC.
7. Solo entonces ejecuta la escritura y la registra en el audit log.

## Uso

```bash
python scripts/validate.py <spec.md> [--approval <registro.json>] [--json]
python scripts/generate_report.py <spec.md> [--approval <registro.json>]
python scripts/enforce.py evaluate --context operacion.json [--spec <spec.md>] [--approval <registro.json>]
python scripts/enforce.py apply    --context operacion.json [--spec <spec.md>] [--approval <registro.json>]
```

Contexto de operación (todos los campos son obligatorios; no se completan solos):

```json
{
  "agent": "agente-1",
  "project": "Spec-First-Guardian",
  "spec_id": "SPEC-001",
  "version": "1.0.0",
  "requirement": "RF-001",
  "task": "TASK-001",
  "operation_type": "create_file",
  "path": "src/code.py",
  "workspace_root": "/ruta/absoluta/al/workspace",
  "content": "contenido a escribir"
}
```

Lado de la autoridad (nunca en el proceso del agente):

```bash
export SPEC_GUARDIAN_AUTHORITY_CONFIG=/etc/spec-guardian/authority.json
python scripts/approval_cli.py request --spec SPEC.md --project ... --scope ... \
  --operations create_file --paths src/code.py --requirements RF-001 --tasks TASK-001 \
  --approver usuario --out request.json
python scripts/approval_cli.py approve --request request.json --event event.json --out approval.json
python scripts/approval_cli.py verify --approval approval.json
```

## Configuración (supervisor)

| Variable | Contenido |
|---|---|
| `SPEC_GUARDIAN_TRUSTED_KEYS` | Ruta a `trusted_keys.json` (0600, fuera del workspace). |
| `SPEC_GUARDIAN_REVOCATIONS_DIR` | Directorio de registros firmados (por defecto `~/.local/state/spec-guardian/revocations`). |
| `SPEC_GUARDIAN_AUDIT_LOG` | Ruta del audit log del gate. |
| `SPEC_GUARDIAN_WORKSPACE` | Workspace del agente (para comprobar protección de rutas). |
| `SPEC_GUARDIAN_AUTHORITY_CONFIG` | Configuración de la autoridad (solo lado confiable). |

`trusted_keys.json`:

```json
{
  "keys": [
    {
      "key_id": "KEY-2026-11-05-001",
      "issuer": "spec-guardian-authority",
      "subject": "usuario",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "revoked": false
    }
  ]
}
```

## Seguridad

- Sin almacén de confianza configurado, toda aprobación se deniega.
- `key_id` desconocido, clave revocada, emisor o sujeto distintos: denegación.
- Los campos `verified`, `revoked`, `signature_valid` o `public_key` del registro
  **no** se consultan: nunca son fuente de confianza.
- Listas de alcance vacías no autorizan nada; `ALCANCE_TOTAL` no es un bypass.
- Si la SPEC cambia después de la aprobación, la autorización deja de servir.
- Registro de revocaciones ausente, corrupto, sin firma o dentro del workspace:
  la comprobación no se considera realizada y se deniega.
- Toda operación sin contexto completo se deniega.

## Enforcement real

Controladas por el gate: `create_file`, `modify_file`, `overwrite_file`,
`delete_file` (resolución segura de rutas, rechazo de symlinks, escritura atómica,
audit log obligatorio).

**NO protegidas** por el gate: escrituras directas del agente con acceso al
filesystem, ejecución de procesos externos, instalación de dependencias,
migraciones y cambios de configuración fuera del gate. Requieren aislamiento del
sistema operativo, contenedor o workspace de solo lectura; el gate no puede
impedirlas por sí solo.

## Pruebas

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Estado de los registros incluidos en el repositorio

`specs/approvals/SPEC-001.json` y `specs/revocations/SPEC-001.json` son registros
**legados**: se firmaron con el contrato anterior (sin identidad autenticada, sin
alcance por operación y sin firma del registro de revocaciones). El runtime los
rechaza y no autorizan ninguna operación. Para habilitar implementación, la
autoridad debe emitir una autorización nueva con `approval_cli.py` y publicar un
registro de revocaciones firmado en `SPEC_GUARDIAN_REVOCATIONS_DIR`.

## Limitaciones

- El proveedor OIDC real requiere emisor, audiencia y JWKS configurados; sin ellos
  la firma queda bloqueada (por diseño).
- El proveedor simulado solo se acepta con `environment="test"` y nunca en producción.
- La integración con orquestadores requiere adaptadores que llamen al gate.
