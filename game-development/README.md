# Spec-First Guardian (SPEC-001)

Gobernanza del desarrollo asistido por IA: **ninguna implementación sin una SPEC
aprobada explícitamente por una persona**.

## Regla fundamental

La aprobación pertenece a una persona autenticada. Ningún agente, subagente u
orquestador puede aprobar, firmar, revocar ni registrar claves.

## Arquitectura: dos dominios separados

```
  DOMINIO A (agentes, UID agente)          DOMINIO B (autoridad, UID servicio)
  ───────────────────────────────          ────────────────────────────────
  leer proyecto                           clave privada Ed25519 (0600)
  redactar SPEC                           almacén de claves de confianza
  preparar alcance                        proveedor OIDC
  solicitar aprobación  ─── socket ───▶   desafío de un solo uso
  solicitar operaciones  ── Unix ────▶    firma de autorizaciones
  recibir decisión                        registro de revocaciones
                                          escritura real del workspace
                                          auditoría encadenada
```

La frontera es de **proceso y de identidad del sistema operativo**, no de clases.
Un agente puede importar el paquete Python que quiera: no tiene la clave, no
puede registrar claves y no puede firmar. La autoridad verifica el UID del par
con `SO_PEERCRED` en cada conexión.

| Componente | Dominio | Función |
|---|---|---|
| `scripts/authority_service.py` | B | Servicio por socket Unix: solicitudes, desafíos, firma, revocaciones, ejecución y auditoría. |
| `scripts/implementation_gate.py` | B | Ejecuta escrituras ancladas a descriptores dentro del proceso de autoridad. |
| `scripts/safe_fs.py` | B | `openat`/`dir_fd`/`O_NOFOLLOW`: elimina la re-resolución de rutas (TOCTOU). |
| `scripts/audit_chain.py` | B | Auditoría encadenada con intención, resultado y bloqueo por cierre ausente. |
| `scripts/workspace_guard.py` | B | Verifica/aplica permisos del workspace y declara `NO PROTEGIDO` cuando no hay separación real. |
| `scripts/install_authority.sh` | B | Instalación Linux: usuario de sistema, directorios, clave, systemd. |
| `scripts/authority_client.py` | A | Única superficie del agente: IPC, sin claves. |
| `scripts/enforce.py` | A | Pide evaluación o ejecución a la autoridad. |
| `scripts/approval_cli.py` | B | Consola de la autoridad (revisar, desafiar, aprobar, revocar, reconciliar). |
| `scripts/validate.py` | A/B | Validación documental y motor de autorización compartido. |
| `scripts/approval_service.py` | B | Identidad, firma y verificación Ed25519. |
| `scripts/revocation_registry.py` | B | Registro firmado de revocaciones. |

## Flujo de aprobación

1. El agente registra la solicitud (`request`): la autoridad lee la SPEC del
   workspace, valida el documento, comprueba que requisitos y tareas existen
   realmente en él y calcula la huella SHA-256.
2. La persona administradora revisa (`pending`) y obtiene un desafío de un solo
   uso (`challenge`) ligado a solicitud, huella y alcance.
3. La persona confirma (`approve`) con su identidad OIDC; la autoridad vuelve a
   leer la SPEC, recalcula la huella y solo entonces firma.
4. Cada operación se autoriza contra esa firma, el alcance, las revocaciones y la
   huella actual; la escritura la ejecuta la autoridad.

El desafío se consume antes de firmar: un fallo posterior no permite reutilizarlo.
Las solicitudes se guardan con integridad SHA-256; una solicitud alterada se
rechaza antes de emitir desafío.

## Uso

Agente:

```bash
export SPEC_GUARDIAN_AUTHORITY_SOCKET=/run/spec-guardian/authority.sock
export SPEC_GUARDIAN_AUTHORITY_UID=<uid del servicio>

python scripts/approval_cli.py request --project Spec-First-Guardian \
  --spec SPEC-001.md --scope IMPLEMENTACION \
  --operations create_file modify_file --paths src/code.py \
  --requirements RF-001 --tasks TASK-001

python scripts/enforce.py evaluate --context operacion.json
python scripts/enforce.py apply    --context operacion.json
```

Contexto (todos los campos son obligatorios; la autoridad impone el workspace):

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
  "workspace_root": "/srv/proyecto",
  "content": "print('hola')\n"
}
```

Autoridad (UID administrador):

```bash
python scripts/approval_cli.py pending
python scripts/approval_cli.py challenge REQ-...
python scripts/approval_cli.py approve REQ-... --challenge ... --id-token-file token.txt --confirm
python scripts/approval_cli.py verify --spec-id SPEC-001 --version 1.0.0
python scripts/approval_cli.py revoke --spec-id SPEC-001 --version 1.0.0 --event EVT-... --reason "..."
python scripts/approval_cli.py audit-verify
python scripts/approval_cli.py reconcile --note "..."
```

## Instalación (Linux)

```bash
sudo ./scripts/install_authority.sh --project-root /srv/proyecto \
     --agent-uid 1001 --admin-uid 1000
```

Crea el usuario `spec-guardian`, `/etc/spec-guardian/authority.json` (modo 0640),
`/var/lib/spec-guardian` (0700), la clave de firma (0600), el almacén de confianza
y la unidad systemd. Se niega si el UID del servicio coincide con el del agente o
el administrador, o si agente y administrador comparten UID.

El workspace queda propiedad del servicio y sin escritura para grupo u otros. El
estado se verifica con:

```bash
python scripts/workspace_guard.py verify /srv/proyecto \
  --service-uid <uid servicio> --agent-uid <uid agente>
```

Sin separación real de UID, el informe es `"protected": false, "same_uid": true`.

## Configuración de la autoridad

`/etc/spec-guardian/authority.json` (0620/0640, root:spec-guardian):

```json
{
  "environment": "production",
  "socket_path": "/run/spec-guardian/authority.sock",
  "state_dir": "/var/lib/spec-guardian",
  "projects": {"Spec-First-Guardian": "/srv/proyecto"},
  "admin_uids": [1000],
  "clients": [{"uid": 1001, "agents": ["agente-1"], "delegates": {"agente-1": ["subagente-1"]}}],
  "approver": "usuario",
  "trusted_keys_file": "/var/lib/spec-guardian/keys/trusted_keys.json",
  "revocations_dir": "/var/lib/spec-guardian/revocations",
  "audit_log": "/var/lib/spec-guardian/audit.jsonl",
  "signing_key_file": "/var/lib/spec-guardian/keys/signing_key.pem",
  "key_id": "KEY-AUTHORITY-001",
  "issuer": "spec-guardian-authority",
  "oidc": {"issuer": "https://idp", "audience": "spec-guardian", "jwks_url": "https://idp/.well-known/jwks.json"},
  "challenge_ttl_seconds": 180,
  "require_distinct_uid": true,
  "allow_simulated_identity": false
}
```

En `production` la autoridad **no arranca** si: el UID del servicio aparece como
cliente o administrador; agente y administrador comparten UID; falta OIDC; falta
la clave; o los archivos/directorios no tienen propietario y permisos correctos.

## Seguridad

- Sin firma verificable contra el almacén de confianza no hay implementación.
- `key_id` desconocido, clave revocada, emisor o sujeto distintos: denegación.
- Los campos `verified`, `revoked`, `signature_valid` o `public_key` del registro
  no se consultan.
- Un `TrustedKeyStore` construido a mano nunca está "configurado": solo una carga
  desde archivo protegido lo habilita.
- Listas vacías no autorizan; `ALCANCE_TOTAL` no es un bypass.
- Requisitos y tareas deben existir en la SPEC; un identificador inventado no se
  autoriza aunque esté en la lista firmada.
- Registro de revocaciones ausente, corrupto, sin firma o inseguro: denegación.
- El desafío de aprobación es de un solo uso y caduca.

## Enforcement real

Ejecutadas por la autoridad: `create_file`, `modify_file`, `overwrite_file`,
`delete_file`, con rutas ancladas a descriptores (`dir_fd`), rechazo de enlaces
simbólicos, escritura atómica en el mismo directorio y verificación del digest.

**NO protegidas** (el gate las deniega, pero no puede impedir que un agente las
ejecute por su cuenta): scripts y procesos externos, instalación de dependencias,
migraciones, cambios de configuración y operaciones de subagentes fuera del
protocolo. Solo el aislamiento del sistema operativo (UID distinto y workspace sin
permisos de escritura para el agente) las bloquea de verdad.

## Pruebas

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Las pruebas unitarias usan identidad simulada y un UID compartido: demuestran el
contrato del servicio, **no** el aislamiento entre UID distintos.

## Limitaciones

- El proveedor OIDC está implementado, pero sin un IdP real configurado no hay
  aprobaciones de producción.
- El aislamiento por UID se implementa y verifica con `workspace_guard.py` y el
  instalador; en este entorno de desarrollo no se han creado dos cuentas reales,
  por lo que el estado local es `NO PROTEGIDO`.
- Windows y macOS no están adaptados ni probados: solo Linux.
- Los registros incluidos en `specs/approvals/` y `specs/revocations/` son legados
  y no autorizan nada en el modelo actual.
