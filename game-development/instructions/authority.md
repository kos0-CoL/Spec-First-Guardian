# Autoridad independiente y modelo de amenazas

## Qué separa a los dominios

| Recurso | Agente | Autoridad |
|---|---|---|
| Clave privada Ed25519 | no accesible | archivo 0600 del usuario del servicio |
| Almacén de confianza | no accesible | archivo 0600, carga validada |
| Registro de revocaciones | no escribible | directorio 0700 del servicio |
| Configuración de seguridad | no accesible | `/etc/spec-guardian`, root:servicio, 0640 |
| Socket de la autoridad | conecta (grupo agentes) | lo crea y autentica por `SO_PEERCRED` |
| Workspace | solo lectura | escritura por el gate |
| Auditoría | no escribible | `audit.jsonl` del servicio |

La autoridad exige además que el UID del servicio, el del administrador y el del
agente sean distintos. Si el servicio arranca con el UID de un agente, el
`preflight` falla y no arranca.

El socket vive en `/run/spec-guardian` (0750, grupo `spec-guardian-agents`) y se
crea con modo 0660 y ese grupo. El agente puede conectarse, pero no leer el
directorio de estado ni la configuración: pertenece solo al grupo de clientes,
no al grupo del servicio.

## Ataques contemplados y respuesta

| Intento | Resultado |
|---|---|
| Construir un `TrustedKeyStore` propio con una clave elegida | el almacén no queda "configurado" sin carga desde archivo validado; la firma no verifica |
| Inyectar un proveedor de identidad falso | el proveedor simulado solo existe con `environment=test`; en producción se exige OIDC |
| Leer la clave privada desde el agente | la clave vive en un proceso y UID distintos; el agente no tiene ruta a ella |
| Cambiar variables de entorno para alterar la confianza | la autoridad no lee configuración de confianza del entorno del agente |
| Importar una solicitud alterada | integridad SHA-256 por solicitud; se rechaza antes del desafío |
| Reutilizar un desafío | se consume antes de firmar y caduca |
| Reutilizar un token para otra aprobación | el desafío está ligado a solicitud, huella y alcance |
| Modificar el registro de revocaciones | directorio del servicio; firma verificada; alteración ⇒ denegación |
| Cambiar la SPEC después de aprobar | la huella no coincide y la operación se deniega |
| Cambiar una ruta durante la autorización | la escritura usa descriptores ya abiertos (`dir_fd`), no la ruta |
| Inventar un requisito o tarea | deben existir en el documento |
| Usar un subagente para eludir el alcance | la cadena de delegación se valida contra la configuración |
| Escribir directamente en el workspace | solo impedido por permisos del SO (`workspace_guard.py`) |

## Qué no está demostrado en este repositorio

- **Aislamiento entre UID reales**: no se han creado dos cuentas en este entorno.
  Las pruebas usan el mismo UID, y el servicio lo declara (`not_enforced`). La
  verificación con cuentas reales se hace con `install_authority.sh` y
  `workspace_guard.py verify`.
- **OIDC real**: el adaptador valida firma, emisor, audiencia, sujeto, `exp` e
  `iat` con JWKS, pero no hay IdP configurado aquí; sin él la firma queda
  bloqueada por diseño.
- **Windows/macOS**: sin adaptadores ni pruebas.
- **Procesos y shell del agente**: fuera del protocolo no hay control; requieren
  contenedor, seccomp o un workspace de solo lectura.

## Operación

```bash
# 1. Instalar (root)
sudo ./scripts/install_authority.sh --project-root /srv/proyecto \
     --agent-uid 1001 --admin-uid 1000

# 2. Configurar OIDC real en /etc/spec-guardian/authority.json

# 3. Arrancar y comprobar
sudo systemctl enable --now spec-guardian-authority
python scripts/workspace_guard.py verify /srv/proyecto \
  --service-uid "$(id -u spec-guardian)" --agent-uid 1001

# 4. Auditoría
python scripts/approval_cli.py audit-verify
```

Si la verificación del workspace falla, el estado es `NO PROTEGIDO` y así debe
declararse: el gate seguirá controlando sus escrituras, pero no las del agente
por otras vías.
