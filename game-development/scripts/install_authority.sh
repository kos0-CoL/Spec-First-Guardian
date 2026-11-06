#!/usr/bin/env bash
# Instalacion de la autoridad de Spec-First Guardian en Linux.
#
# Crea una identidad de sistema dedicada, directorios protegidos, la clave de
# firma (0600, propiedad del servicio), el almacen de confianza y una unidad
# systemd. Debe ejecutarse como root; no se ejecuta desde el proceso del agente.
#
# Uso:
#   sudo ./install_authority.sh --project-root /srv/proyecto \
#        --agent-uid 1001 --admin-uid 1000
#
# El UID del administrador es la persona que aprueba; los agentes deben usar un
# UID distinto del servicio y del administrador. El script se niega si no es asi.
set -euo pipefail

SERVICE_USER="spec-guardian"
SERVICE_GROUP="spec-guardian"
AGENT_GROUP="spec-guardian-agents"
CONFIG_DIR="/etc/spec-guardian"
STATE_DIR="/var/lib/spec-guardian"
RUN_DIR="/run/spec-guardian"
LOG_DIR="/var/log/spec-guardian"
PROJECT_ROOT=""
AGENT_UID=""
ADMIN_UID=""
PYTHON="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --project-root) PROJECT_ROOT="$2"; shift 2 ;;
    --agent-uid) AGENT_UID="$2"; shift 2 ;;
    --admin-uid) ADMIN_UID="$2"; shift 2 ;;
    --service-user) SERVICE_USER="$2"; SERVICE_GROUP="$2"; shift 2 ;;
    *) echo "Argumento no reconocido: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: la instalacion exige root (crea usuarios y unidades de sistema)." >&2
  exit 2
fi
if [ -z "$PROJECT_ROOT" ] || [ -z "$AGENT_UID" ] || [ -z "$ADMIN_UID" ]; then
  echo "ERROR: faltan --project-root, --agent-uid o --admin-uid." >&2
  exit 2
fi
if [ ! -d "$PROJECT_ROOT" ]; then
  echo "ERROR: el proyecto no existe: $PROJECT_ROOT" >&2
  exit 2
fi
if [ "$AGENT_UID" = "$ADMIN_UID" ]; then
  echo "ERROR: el agente y el administrador no pueden compartir UID." >&2
  exit 2
fi

if ! getent group "$SERVICE_GROUP" >/dev/null; then
  groupadd --system "$SERVICE_GROUP"
fi
if ! getent group "$AGENT_GROUP" >/dev/null; then
  groupadd --system "$AGENT_GROUP"
fi
AGENT_USER="$(getent passwd "$AGENT_UID" | cut -d: -f1)"
if [ -z "$AGENT_USER" ]; then
  echo "ERROR: no existe un usuario con UID $AGENT_UID." >&2
  exit 2
fi
usermod -aG "$AGENT_GROUP" "$AGENT_USER"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
SERVICE_UID="$(id -u "$SERVICE_USER")"
if [ "$SERVICE_UID" = "$AGENT_UID" ] || [ "$SERVICE_UID" = "$ADMIN_UID" ]; then
  echo "ERROR: el UID del servicio coincide con el de un agente o administrador." >&2
  exit 2
fi

# El directorio es atravesable (0755) para que agentes y administrador lean
# client.json; la configuracion de la autoridad sigue siendo 0640 root:servicio
# y no es legible por otros.
install -d -m 0755 -o root -g root "$CONFIG_DIR"
chown root:root "$CONFIG_DIR"
chmod 0755 "$CONFIG_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR" "$STATE_DIR/keys" "$STATE_DIR/requests" "$STATE_DIR/approvals" "$STATE_DIR/revocations"
# El directorio del socket es atravesable por el grupo de agentes; el socket
# (0660) solo lo abre ese grupo. El servicio pertenece a ambos grupos.
install -d -m 0750 -o "$SERVICE_USER" -g "$AGENT_GROUP" "$RUN_DIR"
usermod -aG "$AGENT_GROUP" "$SERVICE_USER"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"

# Clave de firma, almacen de confianza y configuracion de cliente verificable.
"$PYTHON" - "$STATE_DIR" "$CONFIG_DIR" "$SERVICE_UID" "$(getent group "$AGENT_GROUP" | cut -d: -f3)" "$RUN_DIR" <<'PY'
import json, os, sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

state, config_dir = Path(sys.argv[1]), Path(sys.argv[2])
service_uid, agent_gid, run_dir = int(sys.argv[3]), int(sys.argv[4]), Path(sys.argv[5])
key_path = state / "keys" / "signing_key.pem"
if not key_path.exists():
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
else:
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
public_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
trusted = state / "keys" / "trusted_keys.json"
trusted.write_text(
    json.dumps(
        {
            "keys": [
                {
                    "key_id": "KEY-AUTHORITY-001",
                    "issuer": "spec-guardian-authority",
                    "subject": "usuario",
                    "public_key_pem": public_pem.decode("ascii"),
                    "revoked": False,
                }
            ]
        },
        indent=2,
    ),
    encoding="utf-8",
)
os.chmod(trusted, 0o600)

# El cliente del agente fija socket, UID/GID esperados y la clave publica
# pinnada. Es legible por el grupo de agentes (solo datos publicos) y solo
# root puede modificarlo.
client_path = config_dir / "client.json"
client_path.write_text(
    json.dumps(
        {
            "version": 1,
            "socket_path": str(run_dir / "authority.sock"),
            "expected_service_uid": service_uid,
            "socket_gid": agent_gid,
            "authority_public_key_pem": public_pem.decode("ascii"),
        },
        indent=2,
    ),
    encoding="utf-8",
)
os.chmod(client_path, 0o644)
PY
chown root:root "$CONFIG_DIR/client.json"
chmod 0644 "$CONFIG_DIR/client.json"

if [ ! -f "$CONFIG_DIR/authority.json" ]; then
  "$PYTHON" - "$CONFIG_DIR/authority.json" "$STATE_DIR" "$RUN_DIR" "$LOG_DIR" "$PROJECT_ROOT" "$AGENT_UID" "$ADMIN_UID" "$(getent group "$AGENT_GROUP" | cut -d: -f3)" <<'PY'
import json, os, sys

config_path, state, run, log, project, agent_uid, admin_uid, agent_gid = sys.argv[1:9]
config = {
    "environment": "production",
    "socket_path": f"{run}/authority.sock",
    "socket_group_gid": int(agent_gid),
    "state_dir": state,
    "projects": {"Spec-First-Guardian": project},
    "admin_uids": [int(admin_uid)],
    "clients": [{"uid": int(agent_uid), "agents": ["agente-1"], "delegates": {}}],
    "approver": "usuario",
    "trusted_keys_file": f"{state}/keys/trusted_keys.json",
    "revocations_dir": f"{state}/revocations",
    "audit_log": f"{state}/audit.jsonl",
    "signing_key_file": f"{state}/keys/signing_key.pem",
    "key_id": "KEY-AUTHORITY-001",
    "issuer": "spec-guardian-authority",
    "oidc": {"issuer": "https://IDP.EJEMPLO", "audience": "spec-guardian", "jwks_url": "https://IDP.EJEMPLO/.well-known/jwks.json"},
    "challenge_ttl_seconds": 180,
    "require_distinct_uid": True,
    "allow_simulated_identity": False,
}
with open(config_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
os.chmod(config_path, 0o640)
PY
  chown root:"$SERVICE_GROUP" "$CONFIG_DIR/authority.json"
fi

cat > /etc/systemd/system/spec-guardian-authority.service <<UNIT
[Unit]
Description=Spec-First Guardian authority
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=$PYTHON $PROJECT_ROOT/game-development/scripts/authority_service.py --config $CONFIG_DIR/authority.json
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$STATE_DIR $RUN_DIR $LOG_DIR $PROJECT_ROOT

[Install]
WantedBy=multi-user.target
UNIT

# El workspace queda en solo lectura para el agente: propietario el servicio.
"$PYTHON" "$PROJECT_ROOT/game-development/scripts/workspace_guard.py" protect "$PROJECT_ROOT" \
  --service-uid "$SERVICE_UID" --service-gid "$(id -g "$SERVICE_USER")" --agent-uid "$AGENT_UID" >/dev/null || {
    echo "AVISO: no se pudo aplicar la proteccion del workspace; el estado es NO PROTEGIDO." >&2
  }

systemctl daemon-reload
echo "Instalado. Falta:"
echo "  1. Configurar OIDC real en $CONFIG_DIR/authority.json"
echo "  2. systemctl enable --now spec-guardian-authority"
echo "  3. Verificar: workspace_guard.py verify $PROJECT_ROOT --service-uid $SERVICE_UID --agent-uid $AGENT_UID"
