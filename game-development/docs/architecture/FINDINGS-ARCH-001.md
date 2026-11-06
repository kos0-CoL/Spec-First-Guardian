# FINDINGS-ARCH-001 — Informe de auditoría y riesgos

**Estado:** DRAFT — observaciones de lectura, no especificación normativa  
**Fecha:** 2026-11-06  
**Autor:** Buffy (auditoría asistida)  
**Alcance:** checkout `game-development/` en commit `5f070594a07c289dcda03f8f76eac7e2241d1974`; revisión estática más suite unittest existente.  
**Autoridad documental:** evidencia informativa; no autoriza cambios ni invalida SPEC-001.  
**Dependencias:** ARCH-001, CURRENT-STATE-MAP, ADR-001, SPEC-ARCH-001-HARDENING, PLAN-ARCH-001.  
**Metodología:** lectura de fuentes reales, tests, docs, schema, plantilla, `requirements.txt`, inventario; `python3 -m unittest discover -s tests -p 'test_*.py'`. No se ejecutó instalador, operación root, red IdP, systemd, multi-UID ni pruebas destructivas.

## Resumen ejecutivo

El repositorio tiene una base Linux/Python con autoridad por Unix socket, atestación Ed25519, firma de autorización, validación de scope, revocaciones, gate de cuatro operaciones de archivo y hash-chain de auditoría. Eso no demuestra una implantación de producción completa: el flujo OIDC Authorization Code + PKCE/callback no existe y el camino de aprobación de servicio tiene un orden de persistencia defectuoso; auditoría depende de marcadores y estado parcial por instancia; durabilidad directory fsync se reporta como éxito aunque se ignore error; montaje/hardlink/races no quedan suficientemente cubiertos; instalador sobrescribe almacén de confianza; Skill y docs discrepan sobre enforcement.

## Clasificación

- **EXISTENTE Y VERIFICADO:** sólo componentes con tests unitarios que prueban comportamientos acotados.
- **EXISTENTE, NO VERIFICADO:** código presente, sin evidencia runtime representativa.
- **INCOMPLETO:** contrato esencial falta.
- **INCONSISTENTE:** código/docs divergen o status no representa requisito.
- **PENDIENTE:** propuesta de ARCH/SPEC.
- **NO PROTEGIDO:** no hay mecanismo que impida una vía alternativa.

## P0 — bloqueadores antes de producción

### P0-1 Ciclo de aprobación declara APPROVED demasiado pronto

**Evidencia:** `scripts/authority_service.py`, `Authority.approve()`: después de checks de hash/review importa request, establece `challenge_used=True`, `status="APPROVED"` y `_save_request(request)`; recién luego llama `_approval_event()` y `service.approve_request()`. El camino production `_approval_event()` siempre lanza `SETUP INCOMPLETE` porque no existe callback/session con PKCE. Si auth o firma fallan se pudo persistir estado falsamente APPROVED y challenge consumido. Además bundle y audit commit se realizan después de registrar firma; fallos parciales requieren recovery no explicitada.

**Riesgo:** representación de autorización aprobada sin identidad autenticada/registro firmado; estado parcial/replay concurrente/restart.

**Estado:** INCONSISTENTE / INCOMPLETO; el rechazo de producción es fail-closed para respuesta de autorización, pero estado persistente puede mentir. No se ejecutó fault injection.

**Necesita:** RF-001/002/006, transacción/journal/CAS, no activar hasta persistencia completa. Mantener producción bloqueada.

### P0-2 OIDC real incompleto

**Evidencia:** `authority_service._approval_event()` explícitamente deniega producción por falta callback PKCE; CLI propone `--id-token-file`; `approval_service.OIDCIdentityProvider` valida un ID token RS256/claims/nonce/auth_time pero no implementa Authorization Code, PKCE, session o state atado a navegador. `_consumed_nonces`/token hashes viven en memoria.

**Riesgo:** token directo no demuestra que la persona completó autenticación ligada a sesión/solicitud; replay tras reinicio y no binding state/PKCE.

**Estado:** INCOMPLETO. Configurar issuer/JWKS no basta para habilitar producción.

**Necesita:** callback seguro, sesión server-side, PKCE S256, state/nonce, expected subject, freshness, replay durable, UI confirmación y pruebas de integración. No se verificó IdP.

### P0-3 Auditoría no demuestra fail-stop global bajo fallos

**Evidencia:** `AuditChain._poisoned` pertenece a instancia; cada `ImplementationGate` crea `AuditChain` nuevo y `_audit_unavailable` se guarda en esa instancia. `mark_incomplete()` intenta escribir health y block; al fallar escribe health unavailable best-effort y eleva. `Authority._operation_decision()` usa `_audit_unhealthy` también en memoria y archivos, pero los componentes/gates pueden re-instanciarse. Si log/marker/health/filesystem fallan conjuntamente, no se demuestra estado durable verificable ni latch global en proceso; en reinicio no hay prueba completa de matriz. `clear_incomplete` añade evento con `allow_blocked=True` y luego elimina marcador; crash entre etapas requiere recovery.

**Riesgo:** distinta vista de health por gate/worker y tras reinicio; bloqueo no durable o estado desconocido traducido inconsistentemente.

**Estado:** INCOMPLETO; tests cubren marker básico y log perdido, no fallo simultáneo/multi-process/restart.

**Necesita:** estados diferenciados, fuente coordinada cross-process, latch emergency a nivel Authority, validación al inicio/cada concesión, fail-closed si cualquier evidencia ausente, reconciliación admin autenticada/auditable y tests SA-006.

### P0-4 Aprobación/auditoría y persistencia no son una transacción

**Evidencia:** `Authority.approve()` persiste request, firma en memoria, luego request status, approval bundle, audit append secuenciales; `revoke()`/`revoke_key()` escriben registro/keys antes de audit. Hay manejo parcial de fallos post side effect en revokes, pero no transaction journal completo. Puede haber efecto aplicado y respuesta denegada/audit incompleto.

**Riesgo:** estados indeterminados, duplicados y falsos resultados después de reinicio.

**Estado:** INCOMPLETO; no se ejecutó crash injection.

**Necesita:** idempotency/event IDs, commit journal, regla no ACTIVE hasta durable commit; `INDETERMINATE`/reconciliation para post-effect failures; sin rollback ciego.

## P1 — seguridad/compatibilidad importantes

### P1-1 Revisión paginada no prueba presentación ni consentimiento

`spec_page()` sirve secuencialmente y guarda `review_next_offset`/`review_fingerprint`; `challenge.review_pages` calcula pages; cliente `AuthorityClient.approve()` envía `review_complete=True` cuando hay `review_pages`. Esto prueba (si storage no se manipula) secuencia solicitada/servida hasta longitud y hash asociada. No prueba que el contenido fue presentado/renderizado por UI, que el sujeto humano lo vio, ni que un humano confirmó; valores de finalización son cliente. No se afirma que comprensión sea demostrable. Requiere sesión humana de autoridad y confirmación explícita ligada al `spec_sha256` + `scope_sha256`.

**Estado:** INCOMPLETO para consentimiento.

### P1-2 SPEC y PLAN mezclados

`templates/technical-specification.md` incluye `## Plan de implementación`; `validate.py.REQUIRED_SECTIONS` exige `plan de implementacion`; fixtures `DRAFT_SPEC` tienen ese capítulo. Contradice separación objetivo. SPEC-001 histórica también contiene plan, no debe migrarse o rehashearse silenciosamente.

**Estado:** INCONSISTENTE. Requiere formato legacy y migración preservando fuente/hash/approval.

### P1-3 Workspace guard sólo caracteriza raíz del montaje

`_mount_type(root)` lee `/proc/self/mountinfo` y devuelve mount type del longest matching root path. Iteración luego usa `os.walk`, lstat y xattr por path, pero no compara mount ID por entry, no rechaza bind/nested mounts, no verifica `st_nlink` de hardlinks, y el tree puede cambiar durante walk/chown/chmod. Symlinks y archivos especiales sí se detectan/rechazan; ACL_UNKNOWN bloquea. La allowlist ENOTSUP en filesystem types no demuestra cada montaje/entry. `protect()` opera path list y luego re-verifica, pero race entre pasos no queda cerrada.

**Riesgo:** límites de propiedad/escritura por filesystem anidado, hardlink a inode fuera workspace, TOCTOU en protección.

**Estado:** EXISTENTE, NO VERIFICADO / INCOMPLETO. Una root mount check no basta.

**Política propuesta:** reject mounts internos salvo allowlist explícita, mount IDs/source/type por entry, hardlink no permitido por defecto, recorrido FD-relative y recheck; no verificable => `protected=false`. Mantener estados ACL.

### P1-4 safe_fs informa éxito aunque fsync de directorio falle

`safe_fs._fsync_dir()` captura y descarta todo `OSError`; create/modify/overwrite/delete retorna digest o None tras llamada, por tanto no diferencia syscall ejecutado vs persistencia durable. File fsync falla y propagación existe; create intenta unlink on failure pero no confirma cleanup durable. Para rename/unlink post side effect, un error puede dejar persistencia desconocida.

**Estado:** INCOMPLETO, conclusión estática directa; no inyecté fallo.

**Necesita:** outcome states, no durable success; bloqueo/gate y audit indeterminate post-side effect; tests fsync file/dir.

### P1-5 Installer sobrescribe trust store y client config

`install_authority.sh` siempre ejecuta embedded Python que siembra `trusted_keys.json` desde clave actual, escribiéndolo cada corrida con una sola key `revoked:false`; no comprueba preexistencia ni preserva keys/revocation. `client.json` también se escribe siempre. `authority.json` sólo se crea si no existe, no hay modo de upgrade/migrate/diff. El unit systemd se reescribe. Reinstall puede restablecer una clave previamente revocada y eliminar trusted keys/custom client settings.

**Estado:** INCONSISTENTE / riesgo alto; el script no se ejecutó (requiere root).

**Necesita:** modos INSTALL/VERIFY/UPGRADE/RECONFIGURE, atomic preserve, backups, monotonic revocation, key rotation explícita, validation de UID/proyecto/client pins.

### P1-6 Skill y enforcement claims divergentes

`game-development/SKILL.md` afirma escrituras protegidas incluyen config, scripts, deps, migrations, Git, escrituras indirectas y delegación, pero su propia sección Enforcement real dice gate ejecuta cuatro operaciones de archivo y operaciones directas/procesos/dependencies/migrations no están protegidos sin OS isolation. `instructions/rules.md` aún enumera amplias operaciones como sujetas a enforcement; `README` y `authority.md` sí aclaran limits. No hay code mechanism que intercepte procesos externos, scripts, instalación, migrations o Git directos.

**Estado:** INCONSISTENTE; vías fuera del gate NO PROTEGIDO salvo OS restrictions comprobadas. La suite misma documenta mismo UID simulado.

**Necesita:** clasificación A gate-mediated, B OS-restricted con evidencia, C not protected; Skill transversal y domains luego, preservar contenido.

### P1-7 Otras observaciones

- `Authority.status()` reporta setup readiness en `test` como true por diseño y `approval_ready` sólo para test; no tratar como production readiness. `installed=True` parece “instancia presente” no verificación instalación sistema.
- `spec_page()` sólo requiere `uid` arg sin comprobar explícitamente admin/client en método (revisar dispatch allowlists y authorization). Riesgo de exposición de documento/scope a cualquier peer permitido, no prueba de exploit; necesita contract test / comprobar routing.
- `challenge()` devuelve `oidc_state` y `session_id` al caller (potencialmente proceso agente), y `AuthorityClient.approve` reenvía esos valores; state/session no son secreto de login si los controla agente. Callback debe ligar server side y no confiar en payload agente.
- `approve()` llama `_require_healthy_audit()` antes lock, luego re-verifica files pero el lock sólo `threading.RLock` del proceso, sin multiprocess CAS; challenge replay entre instancias no prevenido mediante storage transaction.
- `safe_fs.write_file(mode="overwrite")`: `_stat_at` captura cualquier `UnsafePathError` como si el destino no existiera (incluye errors distintos de missing en el helper); una revisión futura debe distinguir ENOENT de errores y no convertir inaccesibilidad en “absent”.
- `read_file()` hace lstat y luego open; O_NOFOLLOW impide symlink final, pero no valida que el file descriptor sea el mismo inode lstat si reemplazo regular concurrente. Data hash/canonical checks podrían ser coherentes con read bytes, pero race policy sigue abierta.

## P2 — modularidad y contratos

- `validate.py` combina parsing documental y policy/authorization (`document_problems`, revocation, scope, `authorize_operation`); Authority/ImplementationGate vuelven a derivar checks. Riesgo de lógica duplicada y drift.
- API pública es protocolo Unix socket v2 implícito, DTOs no especificados y métodos Python internos; no hay contrato de conformidad adapters.
- Agent Client autentica authority con SO_PEERCRED/attestation tests; test es útil pero usa same UID y simula; no sustituye UIDs reales.
- Dependencias visibles: `cryptography>=42`, `jsonschema>=4.19`, `PyYAML>=6`, `PyJWT>=2.8`. No se encontró pyproject/setup/lock/CI en inventario acotado; no se evaluó resolución ni advisories CVE actuales.
- referencias y templates game-specific están integradas con Skill general; migration map recomendado, sin mover ahora.

## Tests y evidencia

**Ejecutado en este turno:**
- `python3 -m unittest discover -s tests -p 'test_*.py'` → `Ran 113 tests ... OK` (33.915 s). Incluye unit tests sobre service/crypto/validator/gate/filesystem/ACL basic/test preflight.
- Lectura estática de fuentes indicadas, docs, schema, templates, tests, examples/references y requirements; inventario local.
- Git: branch `main`, HEAD `5f070594a07c289dcda03f8f76eac7e2241d1974`, upstream `origin/main`, `0 0`, working tree limpio al inicio.

**No ejecutado / limitaciones:**
- Ningún `py_compile` adicional necesario para documentos; no tests de lint/schema Markdown.
- No OIDC real/JWKS remoto/Authorization Code/PKCE/UI callback.
- No root/installer/systemd ni modificaciones del host.
- No dos UIDs reales, bind/nested mounts, filesystem crash/power-loss, fsync fault injection, multiprocess concurrency/restart.
- No Windows/macOS, procesos externos o adaptación de IDE/orchestrator.
- Suite unittest pudo crear `__pycache__` como efecto normal; estado Git de fuentes limpio al inicio y documentos nuevos sólo en `docs/architecture/`.

## Riesgos residuales y decisiones

P0 bloquean declarar production ready. Antes de implementación resolver preguntas de `SPEC-ARCH-001` sobre broker, legacy approvals, OIDC UI/callback, durable storage, allowlist mounts y recovery de indeterminate. La auditoría presente es revisión estática más unit tests, no penetration test ni revisión criptográfica independiente.