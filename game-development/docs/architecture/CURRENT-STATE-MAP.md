# CURRENT-STATE-MAP — Correspondencia de estado actual

**Estado:** DRAFT  
**Fecha:** 2026-11-06  
**Autor:** Buffy (auditoría de lectura)  
**Alcance:** inventario y correspondencia del checkout `main` inspeccionado. No cambia código ni prescribe que un módulo se mueva ya.  
**Autoridad documental:** mapa informativo; no normativa.  
**Dependencias:** `ARCH-001.md`, `ADR-001.md`, `SPEC-ARCH-001-HARDENING.md`, `FINDINGS-ARCH-001.md`.  
**Relación:** evalúa situación observada; acciones son recomendaciones candidatas, no autorización de implementación.

**Commit:** `5f070594a07c289dcda03f8f76eac7e2241d1974`; rama `main`, upstream `origin/main`, divergencia 0/0, working tree limpio al inicio. Todas las rutas de abajo son relativas a `game-development/`.

## Criterio de estado
- `EXISTENTE Y VERIFICADO`: mecanismo presente y evidencia automatizada o estática acotada; nunca implica seguridad de producción global.
- `EXISTENTE, NO VERIFICADO`: implementado pero falta prueba representativa real.
- `INCOMPLETO`: falta parte esencial del contrato.
- `INCONSISTENTE`: documentación/código o módulos divergen.
- `PENDIENTE`: sólo objetivo propuesto.
- `NO PROTEGIDO`: rutas alternativas explícitamente no impedidas.

## Inventario y mapa

| Archivo actual | Responsabilidad actual | Componente objetivo | Dependencias/interfaces actuales | Duplicaciones / problemas | Estado | Acción recomendada |
|---|---|---|---|---|---|---|
| `SKILL.md` | Instrucción portable; afirma flujo, autoridad y enforcement; nombra operaciones | Skill Layer | workflow, enforcement, authority; comandos CLI | Afirmaciones de six etapas/operaciones globales frente a siete estados y gate real de cuatro escrituras; declara aislamiento como arquitectura, no evidencia | INCONSISTENTE | REORGANIZAR (en futuro): conservar reglas universales; migrar conocimiento de game dev a especialización y atenuar claims según evidencia |
| `README.md` | Arquitectura, protocolo, instalación y límites | Integration Toolkit / docs | scripts Authority/Client/Broker; Unix socket | Afirma desafío consumido antes de firmar, pero actual approve marca APPROVED antes de autenticar/firmar; pasos de producción no garantizan OIDC callback | INCONSISTENTE | CONSERVAR y alinear tras aprobación de SPEC |
| `instructions/workflow.md` | Workflow documental y aprobación | Skill Layer / Specification Engine | estados/validator | Seis etapas; enumera siete estados oficiales; mezcla documentación y acciones de implementación | EXISTENTE, NO VERIFICADO | CONSERVAR, separar interfaces y comunicar enforcement real |
| `instructions/enforcement.md` | Contrato y límites de gate | Policy / Implementation Gate / Broker / Audit | safe_fs, audit, authority | Describe cuatro operaciones y límites; promete bloqueo de nuevas operaciones; fail-stop cross-process incompleto | INCONSISTENTE | CONSERVAR conceptos; reespecificar garantías y evidencia |
| `instructions/authority.md` | Threat model operativo, dominios y límites | Authority / Workspace / Audit | install, client, guard, OIDC | Declara quién tiene capacidad de escritura autoridad; montaje/hardlink no analizados suficientemente; es material de dominio útil para especialización | EXISTENTE, NO VERIFICADO | REORGANIZAR a documentación de core + deployment Linux, no mover hasta aprobación |
| `instructions/rules.md` | reglas universales y claims de enforcement | Skill Layer / Policy | workflow; SPEC-001 | afirma procesos, scripts, deps, migraciones sujetas a control global, aunque proceso sólo niega petición gate y no bloquea ejecución directa; duplicación estados con workflow | INCONSISTENTE / NO PROTEGIDO | REEMPLAZAR (futuro) claims por niveles A/B/C; conservar aprobación humana y estados |
| `instructions/quality-standards.md` | checklist de calidad SPEC | Specification Engine | validate | cubre criterios/ambigüedad; no Plan separado | EXISTENTE, NO VERIFICADO | CONSERVAR y ampliar tras SPEC |
| `templates/technical-specification.md` | plantilla SPEC, incluye Plan y aprobación | Specification Engine | `validate.py`, schema | Contiene sección `Plan de implementación`; metadatos approval textuales confunden autoridad, aunque approval externo | INCONSISTENTE | SEPARAR template SPEC/PLAN con compatibilidad legacy explícita |
| `assets/schemas/spec.schema.json` | valida frontmatter mínimo | Specification Engine | PyYAML/jsonschema validate.py | `additionalProperties:true`; schema sólo metadata, no campos cuerpo, no legacy version | EXISTENTE, NO VERIFICADO | INTEGRAR schema/versionado y migración no destructiva |
| `scripts/validate.py` | parsea Markdown, estado, secciones, IDs, approval/revocation/scope | Specification Engine + Policy (mezclados) | PyYAML, jsonschema, approval_service, revocation_registry | `REQUIRED_SECTIONS` obliga plan; realiza validación documental y política/autorización en mismo módulo; duplicidad `document_problems` y checks posteriores | INCONSISTENTE | SEPARAR contratos lógicos; preservar API legacy durante transición |
| `scripts/approval_service.py` | tokens OIDC RS256, identidad, firma/verificación Ed25519, store | Authority | PyJWT, cryptography | Provider mantiene replay sets sólo en memoria; `auth_time` requiere presencia/edad, comprobar límites futuros; ningún callback/PKCE; no usar como auth de producción aislada | INCOMPLETO | SEPARAR Identity/Approval lógicamente, completar callback y replay persistente; production deny permanece |
| `scripts/authority_service.py` | Unix socket server; solicitud/revisión/desafío/aprobación/autorización/admin y firma | Authority + Audit + Policy + Gate/Broker mezclados | client, approval, audit, gate, safe_fs, validate, revocation | approve guarda USED/APPROVED antes de `_approval_event`; production `_approval_event` deniega por callback inexistente; operación sobre gate en proceso de authority; status setup flags pueden sobrestimar setup (test readiness); lock sólo proceso | INCOMPLETO / INCONSISTENTE | SEPARAR flujos/estados transaccionales como módulos lógicos; callback y audit lock cross process en SPEC |
| `scripts/authority_client.py` | valida config/socket/peer/atestación; IPC y helpers | Integration Toolkit / Adapter | Unix, SO_PEERCRED, Ed25519 | API `approve` envía state/session y datos revisión, no autenticación de UI; campos de revisión son cliente | EXISTENTE, NO VERIFICADO | CONSERVAR protocolo, reemplazar API auth con broker/session server-side |
| `scripts/implementation_gate.py` | autorización, intención/resultado, operaciones archivos | Implementation Gate (y parcialmente Broker) | validate, safe_fs, audit, revocations | gate nuevo por cada llamada; `_audit_unavailable` local; bloqueo depende archivos compartidos; no cubre procesos; resultado de write puede estar hecho pero respuesta durable incorrecta | INCONSISTENTE | SEPARAR Policy/Gate/Broker sin ampliar operaciones salvo SPEC aprobada |
| `scripts/safe_fs.py` | traversal por `dir_fd`, `O_NOFOLLOW`, create/replace/delete/read | Workspace Broker | libc/POSIX | `_fsync_dir` ignora OSError y devuelve digest/éxito; `modify` usa rename reemplazando inode; hardlinks aceptados; no trata mounts anidados | INCOMPLETO | REEMPLAZAR contrato de durabilidad por resultados diferenciados, política filesystem |
| `scripts/workspace_guard.py` | inspecciona/modifica ownership/mode/ACL en Linux | Workspace Broker/deployment bootstrap | `/proc/self/mountinfo`, xattr, os.walk | inspecciona mount type raíz y usa per-entry ACL, no identidad de mount por entry; hardlinks; race entre walk y protect/verify; set ACL absent por allowlist filesystem; no prueba UID real | EXISTENTE, NO VERIFICADO / INCOMPLETO | REEMPLAZAR comprobación con snapshot/dirfd, mount IDs, nlink policy y reject mounts no autorizados |
| `scripts/audit_chain.py` | log JSONL hash chained, salud, marker, reconcile | Audit Service | filesystem, flock, atomic writes | `_poisoned` por instancia; los gates nuevos no ven el boolean; si log/marker/health falla simultáneamente, no hay coordinación durable; reconcile append de audit usa `allow_blocked`; bloqueo inter-proceso no cubre todos los reads | INCOMPLETO | SEPARAR health/lock protocol, fail-stop process latch y almacén durable; preservar evidencia |
| `scripts/revocation_registry.py` | verifica/firma registros de revocación | Authority / Policy | approval key store, filesystem | archivo ausente bloquea, atomic write; lifecycle de clave/install puede sobrescribir revocation de key store | EXISTENTE, NO VERIFICADO | CONSERVAR API, integrar transacciones y monotonicidad de revocaciones |
| `scripts/install_authority.sh` | instala user/groups/config/keys/client/systemd y protege workspace | Deployment / Workspace | Linux tools, Python, systemd, OIDC values | reescribe trusted key store cada instalación con key no-revoked; `client.json` siempre se reescribe, config sólo si falta; sin modos VERIFY/UPGRADE/RECONFIGURE; systemd unit se reescribe | INCONSISTENTE / riesgo P1 | REEMPLAZAR flujo instalador por subcomandos con preflight, backup, diff y preservación monotónica |
| `scripts/approval_cli.py` | interfaz humana admin para status/request/pending/challenge/approve/revoke/reconcile | Adapter / Management | authority_client, token file CLI | `--id-token-file` no resuelve callback PKCE; sujeto humano aún bloqueado en producción | INCOMPLETO | REORGANIZAR a interfaz de sesión segura, no recibir bearer como sustituto de login |
| `scripts/enforce.py` | cliente CLI evaluate/apply | Adapter / Enforcement API | authority_client | refleja sólo métodos de gate; puede inducir claim de operaciones más amplias si docs no acotadas | EXISTENTE, NO VERIFICADO | CONSERVAR como adaptación del contrato canónico |
| `scripts/generate_report.py` | informe de validación | Specification Engine / Adapter | validate | salida informativa, no autorización | EXISTENTE, NO VERIFICADO | CONSERVAR y etiquetar resultado como no constitutivo de aprobación |
| `tests/test_authority.py` | IPC, aprobación test, scope/replay/revoke, preflight/client auth | Authority contract | bootstrap simulado, mismo UID | test de challenge single-use aprueba antes del segundo intento; no fuerza fallos de persistencia ni concurrencia callback | EXISTENTE Y VERIFICADO (unit tests) | INTEGRAR pruebas transaccionales/real OIDC/multi-UID en fase 1 |
| `tests/test_gate.py` | autorización, escritura de cuatro operaciones, audit fail | Gate | soporte mocks/local fs | test repara marker manipulando estado privado; no prueba proceso nuevo o almacenamiento fallido concurrente | EXISTENTE Y VERIFICADO (unit tests) | AMPLIAR fault injection/restart, no debilitar assertions |
| `tests/test_safe_fs.py` | rutas seguras, auditoría, workspace guard | Workspace/Audit | tmp dirs local | no test de fsync failures, bind mounts, hardlinks, race completa | EXISTENTE Y VERIFICADO (unit tests) | AMPLIAR matrix Linux fs y durability |
| `tests/test_validate.py` | status canonical, schema, signature, revocation | Specification/Policy | helpers identity simulated | fixture de SPEC exige plan; no migration legacy separation | EXISTENTE Y VERIFICADO (unit tests) | MIGRAR fixtures manteniendo estado histórico |
| `tests/support.py` | factories y SPEC fixture | Test support | filesystem temporario | mismo UID/proveedor simulado deliberados; es evidencia de límites, no de prod | EXISTENTE Y VERIFICADO | CONSERVAR como fixture claramente sólo tests |
| `specs/SPEC-001.md` | documento de alcance aprobado | Specification Engine | registro externo indicado en docs | YAML incluye `approver`/`approved_at`; los scripts no los toman como proof; validador requiere Plan | EXISTENTE, NO VERIFICADO como evidencia firmada | CONSERVAR inmutable; no reescribir como parte de migración sin nueva aprobación |
| `specs/approvals/SPEC-001.json` | artefacto legado | Approval Authority | JSON | README afirma legacy no autoriza modelo actual | EXISTENTE, NO VERIFICADO | CONSERVAR como evidencia histórica, etiquetar legada |
| `specs/revocations/SPEC-001.json` | artefacto legado | Audit/Authority | JSON | fuera de state configurado instalado por defecto | EXISTENTE, NO VERIFICADO | CONSERVAR como histórico |
| `requirements.txt` | dependencias Python | Integration/Core | cryptography, jsonschema, PyYAML, PyJWT | sin locks/markers de plataforma ni empaquetado formal | EXISTENTE, NO VERIFICADO | CONSERVAR, decidir pin/compatibilidad en SPEC futura |
| `assets/diagrams/workflow.mmd` | diagrama de flujo seis etapas | Skill Layer | docs/workflow | no representa estados internos approval/audit ni callback | INCONSISTENTE | ACTUALIZAR después de aprobación documental |
| `examples/example_01.md`, `example_02.md` | ejemplos de documentos | Specification Engine | template/validator | revisar cada uno para legacy plan/migration | EXISTENTE, NO VERIFICADO | CONSERVAR; añadir compatibilidad etiquetada |
| `references/architecture.md`, `best-practices.md`, `game-design.md`, `performance.md` | conocimiento general, principalmente game domain | Skill Layer / specialization | SKILL.md | mezcla base transversal con dominio game | REORGANIZAR candidato | MIGRAR a `skills/domains/game-development/` conservando contenido útil, sin mover ahora |
| `templates/bug-report.md`, `game-design-document.md` | artefactos de dominio | specialization | references game design | específicos de game dev | REORGANIZAR candidato | Migrar a domain package en SPEC posterior |
| `docs/architecture/*` (este set) | borradores actuales | Architecture governance | usuario aprueba | son propuesta, no core y no normativa | EXISTENTE, DRAFT | CONSERVAR para revisión; cambios requieren aprobación documental |

## Correspondencia de responsabilidades por componente objetivo

| Componente objetivo | Estado actual | Archivos candidatos | Clasificación global |
|---|---|---|---|
| Skill Layer | reglas y conocimiento en `SKILL.md`, `instructions/`, `references/` | docs universales + dominio game | INCONSISTENTE |
| Specification Engine | parser/validator/schema/template | validate/schema/templates/specs | EXISTENTE, NO VERIFICADO para separación SPEC/PLAN |
| Identity & Approval Authority | provider, signer y servicio socket | approval_service, authority_service, approval_cli | INCOMPLETO |
| Policy Engine | disperso en validate + authority + gate | validate, authority_service, implementation_gate | INCONSISTENTE / INTEGRAR contractualmente |
| Implementation Gate | cuatro operaciones de archivo | implementation_gate, autoridad IPC | EXISTENTE, NO VERIFICADO en producción |
| Workspace Broker | embebido en authority/gate/safe_fs | authority_service, implementation_gate, safe_fs | INCOMPLETO como proceso y durabilidad |
| Audit Service | módulo audit_chain dentro de authority/gate | audit_chain, authority_service, gate | EXISTENTE, NO VERIFICADO fail-stop multi-instance |
| Integration Toolkit | CLI, socket client, enforce | authority_client, approval_cli, enforce, report | EXISTENTE, NO VERIFICADO conformidad |
| Adaptadores | Unix socket/CLI sólo; no provider adapters | authority_client, approval_cli, enforce | PENDIENTE |
| Interfaces públicas | protocolo IPC v2 implícito y métodos Python | authority_client/service, scripts | INCOMPLETO; sin contrato versionado independiente |

## Correspondencia de Skill transversal/domains

- Conservar `game-development/SKILL.md` hasta que se apruebe y ejecute plan de migración.
- Crear en fase posterior `skills/spec-first-guardian/SKILL.md` con reglas universales (SPEC previa, aprobación humana, no self-approval, denegación por defecto, límites reales).
- Especialización `skills/domains/game-development/`: contenido útil de `references/game-design.md`, `performance.md`, `best-practices.md` y templates de diseño; decidir arquitectura/general references tras revisión por contenido.
- Especializaciones web/backend: sólo tras SPEC de dominio, sin duplicar reglas universales; referencian la Skill transversal.
- Mantener alias/README en rutas existentes durante migración; medir adopción antes de retirar rutas legacy.

## Estado de repositorio y límites de auditoría

La inspección observó 39 archivos versionables no generados listados por `find` (incluye documentos de este borrador creados tras estado inicial; inventario fuente antes de escritura se refleja arriba); `__pycache__` existía antes/después por ejecución Python, no es fuente objetivo. Dependencias de `requirements.txt`, sin manifest de empaquetado o lock visible en inventario. Tests: cuatro módulos unittest y `support.py`. No observé CI workflow en búsqueda acotada del árbol actual.

Las clasificaciones “verificado” se refieren a suite unitaria ejecutada, no a IdP real, dos cuentas OS, systemd, filesystem con fallos, ataques multi-proceso ni Windows/macOS.