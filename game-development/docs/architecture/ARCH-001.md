# ARCH-001 — Arquitectura objetivo de Spec-First Guardian

**Estado:** DRAFT — no normativa hasta aprobación explícita del usuario  
**Fecha:** 2026-11-06  
**Autor:** Buffy (borrador técnico generado para revisión humana)  
**Alcance:** arquitectura evolutiva del framework; no autoriza implementación ni despliegue.  
**Autoridad documental:** este documento no prevalece sobre SPEC-001 ni sobre políticas globales; será propuesta normativa sólo tras aprobación humana explícita y control de versión.  
**Dependencias:** `CURRENT-STATE-MAP.md`, `ADR-001.md`, `SPEC-ARCH-001-HARDENING.md`, `PLAN-ARCH-001.md`, `FINDINGS-ARCH-001.md`.  
**Relación:** describe destino; el mapa describe realidad observada. La SPEC define requisitos de cambio; el PLAN sólo su secuencia de ejecución.

## 1. Visión y principios

Spec-First Guardian (SFG) es un **AI Agent Governance & Enforcement Framework** agnóstico de modelos, IDEs, orquestadores y proveedores de agentes. Gobierna especificaciones, identidad/aprobación humana, políticas y operaciones mediadas.

SFG no es agente de programación, orquestador, proveedor de modelos, IDE ni SaaS/plataforma en esta fase. Su principio inalterable es: **ningún agente puede implementar, modificar o extender software sin una SPEC validada y aprobada explícitamente por el usuario humano**. Ningún agente, adaptador, servicio, gate o autoridad técnica suplanta a la persona aprobadora.

Principios: denegación por defecto; autorización ligada a hash de SPEC y alcance canónico; separación autoridad/ejecución; estados documentales oficiales preservados; evidencia auditable; declarar límites reales; compatibilidad migratoria explícita; minimizar procesos y abstracciones; no conceder permiso si evidencia, persistencia o identidad son inciertas.

Los siete estados oficiales permanecen exactamente: `DRAFT`, `UNDER_REVIEW`, `PENDING_USER_APPROVAL`, `APPROVED`, `REJECTED`, `SUPERSEDED`, `ARCHIVED`. Los estados de solicitud, desafío, autenticación, autorización y auditoría son dominios de estado separados y no añaden estados documentales.

## 2. Distribución de procesos y límites de confianza

### A. Agent Runtime — no confiable

Agentes, subagentes y adaptadores cliente son entradas no confiables. Pueden leer contexto permitido, proponer SPEC/PLAN y solicitar operaciones; sus declaraciones de identidad, revisión, pertenencia y éxito no son evidencia autorizante. No reciben claves privadas ni escritura directa al workspace protegido. En el sistema actual el aislamiento OS no está demostrado en UIDs reales.

### B. Authority Service — confiable sólo por instalación verificada

Proceso Linux separado, UID de servicio, configuración protegida. Valida identidad humana (OIDC real), desafío/estado/nonce/PKCE, SPEC, hashes y políticas; firma y emite decisiones; controla revocaciones. No ejecuta por sí misma operaciones de filesystem sin el broker. La autorización exige que el aprobador humano sea el sujeto esperado; el agente nunca puede aprobarse a sí mismo.

### C. Workspace Broker — proceso separado recomendado

Broker con permisos OS mínimos para realizar únicamente las operaciones autorizadas sobre raíces permitidas. Consume órdenes autenticadas emitidas por Authority Service y devuelve evidencia de ejecución/durabilidad. No autentica ni aprueba, no decide políticas y no firma autorizaciones. Autoridad no debe aceptar rutas, UID o alcance aportados por agente como fuente de confianza.

### D. Audit & Management — lógica aislada, sin obligación de microservicio

Primera versión puede ser módulo/servicio dentro del proceso Authority con almacenamiento persistente protegido; el mecanismo de bloqueo de emergencia debe alcanzar al proceso de autoridad incluso si el archivo de salud no es escribible. Un proceso independiente de auditoría sólo se justifica si un almacén/collector externo aporta independencia operativa demostrada. Reconciliación es administrativa humana, autenticada y auditable.

La división lógica no obliga a convertir módulos en microservicios. Inicialmente se recomiendan dos procesos obligatorios (Agent Runtime y Authority+Audit); el Workspace Broker puede ser proceso separado si la superficie de privilegio de escritura justifica IPC y protocolo dedicados. No conceder capacidades amplias al servicio de autoridad si la separación efectiva del broker aún no está implementada.

## 3. Componentes lógicos

| Componente | Responsabilidad/entradas | Salidas y datos | Permisos y dependencias | Interfaces/errores/confianza | Prohibiciones |
|---|---|---|---|---|---|
| 1. Skill Layer | Reglas universales de uso; instrucciones para agente/adaptador. Entrada: petición y documentación visible. | Produce propuesta de SPEC/PLAN y solicitud de operaciones. Lee sólo contexto autorizado. No modifica estado de autoridad. | Sin privilegios; depende de contratos públicos, no de proveedor IA. | Integrations API; errores: instrucciones ausentes/contradictorias, contrato no disponible. Runtime no confiable. | No afirmar enforcement OS que no exista; no aprobar ni firmar; no ampliar alcance ni ejecutar una alternativa. |
| 2. Specification Engine | Crear/parsear/validar/versionar SPEC y PLAN separados; aplicar esquema y trazabilidad. | SPEC validada, hash canónico, informe de errores; PLAN enlazado a SPEC pero no puede cambiar sus requisitos. Datos: contenido documental, estados oficiales. | Lectura de proyecto; escrituras de documentos sólo vía autorización. Depende de schema/validator. | Specification API; errores: inválida, ambigua, hash cambiado, incompatible/histórica. El documento puede ser controlado por agente hasta presentación. | No inferir aprobación del frontmatter; no introducir estados nuevos; no ejecutar tareas. |
| 3. Identity & Approval Authority | Completar OIDC Authorization Code + PKCE/callback, autenticación reciente, identidad sujeto esperado, consentimiento humano, firma de autorización. | Evento firmado con hash SPEC/alcance, sujeto/issuer, timestamps y expiración; estado desafío/auth separado. | Claves/credenciales sólo dentro de proceso protegido; depende de IdP OIDC y almacén fiable. | Approval API; errores: state/nonce/PKCE/sujeto/token/expiración/replay, firma/persistencia. Frontera humana explícita. | No aceptar token directo sin sesión callback verificada; no hacer APPROVED antes de persistir el bundle; ningún autoaprobador. |
| 4. Policy Engine | Evaluar política global, estado/versión SPEC, scope, operación, identidad, revocación y restricciones. Entrada: contexto autenticado y hashes recuperados desde autoridad. | decisión `ALLOW` o `DENY` con razones y obligaciones. | Sólo autoridad; reglas deterministas; sin permitir bypass por adaptador. | Policy API; errores: evidencia no verificable, regla ausente, revocación desconocida. Datos cliente no confiables. | No ejecutar; no convertir estado desconocido en allow; no confiar en flags de cliente. |
| 5. Implementation Gate | Orquestar evaluación + intención durable + orden al broker + resultado durable. Hoy sólo cuatro operaciones de archivo. | decisión y recibo de operación; deny si intención o resultado no durables. | Authority/Broker; dependencias de Audit, Policy, Specification y Workspace APIs. | Enforcement API; errores: audit unavailable, denied, broker failure, persistence unknown. | No permitir procesos/scripts/deps/migraciones salvo que un backend OS real los intercepte; no reabrir un segundo camino. |
| 6. Workspace Broker | Ejecutar operación acotada en descriptor de raíz aprobada; proteger contra traversal/symlink/TOCTOU, montajes y hardlinks según política. | recibo con objeto, digest, resultado de persistencia (confirmada/no verificable). | Privilegios sólo sobre workspace autorizado; mínimo privilegio. | Workspace API, IPC autenticado; errores: ruta insegura, montaje no autorizado, tipo/hardlink, write/fsync failure, race. Workspace es frontera adversaria. | No autorizar, firmar, elegir scope o ejecutar comandos generales. |
| 7. Audit Service | Registrar eventos hash-chain y estado de salud, bloqueos persistentes, intención/resultado/reconciliación. | secuencia verificable, clasificación HEALTHY/INCOMPLETE/CORRUPT/UNAVAILABLE/RECONCILIATION_REQUIRED. | Escritura sólo authority; fsync y almacenamiento definido. | Audit API; errores: append/verify/fsync/marker/health unavailable, corrupción, evento no durable. | No convertir falta de evidencia en éxito; no permitir borrar/limpiar bloqueo sin reautenticación y evento de reconciliación. |
| 8. Integration Toolkit | SDK/CLI y ayudas comunes para integrar IDEs/orquestadores/runtime con APIs canónicas. | solicitudes canónicas/recibos; manejo de capacidades y errores comunes. | Sin privilegio de firma/ejecución; depende de Authority API y auth del cliente. | Integration API; errores: versión/protocolo, unavailable, denied, timeout ambiguo. | No implementar autoridad alternativa, caché autorizante ni escritura fuera de gate. |
| 9. Adaptadores | Mapear eventos/acciones de proveedor a contratos neutrales. | contextos tipados; respuesta al usuario con razones. | Plugins aislados y mínimo permiso; dependen sólo de interfaces públicas. | Contratos versionados; errores explícitos. Cada adaptador no confiable hasta pruebas de conformidad. | No tener bypass, decidir humano, cambiar estados o ampliar acciones. |
| 10. Interfaces públicas | Contratos Specification, Approval, Authority, Policy, Enforcement, Workspace, Audit, Integration. | Tipos estables, errores, versionado, capacidades, evidencia. | Independientes de transporte; implementaciones iniciales Unix socket y Python API interna, no garantía de red. | Versionado de protocolo y esquemas; rechazar campos/desconocidos según política. | No exponer detalles secretos ni confiar en tipo de cliente como autenticación. |

## 4. Contratos propuestos (resumen)

Las interfaces completas y sus validaciones están en `SPEC-ARCH-001-HARDENING.md`, sección 11. Toda operación de cambio requiere identidad autenticada y autorización canónica común. Ningún adaptador puede reimplementar la evaluación o usar un canal paralelo.

## 5. Modelo de datos y estados

- `Specification`: id, version, estado oficial, contenido/huella, metadatos; no contiene aprobación de autoridad confiable.
- `Plan`: id/version, referencia hash de SPEC, tareas/orden/archivos/dependencias/pruebas/rollback/evidencias; no puede añadir requisitos ni acceptance criteria.
- `ApprovalRequest`: solicitud durable; estado de solicitud separado de estados oficiales de SPEC.
- `Challenge`: hash de secreto, `state`, `nonce`, sesión server-side, PKCE verifier/challenge, expiración, contador/consumido; jamás exponer verifier ni nonce secreto al Agent Runtime.
- `AuthenticationAttempt`: pending/succeeded/failed/expired/replayed como estados internos, ligados a la solicitud y sesión; éxito sólo después de validar callback OIDC.
- `Authorization`: sólo activa tras firma, persistencia de bundle y evento auditado confirmados. Un fallo parcial crea estado indeterminado/reconciliación y bloquea, nunca `APPROVED` falso.
- `AuditHealth`: estado duradero + bit de emergencia en proceso authority. Estado desconocido equivale a denegación.

## 6. Flujos críticos

### Aprobación (transacción lógica)
1. Authority carga y valida SPEC/hash, alcance/hash, estado documental aprobable y autorización de administrador.
2. Crea desafío aleatorio de un uso, secreto state/nonce en sesión server-side, PKCE verifier aleatorio secreto y challenge S256; persiste preparación durable antes de redirigir al IdP.
3. Callback valida sesión, state constant-time, expiración y PKCE en intercambio de código; valida ID token con issuer/audience/JWKS/algoritmo/exp/iat/auth_time/nonce/sub exactos, sujeto esperado, `azp` cuando aplique; consume código/nonce/token de modo atómico/replay-protected.
4. Relee SPEC de fuente segura y scope inmutable; ambos hashes deben coincidir. Usuario realiza confirmación explícita del contenido y alcance exactos.
5. Consume desafío mediante compare-and-swap/lock persistente; la concurrencia permite un solo ganador. Autentica antes de consumir definitivamente o registra intento fallido e invalida desafío de modo seguro; política exacta se define en SPEC P0.
6. Firma registro canónico; escribe bundle/índice con atomic replace + fsync archivo/directorio; persiste evento `approval_committed` en auditoría; sólo entonces presenta autorización activa y estado de solicitud `APPROVED` (no estado documental nuevo). Si cualquier paso resulta ambiguo, no concede y exige reconciliación.

### Operación
1. Authority comprueba audit health y autenticación OS/IPC; carga bundle vigente, revocaciones verificadas, SPEC actual y política.
2. Escribe intención durable confirmada antes de ordenar broker.
3. Broker ejecuta una sola operación en scope y retorna digest/resultado/durabilidad diferenciada.
4. Audit escribe resultado durable. Sólo después devuelve éxito completo; si la ejecución ocurrió pero resultado/audit no se confirma, devuelve estado indeterminado/no durable, pone proceso en emergencia y bloquea nuevas concesiones hasta reconciliar.

## 7. Paginación y consentimiento

`review_next_offset` demuestra secuencia de contenido servido/entregado al cliente; `review_fingerprint` vincula el contenido servido con un hash; `review_pages` sólo cuenta páginas según tamaño/algoritmo declarado; `review_complete` es una declaración de cliente y no demuestra renderizado, presencia humana, lectura ni comprensión. La paginación no es prueba de consentimiento.

Requisito objetivo: UI/flujo de autoridad presenta contenido íntegro de SPEC y alcance desde la autoridad, confirma hash exacto (más algoritmo/encoding), y requiere acción humana explícita (p.ej. botón de confirmación por sesión protegida) firmada/registrada junto al hash SPEC y scope. Un agente no puede emitir dicha acción mediante API de agente. No afirmar que el usuario leyó o comprendió; sólo que la interfaz entregó el contenido y recibió confirmación explícita autenticada.

## 8. Instalación y evolución de contratos

Instalación declarativa con operaciones `INSTALL`, `VERIFY`, `UPGRADE`, `RECONFIGURE`; sin sobrescritura destructiva de trust store/config. Las claves revocadas son monotónicas y nunca se restauran por reinstall; rotación añade nueva clave, valida publicación/consumo y retira antigua mediante autorización auditada. Compatibilidad de formatos se versiona; legacy specs siguen validables en modo histórico, con migración explícita y hash/approval anterior preservados.

## 9. Evolución en cuatro fases

1. **FASE 1 — Framework Core (prioridad única):** contratos, Specification/Plan separados, aprobación OIDC completa, policy, gate, broker POSIX acotado, auditoría fail-stop, instalación/migración, threat model y pruebas de integración con identidades reales. No asumir producción hasta evidencia.
2. **FASE 2 — Integraciones y adaptadores:** conformidad, SDK, IDE/orquestadores diversos, rutas sólo al núcleo común. No variar autorización.
3. **FASE 3 — Governance Platform:** gestión multi-proyecto/organización, telemetría/administración central y servicios remotos sólo con nuevo threat model, aprobación y aislamiento probados.
4. **FASE 4 — Ecosistema y marketplace:** extensiones firmadas y revisadas, capacidades mínimas y sandbox. Fuera de alcance actual.

No desarrollar ahora marketplace, facturación, SaaS, editor, modelos propios, orquestador completo ni administración comercial de usuarios. Los puntos de extensión son contratos versionados, capacidades declarativas, transport adapters, storage adapters y conformance suite.

## 10. Seguridad y aceptación arquitectónica

La arquitectura no queda aprobada por existir este borrador. Antes de convertirla en normativa, el usuario debe revisar separación de procesos, estado de autorización, política de legacy SPEC, garantías de durabilidad, protocolo de aprobación y permisos OS. Ningún componente se considera verificado por este diseño; ver mapa y hallazgos.