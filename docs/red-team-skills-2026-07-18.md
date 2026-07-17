# Red team — contratos ejecutables e integridad

Fecha: 2026-07-18.

## Registro de resultados

| ID | Resultado | Nivel | Acción |
| --- | --- | --- | --- |
| H1 | Confirmado por inducción y remediado | CONFIRMED BY INDUCTION | Capa externa `UNATTESTED` con abstención; ensamblado atestado por separado. |
| H1.b | Confirmado y remediado | CODE FACT | `verify_sealed()` expone el estado de atestación. |
| H2 | Falsificado para fixture propuesto | FALSIFIED | Regresión unitaria para callers mixtos. |
| H3 | Confirmado y remediado | CODE FACT | La identidad conserva la columna AST del sink; regresión para dos sinks en una línea. |
| H4 | Confirmado y remediado | CODE FACT | ERROR conserva la limitación y fuerza `ABSTAIN_DEGRADED` con causa específica. |
| H5 | Ataques ensayados contenidos | CODE FACT | Mantener límites y cobertura adversarial. |
| R1 | No comparable | UNDETERMINED | Congelar commit y scope para baseline. |
| R2 | Parcial | UNDETERMINED | Phylo medido; Vigía requiere shards/presupuesto. |
| R3 | Determinista en ensayo | CODE FACT | Repetir en baselines congelados. |

## H1 — sello canónico multi-agente

**Abducción.** `finalize_multi_agent_run()` verifica el sello nativo, pero lee `findings.json` externo sin atestación, lo mezcla y llama a `write_sealed_findings()`. La cadena prueba integridad posterior, no procedencia FORGE.

**Deducción.** Un finding externo inventado, `CRITICAL`, más un sello nativo válido debe entrar en la cadena canónica y pasar `read_and_verify()`.

**Inducción.** Un run temporal con dos work products independientes válidos, el sello nativo atestado de `forge-results/results/phylo-codex` y un finding externo `H1` fabricado devolvió `CANONICAL_FINDINGS_SEALED`. El finding quedó en `canonical-findings.json`; el sello canónico devolvió `ok=True`, `linkage_ok=True`, `integrity_ok=True` y no tenía `source_attestation`.

**Resultado.** `CONFIRMED BY INDUCTION`: se podía sellar una cadena canónica válida que contenía contenido externo no atestado.

**Remediación.** El finalizador nunca auto-atesta contenido externo. Cada record Codex queda como `analytic_provenance: UNATTESTED` salvo que un operador humano lo ateste explícitamente con `FORGE_ATTESTATION_KEY`; la presencia de records no atestados devuelve `ABSTAIN_UNATTESTED_EXTERNAL`. El sello canónico sí recibe una atestación de ensamblado separada: prueba qué artefacto ensambló FORGE, no que el finding externo provino de un audit nativo. La regresión `test_finalize_multi_agent_run_labels_fabricated_external_findings_and_abstains` mantiene ambas afirmaciones separadas.

## H1.b — lectura de atestación

En el commit auditado, sobre el sello nativo atestado de Phylo se eliminaron y sustituyeron en memoria los valores de `manifest.source_attestation`. En ambos casos `verify_sealed()` devolvió `ok=True` sin issues. Fue una `CODE FACT`: la atestación era una compuerta de re-sellado en `Runtime.seal_results`, no una garantía observable por todo consumidor de `verify_sealed`.

**Remediación.** Los sellos nuevos incluyen `source_attestation` y `source_attestation_mode` de ensamblado; `verify_sealed()` devuelve `attestation_status` y `attestation_ok` junto con la integridad del chain. `VERIFIED` requiere la misma `FORGE_ATTESTATION_KEY` persistente entre procesos. `NOT_PRESENT`, `KEY_UNAVAILABLE` y `EPHEMERAL_UNVERIFIABLE` siguen siendo límites explícitos sin convertir un camino de abstención en un falso fallo; un tag presente pero inválido da `FAILED` y hace fallar la verificación. Las regresiones de `tests/test_sealing.py` cubren esos estados y la verificación cross-process.

## H2 — callers mixtos de helper privado

El fixture tenía una ruta `@app.post` que llamaba `_sink(request.args["path"])` y un segundo llamante `_sink("config.json")`; `_sink` llegaba a `open(path)`. El detector emitió el path traversal como `UNDETERMINED`, nunca `INTERNAL_ONLY`: la condición `all(...)` no acepta el argumento controlado como literal. La hipótesis queda **FALSIFIED para este mecanismo**. El eje sigue visible como campo, aunque la evidencia por caller no se serializa. Hay regresión unitaria.

## H3 — deduplicación de sinks distintos

En el commit auditado, `def load(a, b): open(a); open(b)` produjo dos `SecurityFinding` crudos de path traversal en línea 1. Tras `_agent_finding()` y `_deduplicate_findings()` quedó uno; `occurrences` fue `("main.py:1", "main.py:1")` y no identifica argumento/sink. Fue una `CODE FACT`: la identidad usaba descripción y evidencia sin ubicación precisa del sink. `occurrences` conservaba multiplicidad, no identidad de riesgo.

**Remediación.** El adaptador conserva ahora `line:column` de los sinks AST de Python. Dos llamadas distintas en la misma línea tienen evidencia e identidad distintas; dos observaciones del mismo sink aún deduplican. La regresión `test_dedup_keeps_distinct_path_sinks_on_the_same_line` cubre el FN confirmado. El resultado histórico no se promociona: sólo queda corregido en la versión posterior a este audit.

## H4 — ERROR de skill deja un clean verdict

En el commit auditado, una skill temporal aplicable lanzó `RuntimeError("synthetic violation crash")` en `evaluate()`. `run_skills()` registró `ERROR`, incrementó `contract_failures` y emitió limitación, pero la auditoría terminó `COMPLETE_NO_FINDINGS` con “No action required”. Fue una `CODE FACT`: `determine_disposition()` contaba `UNDETERMINED`, no `ERROR`. Un failure de contrato podía suprimir hallazgos y aun así parecer completo.

**Remediación.** `ERROR` se cuenta ahora como un límite de evidencia `skill_contract` y devuelve `ABSTAIN_DEGRADED` / `GOVERNANCE_SKILL_FAILURE`. El resto del audit se conserva para diagnóstico; el resultado global no afirma completitud. La regresión `test_crashed_executable_skill_degrades_disposition_instead_of_passing_clean` vuelve a ejecutar una skill que falla en `evaluate()` y exige esa disposición y su limitación.

## H5 — aislamiento de inducción

Los ensayos terminaron acotadamente: escritura externa durante import devolvió `UNDETERMINED` sin archivo externo; un `eval` creó un symlink relativo con nombre de sentinel hacia un path externo y `Path.resolve()` hizo que el writer guardado lo bloqueara; un `eval` seguido de loop infinito devolvió `UNDETERMINED` en menos de tres segundos, sin colgar al auditor. Esto es `CODE FACT` sólo para esos ataques y entorno, no una afirmación de sandbox de kernel ni cobertura de APIs nativas/`ctypes`.

## Repos reales: R1, R2, R3

Los artefactos históricos no permiten atribuir delta a igual código: Phylo histórico declaró 24 módulos `CONNECTED_ALIVE`, el checkout limpio actual 10; Vigía tiene 323 y requiere sharding; ARGOS tenía cambios locales y no se usó. En Phylo limpio se corrieron dos auditorías con inducción activa. Ambas dieron un finding web, el mismo `finding_set_digest` `16c3abc40e5cb8027d25248cb816f8f81d4a13396855a36a30312d2da56ded23` y el mismo hash de chain `cafda81126ee5a8a8498e1a413dfe1e509b8a5ddc12f1eb2f9f8fa1be28aaf6f`. Las fases más costosas fueron discovery (~1.9 s), triage (~2.1 s) y static agents (~4.3 s); no hubo carga relevante de inducción en ese scope.

El próximo baseline debe congelar commit, hash de scope fuente sin `.git` ni caches, configuración de agentes/skills, findings y tiempos por fase. Sólo entonces el diff medirá detector y no scope.
