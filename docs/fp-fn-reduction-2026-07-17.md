# Reducción de falsos positivos y falsos negativos

Fecha de cierre: 2026-07-17.

Este documento registra el contrato implementado para medir y reducir FP/FN.
Una señal estática no se presenta como defecto confirmado: los artefactos
conservan evidencia, nivel epistémico y abstenciones.

## Medición reproducible

`tests/corpus/manifest.json` usa hallazgos exactos `{family, path, line}`. La
métrica primaria compara la tripla completa: familia correcta en línea
incorrecta equivale a un FP y un FN. `forge.precision` mantiene `by_family`
como vista agregada y emite `by_finding_family` y `global` como métricas
exactas.

El corpus contiene FP-001 a FP-004, los cuatro agentes y casos positivos y
negativos para las familias ampliadas. Gates:

```bash
python3 -m forge.precision --corpus tests/corpus \
  --min-precision 0.95 --min-recall 0.90
```

## Precisión

- Paths Python propagan `basename`, `normpath`, `realpath`, `resolve`,
  `Path.name`, allowlists y extensiones por punto fijo.
- JS/TS propaga `basename`, `resolve` y `normalize` por asignaciones simples.
  Sigue siendo un análisis léxico acotado, no un parser JavaScript.
- Paths registran `ATTACKER_CONTROLLED`, `INTERNAL_ONLY` o `UNDETERMINED`.
- Severidad deriva determinísticamente de familia, nivel epistémico,
  controlabilidad y explotabilidad. Sin control de atacante y evidencia
  plausible/confirmada no hay HIGH ni CRITICAL.
- La deduplicación conserva las apariciones agrupadas en `occurrences`.

## Recall e inducción

No existe cap de cinco candidatos: todos pasan a verificación; los reportes
pueden agrupar para lectura, pero el set sellado permanece completo.

La inducción usa `spawn`, límites de CPU/memoria/FDs y un worker que bloquea
red, procesos y escrituras fuera del tempdir antes de importar el objetivo.
Es defensa en profundidad de Python, no una frontera de seguridad de kernel.

Harnesses activos:

- parser: entrada malformada;
- eval/exec: sentinel limitado al tempdir;
- subprocess: sonda en memoria, sin proceso real;
- float threshold: comparación diferencial con `Decimal` exacto.
- SQL injection: receptor SQL en memoria, sin conexión a base real.

Familias sin harness compatible quedan `UNDETERMINED`. Confirmación significa
sólo que la conducta del harness se reprodujo; no prueba RCE, impacto de
producción ni explotabilidad general.

Se ampliaron dinero como float (literales, divisiones y tipos SQL), SQL
concatenado hacia `.execute()` y parámetros que llegan a argv de subprocess.
Las consultas parametrizadas y argv constantes están cubiertos como negativos.

## Cobertura e integración

La cobertura informa por lenguaje archivos `analyzed` y `abstained`; builds,
caches, resultados previos y binarios quedan fuera de política. Esta es la
política explícita de cobertura JS/TS mientras no exista parser estructural.

El cierre multi-agente exige exactamente abducción, deducción e inducción por
`hypothesis_id`. `findings.json`, `report.md`, `report.json` y el sello
canónico comparten un digest. La comparación registra identidad de set, hash
de scope, versión, agentes y skills; no calcula `coverage_delta` si cambia el
scope.

## Validación

```bash
python3 -m pytest -q
python3 -m forge.precision --corpus tests/corpus \
  --min-precision 0.95 --min-recall 0.90
```

El cierre pasó con 263 tests. Los commits incluyen coautoría de Terra (Codex /
ChatGPT 5.6).
