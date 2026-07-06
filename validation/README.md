# Capa de validación y trazabilidad

Esta capa convierte al agente de **"prototipo funcional"** en **"sistema
confiable y auditable"**. Es la contribución metodológica central de la tesis:
la calidad del agente **se demuestra, no se declara**.

## Marco: las tres dimensiones (Russell & Norvig, 2021)

Un agente racional selecciona, para cada secuencia de percepciones, la acción que
maximiza su medida de rendimiento dado su conocimiento. Validamos eso en tres
dimensiones, cada una con métricas reproducibles:

| Dimensión | Pregunta | Módulo |
|---|---|---|
| **Control** | ¿Hace lo que debe y no lo que no debe, de forma predecible? | `metrics/control.py` |
| **Autonomía** | ¿Sus decisiones autónomas son correctas verificablemente? | `metrics/autonomy.py` |
| **Knowledge** | ¿Su base de conocimiento es correcta, completa y aplicable? | `metrics/knowledge.py` |

La capa `traceability/` (hermana, en la raíz del agente) registra cada decisión
del ciclo agéntico, dando **trazabilidad completa** para auditar cada alerta.

## Cómo funciona

1. **Escenarios** (`scenarios/`): cada uno es un directorio con `scenario.yaml`
   (qué es y cómo se ejecuta) y `expected.yaml` (qué debería concluir el agente).
   Se agrupan en `positive/`, `negative/`, `ambiguous/`.
2. **Runner** (`scenario_runner.py`): ejecuta setup/execute/teardown (scripts que
   **aprueba y ejecuta el investigador**), recolecta las alertas del agente en la
   ventana temporal, y compara contra el `expected.yaml`.
3. **Métricas** (`metrics/`): agregan los resultados en las tres dimensiones.
4. **Rúbrica** (`quality_rubric.py`): evaluación cualitativa humana de las
   narrativas (0-5 en 5 ejes).
5. **Reporte** (`reporting/`): consolida todo en Markdown + JSON.

## Criterios de decisión acordados

- **Escenarios ambiguos**: la respuesta **correcta es expresar incertidumbre**,
  es decir, NO afirmar una CVE conocida con confianza ≥ 0.6. Un falso
  reconocimiento (encasillar lo desconocido en una CVE conocida) cuenta como
  fallo (`false_recognition_rate`).
- **Cross-check de knowledge**: **manual**, sin red. El investigador valida cada
  CVE contra NVD/MITRE y registra el score en `knowledge_consistency.yaml`.
- **Presupuesto de campaña**: 500k tokens (configurable `VALIDATION_TOKEN_BUDGET`).
- **Ejecución**: por tipo, en corridas separadas (control de carga/costo).

## Uso (CLI)

```bash
python validation_cli.py run-scenario cve-2023-0264-basic     # un escenario
python validation_cli.py run-batch negative                    # todos de un tipo
python validation_cli.py run-campaign                          # batería completa
python validation_cli.py report <campaign_id>                  # reimprime un reporte
python validation_cli.py query-traces --analysis-id <id>       # audita una traza
python validation_cli.py evaluate-quality <alert_id>           # rúbrica manual
```
Opciones estándar: `--dry-run`, `--verbose`, `--output-format {markdown,json}`.

## Cómo agregar un escenario nuevo

1. Creá `scenarios/<tipo>/<mi-escenario>/`.
2. Escribí `scenario.yaml` (usá los existentes como plantilla).
3. Escribí `expected.yaml` con el ground truth (`should_alert`,
   `should_identify_cves`, `should_link_component`, rangos de confianza, tolerancias).
4. Opcional: `setup.sh` / `execute.sh` / `teardown.sh` (los ejecuta el investigador).
5. Corré `python validation_cli.py run-scenario <mi-escenario>`.

> Los escenarios provistos son **scaffolding con `TODO`**: completá los
> parámetros empíricos reales (usuarios, timings, intensidad) antes de correrlos.

## Cómo interpretar el reporte

- **CONTROL**: `crash_rate` y `timeout_rate` bajos + `termination_rate` alto =
  agente predecible. `budget_adherence` = tokens consumidos / presupuestados.
- **AUTONOMÍA**: `precision`/`recall`/`f1` de detección, `identification_accuracy`
  (CVE correcta) y `component_linking_accuracy` (capa correcta).
- **KNOWLEDGE**: `coverage` (CVEs conocidas detectables), `generalization_rate`
  (variantes), `rejection_rate_on_unknown` vs `false_recognition_rate` (manejo de
  lo desconocido), `knowledge_consistency_score` (cross-check manual).
- **Análisis de fallos**: cada escenario no-pass lista sus mismatches y los
  `analysis_ids` para ir a la traza completa (`query-traces`).

## Decisiones de diseño

- **Observación, no intervención**: la trazabilidad se engancha en el ReAct como
  capa opcional (`recorder=None` → comportamiento idéntico). No se tocó la lógica
  del agente ni el esquema de alerta.
- **Reproducibilidad**: las métricas son funciones puras sobre `ScenarioResult`;
  mismos inputs → mismo resultado. Testeadas sin VPS ni Keycloak (fixtures).
- **Dependencias inyectables**: el runner recibe el proveedor de alertas y el
  ejecutor de scripts, para testear la comparación de forma aislada.
- **Limitación conocida**: `tokens_used` requiere el logging de `usage` de
  DeepSeek (pendiente); hasta entonces `budget_adherence` reporta sobre 0.
