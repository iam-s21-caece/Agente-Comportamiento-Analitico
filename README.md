# Agente de análisis de seguridad para Keycloak

Agente de IA que, alojado en la misma VPS donde corre una instancia de Keycloak,
observa el comportamiento del sistema y del contenedor durante ataques
controlados, interpreta las señales a la luz de un conocimiento previo sobre las
vulnerabilidades, y produce **alertas analíticas estructuradas** que identifican
y explican cada ataque vinculándolo a la arquitectura afectada.

Proyecto de **tesis de grado en informática** (ciberseguridad ofensiva/defensiva).
El agente se evalúa empíricamente comparando sus alertas contra la verdad conocida
de los ataques ejecutados de forma controlada por el investigador.

## Marco teórico

El agente es **híbrido** entre las categorías clásicas de Russell & Norvig (2021):

- **Basado en modelos**: mantiene una representación interna del mundo (estado de
  Keycloak, métricas del sistema, eventos de autenticación) y conocimiento
  estructurado sobre las vulnerabilidades (`knowledge_base/`).
- **Basado en objetivos**: el bucle **ReAct** (Yao et al. 2023) opera
  teleológicamente persiguiendo el objetivo de emitir una alerta correcta y
  completa para cada ataque observado.

Patrón de razonamiento interno (ReAct): el LLM razona → decide qué herramienta
invocar → recibe el resultado → razona otra vez → emite la alerta cuando tiene
evidencia suficiente.

## Repositorios de referencia

Este agente **integra patrones** de los siguientes proyectos (no son forks; se
citan como inspiración):

- [`ringa-tech/tu-primer-agente-de-ia`](https://github.com/ringa-tech/tu-primer-agente-de-ia)
  — patrón ReAct simple con tool calling.
- [`iam-s21-caece/keycloak-security-monitor`](https://github.com/iam-s21-caece/keycloak-security-monitor)
  — captura de eventos de Keycloak en tiempo real + LLM.
- [`iam-s21-caece/iam-auditor`](https://github.com/iam-s21-caece/iam-auditor)
  — patrón híbrido: checks deterministas + análisis narrativo con LLM.

## Las dos CVEs y su asimetría

| Aspecto                | CVE-2026-33871 (DoS)        | CVE-2023-0264 (OIDC)          |
|------------------------|-----------------------------|-------------------------------|
| Volumen de evidencia   | Alto                        | Bajo                          |
| Tipo de señal          | Volumétrica (umbrales)      | Correlacional (relaciones)    |
| Capa afectada          | Infraestructura (Netty)     | Aplicación (OIDC)             |
| Densidad               | Series temporales continuas | Eventos discretos puntuales   |
| Detección por umbral   | Funciona                    | No funciona                   |
| Detección por correlación | Sirve, no necesaria      | Única vía                     |

Manejar ambas arquitecturas de evidencia es el **aporte empírico central** de la
tesis. El agente combina:

- **Checks deterministas** (`deterministic_checks/`): umbrales relativos a
  baseline para el DoS; correlación LOGIN↔CODE_TO_TOKEN para el hijacking.
- **Razonamiento LLM** (`agent_core/`): interpreta los resultados, consulta el
  conocimiento de las CVEs y redacta la narrativa de la alerta.

## Arquitectura del código

```
agente/
├── config/              # settings (pydantic-settings) + logging JSON
├── knowledge_base/      # definiciones YAML de las CVEs + loader
├── signal_collector/    # host (psutil), contenedor (docker), eventos (Admin REST API / H2)
├── deterministic_checks/# umbrales DoS + correlación OIDC
├── agent_core/          # cliente LLM (DeepSeek), tools, bucle ReAct, prompts
├── alert_builder/       # esquema Pydantic de la alerta + builder + sink (jsonl)
├── traceability/        # registro auditable del ciclo agéntico (runtime)
├── validation/          # evaluación empírica: escenarios + 3 dimensiones R&N + reportes
├── dashboard/           # UI de solo lectura de las alertas (servida por el agente)
├── tests/               # tests unitarios + fixtures
├── validation_cli.py    # CLI de campañas de validación (offline)
└── main.py              # entry point (modos oneshot / continuous)
```

## Instalación

> El agente vive en `/root/keycloak/agente/` (paralelo a Keycloak) y **no modifica
> nada fuera de su carpeta**. Usar un **venv local**, nunca instalar global.

```bash
cd /root/keycloak/agente
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # completar DEEPSEEK_API_KEY y credenciales de Keycloak
```

## Uso

```bash
# Modo continuo (foco de esta iteración): monitorea y alerta en loop.
python main.py --mode continuous

# Modo oneshot: un análisis reproducible de extremo a extremo.
python main.py --mode oneshot

# Sin LLM: solo checks deterministas (útil para debug / sin API key).
python main.py --mode oneshot --no-llm

# Evaluación empírica (precision/recall, escenarios, reportes): módulo aparte.
python validation_cli.py run-batch positive
```

La alerta se imprime como JSON estructurado y cada paso del ReAct se loguea en
JSON para análisis post-hoc.

### Ejemplo de alerta (resumida)

```json
{
  "alert_id": "alert-ab12cd34ef56",
  "severity": "critical",
  "chained": false,
  "detected_cves": [
    {
      "cve_id": "CVE-2023-0264",
      "confidence": 0.95,
      "affected_component": { "layer": "application", "specific_module": "CODE_TO_TOKEN" },
      "narrative": "mallory reutilizó el session_id de alice en el CODE_TO_TOKEN..."
    }
  ],
  "summary": "Account takeover OIDC por reuse de session_id."
}
```

## Despliegue en la VPS (contenedor)

El agente se empaqueta en su **propio contenedor** (Dockerfile y compose
dedicados, sin tocar el `docker-compose.yml` ni el `Dockerfile` de Keycloak) y
corre de forma constante en modo `continuous`.

```bash
cd /root/keycloak/agente
cp .env.example .env          # completar DEEPSEEK_API_KEY y credenciales
docker compose -f docker-compose.agente.yml up -d --build
docker logs -f keycloak-security-agent
```

### Por qué el contenedor necesita acceso al host

El agente mide el **host** y la **JVM de Keycloak**, por eso el compose define:

- `pid: host` → para ver el proceso `java` de Keycloak y los threads reales (sin
  esto la detección volumétrica de CVE-2026-33871 no funciona).
- `network_mode: host` → para alcanzar `https://localhost:8443` y que el CPU%
  medido sea el del host.
- montaje de `/var/run/docker.sock` → para `docker stats` (container_metrics) y el
  fallback H2 (`docker exec`).

### Dónde quedan las respuestas (alertas)

Las alertas se exponen en **dos lugares**:

1. **Directorio persistido en la VPS** (volumen `./data` → `/data` del contenedor):
   - `data/alerts/alerts.jsonl` — una alerta por línea (acumulativo).
   - `data/alerts/alert-<id>.json` — un archivo legible por alerta.
   - `data/baseline.json` — baseline persistido (sobrevive reinicios).
2. **Stdout / `docker logs`** — la alerta y cada paso del ReAct en JSON.

El directorio de alertas es configurable con `ALERTS_DIR` (en el contenedor se
fija a `/data/alerts`).

## Tests

```bash
pytest                       # corre todos los tests
pytest tests/test_deterministic_checks.py -v
```

Los tests de `deterministic_checks` y `signal_collector` usan fixtures de eventos
y métricas (no requieren Keycloak ni red). El test de `react_loop` usa un cliente
LLM falso (sin llamadas a la API).

## Decisiones de diseño

Tomadas/consultadas con el investigador durante esta primera iteración:

1. **Realm monitoreado**: `poc` (el que usan `index.html`/`index1.html` para el
   login). Configurable vía `KEYCLOAK_REALM`.
2. **Baseline de DoS**: **híbrido**. Si existe `config/baseline.json` se lee; si
   no, se calcula al iniciar muestreando N segundos de estado normal y se
   persiste. Asume que el arranque ocurre sin ataque en curso.
3. **Esquema de alerta**: implementado tal como lo propone el prompt de tesis
   (`Alert` / `DetectedCVE` / `AffectedComponent` / `Evidence`). Revisable.
4. **Modo de operación**: **continuous** como foco, con `oneshot` también
   disponible por CLI para evaluación reproducible.
5. **Evaluación empírica**: unificada en `validation/` (TP/FP/FN,
   precision/recall/F1 y componente en la dimensión *autonomía*; cobertura y
   rechazo en *knowledge*; control de terminación/tokens en *control*; rúbrica
   de calidad). Se ejecuta offline con `validation_cli.py`, desacoplada del
   runtime del agente. La trazabilidad del razonamiento vive en `traceability/`.

Otras decisiones técnicas:

- **Cliente LLM intercambiable**: todo depende de la interfaz `LLMClient`; la
  implementación inicial es `DeepSeekClient` (API compatible con el SDK de OpenAI).
- **Acceso a eventos**: preferentemente vía **Admin REST API** (JSON estructurado);
  `h2_fallback.py` queda como respaldo vía `docker exec` a la base H2.
- **TLS**: el entorno usa certificados *self-signed*, por lo que las llamadas a
  Keycloak usan `verify=False` de forma **deliberada y declarada** (ver comentarios
  en `signal_collector/keycloak_events.py`). No usar `verify=True` contra esta
  instancia.
- **Secretos**: solo en `.env` (nunca hardcodeados); se versiona `.env.example`.
- **Umbrales DoS relativos al baseline**: los valores absolutos validados
  empíricamente son orientativos; los checks comparan contra `baseline * factor`
  con un piso absoluto opcional, porque los valores varían entre runs.

## Restricciones de seguridad del proyecto

- No modifica nada fuera de `agente/` (ni `docker-compose.yml` ni el `Dockerfile`).
- No ejecuta los ataques: los ejecuta el investigador manualmente.
- No instala dependencias globalmente (venv local).

## Referencias

- Russell, S., & Norvig, P. (2021). *Artificial Intelligence: A Modern Approach*
  (4th ed.). Pearson.
- Yao, S., et al. (2023). *ReAct: Synergizing Reasoning and Acting in Language
  Models*. ICLR 2023.
