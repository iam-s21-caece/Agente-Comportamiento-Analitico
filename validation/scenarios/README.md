# Escenarios de validación

Cada escenario es una carpeta con dos artefactos:

- **`scenario.yaml`** — qué es y cómo se ejecuta (`setup`/`execute`/`teardown`
  opcionales + `post_window_seconds`).
- **`expected.yaml`** — el *ground truth*: qué debería concluir el agente
  (`should_alert`, `should_identify_cves`, componente, rango de confianza,
  `acceptable_uncertainty`). Es lo que `scenario_runner.compare()` usa para
  dar `pass` / `partial` / `fail`.

## Tipos

| Tipo | Qué prueba | Correcto = |
|---|---|---|
| `positive/` | Un ataque real ocurre | el agente **alerta** la(s) CVE(s) con la capa y confianza esperadas |
| `negative/` | Actividad **legítima** (carga alta, multiusuario) | el agente **NO alerta** (mide falsos positivos) |
| `ambiguous/` | Patrón que no encaja limpio en las CVEs conocidas | el agente **expresa incertidumbre**, sin afirmar una CVE conocida con alta confianza |

## Cómo se corren

```bash
python validation_cli.py run-batch positive     # o negative / ambiguous
python validation_cli.py run-scenario cve-2023-0264-basic
```

El runner: (1) marca `t0`, (2) ejecuta `execute` si existe, (3) recolecta las
alertas de `alerts.jsonl` en la ventana `[t0, t0+post_window]`, (4) compara
contra `expected.yaml`.

## Los scripts `execute.sh` NO están versionados (a propósito)

Los `execute.sh` **disparan los ataques** y los provee/ejecuta el investigador en
la VPS autorizada — no se commitean en el repo por ser ofensivos. Si un
`execute` referenciado no existe, el runner lo avisa y sigue: podés generar la
actividad **a mano** (correr el ataque o la carga legítima) dentro de la ventana
y el runner igual recolecta y evalúa las alertas. Para los `negative/` de tráfico
normal, la "actividad" es simplemente uso legítimo (logins reales, carga) durante
la ventana.
