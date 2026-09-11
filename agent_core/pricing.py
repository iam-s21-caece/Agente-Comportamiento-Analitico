"""Estimación de costo en USD del consumo de tokens de DeepSeek.

Función pura: dado el desglose de tokens de un análisis (tal como lo persiste la
traza en su evento ``analysis_end``) y los precios de la configuración, devuelve
el costo estimado. Vive junto al cliente LLM porque es conocimiento del proveedor;
la capa de validación la usa para poblar ``ScenarioResult.estimated_cost_usd``.
"""

from __future__ import annotations

from typing import Mapping

from config.settings import Settings, get_settings


def estimate_cost_usd(tokens: Mapping[str, int], settings: Settings | None = None) -> float:
    """Estima el costo en USD de un consumo de tokens.

    Args:
        tokens: desglose con ``cache_miss_tokens``, ``cache_hit_tokens`` y
            ``completion_tokens`` (los campos que persiste la traza).
        settings: configuración con los precios; si se omite se usa la global.

    Returns:
        Costo estimado en USD (input cache-miss + input cache-hit + output).
    """
    s = settings or get_settings()
    miss = int(tokens.get("cache_miss_tokens", 0) or 0)
    hit = int(tokens.get("cache_hit_tokens", 0) or 0)
    completion = int(tokens.get("completion_tokens", 0) or 0)
    cost = (
        miss / 1_000_000 * s.deepseek_price_input_miss_per_1m
        + hit / 1_000_000 * s.deepseek_price_input_hit_per_1m
        + completion / 1_000_000 * s.deepseek_price_output_per_1m
    )
    return round(cost, 6)
