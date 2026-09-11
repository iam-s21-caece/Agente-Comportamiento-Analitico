"""Abstracción del cliente LLM e implementación DeepSeek.

El agente debe ser intercambiable de proveedor a futuro, por lo que el resto del
código depende únicamente de la interfaz ``LLMClient``. La implementación inicial
es ``DeepSeekClient``, que usa la API oficial de DeepSeek (compatible con el SDK
de OpenAI) con soporte de tool calling.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any

from config.logging_config import get_logger
from config.settings import Settings, get_settings

logger = get_logger(__name__)


@dataclass
class ToolCall:
    """Una invocación de tool solicitada por el LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Usage:
    """Consumo de tokens de una llamada al LLM.

    Se captura de ``completion.usage`` para habilitar las métricas de costo y de
    adherencia al presupuesto (``control.budget_adherence``). Los campos de caché
    son específicos de DeepSeek (0 si el proveedor no los expone); permiten
    computar el costo real, ya que un token de prompt servido de caché es mucho
    más barato que uno nuevo.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        """Suma dos consumos (para acumular a lo largo de un análisis ReAct)."""
        return Usage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
            cache_hit_tokens=self.cache_hit_tokens + other.cache_hit_tokens,
            cache_miss_tokens=self.cache_miss_tokens + other.cache_miss_tokens,
        )


@dataclass
class LLMResponse:
    """Respuesta del LLM, con texto y/o pedidos de tool calling."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None
    usage: Usage = field(default_factory=Usage)

    @property
    def wants_tools(self) -> bool:
        """``True`` si el LLM pidió ejecutar al menos una tool."""
        return bool(self.tool_calls)


class LLMClient(abc.ABC):
    """Interfaz común a cualquier proveedor LLM."""

    @abc.abstractmethod
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Envía una conversación al LLM y devuelve su respuesta.

        Args:
            messages: historial de mensajes (formato OpenAI-like).
            tools: especificaciones de tools disponibles (JSON schema).

        Returns:
            LLMResponse con texto y/o tool calls.
        """
        raise NotImplementedError


class DeepSeekClient(LLMClient):
    """Cliente LLM contra la API de DeepSeek (compatible OpenAI)."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Inicializa el cliente DeepSeek.

        Args:
            settings: configuración; si se omite se usa la global.

        Raises:
            RuntimeError: si falta la API key o el SDK de OpenAI.
        """
        self.settings = settings or get_settings()
        if not self.settings.deepseek_api_key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY no configurada. Definila en el entorno/.env."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "El paquete 'openai' es requerido para DeepSeekClient."
            ) from exc

        self._client = OpenAI(
            api_key=self.settings.deepseek_api_key,
            base_url=self.settings.deepseek_base_url,
            timeout=self.settings.llm_timeout_seconds,
        )

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Implementación de ``LLMClient.chat`` para DeepSeek.

        Args:
            messages: historial de mensajes.
            tools: tools disponibles (JSON schema OpenAI-like).

        Returns:
            LLMResponse normalizada.
        """
        kwargs: dict[str, Any] = {
            "model": self.settings.deepseek_model,
            "messages": messages,
            "temperature": self.settings.llm_temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        completion = self._client.chat.completions.create(**kwargs)
        choice = completion.choices[0]
        message = choice.message

        tool_calls: list[ToolCall] = []
        for call in message.tool_calls or []:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                logger.warning(
                    "Argumentos de tool no parseables",
                    extra={"tool": call.function.name},
                )
                args = {}
            tool_calls.append(
                ToolCall(id=call.id, name=call.function.name, arguments=args)
            )

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            raw=message,
            usage=_extract_usage(getattr(completion, "usage", None)),
        )


def _extract_usage(usage: Any) -> Usage:
    """Normaliza el objeto ``usage`` de la API a nuestro dataclass ``Usage``.

    Args:
        usage: campo ``completion.usage`` del SDK (o ``None``).

    Returns:
        ``Usage`` con los tokens; ceros si el proveedor no lo expone.
    """
    if usage is None:
        return Usage()
    prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
    hit = int(getattr(usage, "prompt_cache_hit_tokens", 0) or 0)
    miss = int(getattr(usage, "prompt_cache_miss_tokens", 0) or 0)
    # Si el proveedor no discrimina caché, se asume que todo el prompt es "miss".
    if hit == 0 and miss == 0:
        miss = prompt
    return Usage(
        prompt_tokens=prompt,
        completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
        cache_hit_tokens=hit,
        cache_miss_tokens=miss,
    )
