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
class LLMResponse:
    """Respuesta del LLM, con texto y/o pedidos de tool calling."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None

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
        )
