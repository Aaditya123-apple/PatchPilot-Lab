"""Async client for NVIDIA models served on Nebius AI Cloud through its OpenAI-compatible API.

Adds what the agents need on top of the OpenAI SDK: retries with exponential backoff, a
fallback chain across models, a shared concurrency limit, streaming, reasoning-trace removal
and tolerant JSON parsing of model output.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Sequence

import openai
from openai import AsyncOpenAI

from .config import Settings, get_settings

Message = dict[str, str]

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?P<lang>[\w+#.-]*)[ \t]*\r?\n(?P<body>.*?)```", re.DOTALL)

_RETRYABLE: tuple[type[Exception], ...] = (
    openai.RateLimitError,
    openai.APITimeoutError,
    openai.APIConnectionError,
    openai.InternalServerError,
)
_TRY_NEXT_MODEL: tuple[type[Exception], ...] = (openai.NotFoundError, openai.UnprocessableEntityError)


class NebiusError(RuntimeError):
    """Raised when no configured model could serve a request."""


@dataclass
class ChatResult:
    content: str
    model: str
    latency_s: float
    prompt_tokens: int = 0
    completion_tokens: int = 0


def strip_reasoning(text: str | None) -> str:
    """Remove <think>…</think> traces that Nemotron reasoning models can emit."""
    cleaned = _THINK_RE.sub("", text or "")
    lower = cleaned.lower()
    if "<think>" in lower:  # an unterminated trace means the answer was cut off inside it
        cleaned = cleaned[: lower.index("<think>")]
    return cleaned.strip()


def extract_code_blocks(text: str) -> list[tuple[str, str]]:
    return [(m.group("lang").lower(), m.group("body")) for m in _FENCE_RE.finditer(text or "")]


def _first_json_span(text: str) -> str | None:
    for i, ch in enumerate(text):
        if ch not in "{[":
            continue
        depth, in_str, escaped = 0, False, False
        for j in range(i, len(text)):
            c = text[j]
            if in_str:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    candidate = text[i : j + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except ValueError:
                        break
    return None


def parse_json_payload(text: str) -> Any:
    """Parse JSON from a model reply that may include reasoning, prose or code fences."""
    cleaned = strip_reasoning(text)
    candidates = [cleaned] + [body for lang, body in extract_code_blocks(cleaned) if lang in ("json", "")]
    for candidate in candidates:
        try:
            return json.loads(candidate.strip())
        except ValueError:
            continue
    span = _first_json_span(cleaned)
    if span is not None:
        return json.loads(span)
    raise ValueError("No JSON value found in model output")


class NebiusClient:
    """Chat client for Nebius AI Cloud with retries and NVIDIA model fallbacks."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: Any | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.settings = settings or get_settings()
        if client is None and self.settings.api_key:
            client = AsyncOpenAI(
                api_key=self.settings.api_key,
                base_url=self.settings.base_url,
                timeout=self.settings.timeout_s,
                max_retries=0,
            )
        self._client = client
        self._sleep = sleep
        self._sem: asyncio.Semaphore | None = None
        self.models_used: list[str] = []
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def models(self) -> list[str]:
        return list(self.settings.model_chain)

    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.settings.max_concurrency)
        return self._sem

    def _backoff(self, attempt: int) -> float:
        return min(8.0, 0.5 * 2**attempt) + random.uniform(0, 0.25)

    def _note_model(self, name: str) -> None:
        if name not in self.models_used:
            self.models_used.append(name)

    def _require_client(self) -> Any:
        if self._client is None:
            raise NebiusError("NEBIUS_API_KEY is not configured, so Nebius inference is unavailable.")
        return self._client

    async def chat(
        self,
        messages: Sequence[Message],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> ChatResult:
        client = self._require_client()
        errors: list[str] = []
        for name in [model] if model else self.models:
            use_json = json_mode
            attempt = 0
            while True:
                kwargs: dict[str, Any] = {
                    "model": name,
                    "messages": list(messages),
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                if use_json:
                    kwargs["response_format"] = {"type": "json_object"}
                start = time.perf_counter()
                try:
                    async with self._semaphore():
                        response = await client.chat.completions.create(**kwargs)
                except openai.AuthenticationError as exc:
                    raise NebiusError(f"Nebius rejected the API key: {exc}") from exc
                except _TRY_NEXT_MODEL as exc:
                    errors.append(f"{name}: {type(exc).__name__}")
                    break
                except openai.BadRequestError as exc:
                    if use_json:  # some models reject response_format; retry without it
                        use_json = False
                        continue
                    errors.append(f"{name}: {type(exc).__name__}")
                    break
                except _RETRYABLE as exc:
                    if attempt < self.settings.max_retries:
                        await self._sleep(self._backoff(attempt))
                        attempt += 1
                        continue
                    errors.append(f"{name}: {type(exc).__name__} after {attempt + 1} attempts")
                    break
                except openai.APIStatusError as exc:
                    errors.append(f"{name}: HTTP {exc.status_code}")
                    break
                return self._result(response, name, start)
        raise NebiusError("All Nebius models failed: " + "; ".join(errors))

    def _result(self, response: Any, name: str, start: float) -> ChatResult:
        choices = getattr(response, "choices", None) or []
        content = choices[0].message.content if choices else ""
        usage = getattr(response, "usage", None)
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        used = getattr(response, "model", None) or name
        self.calls += 1
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self._note_model(used)
        return ChatResult(
            content=strip_reasoning(content),
            model=used,
            latency_s=round(time.perf_counter() - start, 3),
            prompt_tokens=prompt,
            completion_tokens=completion,
        )

    async def chat_json(self, messages: Sequence[Message], **kwargs: Any) -> Any:
        result = await self.chat(messages, json_mode=True, **kwargs)
        try:
            return parse_json_payload(result.content)
        except ValueError:
            repair = [
                *messages,
                {"role": "assistant", "content": result.content},
                {"role": "user", "content": "That reply was not valid JSON. Reply with only the JSON value."},
            ]
            retry = await self.chat(repair, json_mode=True, **kwargs)
            return parse_json_payload(retry.content)

    async def stream(
        self,
        messages: Sequence[Message],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> AsyncIterator[str]:
        """Yield content deltas, falling back to the next model if one cannot start a stream."""
        client = self._require_client()
        errors: list[str] = []
        for name in [model] if model else self.models:
            try:
                stream = await client.chat.completions.create(
                    model=name,
                    messages=list(messages),
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                )
            except openai.AuthenticationError as exc:
                raise NebiusError(f"Nebius rejected the API key: {exc}") from exc
            except (*_TRY_NEXT_MODEL, *_RETRYABLE, openai.BadRequestError, openai.APIStatusError) as exc:
                errors.append(f"{name}: {type(exc).__name__}")
                continue
            self._note_model(name)
            self.calls += 1
            async for chunk in stream:
                choices = getattr(chunk, "choices", None) or []
                if not choices:
                    continue
                delta = getattr(choices[0].delta, "content", None)
                if delta:
                    yield delta
            return
        raise NebiusError("All Nebius models failed to stream: " + "; ".join(errors))
