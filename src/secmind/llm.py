from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from secmind.config import Settings

T = TypeVar("T", bound=BaseModel)


class ModelGatewayError(RuntimeError):
    pass


class RetryableModelError(ModelGatewayError):
    pass


@dataclass
class ModelCallMeta:
    model_id: str
    prompt_version: str
    response_sha256: str
    duration_ms: int
    used_fallback: bool


class QwenGateway:
    """OpenAI-compatible Qwen gateway with retry, circuit breaking, and fallback."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.AsyncClient(timeout=settings.model_timeout_seconds)
        self._owns_client = client is None
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def structured(
        self,
        *,
        role: str,
        system_prompt: str,
        user_prompt: str,
        output_model: type[T],
        prompt_version: str,
    ) -> tuple[T, ModelCallMeta]:
        if self.settings.demo_mode:
            raise ModelGatewayError("Model calls are disabled in deterministic demo mode")
        if not self.settings.qwen_api_key:
            raise ModelGatewayError("SECMIND_QWEN_API_KEY is not configured")
        primary = self.settings.planner_model if role == "planner" else self.settings.worker_model
        candidates = list(dict.fromkeys([primary, self.settings.fallback_model]))
        last_error: Exception | None = None
        for index, model_id in enumerate(candidates):
            if self._open_until.get(model_id, 0) > time.monotonic():
                continue
            try:
                raw, duration_ms = await self._request_with_retry(
                    model_id, system_prompt, user_prompt, output_model.model_json_schema()
                )
                parsed = self._parse_model(raw, output_model)
                self._failures[model_id] = 0
                return parsed, ModelCallMeta(
                    model_id=model_id,
                    prompt_version=prompt_version,
                    response_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                    duration_ms=duration_ms,
                    used_fallback=index > 0,
                )
            except (ModelGatewayError, ValidationError, json.JSONDecodeError) as exc:
                last_error = exc
                failures = self._failures.get(model_id, 0) + 1
                self._failures[model_id] = failures
                if failures >= 3:
                    self._open_until[model_id] = time.monotonic() + 60
        raise ModelGatewayError(f"All configured models failed: {last_error}")

    async def embeddings(self, texts: list[str]) -> list[list[float]]:
        """Create embeddings for the Qdrant boundary without exposing provider details upstream."""
        if not texts or any(not text.strip() for text in texts):
            raise ValueError("Embedding input must contain non-empty text")
        if self.settings.demo_mode:
            raise ModelGatewayError("Embedding calls are disabled in deterministic demo mode")
        if not self.settings.qwen_api_key:
            raise ModelGatewayError("SECMIND_QWEN_API_KEY is not configured")
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=0.5, max=8),
            retry=retry_if_exception_type((RetryableModelError, httpx.TimeoutException)),
            reraise=True,
        ):
            with attempt:
                response = await self._client.post(
                    f"{self.settings.qwen_base_url.rstrip('/')}/embeddings",
                    headers={"Authorization": f"Bearer {self.settings.qwen_api_key}"},
                    json={"model": self.settings.embedding_model, "input": texts},
                )
                if response.status_code in {408, 409, 429} or response.status_code >= 500:
                    raise RetryableModelError(f"Retryable embedding response: {response.status_code}")
                if response.status_code >= 400:
                    raise ModelGatewayError(f"Embedding response: {response.status_code}")
                try:
                    rows = sorted(response.json()["data"], key=lambda item: item["index"])
                    vectors = [[float(value) for value in row["embedding"]] for row in rows]
                except (KeyError, TypeError, ValueError) as exc:
                    raise ModelGatewayError("Malformed embedding response") from exc
                if len(vectors) != len(texts):
                    raise ModelGatewayError("Embedding response count does not match input count")
                return vectors
        raise AssertionError("Retry loop exited unexpectedly")

    async def _request_with_retry(
        self, model_id: str, system_prompt: str, user_prompt: str, schema: dict[str, Any]
    ) -> tuple[str, int]:
        started = time.monotonic()
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=0.5, max=8),
            retry=retry_if_exception_type((RetryableModelError, httpx.TimeoutException)),
            reraise=True,
        ):
            with attempt:
                response = await self._client.post(
                    f"{self.settings.qwen_base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {self.settings.qwen_api_key}"},
                    json={
                        "model": model_id,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0,
                        "response_format": {
                            "type": "json_schema",
                            "json_schema": {"name": "secmind_output", "schema": schema},
                        },
                    },
                )
                if response.status_code in {408, 409, 429} or response.status_code >= 500:
                    raise RetryableModelError(f"Retryable model response: {response.status_code}")
                if response.status_code >= 400:
                    raise ModelGatewayError(f"Model response: {response.status_code}")
                body = response.json()
                try:
                    content = body["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError) as exc:
                    raise ModelGatewayError("Malformed model response") from exc
                return str(content), int((time.monotonic() - started) * 1000)
        raise AssertionError("Retry loop exited unexpectedly")

    @staticmethod
    def _parse_model(raw: str, output_model: type[T]) -> T:
        text = raw.strip()
        if text.startswith("```"):
            text = text.removeprefix("```json").removeprefix("```")
            text = text.rsplit("```", 1)[0]
        return output_model.model_validate_json(text)


async def close_gateway_safely(gateway: QwenGateway) -> None:
    try:
        await gateway.close()
    except (httpx.HTTPError, asyncio.CancelledError):
        pass
