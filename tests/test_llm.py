from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from secmind.llm import ModelGatewayError, QwenGateway


class Output(BaseModel):
    answer: str


@pytest.mark.asyncio
async def test_gateway_retries_retryable_response(settings) -> None:
    settings.demo_mode = False
    settings.qwen_api_key = "test-key"
    settings.fallback_model = "qwen-fallback"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(429, json={"error": "limited"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({"answer": "ok"})}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
    )
    await client.aclose()
    assert output.answer == "ok"
    assert meta.model_id == settings.planner_model
    assert calls == 3


@pytest.mark.asyncio
async def test_gateway_requires_enabled_credentials(settings) -> None:
    gateway = QwenGateway(settings)
    with pytest.raises(ModelGatewayError, match="demo mode"):
        await gateway.structured(
            role="worker",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    settings.demo_mode = False
    with pytest.raises(ModelGatewayError, match="not configured"):
        await gateway.structured(
            role="worker",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_falls_back_after_invalid_primary_output(settings) -> None:
    settings.demo_mode = False
    settings.qwen_api_key = "test-key"
    settings.fallback_model = "qwen-fallback"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = "not-json" if body["model"] == settings.planner_model else '{"answer":"fallback"}'
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
    )
    await client.aclose()
    assert output.answer == "fallback"
    assert meta.used_fallback is True


@pytest.mark.asyncio
async def test_gateway_embeddings(settings) -> None:
    settings.demo_mode = False
    settings.qwen_api_key = "test-key"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0, 1]},
                    {"index": 0, "embedding": [1, 0]},
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    vectors = await gateway.embeddings(["first", "second"])
    await client.aclose()
    assert vectors == [[1.0, 0.0], [0.0, 1.0]]
    with pytest.raises(ValueError, match="non-empty"):
        await gateway.embeddings([])
