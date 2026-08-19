import json

from ai.provider import AIProviderError, OpenAICompatibleProvider, provider_candidates
from ai.service import classify_request


def test_request_classification_is_deterministic():
    assert classify_request("Olá, quem é você?") == ("simple", "low")
    assert classify_request("Analise este problema de programação e encontre o erro.")[0] == "complex"
    assert classify_request("Explique o que é uma API.") == ("simple", "low")


def test_provider_order_keeps_groq_primary_and_skips_empty_optional_providers(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "auto")
    monkeypatch.setenv("GROQ_API_KEY", "test-groq")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("KIMI_API_KEY", "test-kimi")
    providers = provider_candidates()
    assert [provider.name for provider in providers] == ["groq", "kimi"]


def test_provider_payload_contains_reasoning_and_allowlisted_tools(monkeypatch):
    provider = OpenAICompatibleProvider("https://example.test/chat", "test-key", "test-model", "groq", "medium")
    captured = {}

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 3}}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr("ai.provider.requests.post", fake_post)
    provider.chat(messages=[{"role": "user", "content": "Olá"}], reasoning_effort="low", tools=[{"type": "function"}])
    assert captured["json"]["reasoning_effort"] == "low"
    assert captured["json"]["tools"] == [{"type": "function"}]
    assert "test-key" not in json.dumps(captured["json"])


def test_provider_errors_are_marked_retryable_by_status():
    error = AIProviderError("temporário", status_code=429)
    assert error.retryable is True


def test_provider_stream_decodes_utf8_without_mojibake(monkeypatch):
    provider = OpenAICompatibleProvider("https://example.test/chat", "test-key", "test-model", "groq")

    class FakeResponse:
        status_code = 200

        def iter_lines(self, decode_unicode=False):
            assert decode_unicode is False
            yield 'data: {"choices":[{"delta":{"content":"Você está protegido"}}]}'.encode("utf-8")
            yield b"data: [DONE]"

        def close(self):
            pass

    monkeypatch.setattr(provider, "_request", lambda *args, **kwargs: FakeResponse())
    chunks = provider.stream(messages=[{"role": "user", "content": "status"}])
    assert "".join(chunks) == "Você está protegido"
