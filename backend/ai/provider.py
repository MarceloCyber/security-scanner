"""Provider abstraction for grounded Iron AI responses."""

import json
import os
from typing import Any

import requests


class AIProvider:
    name = "unknown"

    def structured_output(self, *, intent: str, context: dict[str, Any], message: str = "") -> dict[str, Any]:
        raise NotImplementedError


class LocalProvider(AIProvider):
    name = "local-deterministic"

    def structured_output(self, *, intent: str, context: dict[str, Any], message: str = "") -> dict[str, Any]:
        score = context.get("score", 0)
        findings = context.get("findings", [])
        if intent == "summary":
            return {"summary": f"O Security Score atual é {score}/100. Existem {len(findings)} riscos abertos priorizados por score determinístico.", "facts": context, "recommendations": ["Comece pelo risco com maior score e valide a correção no próximo scan."] if findings else ["Cadastre ativos e execute um scan para criar a visão inicial de risco."]}
        if intent == "remediation":
            return {"summary": "Plano de remediação baseado nos findings persistidos.", "actions": [{"priority": index + 1, "finding_id": item["id"], "action": item.get("remediation") or "Investigar evidência e aplicar correção recomendada pelo scanner."} for index, item in enumerate(findings[:7])]}
        return {"summary": "Não há dados suficientes na Iron AI para confirmar isso." if not findings else f"O maior risco registrado possui score {findings[0].get('risk_score', 0)}.", "facts": context, "recommendations": ["Use a evidência do finding e confirme a correção com novo scan."]}


class OpenAICompatibleProvider(AIProvider):
    """OpenAI-compatible adapter with a strict JSON and grounding contract."""

    def __init__(self, base_url: str, api_key: str, model: str, name: str, reasoning_effort: str | None = None, temperature: float = 0.15, max_completion_tokens: int = 2048):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.name = name
        self.reasoning_effort = reasoning_effort
        self.temperature = temperature
        self.max_completion_tokens = max_completion_tokens

    def structured_output(self, *, intent: str, context: dict[str, Any], message: str = "") -> dict[str, Any]:
        compact_context = json.dumps(context, ensure_ascii=False, default=str)[:24000]
        system = (
            "Você é a Iron AI, copiloto defensivo da Iron AI Security Platform para PMEs. "
            "Responda em português brasileiro, de forma direta e acionável. Use SOMENTE os fatos no contexto JSON. "
            "Nunca invente scans, CVEs, ativos ou evidências. Se faltarem dados, diga exatamente o que falta. "
            "Não revele segredos e não forneça instruções ofensivas. Retorne JSON válido com as chaves "
            "summary (string), recommendations (array de strings) e actions (array de objetos com priority, finding_id e action)."
        )
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": f"Intenção: {intent}\nPergunta: {message}\nContexto autorizado:\n{compact_context}"},
            ],
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        response = requests.post(
            self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=35,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.strip("`")
            if content.startswith("json"):
                content = content[4:].lstrip()
        result = json.loads(content)
        if not isinstance(result, dict) or not isinstance(result.get("summary"), str):
            raise ValueError("AI provider returned an invalid structured response")
        result.setdefault("recommendations", [])
        result.setdefault("actions", [])
        return result


def configured_provider() -> AIProvider:
    preferred = (os.getenv("AI_PROVIDER") or "auto").strip().lower()
    groq_key = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    kimi_key = os.getenv("KIMI_API_KEY") or os.getenv("MOONSHOT_API_KEY")
    openrouter_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY")
    if preferred in {"gemini", "google"} and gemini_key:
        return OpenAICompatibleProvider(
            os.getenv("GEMINI_CHAT_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
            gemini_key,
            os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite"),
            "gemini",
            reasoning_effort=(os.getenv("GEMINI_REASONING_EFFORT") or "low").lower(),
            max_completion_tokens=2048,
        )
    if preferred in {"kimi", "moonshot"} and kimi_key:
        effort = (os.getenv("KIMI_REASONING_EFFORT") or "high").lower()
        if effort not in {"low", "high", "max"}:
            effort = "high"
        return OpenAICompatibleProvider(
            os.getenv("KIMI_CHAT_URL", "https://api.moonshot.ai/v1/chat/completions"),
            kimi_key,
            os.getenv("KIMI_MODEL", "kimi-k2.6"),
            "kimi",
            reasoning_effort=effort,
            temperature=1.0,
            max_completion_tokens=16384,
        )
    if preferred == "groq" and groq_key:
        return OpenAICompatibleProvider(
            "https://api.groq.com/openai/v1/chat/completions",
            groq_key,
            os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
            "groq",
        )
    if preferred == "openrouter" and openrouter_key:
        return OpenAICompatibleProvider(
            "https://openrouter.ai/api/v1/chat/completions",
            openrouter_key,
            os.getenv("AI_MODEL", "meta-llama/llama-3.1-8b-instruct"),
            "openrouter",
        )
    if preferred == "auto":
        if groq_key:
            return OpenAICompatibleProvider(
                "https://api.groq.com/openai/v1/chat/completions",
                groq_key,
                os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
                "groq",
            )
        if gemini_key:
            return OpenAICompatibleProvider(
                os.getenv("GEMINI_CHAT_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
                gemini_key,
                os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite"),
                "gemini",
                reasoning_effort=(os.getenv("GEMINI_REASONING_EFFORT") or "low").lower(),
            )
        if kimi_key:
            return OpenAICompatibleProvider(
                os.getenv("KIMI_CHAT_URL", "https://api.moonshot.ai/v1/chat/completions"),
                kimi_key,
                os.getenv("KIMI_MODEL", "kimi-k2.6"),
                "kimi",
                reasoning_effort=(os.getenv("KIMI_REASONING_EFFORT") or "high").lower(),
                temperature=1.0,
                max_completion_tokens=16384,
            )
        if openrouter_key:
            return OpenAICompatibleProvider(
                "https://openrouter.ai/api/v1/chat/completions",
                openrouter_key,
                os.getenv("AI_MODEL", "meta-llama/llama-3.1-8b-instruct"),
                "openrouter",
            )
    return LocalProvider()
