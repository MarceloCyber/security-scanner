"""Provider adapters and fallback router for Iron AI."""
import json
import logging
import os
import time
import requests

logger = logging.getLogger(__name__)

class AIProviderError(RuntimeError):
    def __init__(self, message, status_code=None, retryable=True):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable

class AIProvider:
    name = 'unknown'
    model = 'unknown'
    def chat(self, *, messages, reasoning_effort='medium', tools=None, structured=False):
        raise NotImplementedError
    def stream(self, *, messages, reasoning_effort='medium', tools=None):
        raise NotImplementedError
    def structured_output(self, *, intent, context, message=''):
        result = self.chat(messages=[
            {'role': 'system', 'content': structured_system_prompt()},
            {'role': 'user', 'content': structured_user_prompt(intent, message, context)}
        ], reasoning_effort='medium', structured=True)
        content = (result.get('content') or '').strip()
        if content.startswith(chr(96) * 3):
            content = content.strip(chr(96))
            if content.startswith('json'):
                content = content[4:].lstrip()
        try:
            data = json.loads(content)
        except (ValueError, TypeError) as exc:
            raise AIProviderError('Resposta estruturada inválida', retryable=False) from exc
        if not isinstance(data, dict) or not isinstance(data.get('summary'), str):
            raise AIProviderError('Resposta estruturada inválida', retryable=False)
        data.setdefault('recommendations', [])
        data.setdefault('actions', [])
        return data

class LocalProvider(AIProvider):
    name = 'local-deterministic'
    model = 'local'
    def chat(self, *, messages, reasoning_effort='medium', tools=None, structured=False):
        question = next((m.get('content', '') for m in reversed(messages) if m.get('role') == 'user'), '')
        return {'content': 'Estou no modo local. Pergunta recebida: ' + question, 'tool_calls': [], 'usage': None}
    def stream(self, *, messages, reasoning_effort='medium', tools=None):
        text = self.chat(messages=messages)['content']
        for i in range(0, len(text), 80):
            yield text[i:i + 80]
    def structured_output(self, *, intent, context, message=''):
        findings = context.get('findings', [])
        if intent == 'remediation':
            actions = [{'priority': i + 1, 'finding_id': f['id'], 'action': f.get('remediation') or 'Investigar e corrigir o finding.'} for i, f in enumerate(findings[:7])]
            return {'summary': 'Plano de remediação baseado nos findings persistidos.', 'actions': actions, 'recommendations': []}
        if intent == 'finding':
            summary = 'O maior risco registrado possui score {}.'.format(findings[0].get('risk_score', 0)) if findings else 'Não há dados suficientes na Iron AI para confirmar isso.'
        else:
            summary = 'O Security Score atual é {}/100. Existem {} riscos abertos.'.format(context.get('score', 0), len(findings))
        return {'summary': summary, 'facts': context, 'recommendations': ['Valide a correção com novo scan.'] if findings else ['Cadastre ativos e execute um scan.'], 'actions': []}

class OpenAICompatibleProvider(AIProvider):
    def __init__(self, base_url, api_key, model, name, reasoning_effort=None, temperature=0.15, max_completion_tokens=2048):
        self.base_url, self.api_key, self.model, self.name = base_url, api_key, model, name
        self.reasoning_effort, self.temperature, self.max_completion_tokens = reasoning_effort, temperature, max_completion_tokens
    def _body(self, messages, reasoning_effort, tools=None, stream=False, structured=False):
        body = {'model': self.model, 'messages': messages, 'temperature': self.temperature, 'max_completion_tokens': self.max_completion_tokens}
        if stream:
            body['stream'] = True
        if self.reasoning_effort and reasoning_effort != 'none':
            body['reasoning_effort'] = reasoning_effort
        if tools:
            body.update({'tools': tools, 'tool_choice': 'auto', 'parallel_tool_calls': False})
        if structured:
            body['response_format'] = {'type': 'json_object'}
        return body
    def _request(self, messages, reasoning_effort, tools=None, stream=False, structured=False):
        try:
            response = requests.post(self.base_url, headers={'Authorization': 'Bearer ' + self.api_key, 'Content-Type': 'application/json'}, json=self._body(messages, reasoning_effort, tools, stream, structured), timeout=(8, 60), stream=stream)
            response.encoding = 'utf-8'
            return response
        except requests.RequestException as exc:
            raise AIProviderError('Falha de conexão com o provider') from exc
    def chat(self, *, messages, reasoning_effort='medium', tools=None, structured=False):
        started = time.monotonic()
        response = self._request(messages, reasoning_effort, tools, structured=structured)
        if response.status_code >= 400:
            logger.warning('ai_provider_error provider=%s model=%s status=%s duration=%s', self.name, self.model, response.status_code, round(time.monotonic() - started, 3))
            raise AIProviderError('Provider recusou a solicitação', response.status_code, response.status_code in (408, 409, 425, 429) or response.status_code >= 500)
        try:
            data = response.json()
            message = (data.get('choices') or [{}])[0].get('message') or {}
            usage = data.get('usage')
            logger.info('ai_provider_ok provider=%s model=%s duration=%s total_tokens=%s tool_calls=%s', self.name, self.model, round(time.monotonic() - started, 3), (usage or {}).get('total_tokens') if isinstance(usage, dict) else None, len(message.get('tool_calls') or []))
            return {'content': message.get('content') or '', 'tool_calls': message.get('tool_calls') or [], 'usage': usage}
        except (ValueError, TypeError, KeyError) as exc:
            raise AIProviderError('Resposta inválida do provider', retryable=False) from exc
    def stream(self, *, messages, reasoning_effort='medium', tools=None):
        response = self._request(messages, reasoning_effort, tools, True)
        if response.status_code >= 400:
            raise AIProviderError('Provider recusou a solicitação', response.status_code, response.status_code in (408, 409, 425, 429) or response.status_code >= 500)
        try:
            # APIs OpenAI-compatible stream JSON as UTF-8. Relying on
            # requests' inferred response encoding can turn "você" into
            # "vocÃª" when the provider omits charset from Content-Type.
            for raw in response.iter_lines(decode_unicode=False):
                line = (raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else (raw or '')).strip()
                if not line or not line.startswith('data:'):
                    continue
                payload = line[5:].strip()
                if payload == '[DONE]':
                    break
                try:
                    delta = ((json.loads(payload).get('choices') or [{}])[0].get('delta') or {}).get('content')
                    if delta:
                        yield delta
                except (ValueError, TypeError, KeyError):
                    logger.warning('ai_provider_stream_invalid_chunk provider=%s model=%s', self.name, self.model)
        finally:
            response.close()

def provider_candidates(preferred=None):
    choice = (preferred or os.getenv('AI_PROVIDER') or 'auto').strip().lower()
    choice = {'google': 'gemini', 'moonshot': 'kimi'}.get(choice, choice)
    groq = os.getenv('GROQ_API_KEY') or os.getenv('GROQ_KEY')
    gemini = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
    kimi = os.getenv('KIMI_API_KEY') or os.getenv('MOONSHOT_API_KEY')
    specs = {
        'groq': (groq, 'https://api.groq.com/openai/v1/chat/completions', os.getenv('GROQ_MODEL', 'openai/gpt-oss-20b'), 'medium', .15, 2048),
        'gemini': (gemini, os.getenv('GEMINI_CHAT_URL', 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'), os.getenv('GEMINI_MODEL', 'gemini-3.1-flash-lite'), os.getenv('GEMINI_REASONING_EFFORT', 'low'), .15, 2048),
        'kimi': (kimi, os.getenv('KIMI_CHAT_URL', 'https://api.moonshot.ai/v1/chat/completions'), os.getenv('KIMI_MODEL', 'kimi-k2.6'), os.getenv('KIMI_REASONING_EFFORT', 'high'), 1.0, 16384)
    }
    order = ['groq', 'gemini', 'kimi'] if choice == 'auto' else [choice] + [name for name in ('groq', 'gemini', 'kimi') if name != choice]
    result = []
    for name in order:
        if name not in specs or not specs[name][0]:
            continue
        key, url, model, effort, temperature, max_tokens = specs[name]
        result.append(OpenAICompatibleProvider(url, key, model, name, effort, temperature, max_tokens))
    return result

def configured_provider():
    candidates = provider_candidates()
    return candidates[0] if candidates else LocalProvider()

def structured_system_prompt():
    return 'Você é o Iron AI, copiloto defensivo. Responda em português e use somente fatos autorizados. Retorne JSON válido com summary, recommendations e actions.'

def structured_user_prompt(intent, message, context):
    return 'Intenção: {}\\nPergunta: {}\\nContexto autorizado:\\n{}'.format(intent, message, json.dumps(context, ensure_ascii=False, default=str)[:24000])
