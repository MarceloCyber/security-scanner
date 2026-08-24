# Gestão de políticas e SIEM nativo

## Migração

Antes de publicar a nova versão, execute no ambiente que aponta para o banco de produção:

```bash
python migrations/run.py
```

A migração `021_policies_and_siem` é aditiva e cria as tabelas de políticas, versões, aceites, fontes, regras, eventos, incidentes e fila de alertas do SIEM.

## Gestão de políticas

Em `Conformidade > Políticas de segurança`, um owner/admin pode:

1. Criar uma política como rascunho.
2. Enviar o rascunho para aprovação.
3. Publicar a versão aprovada.
4. Registrar o aceite individual de cada membro.

Cada alteração de conteúdo cria uma versão imutável. Publicações registram autor, data de aprovação, próxima revisão e entram na trilha de auditoria.

## SIEM

Em `SIEM`, crie uma fonte e guarde a chave exibida uma única vez. A fonte envia lotes para:

```http
POST /api/siem/ingest
X-Iron-AI-SIEM-Key: isiem_...
Content-Type: application/json
```

Exemplo de lote:

```json
{
  "events": [
    {
      "event_type": "authentication",
      "severity": "medium",
      "source_ip": "203.0.113.10",
      "user_name": "admin",
      "action": "login",
      "outcome": "failure",
      "message": "Falha de autenticação",
      "payload": {"failed_attempts": 6}
    }
  ]
}
```

As regras aceitam `all` ou `any` com os campos `event_type`, `severity`, `source_ip`, `user_name`, `action`, `outcome`, `message` e campos aninhados em `payload.*`. Os operadores são `equals`, `contains`, `in`, `gte` e `lte`.

Uma correspondência cria ou atualiza um incidente, registra evidência do evento e enfileira alertas conforme as assinaturas configuradas em `Monitoramento > Alertas`. O worker existente entrega os alertas e mantém tentativas/retries.

Eventos passam por limite de tamanho, autenticação por chave hash, rate limit, isolamento por organização e auditoria das alterações administrativas. Revogar a fonte interrompe a ingestão imediatamente.

O worker remove payloads brutos após 90 dias por padrão e mantém os incidentes para histórico. Ajuste com `SIEM_RETENTION_DAYS` entre 7 e 3650 dias.
