# Iron AI — passo a passo para produção

Este é o roteiro mínimo para publicar a Iron AI com pagamentos, copiloto, jobs e isolamento de dados funcionando. Execute primeiro com chaves de teste e só depois troque o Stripe para `live`.

## 1. Preparar os serviços

Crie estes recursos no provedor escolhido:

1. Aplicação web Python com domínio HTTPS, por exemplo `app.suaempresa.com.br`.
2. PostgreSQL gerenciado com backup automático e restauração pontual.
3. Redis gerenciado com TLS.
4. Um processo web, um worker e um scheduler usando o mesmo código e as mesmas variáveis.
5. Monitoramento externo para `GET /api/health` e readiness para `GET /api/ready`.

Não use SQLite em produção. Ele permanece apenas para `./start.sh --local`.

## 2. Validar o código antes do deploy

Na raiz do projeto:

```bash
./install.sh
venv/bin/python3 -m pytest -q
venv/bin/python3 -m compileall -q backend migrations scripts
node --check frontend/js/platform.js
node --check frontend/js/modern-app.js
```

O deploy deve ser interrompido se algum comando falhar.

## 3. Gerar os segredos

Gere valores diferentes dos usados localmente:

```bash
openssl rand -base64 64
venv/bin/python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

O primeiro valor será `SECRET_KEY`; o segundo, `CREDENTIAL_ENCRYPTION_KEY`. Salve-os somente no cofre de secrets do provedor. Não coloque esses valores no Git.

## 4. Configurar as variáveis

Defina no processo web, worker e scheduler:

```dotenv
APP_ENV=production
DATABASE_URL=postgresql://USUARIO:SENHA@HOST:5432/BANCO?sslmode=require
REDIS_URL=rediss://USUARIO:SENHA@HOST:6379/0
SECRET_KEY=SEGREDO_ALEATORIO_COM_PELO_MENOS_48_CARACTERES
CREDENTIAL_ENCRYPTION_KEY=CHAVE_FERNET_GERADA

FRONTEND_URL=https://app.suaempresa.com.br
ALLOWED_ORIGINS=https://app.suaempresa.com.br
ALLOWED_HOSTS=app.suaempresa.com.br

GROQ_API_KEY=CHAVE_REAL
GROQ_MODEL=llama-3.1-8b-instant

STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

SMTP_HOST=HOST_SMTP
SMTP_PORT=587
SMTP_USER=USUARIO_SMTP
SMTP_PASSWORD=SENHA_SMTP
FROM_EMAIL=security@suaempresa.com.br
FROM_NAME=Iron AI
```

Para usar Kimi K3 no lugar da Groq, configure `AI_PROVIDER=kimi`, `KIMI_API_KEY`, `KIMI_MODEL=kimi-k3` e `KIMI_REASONING_EFFORT=high`. Não mantenha duas chaves sem definir explicitamente `AI_PROVIDER`.

Para PIX/boleto, acrescente:

```dotenv
MERCADOPAGO_ACCESS_TOKEN=APP_USR-...
MERCADOPAGO_WEBHOOK_SECRET=SEGREDO_DO_WEBHOOK
```

Sem os dois valores do Mercado Pago, PIX e boleto ficam ocultos e o webhook retorna `503`.

## 5. Configurar os processos

Comandos de produção:

```text
web:       python migrations/run.py && cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
worker:    cd backend && python -m workers.runner
scheduler: cd backend && python -m workers.scheduler
```

O [Procfile](../Procfile) já contém esses comandos. Execute migrations uma única vez por release; o runner registra cada versão em `schema_migrations` e é idempotente.

## 6. Configurar Stripe em modo de teste

1. No Stripe, use inicialmente `sk_test_...` e `pk_test_...`.
2. Cadastre o endpoint HTTPS `https://app.suaempresa.com.br/api/payments/stripe-webhook`.
3. Assine estes eventos:
   - `checkout.session.completed`
   - `customer.subscription.deleted`
   - `customer.subscription.updated`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copie o signing secret `whsec_...` para `STRIPE_WEBHOOK_SECRET`.
5. Envie um evento de teste pelo Stripe e confirme resposta HTTP `200`.
6. Faça uma assinatura completa com cartão de teste e confirme no banco:
   - usuário com `subscription_status=active`;
   - plano correto;
   - `stripe_customer_id` preenchido;
   - `stripe_subscription_id` preenchido somente no Starter recorrente;
   - vigência de 4 meses no Professional e 1 ano no Enterprise.
7. Teste falha de pagamento, cancelamento e renovação.
8. Somente depois repita a configuração com chaves `live` e um pagamento real controlado.

Os Price IDs são opcionais. Se configurar `STRIPE_PRICE_ID_STARTER`, ele deve apontar para um preço recorrente mensal de R$ 389,90. `STRIPE_PRICE_ID_PROFESSIONAL` e `STRIPE_PRICE_ID_ENTERPRISE` devem apontar para preços únicos de R$ 3.789,90 e R$ 8.989,90. Sem esses IDs, a aplicação cria os dados de preço diretamente em cada Checkout. O parcelamento de Professional e Enterprise é solicitado ao Stripe e aparece apenas para conta, região e cartão elegíveis.

O Enterprise custa R$ 8.989,90 em pagamento único e libera 1 ano de acesso após confirmação do Stripe. O Professional custa R$ 3.789,90 e libera 4 meses; ambos bloqueiam o acesso no vencimento e oferecem renovação pelo login. O Starter custa R$ 389,90 por mês em cobrança recorrente. Iron AI Shield e Iron AI Labs continuam exclusivos do Enterprise; o Labs também exige `is_developer=true`.

## 7. Configurar Mercado Pago, se usado

1. Cadastre `https://app.suaempresa.com.br/api/payments/mercadopago-webhook`.
2. Configure token e segredo do webhook.
3. Envie uma notificação assinada de teste e confirme HTTP `200`.
4. Teste PIX aprovado, expirado e rejeitado.
5. Confirme que requisições sem `x-signature`, `x-request-id` e `data.id` recebem `401`.

## 8. Configurar Iron AI e integrações

1. Acesse Configurações e confirme `Iron AI: conectada · groq`.
2. Faça uma pergunta sobre um finding real.
3. Proponha uma tarefa, aprove como owner/admin e execute; confirme a tarefa e o log de auditoria.
4. Em Integrações, conecte o GitHub com token de menor privilégio e sincronize um repositório de teste.
5. AWS e Microsoft 365 continuam “Em breve” e não devem ser anunciados como integrações ativas.

## 9. Validar MFA, gates e conformidade

1. Em **Configurações → Segurança**, configure TOTP, confirme um código e guarde os códigos de recuperação.
2. Saia e confirme que senha sem MFA é recusada; teste também um código de recuperação uma única vez.
3. Em **Configurações → DevSecOps**, crie uma chave com validade curta e armazene-a no cofre de secrets do CI.
4. Envie um SARIF de teste a `/api/pipeline/ingest`, confirme deduplicação e valide um gate bloqueado e outro aprovado.
5. Revogue a chave e confirme que ela recebe `401` imediatamente.
6. Em **Conformidade**, confirme que controles automáticos refletem os dados reais e que apenas owner/admin altera evidências manuais.

## 10. Criar os acessos corretos

- Cliente Starter: usa a plataforma principal sem monitoramento de eventos em tempo real, Iron AI Shield e Iron AI Labs.
- Cliente Professional: adiciona sensores em tempo real e contenção WAF aprovada, sem Iron AI Shield e sem Iron AI Labs.
- Cliente Enterprise: recebe Iron AI Shield.
- Desenvolvedor Enterprise: além do plano ativo, recebe `is_developer=true` pelo painel administrativo e pode abrir a área avançada.
- `is_admin=true` não ignora a exigência Enterprise.

Remova usuários e senhas locais, principalmente `localadmin`, antes de migrar qualquer banco para produção.

## 11. Checklist de segurança e operação

- TLS obrigatório e redirecionamento HTTP → HTTPS.
- CDN/WAF com proteção DDoS e rate limiting na borda.
- Banco e Redis sem exposição pública desnecessária.
- Backups automáticos e teste documentado de restauração.
- Logs centralizados sem tokens, senhas ou conteúdo sensível.
- Alertas para HTTP 5xx, fila parada, worker parado, falha SMTP e webhook rejeitado.
- Rotação periódica de Stripe, Groq, SMTP, GitHub e chaves internas.
- SAST, dependency scan e revisão de permissões antes de cada release.
- Política de retenção e exclusão de dados conforme LGPD.

## 12. Aceite final

Após o deploy, execute:

```bash
curl --fail https://app.suaempresa.com.br/api/health
curl --fail https://app.suaempresa.com.br/api/ready
```

Depois valide manualmente login e MFA, onboarding, target autorizado, scan, relatório PDF, Iron AI, aprovação de ação, gate de CI, conformidade, os três checkouts de teste, webhook, vencimento/renovação, Iron AI Shield Enterprise e bloqueio `403` das funcionalidades restritas.

Só considere o ambiente pronto quando `/api/ready` retornar `200` e todos os itens acima tiverem evidência. Nenhum software pode ser garantido como invulnerável; segurança também depende da infraestrutura e da operação contínua.

Para Enterprise, valide adicionalmente SSO OIDC com MFA no IdP, sincronização GitLab/Azure DevOps, criação de tarefa Jira, DAST autenticado sem vazamento em redirect, heartbeats de worker/scheduler e exportação do pacote de auditoria.
