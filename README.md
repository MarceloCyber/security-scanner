# Iron AI Security Platform

Plataforma brasileira de gestão contínua de segurança para pequenas e médias empresas. A Iron AI reúne inventário de ativos, scans web seguros, findings de múltiplas ferramentas, priorização de risco, remediação, relatórios, conformidade e um copiloto conectado aos dados autorizados de cada organização.

## Produto

- **Iron AI Security Platform** — experiência principal para gestores e times técnicos.
- **Iron AI Copilot** — explica riscos reais, recomenda prioridades e propõe ações sujeitas a aprovação humana.
- **Iron AI Shield** — workspace AppSec Enterprise.
- **Iron AI Labs** — ferramentas avançadas, disponíveis somente para desenvolvedores autorizados no Enterprise.
- **Iron AI Security Gates** — ingestão SARIF/findings e bloqueio de pipeline por severidade.

Os dados são isolados por organização. Chaves de integração são criptografadas, chaves de pipeline são armazenadas somente como hash e ações da IA exigem aprovação e ficam na auditoria.

## Executar localmente

```bash
./install.sh
./create-local-user.sh
./start.sh --local
```

Acesse `http://localhost:8000`. Para usar PostgreSQL e os serviços configurados no `.env`, execute `./start.sh` sem `--local`.

Worker e scheduler são processos separados:

```bash
./worker.sh --local
./scheduler.sh --local
```

O `start.sh` aplica migrations automaticamente e encerra com uma mensagem clara quando a porta escolhida já está ocupada. Para usar outra porta:

```bash
PORT=8010 ./start.sh --local
```

## Validação

```bash
venv/bin/python3 -m pytest -q
venv/bin/python3 -m compileall -q backend migrations scripts
node --check frontend/js/platform.js
node --check frontend/js/modern-app.js
```

## Fluxos reais disponíveis

1. Cadastre um domínio, aplicação ou API em **Ativos**.
2. Execute uma análise em **Monitoramento**. O scanner web faz verificações somente leitura de HTTP, HTTPS, DNS, TLS, redirects, headers e cookies.
3. Consulte findings deduplicados e priorizados em **Riscos**.
4. Gere PDF executivo ou técnico em **Relatórios**.
5. Use **Conformidade** para acompanhar controles automáticos e evidências organizacionais.
6. Pergunte à **Iron AI** sobre dados reais da organização; propostas de mudança passam por aprovação humana.
7. Em **Configurações**, habilite MFA e crie chaves para CI/CD.

Para ingestão no pipeline, envie SARIF 2.x ou findings normalizados a `POST /api/pipeline/ingest` usando o header `X-Iron-AI-Key`. A resposta inclui `quality_gate.passed`, que pode encerrar o build com erro.

## Segurança operacional

Execute scans somente em ativos para os quais exista autorização. A plataforma não deve ser anunciada como certificação, parecer jurídico ou garantia de invulnerabilidade. Produção exige HTTPS, PostgreSQL e Redis gerenciados, backups testados, WAF/CDN, observabilidade, rotação de segredos e revisão contínua.

Consulte [PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) para o deploy e [COMPETITIVE_ROADMAP.md](docs/COMPETITIVE_ROADMAP.md) para o escopo competitivo e as lacunas ainda abertas.
