# Iron AI — capacidades Enterprise adicionadas

## Kimi K3

A Iron AI aceita Groq, Kimi/Moonshot e OpenRouter pelo mesmo contrato de resposta estruturada. Para usar Kimi K3:

1. Crie uma API key em `https://platform.kimi.ai`.
2. Configure no cofre de secrets do servidor:

```dotenv
AI_PROVIDER=kimi
KIMI_API_KEY=chave_da_moonshot
KIMI_MODEL=kimi-k3
KIMI_CHAT_URL=https://api.moonshot.ai/v1/chat/completions
KIMI_REASONING_EFFORT=high
```

3. Reinicie somente o processo web e confirme em **Configurações → Segurança** que o provedor exibido é `kimi`.

Não coloque a chave no frontend. Se a API Kimi falhar, o copiloto usa o motor determinístico local e identifica a resposta como fallback.

Executar os pesos Kimi K3 localmente não é uma opção prática para uma PME comum: o modelo oficial tem trilhões de parâmetros e requer infraestrutura de inferência especializada. “Open weights” não significa que o modelo completo rode em um notebook sem GPU.

## SSO corporativo

Foi implementado OpenID Connect Authorization Code com PKCE, nonce, state, código de troca de uso único e validação de assinatura JWKS. É compatível com Microsoft Entra ID, Okta, Auth0 e provedores OIDC equivalentes.

- recurso exclusivo Enterprise;
- somente usuários previamente cadastrados na organização entram;
- domínio de email é validado;
- por padrão o IdP precisa comprovar MFA em `amr` ou `acr`;
- client secret é criptografado;
- nenhum token do IdP é enviado ao navegador.

No IdP, cadastre a callback:

```text
https://SEU_DOMINIO/api/auth/sso/callback
```

SAML 2.0 não foi simulado. Ele deve ser acrescentado somente quando houver um IdP real, metadata XML, certificados de assinatura, regras de rotação e testes de logout/clock skew. Para novos clientes, OIDC é a integração recomendada.

## GitLab, Azure DevOps e Jira

Em **Integrações**, cada conexão valida a credencial no serviço real antes de persistir:

- GitLab: token `read_api`; aceita GitLab.com ou instalação pública HTTPS.
- Azure DevOps: PAT com leitura de projetos e código.
- Jira Cloud: email + API token; sincroniza projetos e cria tarefa a partir de um finding.

Tokens são criptografados e não retornam à interface. URLs customizadas passam por proteção SSRF e hosts privados/locais são recusados.

## DAST autenticado seguro

No modal de scan, o Enterprise pode salvar Bearer token, API key em header ou cookie de sessão. A credencial:

- fica criptografada;
- é enviada apenas para o mesmo esquema, host e porta do ativo;
- não acompanha redirects para outra origem;
- não aparece em logs, findings ou resultados;
- é usada somente em requisições de leitura.

O recurso não executa login automático nem payloads de exploração. Tokens curtos e conta de teste com menor privilégio são recomendados.

## Operação 24x7

O Blueprint agora separa API, worker e scheduler. Worker e scheduler registram heartbeats consultados em **Prontidão operacional**. Isso detecta processo parado, mas um SLA 24x7 ainda exige:

- instâncias pagas sem suspensão;
- redundância e autoscaling;
- alertas externos para `/api/health` e `/api/ready`;
- logs/APM centralizados;
- backup e restauração testados;
- escala e plantão humano definidos contratualmente.

## Auditoria e certificações

Owner/admin pode exportar um pacote de evidências com inventário, findings, conformidade e trilha de auditoria. O backend calcula SHA-256 canônico e registra o digest no banco.

Esse pacote ajuda uma auditoria independente, mas não concede ISO 27001, SOC 2, PCI DSS ou outra certificação. Certificações avaliam tecnologia, pessoas, processos, contratos e evidências ao longo do tempo e precisam de entidade externa qualificada.
