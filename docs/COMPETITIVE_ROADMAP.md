# Iron AI — posição competitiva para PMEs

## Onde o produto já compete

A Iron AI já entrega uma fundação ASPM utilizável: inventário multi-tenant, análise web segura, normalização e deduplicação de findings, priorização por risco, histórico, remediação, relatórios, integração GitHub, ingestão SARIF, gates de CI/CD, MFA, auditoria, conformidade orientada a evidências e copiloto contextual com aprovação humana.

O posicionamento recomendado não é “uma Conviso mais barata”, e sim **segurança contínua simples, verificável e acessível para PMEs brasileiras**. Isso reduz a complexidade comercial e evita prometer profundidade enterprise que ainda depende de operação, integrações e certificações externas.

## Diferenciais adequados ao público

- onboarding em linguagem de negócio;
- preço e limites previsíveis;
- visão executiva e técnica no mesmo produto;
- LGPD e evidências operacionais sem alegar certificação;
- implantação progressiva, sem exigir um grande time AppSec;
- IA explicável, limitada aos dados do tenant e com aprovação humana;
- entrada aberta para Semgrep, Trivy, Checkov, Sonar e qualquer ferramenta SARIF.

## Lacunas antes de declarar paridade enterprise

1. SSO/SAML, SCIM e revisão completa de ciclo de vida de identidades.
2. Integrações produtivas adicionais: GitLab, Bitbucket, Azure DevOps, Jira e Slack/Teams.
3. Sensores SAST/SCA/secret/IaC executados e mantidos pela própria operação, além da ingestão atual.
4. DAST autenticado com navegador e políticas seguras por ambiente.
5. SLA operacional, suporte, telemetria, resposta a incidentes e recuperação testada 24x7.
6. Pentest independente, threat modeling e validação de segurança do produto.
7. Certificações e programa formal de privacidade/segurança; código sozinho não produz certificação.
8. Billing Enterprise automatizado caso a venda deixe de ser contratual/manual.

## Ordem recomendada

- **Agora:** estabilizar produção, testar pagamentos/webhooks, observabilidade e backup/restauração.
- **Próximo ciclo:** GitLab/Jira/Azure DevOps, templates de pipeline e notificações.
- **Depois:** SSO/SAML, políticas customizadas de gate e DAST autenticado isolado.
- **Escala:** operação 24x7, auditorias independentes, certificações e ecossistema de parceiros.

Cada item deve entrar em produção com testes de isolamento tenant, autorização, abuso, rollback, observabilidade e documentação. Nenhuma tela “Em breve” deve ser comercializada como integração funcional.
