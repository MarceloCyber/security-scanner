# Monitoramento defensivo em tempo real

O painel de Monitoramento recebe telemetria assinada do ativo e atualiza incidentes em até cinco segundos enquanto a tela está aberta. Scans externos isolados não enxergam tráfego que chega ao servidor; por isso ao menos um sensor, proxy ou WAF precisa enviar eventos.

## Conectar Nginx

1. Na plataforma, abra `Monitoramento > Ativar proteção guiada > Conectar a telemetria`, escolha o ativo e gere a instalação.
2. Execute o comando exibido no servidor do Nginx. Ele baixa o coletor, troca um token de uso único por uma chave permanente, detecta o access log e cria o serviço `iron-ai-sensor.service`.
3. A tela reconhece automaticamente quando o token foi trocado e mostra o sensor instalado.
4. Confirme que o access log usa o formato `combined`. Atrás do Cloudflare, configure o Nginx para registrar `CF-Connecting-IP` somente a partir das redes confiáveis do provedor.

Quando a plataforma estiver em `localhost` e o Nginx estiver em outro servidor, informe no campo de endpoint uma URL HTTPS pública temporária ou a URL da Iron AI em produção. O servidor remoto não consegue acessar o `localhost` do operador.

Para instalação manual ou troubleshooting, execute o coletor diretamente:

```bash
IRON_AI_SENSOR_KEY='chave_exibida_uma_vez' python3 iron_ai_sensor.py \
  --log /var/log/nginx/access.log \
  --endpoint https://app.sua-iron-ai.com
```

O coletor envia apenas IP, método, caminho, status, user-agent e contagens agregadas. Ele não envia corpo, cookies ou headers de autorização.

### Contenção no próprio servidor

O agente 1.1 anuncia a capacidade `host_firewall` somente quando está executando como root e encontra `nftables` ou `iptables`. Depois que um owner/admin aprova um incidente, ele recebe apenas uma ação tipada com `block_ip` ou `unblock_ip`; não existe operação para executar comandos arbitrários.

- `nftables`: usa a tabela isolada `inet iron_ai`, sets separados para IPv4/IPv6 e timeout de 24 horas.
- `iptables`: fallback para hosts antigos, com regra identificada pelo ID auditável da ação.
- IPs privados, reservados, loopback e redes conhecidas do Cloudflare são recusados tanto pela API quanto pelo agente.
- A remoção também exige confirmação e é reconciliada pelo sensor. Após reinício do servidor, ações ainda válidas são reaplicadas.

O firewall local protege conexões que chegam diretamente ao servidor. Se o tráfego passa por um reverse proxy, o pacote pode chegar com o IP do proxy; nesse cenário, o bloqueio correto do visitante deve ser aplicado no proxy/WAF, como o Cloudflare.

## Integrar outro WAF, firewall ou SIEM

Envie lotes de até 100 agregados para `POST /api/security-monitoring/ingest`, com o header `X-Iron-AI-Sensor-Key`:

```json
{
  "events": [{
    "signal": "web_scan",
    "source_ip": "203.0.113.20",
    "method": "GET",
    "path": "/.env",
    "status_code": 404,
    "request_count": 32,
    "window_seconds": 60,
    "distinct_paths": 24,
    "source": "waf"
  }]
}
```

Signals aceitos: `port_scan`, `web_scan`, `reconnaissance`, `brute_force`, `credential_stuffing`, `exploit_attempt`, `path_traversal`, `sql_injection`, `xss`, `ddos`, `unauthorized_access` e `malware`. Eventos sem signal também são classificados por volume, status, caminhos e user-agent.

## Contenção Cloudflare

Em `Monitoramento > Ativar proteção guiada > Conectar o Cloudflare`, informe o domínio e um API Token restrito com leitura da zona e escrita de regras de acesso do firewall. A plataforma localiza o Zone ID automaticamente; o preenchimento manual continua disponível como opção avançada. A credencial é criptografada e nunca retorna ao navegador.

O bloqueio nunca é automático: owner ou admin precisa confirmar cada IP. A ação cria uma IP Access Rule real no Cloudflare, fica registrada na auditoria e pode ser removida pelo mesmo incidente.

## Estratégia híbrida automática

O botão `Bloquear IP` não exige que o operador escolha um provedor:

1. Se o Cloudflare estiver conectado, a origem é bloqueada no edge para o domínio protegido.
2. Se houver um sensor ativo com firewall habilitado no servidor do ativo, uma regra local temporária também é enfileirada.
3. Se apenas uma dessas camadas estiver disponível, a plataforma usa somente essa camada e informa a cobertura real.

Cloudflare não protege SSH, banco de dados, portas diretas ou domínios que não passam pelo proxy. O firewall do host cobre tráfego direto daquele servidor, mas não substitui firewall de rede, security groups, EDR ou correção da vulnerabilidade.

## Teste seguro do bloqueio real

O teste assistido não exige instalar o sensor. Ele precisa apenas de uma camada pronta — Cloudflare ou firewall do servidor — e de um ativo cadastrado.

1. Em `Monitoramento > Ativar proteção guiada`, conecte o Cloudflare. Se preferir bloquear diretamente no servidor, conecte o sensor como opção avançada.
2. Clique em `Testar agora` e depois em `Criar link de teste`.
3. Envie o link temporário ao seu celular, desligue o Wi-Fi e abra pelo 4G/5G. O link registra somente o IP público e expira em 10 minutos; nenhum ataque é executado.
4. A tela encontra o incidente automaticamente. Confira se o IP pertence à conexão móvel e clique em `Bloquear IP`.
5. Confirme a recusa por essa mesma conexão e valide que o site continua disponível por outra rede.
6. Clique uma vez em `Remover bloqueio`; a plataforma remove todas as camadas ativas daquele incidente.

Para uma origem já conhecida, use `Monitoramento > Bloquear IP`, escolha o ativo, informe o IP público e registre o motivo. A confirmação humana continua obrigatória e a ação fica na auditoria. IPs privados, loopback, reservados, multicast e redes conhecidas da Cloudflare são recusados.

Em desenvolvimento, o link precisa ser alcançável pelo celular. `localhost` não é acessível pelo 4G/5G; use uma URL HTTPS temporária para a aplicação ou teste depois do deploy em produção.

Não bloqueie endereços compartilhados, IPs de CDN/proxy, sua conexão administrativa ou qualquer origem de terceiro. Para apenas validar as credenciais, conecte o WAF e pare antes da aprovação: essa etapa consulta a zona, mas não cria regra.

## Migration e deploy

O schema do teste assistido é criado por `migrations/017_assisted_containment_tests.py`. A migration `018_repair_host_firewall_schema.py` reconcilia instalações nas quais a migration 016 não chegou a adicionar todas as colunas. O Render executa `python migrations/run.py` no `preDeployCommand` e novamente, de forma idempotente, antes de iniciar a API. Assim, a aplicação não sobe com código novo e schema antigo mesmo quando a etapa pre-deploy não for executada pelo ambiente. Essas migrations são aditivas: não removem nem renomeiam tabelas ou colunas existentes.

## Limites reais

- A plataforma detecta o que os sensores conectados conseguem observar; nenhum produto garante identificar toda tentativa de invasão.
- Bloquear um IP reduz tráfego daquela origem, mas não substitui correção da vulnerabilidade, investigação de acessos bem-sucedidos, rotação de credenciais ou resposta a incidente.
- Não bloqueie endereços de CDN, load balancer ou proxy. Valide o IP real do cliente antes de executar contenção. A Iron AI rejeita automaticamente endereços privados, reservados e faixas conhecidas do Cloudflare.
