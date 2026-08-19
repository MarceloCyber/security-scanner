# Monitoramento defensivo em tempo real

O painel de Monitoramento recebe telemetria assinada do ativo e atualiza incidentes em até cinco segundos enquanto a tela está aberta. Scans externos isolados não enxergam tráfego que chega ao servidor; por isso ao menos um sensor, proxy ou WAF precisa enviar eventos.

## Conectar Nginx

1. Na plataforma, abra `Monitoramento > Conectar telemetria`, escolha o ativo e crie a chave.
2. Copie `scripts/iron_ai_sensor.py` para o servidor do Nginx.
3. Confirme que o access log usa o formato `combined`. Atrás de CDN/proxy, configure o Nginx para registrar o IP real somente a partir dos proxies confiáveis do provedor.
4. Execute por um process manager, usando a origem HTTPS pública da Iron AI:

```bash
IRON_AI_SENSOR_KEY='chave_exibida_uma_vez' python3 iron_ai_sensor.py \
  --log /var/log/nginx/access.log \
  --endpoint https://app.sua-iron-ai.com
```

O coletor envia apenas IP, método, caminho, status, user-agent e contagens agregadas. Ele não envia corpo, cookies ou headers de autorização.

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

Em `Monitoramento > Conectar WAF`, informe o Zone ID e um API Token restrito à zona com permissões de leitura da zona e escrita de regras de acesso do firewall. A credencial é criptografada e nunca retorna ao navegador.

O bloqueio nunca é automático: owner ou admin precisa confirmar cada IP. A ação cria uma IP Access Rule real no Cloudflare, fica registrada na auditoria e pode ser removida pelo mesmo incidente.

## Teste seguro do bloqueio real

Faça o primeiro teste em uma zona ou subdomínio de homologação, nunca diretamente no ativo principal. Use um IP público dedicado que você controla (por exemplo, uma VPS descartável) e confirme que ele não é o IP usado para administrar a Iron AI ou o Cloudflare.

1. Em `Monitoramento > Conectar WAF`, conecte a zona de homologação com um API Token limitado àquela zona.
2. Instale o sensor no proxy da homologação e confirme que aparece como ativo.
3. Da VPS de teste, faça algumas requisições inofensivas para um caminho propositalmente suspeito da sua própria aplicação, como `/.env`, sem enviar payloads.
4. Aguarde o incidente aparecer, confira se o IP exibido é exatamente o IP público da VPS e aprove o bloqueio.
5. Repita uma requisição da VPS e confirme a recusa pelo Cloudflare. De outra conexão, confirme que o site continua disponível.
6. Use `Remover bloqueio` no incidente e confirme que a VPS volta a acessar.

Não bloqueie endereços compartilhados, IPs de CDN/proxy, sua conexão administrativa ou qualquer origem de terceiro. Para apenas validar as credenciais, conecte o WAF e pare antes da aprovação: essa etapa consulta a zona, mas não cria regra.

## Limites reais

- A plataforma detecta o que os sensores conectados conseguem observar; nenhum produto garante identificar toda tentativa de invasão.
- Bloquear um IP reduz tráfego daquela origem, mas não substitui correção da vulnerabilidade, investigação de acessos bem-sucedidos, rotação de credenciais ou resposta a incidente.
- Não bloqueie endereços de CDN, load balancer ou proxy. Valide o IP real do cliente antes de executar contenção.
