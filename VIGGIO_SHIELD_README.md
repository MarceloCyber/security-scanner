# Viggio Shield - Sistema de Monitoramento de Segurança

## 📋 Visão Geral

O **Viggio Shield** é um módulo completo de monitoramento de segurança em tempo real que permite conectar e observar:

- 🌐 **Redes** - Monitore sua infraestrutura de rede
- 💻 **Servidores** - Supervisione servidores e suas portas
- 🔌 **APIs** - Acompanhe disponibilidade e performance de APIs
- 📱 **Aplicações Web** - Monitore aplicações e sites

## ✨ Principais Funcionalidades

### 1. Monitoramento em Tempo Real
- Verificações periódicas automáticas (configuráveis)
- Detecção de downtime e problemas de conectividade
- Medição de tempo de resposta e latência
- Cálculo de uptime em tempo real

### 2. Detecção de Incidentes
- **Port Scanning** - Detecta varreduras de portas
- **Brute Force** - Identifica tentativas de força bruta
- **DDoS** - Alerta sobre possíveis ataques distribuídos
- **Acesso Não Autorizado** - Monitora tentativas de acesso indevido
- **Anomalias** - Identifica comportamentos anormais

### 3. Sistema de Alertas
- Alertas por e-mail configuráveis
- Suporte para alertas via Telegram (opcional)
- Threshold configurável de falhas
- Níveis de severidade: Low, Medium, High, Critical

### 4. Bloqueio Automático de IPs
- Bloqueio manual de IPs maliciosos
- Bloqueio temporário ou permanente
- Gestão centralizada de IPs bloqueados
- Informações de geolocalização e ASN

### 5. Dashboard Completo
- Estatísticas em tempo real
- Gráficos de uptime
- Lista de incidentes ativos
- Histórico de verificações

## 🚀 Como Usar

### Passo 1: Adicionar um Alvo

1. Acesse o **Viggio Shield** pelo menu do dashboard
2. Clique em "**Adicionar Alvo**"
3. Preencha as informações:
   - **Nome**: Identifique seu alvo (ex: "Servidor de Produção")
   - **Tipo**: Escolha entre Servidor, Rede, Aplicação Web ou API
   - **Endereço**: IP, URL ou domínio (ex: `192.168.1.1` ou `https://exemplo.com`)
   - **Portas**: Liste as portas que deseja monitorar (ex: `80,443,22`)
   - **Intervalo**: Frequência de verificação em segundos (padrão: 300s = 5min)
   - **Threshold**: Número de falhas antes de gerar alerta (padrão: 3)

### Passo 2: Configurar Alertas

- ✉️ **E-mail**: Ative para receber alertas por e-mail
- 📱 **Telegram**: Configure seu Chat ID para alertas instantâneos

### Passo 3: Monitorar

O sistema irá:
- ✅ Verificar periodicamente o alvo
- 📊 Atualizar estatísticas de uptime
- 🚨 Gerar alertas quando problemas forem detectados
- 📝 Registrar todos os incidentes

### Passo 4: Gerenciar Incidentes

- Visualize incidentes na aba "Incidentes Recentes"
- Filtre por severidade (Critical, High, Medium, Low)
- Marque incidentes como resolvidos ou falsos positivos
- Adicione notas para documentar ações tomadas

## 🔧 Tipos de Monitoramento

### 1. Servidor / Rede
- Teste de ping (ICMP)
- Verificação de portas TCP
- Detecção de serviços inacessíveis

**Exemplo**:
```
Nome: Servidor de Produção
Tipo: server
Endereço: 192.168.1.10
Portas: 80,443,22,3306
```

### 2. API
- Teste de disponibilidade HTTP/HTTPS
- Medição de tempo de resposta
- Verificação de status code
- Análise de payload

**Exemplo**:
```
Nome: API REST Principal
Tipo: api
Endereço: https://api.example.com/health
Portas: (deixe vazio para APIs)
```

### 3. Aplicação Web
- Teste de carregamento da página
- Verificação de status HTTP
- Medição de performance

**Exemplo**:
```
Nome: Site Corporativo
Tipo: application
Endereço: https://www.example.com
Portas: (deixe vazio)
```

## 📊 Métricas e Estatísticas

### Dashboard Principal
- **Alvos Monitorados**: Total de alvos ativos
- **Uptime Médio**: Porcentagem de disponibilidade
- **Incidentes Abertos**: Problemas não resolvidos
- **Incidentes Críticos**: Alertas de alta prioridade
- **IPs Bloqueados**: Total de bloqueios ativos

### Por Alvo
- **Uptime**: Percentual de disponibilidade
- **Total de Verificações**: Quantidade de checks realizados
- **Falhas**: Número de verificações com problema
- **Última Verificação**: Timestamp da última checagem
- **Incidentes Ativos**: Problemas em aberto

## 🛡️ Detecção de Ameaças

### Port Scanning
Detectado quando há múltiplas tentativas de conexão em diferentes portas em curto período.

### Brute Force
Identificado por múltiplas tentativas de autenticação do mesmo IP.

### DDoS (Distributed Denial of Service)
Alerta quando há volume anormal de requisições de múltiplos IPs.

### Acesso Não Autorizado
Monitora tentativas de acesso a recursos protegidos.

### Anomalias
Comportamentos fora do padrão normal estabelecido.

## 🚫 Bloqueio de IPs

### Bloqueio Manual
1. Acesse os detalhes de um incidente
2. Identifique o IP malicioso
3. Clique em "Bloquear IP"
4. Escolha duração:
   - **Temporário**: Especifique horas (ex: 24h)
   - **Permanente**: Bloqueio indefinido

### Bloqueio Automático
Configure regras de bloqueio automático baseadas em:
- Número de incidentes
- Tipo de ameaça
- Score de ameaça

### Gerenciar Bloqueios
- Visualize todos os IPs bloqueados
- Veja informações de geolocalização
- Remova bloqueios quando necessário
- Configure expiração automática

## 📈 Limites por Plano

| Plano | Alvos | Intervalo Mínimo | Histórico | Alertas |
|-------|-------|------------------|-----------|---------|
| **Free** | 1 | 5 minutos | 7 dias | E-mail |
| **Starter** | 3 | 3 minutos | 30 dias | E-mail |
| **Professional** | 10 | 1 minuto | 90 dias | E-mail + Telegram |
| **Enterprise** | Ilimitado | 30 segundos | Ilimitado | Todos + Webhook |

## 🔔 Configuração de Alertas

### E-mail
Alertas são enviados automaticamente para o e-mail cadastrado quando:
- Um alvo fica indisponível
- Threshold de falhas é atingido
- Incidente crítico é detectado

### Telegram
1. Abra o Telegram e procure por `@BotFather`
2. Crie um bot e obtenha o token
3. Inicie uma conversa com seu bot
4. Obtenha seu Chat ID
5. Configure no Viggio Shield

### Webhook (Enterprise)
Configure endpoints personalizados para receber notificações em formato JSON.

## 🔍 API Endpoints

### Listar Alvos
```
GET /api/viggio-shield/targets
```

### Criar Alvo
```
POST /api/viggio-shield/targets
{
  "name": "Meu Servidor",
  "target_type": "server",
  "target_address": "192.168.1.1",
  "monitoring_ports": [80, 443],
  "check_interval": 300,
  "alert_threshold": 3
}
```

### Verificar Alvo Manualmente
```
POST /api/viggio-shield/targets/{id}/check
```

### Listar Incidentes
```
GET /api/viggio-shield/incidents?severity=critical&status=open
```

### Bloquear IP
```
POST /api/viggio-shield/blocked-ips
{
  "ip_address": "1.2.3.4",
  "reason": "Port scanning detected",
  "duration_hours": 24
}
```

## 💡 Melhores Práticas

1. **Intervalos Adequados**: Não configure intervalos muito curtos para evitar sobrecarga
2. **Alertas Inteligentes**: Configure thresholds adequados para evitar falsos positivos
3. **Documentação**: Adicione notas aos incidentes para histórico
4. **Revisão Regular**: Revise IPs bloqueados periodicamente
5. **Teste Regular**: Use a verificação manual para validar configurações

## 🆘 Solução de Problemas

### Alvo não está sendo verificado
- Verifique se o status está "active"
- Confirme o intervalo de verificação
- Verifique logs de erro

### Muitos falsos positivos
- Aumente o threshold de alertas
- Aumente o intervalo de verificação
- Revise a configuração de rede

### Não recebo alertas
- Verifique configurações de e-mail
- Confirme que alertas estão habilitados
- Verifique pasta de spam

## 🔐 Segurança

- Todas as comunicações são criptografadas
- Credenciais nunca são armazenadas em logs
- IPs são validados antes de bloqueio
- Auditoria completa de todas as ações

## 📞 Suporte

Para suporte técnico ou dúvidas:
- 📧 E-mail: support@ironnet.com
- 💬 Telegram: +5511999121628
- 📚 Documentação completa: `/manual.html`

---

**Viggio Shield** - Proteção Proativa para Sua Infraestrutura 🛡️
