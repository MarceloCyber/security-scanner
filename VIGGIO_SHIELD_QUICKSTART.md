# 🚀 VIGGIO SHIELD - GUIA DE INSTALAÇÃO E ATIVAÇÃO

## ⚡ Instalação Rápida

### Passo 1: Migrar o Banco de Dados

Execute o script de migração para criar as tabelas necessárias:

```bash
cd backend
python migrate_viggio_shield.py
```

**Saída esperada:**
```
🛡️  Iniciando migração do Viggio Shield...
✨ Criando tabela 'monitor_targets'...
✅ Tabela 'monitor_targets' criada com sucesso!
✨ Criando tabela 'monitor_incidents'...
✅ Tabela 'monitor_incidents' criada com sucesso!
✨ Criando tabela 'monitor_logs'...
✅ Tabela 'monitor_logs' criada com sucesso!
✨ Criando tabela 'blocked_ips'...
✅ Tabela 'blocked_ips' criada com sucesso!

📊 RESUMO DA MIGRAÇÃO
============================================================

✅ Tabelas criadas (4):
   • monitor_targets
   • monitor_incidents
   • monitor_logs
   • blocked_ips

✅ Migração concluída com sucesso!

🚀 Você já pode usar o Viggio Shield!
   Acesse: /viggio-shield.html
```

### Passo 2: Reiniciar o Servidor

Se o servidor já estiver rodando, reinicie-o:

```bash
# Ctrl+C para parar
# Depois inicie novamente:
python backend/main.py
```

Ou se estiver usando uvicorn:

```bash
uvicorn backend.main:app --reload
```

### Passo 3: Acessar o Viggio Shield

1. Faça login na plataforma
2. No menu lateral, clique em **"Viggio Shield"** (seção Monitoramento)
3. Ou acesse diretamente: `http://localhost:8000/viggio-shield.html`

---

## ✅ Verificação da Instalação

### 1. Verificar Tabelas Criadas

Execute no seu client SQL:

```sql
-- PostgreSQL
SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'monitor%' OR tablename = 'blocked_ips';

-- SQLite
SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'monitor%' OR name = 'blocked_ips');
```

Você deve ver:
- `monitor_targets`
- `monitor_incidents`
- `monitor_logs`
- `blocked_ips`

### 2. Verificar API

Teste o endpoint do dashboard:

```bash
curl -X GET "http://localhost:8000/api/viggio-shield/dashboard" \
  -H "Authorization: Bearer SEU_TOKEN_JWT"
```

Resposta esperada:
```json
{
  "total_targets": 0,
  "open_incidents": 0,
  "critical_incidents": 0,
  "blocked_ips": 0,
  "average_uptime": 100.0,
  "incidents_by_type": {}
}
```

### 3. Verificar Interface

Acesse: `http://localhost:8000/viggio-shield.html`

Você deve ver:
- ✅ Dashboard com cards de estatísticas
- ✅ Botão "Adicionar Alvo"
- ✅ Seção de Alvos de Monitoramento
- ✅ Seção de Incidentes Recentes

---

## 🧪 Teste Inicial

### Criar seu Primeiro Alvo

1. Clique em **"Adicionar Alvo"**
2. Preencha:
   ```
   Nome: Google (Teste)
   Tipo: API
   Endereço: https://www.google.com
   Intervalo: 300
   Threshold: 3
   ```
3. Clique em **"Criar Alvo"**

### Verificar Manualmente

1. No card do alvo criado, clique em **"Verificar"**
2. Aguarde alguns segundos
3. Deve aparecer: ✅ "Alvo está saudável!"
4. O uptime deve mostrar 100%

---

## 🔧 Troubleshooting

### Erro: "Table already exists"

Se a migração retornar erro dizendo que a tabela já existe:
```bash
# Execute novamente, o script detecta tabelas existentes
python backend/migrate_viggio_shield.py
```

### Erro: "Module not found: viggio_shield_routes"

Certifique-se de que o arquivo foi criado corretamente:
```bash
ls -la backend/routes/viggio_shield_routes.py
```

### Erro: "Connection refused"

Verifique se o banco de dados está rodando:
```bash
# PostgreSQL
pg_isready

# Se usar Docker
docker ps | grep postgres
```

### Interface não carrega

1. Verifique o console do navegador (F12)
2. Confirme que está autenticado
3. Limpe o cache do navegador (Ctrl+Shift+R)

---

## 📦 Dependências

Todas as dependências necessárias já estão no `requirements.txt`:
- ✅ `requests` - Para health checks HTTP
- ✅ `fastapi` - Framework web
- ✅ `sqlalchemy` - ORM para banco de dados
- ✅ `pydantic` - Validação de dados

Não é necessário instalar nada adicional!

---

## 🎯 Primeiros Passos

### 1. Configure um Servidor para Monitorar

```
Nome: Servidor de Produção
Tipo: server
Endereço: 192.168.1.10
Portas: 80,443,22
Intervalo: 300 (5 minutos)
Threshold: 3
```

### 2. Configure uma API

```
Nome: API Backend
Tipo: api
Endereço: https://api.exemplo.com/health
Intervalo: 180 (3 minutos)
Threshold: 2
```

### 3. Configure uma Aplicação Web

```
Nome: Site Principal
Tipo: application
Endereço: https://www.exemplo.com
Intervalo: 300 (5 minutos)
Threshold: 3
```

---

## 📊 Estrutura das Tabelas

### monitor_targets
Armazena os alvos de monitoramento.

### monitor_incidents
Registra todos os incidentes detectados.

### monitor_logs
Logs detalhados de todas as verificações.

### blocked_ips
Lista de IPs bloqueados manualmente ou automaticamente.

---

## 🔐 Permissões

### Por Plano

| Plano | Máx. Alvos | Funciona? |
|-------|------------|-----------|
| Free | 1 | ✅ |
| Starter | 3 | ✅ |
| Professional | 10 | ✅ |
| Enterprise | ∞ | ✅ |

O sistema valida automaticamente o limite baseado no plano do usuário.

---

## 📚 Documentação Completa

Leia a documentação completa em:
- **`VIGGIO_SHIELD_README.md`** - Guia do usuário
- **`VIGGIO_SHIELD_IMPLEMENTATION.md`** - Detalhes técnicos

---

## ✅ Checklist de Ativação

- [ ] Executar migração do banco de dados
- [ ] Reiniciar servidor backend
- [ ] Acessar interface do Viggio Shield
- [ ] Criar primeiro alvo de teste
- [ ] Executar verificação manual
- [ ] Verificar estatísticas no dashboard
- [ ] Configurar alertas por e-mail
- [ ] (Opcional) Configurar alertas Telegram

---

## 🎉 Pronto!

O **Viggio Shield** está instalado e funcionando!

Agora você pode:
- 🎯 Monitorar servidores, redes, APIs e aplicações
- 🚨 Receber alertas de incidentes
- 📊 Visualizar estatísticas em tempo real
- 🚫 Bloquear IPs maliciosos
- 📈 Acompanhar uptime e performance

**Bem-vindo ao Viggio Shield! 🛡️**
