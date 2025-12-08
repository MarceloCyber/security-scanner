# 🧪 GUIA DE TESTES - Security Scanner

Este guia mostra como testar todas as funcionalidades da ferramenta.

---

## ✅ TESTE 1: Instalação e Inicialização

### Passo 1: Instalar
```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner
./install.sh
```

**Resultado Esperado**: 
- ✅ Ambiente virtual criado
- ✅ Dependências instaladas
- ✅ Arquivo .env configurado

### Passo 2: Iniciar Servidor
```bash
./start.sh
```

**Resultado Esperado**:
- ✅ Servidor iniciado na porta 8000
- ✅ Mensagem: "Uvicorn running on http://0.0.0.0:8000"
- ✅ Acesso em http://localhost:8000

---

## ✅ TESTE 2: Autenticação

### Passo 1: Criar Conta
1. Acesse http://localhost:8000
2. Clique em "Registrar-se"
3. Preencha:
   - Usuário: `testuser`
   - Email: `test@example.com`
   - Senha: `Test123!`
4. Clique em "Registrar"

**Resultado Esperado**:
- ✅ Mensagem de sucesso
- ✅ Redirecionamento para login

### Passo 2: Fazer Login
1. Use as credenciais criadas
2. Clique em "Entrar"

**Resultado Esperado**:
- ✅ Login bem-sucedido
- ✅ Redirecionamento para dashboard
- ✅ Nome do usuário visível no header

---

## ✅ TESTE 3: Scan de Código (Cola)

### Passo 1: Acessar Scanner
1. No dashboard, clique em "Scan de Código"
2. Certifique-se que a aba "Colar Código" está ativa

### Passo 2: Testar Código Vulnerável
Cole este código:

```python
import os

# SQL Injection
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute(query)

# XSS
def show_comment(comment):
    return "<div>" + comment + "</div>"

# Hardcoded Secrets
PASSWORD = "admin123"
API_KEY = "sk-1234567890"
SECRET = "my-secret-token"

# Command Injection
def backup(filename):
    os.system("cp " + filename + " /backup/")

# Weak Crypto
import hashlib
def hash_pwd(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# Debug Mode
DEBUG = True
ALLOWED_HOSTS = ['*']
```

### Passo 3: Analisar
1. Clique em "Analisar Código"
2. Aguarde processamento

**Resultado Esperado**:
- ✅ Scan completado
- ✅ Vulnerabilidades encontradas (8+)
- ✅ Gráfico de severidade
- ✅ Lista detalhada de vulnerabilidades
- ✅ Cada vulnerabilidade mostra:
  - Tipo
  - Severidade (cor)
  - Linha do código
  - Descrição
  - Recomendação

**Vulnerabilidades Detectadas**:
1. SQL Injection (linha 5)
2. XSS (linha 9)
3. Broken Authentication - senha hardcoded (linha 12-14)
4. Command Injection (linha 18)
5. Weak Cryptography - MD5 (linha 23)
6. Security Misconfiguration - DEBUG=True (linha 26)

---

## ✅ TESTE 4: Scan de Código (Upload)

### Passo 1: Usar Arquivo de Exemplo
1. Clique na aba "Upload de Arquivo"
2. Selecione: `examples/vulnerable_code.py`
3. Aguarde análise automática

**Resultado Esperado**:
- ✅ Upload bem-sucedido
- ✅ Múltiplas vulnerabilidades detectadas (20+)
- ✅ Relatório detalhado

---

## ✅ TESTE 5: Scan de API

### Teste com API Pública (JSONPlaceholder)

### Passo 1: Configurar
1. Clique em "Scan de API"
2. Preencha:
   - **URL Base**: `https://jsonplaceholder.typicode.com`
   - **Endpoints** (um por linha):
     ```
     /users
     /posts/1
     /comments
     ```
3. Deixe "Header de Autenticação" em branco

### Passo 2: Executar
1. Clique em "Iniciar Scan de API"
2. Aguarde (pode levar 30-60 segundos)

**Resultado Esperado**:
- ✅ Scan de 3 endpoints
- ✅ Verificação de headers de segurança
- ✅ Teste de rate limiting
- ✅ Análise de CORS
- ✅ Relatório por endpoint

### Teste com API Local (Opcional)

Se você tem uma API local rodando:

```
URL Base: http://localhost:3000
Endpoints:
/api/users
/api/login
/api/products
Header: Bearer your-token-here
```

---

## ✅ TESTE 6: Dashboard

### Verificar Estatísticas
1. Clique em "Dashboard" no menu
2. Verifique:
   - Total de scans realizados
   - Total de vulnerabilidades
   - Contadores por severidade
   - Gráfico de barras
   - Lista de scans recentes

**Resultado Esperado**:
- ✅ Números atualizados
- ✅ Gráficos funcionais
- ✅ Scans recentes listados

---

## ✅ TESTE 7: Histórico

### Passo 1: Acessar Histórico
1. Clique em "Histórico" no menu

**Resultado Esperado**:
- ✅ Lista de todos os scans
- ✅ Tipo (código/API)
- ✅ Target (arquivo/URL)
- ✅ Data e hora

### Passo 2: Visualizar Detalhes
1. Clique em um scan da lista

**Resultado Esperado**:
- ✅ Redirecionamento para página correta
- ✅ Resultados recarregados
- ✅ Visualização completa

---

## ✅ TESTE 8: Logout

### Passo 1: Sair
1. Clique no botão "Sair" no menu lateral

**Resultado Esperado**:
- ✅ Logout bem-sucedido
- ✅ Redirecionamento para login
- ✅ Token removido

### Passo 2: Tentar Acessar Dashboard
1. Tente acessar `http://localhost:8000/dashboard.html` diretamente

**Resultado Esperado**:
- ✅ Redirecionamento automático para login
- ✅ Proteção funcionando

---

## ✅ TESTE 9: Responsividade

### Desktop (1920x1080)
- ✅ Layout completo
- ✅ Sidebar visível
- ✅ Gráficos lado a lado

### Tablet (768px)
- ✅ Sidebar compacta
- ✅ Layout adaptado
- ✅ Funcionalidade mantida

### Mobile (375px)
- ✅ Sidebar apenas ícones
- ✅ Conteúdo em coluna única
- ✅ Touch-friendly

---

## ✅ TESTE 10: Performance

### Código Grande
Cole um arquivo com 500+ linhas:

**Resultado Esperado**:
- ✅ Processamento em < 5 segundos
- ✅ Todas vulnerabilidades detectadas
- ✅ Interface responsiva

### Múltiplos Endpoints
Teste 10+ endpoints de API:

**Resultado Esperado**:
- ✅ Processamento sequencial
- ✅ Loading indicator visível
- ✅ Resultados completos

---

## 🐛 TROUBLESHOOTING

### Erro: "Port 8000 already in use"
```bash
# Encontre e mate o processo
lsof -ti:8000 | xargs kill -9

# Ou use outra porta
cd backend
python -m uvicorn main:app --reload --port 8001
```

### Erro: "Module not found"
```bash
# Reinstale dependências
source venv/bin/activate
pip install -r requirements.txt
```

### Erro: "Database locked"
```bash
# Remova o banco e reinicie
rm security_scanner.db
./start.sh
```

### Erro: "CORS"
Se testar de domínio diferente, edite `backend/main.py`:
```python
allow_origins=["http://localhost:8000", "http://seu-dominio.com"]
```

### Interface não carrega
1. Verifique se o servidor está rodando
2. Acesse: http://localhost:8000/api/health
3. Se funcionar, limpe o cache do navegador

---

## 📊 CHECKLIST COMPLETO

### Instalação
- [ ] `./install.sh` executado com sucesso
- [ ] Ambiente virtual criado
- [ ] Dependências instaladas

### Inicialização
- [ ] `./start.sh` funcionando
- [ ] Servidor rodando na porta 8000
- [ ] Interface acessível

### Autenticação
- [ ] Registro de usuário
- [ ] Login funcional
- [ ] Logout funcional
- [ ] Proteção de rotas

### Scan de Código
- [ ] Cole código - funcional
- [ ] Upload arquivo - funcional
- [ ] Vulnerabilidades detectadas
- [ ] Relatório detalhado

### Scan de API
- [ ] Configuração de endpoints
- [ ] Múltiplos testes executados
- [ ] Resultados por endpoint
- [ ] Headers analisados

### Dashboard
- [ ] Estatísticas corretas
- [ ] Gráficos funcionais
- [ ] Scans recentes listados

### Histórico
- [ ] Lista de scans
- [ ] Detalhes acessíveis
- [ ] Filtros funcionais

### Interface
- [ ] Design moderno
- [ ] Responsiva
- [ ] Animações suaves
- [ ] Sem erros de console

---

## 🎯 CENÁRIOS DE TESTE AVANÇADOS

### Cenário 1: Fluxo Completo
1. Criar conta
2. Fazer login
3. Scan código vulnerável
4. Scan API pública
5. Verificar dashboard
6. Consultar histórico
7. Fazer logout

### Cenário 2: Segurança
1. Tentar acessar API sem token
2. Tentar usar token expirado
3. Tentar SQL injection no login
4. Verificar sanitização de inputs

### Cenário 3: Limites
1. Upload de arquivo muito grande
2. Código com 10.000 linhas
3. 100 endpoints simultâneos
4. Caracteres especiais em inputs

---

## 📝 RELATÓRIO DE TESTE

Ao finalizar os testes, você deve ter:

✅ **Funcionalidades Core**: 100%  
✅ **Interface**: 100%  
✅ **Segurança**: 100%  
✅ **Performance**: ✅ Adequada  
✅ **Documentação**: 100%  

---

## 🎉 SUCESSO!

Se todos os testes passaram, sua ferramenta está **100% funcional** e pronta para uso profissional!

**Próximos passos**:
1. Use em projetos reais
2. Customize para suas necessidades
3. Adicione novos scanners
4. Compartilhe feedback

---

**🔐 Lembre-se: Use apenas em sistemas autorizados!**
