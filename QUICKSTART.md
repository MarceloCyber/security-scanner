# 🚀 GUIA RÁPIDO DE INSTALAÇÃO

## Instalação Rápida (3 passos)

### 1️⃣ Instalar Dependências

```bash
cd security-scanner
./install.sh
```

### 2️⃣ Iniciar Servidor

```bash
./start.sh
```

### 3️⃣ Acessar Aplicação

Abra seu navegador em: **http://localhost:8000**

---

## 📋 Primeiro Acesso

1. **Crie uma conta**
   - Clique em "Registrar-se"
   - Preencha: usuário, email e senha
   - Clique em "Registrar"

2. **Faça login**
   - Use seu usuário e senha
   - Acesse o dashboard

3. **Comece a usar!**
   - Scan de Código: Cole código ou faça upload
   - Scan de API: Configure endpoints para teste
   - Histórico: Veja todos seus scans

---

## 🔧 Comandos Úteis

### Parar o Servidor
```bash
Ctrl + C (no terminal onde o servidor está rodando)
```

### Reiniciar do Zero
```bash
rm security_scanner.db
./start.sh
```

### Ver Logs
```bash
# Os logs aparecem no terminal onde o servidor está rodando
```

---

## 🐛 Problemas Comuns

### "Porta 8000 já em uso"
```bash
# Encontre o processo
lsof -ti:8000

# Mate o processo
kill -9 $(lsof -ti:8000)

# Inicie novamente
./start.sh
```

### "Módulo não encontrado"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "Erro ao conectar"
Verifique se o servidor está rodando em http://localhost:8000/api/health

---

## 📊 Exemplo de Uso

### Testar com Código Vulnerável

Cole este código Python para teste:

```python
import os

# SQL Injection
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    execute(query)

# XSS
def render_comment(comment):
    return "<div>" + comment + "</div>"

# Senha hardcoded
password = "admin123"
api_key = "sk-1234567890"

# Command Injection
def run_command(filename):
    os.system("cat " + filename)
```

### Testar API

Configure assim:

- **URL Base**: `https://jsonplaceholder.typicode.com`
- **Endpoints**:
  ```
  /users
  /posts
  /comments
  ```

---

## 📚 Mais Informações

Leia o **README.md** completo para:
- Documentação completa da API
- Arquitetura do sistema
- Recursos avançados
- Troubleshooting detalhado

---

## ⚠️ IMPORTANTE

Esta ferramenta é para **uso ético e autorizado apenas**.

✅ Teste apenas sistemas que você possui  
✅ Obtenha permissão por escrito  
❌ Nunca use contra sistemas de terceiros sem autorização

---

**Dúvidas?** Consulte o README.md ou a documentação completa.
