# 🌐 Como Configurar URLs Públicas

## Passos Rápidos

### 1️⃣ Instale o Ngrok
```bash
brew install ngrok
```

### 2️⃣ Você vai precisar de 3 terminais abertos:

---

### **TERMINAL 1 - Ngrok** 🌐

```bash
ngrok http 8000
```

Você verá algo assim:
```
Session Status    online
Forwarding        https://abc123.ngrok.io -> http://localhost:8000
```

**📋 COPIE O DOMÍNIO:** `abc123.ngrok.io` (sem o https://)

**⚠️ DEIXE ESTE TERMINAL ABERTO!**

---

### **TERMINAL 2 - Servidor Backend** 🚀

```bash
# 1. Configure o domínio público (cole o domínio que você copiou acima)
export PUBLIC_DOMAIN="abc123.ngrok.io"

# 2. Vá para o diretório do backend
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner/backend

# 3. Ative o ambiente virtual
source venv/bin/activate

# 4. Inicie o servidor (IMPORTANTE: use 0.0.0.0)
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**⚠️ DEIXE ESTE TERMINAL ABERTO!**

---

### **TERMINAL 3 - Livre** 💻

Use este terminal para outros comandos que precisar.

---

## 3️⃣ Teste

1. Abra o navegador em `http://localhost:3000` ou use Live Server
2. Vá para **Phishing Generator**
3. Escolha um template (ex: Facebook)
4. Clique em **Gerar Página**
5. Você verá uma URL mascarada tipo:
   ```
   https://facebook.com.abc123.ngrok.io/p/xyz789
   ```
6. **Esta URL funciona de qualquer lugar!** 🎉

---

## ⚠️ Importante

- Cada vez que **reiniciar o ngrok**, o domínio muda
- Quando isso acontecer:
  1. Copie o novo domínio do Terminal 1
  2. No Terminal 2, pare o servidor (`Ctrl+C`)
  3. Execute novamente: `export PUBLIC_DOMAIN="novo-dominio.ngrok.io"`
  4. Inicie o servidor de novo

---

## 🚀 Script Automatizado (RECOMENDADO)

Crie um arquivo chamado `start_public.sh`:

```bash
#!/bin/bash

echo "🚀 Iniciando servidor público..."

# Para processos anteriores
pkill -9 -f ngrok 2>/dev/null
pkill -9 -f "uvicorn main:app" 2>/dev/null

# Inicia ngrok em background
ngrok http 8000 > /dev/null &

echo "⏳ Aguardando ngrok iniciar (3 segundos)..."
sleep 3

# Obtém automaticamente a URL do ngrok
PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*' | head -n 1)
PUBLIC_DOMAIN=$(echo $PUBLIC_URL | sed 's|https://||')

if [ -z "$PUBLIC_DOMAIN" ]; then
    echo "❌ Erro: Não consegui obter o domínio do ngrok"
    echo "Verifique se o ngrok está instalado: brew install ngrok"
    exit 1
fi

echo "✅ Ngrok iniciado!"
echo "🌐 URL Pública: $PUBLIC_URL"
echo "📋 Domínio: $PUBLIC_DOMAIN"
echo ""

# Exporta a variável
export PUBLIC_DOMAIN="$PUBLIC_DOMAIN"

# Inicia o servidor
echo "🚀 Iniciando servidor backend..."
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner/backend
source venv/bin/activate
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Como usar:**
```bash
# Torne executável (só precisa fazer uma vez)
chmod +x start_public.sh

# Execute
./start_public.sh
```

**Este script faz TUDO automaticamente!** 🎯

---

## 🔍 Como Verificar se Está Funcionando

### Opção 1: No terminal onde o ngrok está rodando
Você verá as requisições chegando em tempo real.

### Opção 2: Interface Web do Ngrok
Abra `http://localhost:4040` no navegador - você verá todas as requisições.

### Opção 3: Teste Real
1. Copie a URL mascarada gerada
2. Abra em uma **aba anônima** ou **outro dispositivo**
3. Deve abrir a página de phishing normalmente

---

## 🐛 Problemas Comuns

| Problema | Solução |
|----------|---------|
| `command not found: ngrok` | Execute: `brew install ngrok` |
| URL mostra "Configure PUBLIC_DOMAIN" | Certifique-se de ter executado `export PUBLIC_DOMAIN` no mesmo terminal do servidor |
| "Address already in use" | Execute: `pkill -9 -f "uvicorn main:app"` |
| Ngrok desconecta | Versão gratuita tem limite de 2h. Reinicie o ngrok. |
| URLs não funcionam externamente | Certifique-se de usar `--host 0.0.0.0` no uvicorn |

---

## 💡 Alternativa Mais Simples

Se o ngrok for complicado, use **localhost.run** (não precisa instalar nada):

```bash
# Terminal 1 - Servidor
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner/backend
source venv/bin/activate
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 - Túnel público
ssh -R 80:localhost:8000 nokey@localhost.run
```

Copie a URL que aparecer e use como PUBLIC_DOMAIN.


