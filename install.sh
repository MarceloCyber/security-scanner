#!/bin/bash

set -euo pipefail

echo "🔒 Security Scanner - Inicialização"
echo "=================================="
echo ""

# Localiza um Python real. Em algumas versões do macOS, /usr/bin/python3 existe
# apenas como um stub das Command Line Tools e falha quando é executado.
SYSTEM_PYTHON=""
UV_PYTHON=""
if command -v uv >/dev/null 2>&1; then
    UV_PYTHON="$(uv python find 3.12 2>/dev/null || true)"
fi
for candidate in \
    "$UV_PYTHON" \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3.12 \
    /usr/local/bin/python3 \
    python3.12 \
    python3
do
    if [ -n "$candidate" ] && command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys, ssl, plistlib; assert sys.version_info >= (3, 9)" >/dev/null 2>&1; then
        SYSTEM_PYTHON="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$SYSTEM_PYTHON" ]; then
    echo "❌ Python 3.9 ou superior não está disponível."
    echo "💡 No macOS com Homebrew, execute: brew install python@3.12"
    exit 1
fi

echo "✅ Python encontrado: $($SYSTEM_PYTHON --version) ($SYSTEM_PYTHON)"
echo ""

# Cria ou repara o ambiente virtual. O activate contém caminhos absolutos e
# fica inválido quando a pasta do projeto é movida.
if [ ! -x "venv/bin/python3" ] || ! "venv/bin/python3" -c "import sys, ssl, plistlib; assert sys.prefix != sys.base_prefix" 2>/dev/null; then
    echo "📦 Criando ambiente virtual..."
    if [ -d "venv" ]; then
        mv venv "venv.invalido.$(date +%Y%m%d%H%M%S)"
    fi
    if ! "$SYSTEM_PYTHON" -m venv venv; then
        # pip 26.2 pode falhar no bootstrap em algumas versões do macOS 26
        # ao detectar o trust store. Extrair a wheel oficial é equivalente ao
        # bootstrap e permite usar o modo de certificados compatível abaixo.
        echo "⚠️  Bootstrap padrão do pip indisponível; aplicando modo compatível..."
        "$SYSTEM_PYTHON" -m venv --without-pip --clear venv
        PYTHON_SHORT_VERSION="$($SYSTEM_PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        BUNDLED_PIP="$($SYSTEM_PYTHON -c 'import ensurepip, pathlib; print(next((pathlib.Path(ensurepip.__file__).parent / "_bundled").glob("pip-*.whl")))')"
        "venv/bin/python3" -m zipfile -e "$BUNDLED_PIP" "venv/lib/python$PYTHON_SHORT_VERSION/site-packages"
    fi
    echo "✅ Ambiente virtual criado"
else
    echo "✅ Ambiente virtual já existe"
fi

echo ""
echo "🔧 Ativando ambiente virtual..."
PYTHON_BIN="$(pwd)/venv/bin/python3"

echo ""
echo "📥 Instalando dependências..."
"$PYTHON_BIN" -m pip --use-deprecated=legacy-certs install --upgrade pip > /dev/null 2>&1
"$PYTHON_BIN" -m pip --use-deprecated=legacy-certs install -r requirements.txt

echo ""
echo "⚙️  Configurando ambiente..."

# Cria .env se não existir
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Arquivo .env criado. Por favor, edite-o com suas configurações."
else
    echo "✅ Arquivo .env já existe"
fi

"$PYTHON_BIN" scripts/ensure_local_secrets.py

echo ""
echo "=================================="
echo "✅ Instalação concluída!"
echo ""
echo "Para iniciar o servidor, execute:"
echo "  cd backend"
echo "  ../venv/bin/python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Depois acesse: http://localhost:8000"
echo "=================================="
