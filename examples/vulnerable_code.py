"""
Exemplos de código vulnerável para testar o Security Scanner
NÃO USE ESTES PADRÕES EM CÓDIGO DE PRODUÇÃO!

NOTA: Este arquivo contém código propositalmente incompleto e com erros
para demonstrar vulnerabilidades. Os erros de "não definido" são ESPERADOS.
Este é um arquivo de EXEMPLO apenas para testes do scanner.
"""

# type: ignore  # Ignora erros de linting - este é código de exemplo vulnerável

# ============================================
# EXEMPLO 1: SQL Injection
# ============================================

def login_user(username, password):
    """Vulnerável a SQL Injection"""
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return execute_query(query)

def search_products(search_term):
    """Vulnerável a SQL Injection"""
    sql = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return db.query(sql)


# ============================================
# EXEMPLO 2: Cross-Site Scripting (XSS)
# ============================================

def render_user_comment(comment):
    """Vulnerável a XSS"""
    return f"<div class='comment'>{comment}</div>"

def display_message(msg):
    """Vulnerável a XSS"""
    document.innerHTML = msg


# ============================================
# EXEMPLO 3: Hardcoded Secrets
# ============================================

# Senhas e chaves hardcoded
DATABASE_PASSWORD = "mySecretPassword123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "super_secret_token_xyz"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# ============================================
# EXEMPLO 4: Weak Cryptography
# ============================================

import hashlib

def hash_password(password):
    """Usando MD5 - algoritmo fraco"""
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data):
    """Usando SHA1 - algoritmo fraco"""
    return hashlib.sha1(data.encode()).hexdigest()


# ============================================
# EXEMPLO 5: Command Injection
# ============================================

import os
import subprocess

def backup_file(filename):
    """Vulnerável a Command Injection"""
    os.system(f"cp {filename} /backup/")

def process_image(image_path):
    """Vulnerável a Command Injection"""
    subprocess.call(f"convert {image_path} output.jpg", shell=True)


# ============================================
# EXEMPLO 6: Path Traversal
# ============================================

def read_user_file(filename):
    """Vulnerável a Path Traversal"""
    with open(filename, 'r') as f:
        return f.read()

def serve_static_file(filepath):
    """Vulnerável a Path Traversal"""
    content = open('/var/www/static/' + filepath).read()
    return content


# ============================================
# EXEMPLO 7: Insecure Deserialization
# ============================================

import pickle
import yaml

def load_user_data(data):
    """Vulnerável a Insecure Deserialization"""
    return pickle.loads(data)

def parse_config(config_str):
    """Vulnerável a YAML deserialization"""
    return yaml.load(config_str)


# ============================================
# EXEMPLO 8: Debug Mode Enabled
# ============================================

# Configurações inseguras
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'insecure-secret-key-12345'


# ============================================
# EXEMPLO 9: Sensitive Data Exposure
# ============================================

def get_user_info(user_id):
    """Expõe dados sensíveis"""
    user = db.get_user(user_id)
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'password': user.password,  # NUNCA exponha senhas!
        'credit_card': user.credit_card,  # Dados sensíveis
        'ssn': user.ssn  # Dados sensíveis
    }


# ============================================
# EXEMPLO 10: Missing CSRF Protection
# ============================================

@app.route('/transfer', methods=['POST'])
def transfer_money():
    """Vulnerável a CSRF - sem validação de token"""
    amount = request.form['amount']
    to_account = request.form['to_account']
    # Processa transferência sem verificar CSRF token
    process_transfer(amount, to_account)
    return "Transfer complete"


# ============================================
# EXEMPLO 11: Eval/Exec Usage
# ============================================

def calculate(expression):
    """Uso perigoso de eval"""
    result = eval(expression)
    return result

def run_code(code):
    """Uso perigoso de exec"""
    exec(code)


# ============================================
# EXEMPLO 12: SSL Verification Disabled
# ============================================

import requests

def fetch_api_data(url):
    """Desabilita verificação SSL"""
    response = requests.get(url, verify=False)
    return response.json()


# ============================================
# CÓDIGO SEGURO PARA COMPARAÇÃO
# ============================================

"""
EXEMPLO DE CÓDIGO SEGURO:

# SQL Injection - CORRETO
def login_user_secure(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return db.execute(query, (username, hash_password(password)))

# XSS - CORRETO
import html
def render_comment_secure(comment):
    safe_comment = html.escape(comment)
    return f"<div class='comment'>{safe_comment}</div>"

# Secrets - CORRETO
import os
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
API_KEY = os.getenv('API_KEY')

# Password Hashing - CORRETO
import bcrypt
def hash_password_secure(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Command Execution - CORRETO
import shlex
def backup_file_secure(filename):
    safe_filename = shlex.quote(filename)
    subprocess.run(['cp', safe_filename, '/backup/'])

# File Access - CORRETO
import os.path
def read_user_file_secure(filename):
    base_dir = '/safe/user/files/'
    filepath = os.path.normpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise ValueError("Invalid file path")
    with open(filepath, 'r') as f:
        return f.read()
"""
