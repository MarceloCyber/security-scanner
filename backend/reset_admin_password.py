#!/usr/bin/env python3
"""
Script para resetar a senha do usuário admin
Execute: python3 reset_admin_password.py
"""

import sqlite3
import sys
from pathlib import Path
from getpass import getpass

# Adiciona o diretório backend ao path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from passlib.context import CryptContext
except ImportError:
    print("❌ Erro: passlib não está instalado")
    print("Execute: pip install passlib[bcrypt]")
    sys.exit(1)

# Caminho do banco de dados
DB_PATH = Path(__file__).parent / "security_scanner.db"

def reset_admin_password():
    """Reseta a senha do usuário admin"""
    
    print("=" * 60)
    print("🔐 RESET DE SENHA DO ADMINISTRADOR")
    print("=" * 60)
    print()
    
    if not DB_PATH.exists():
        print(f"❌ Erro: Banco de dados não encontrado em {DB_PATH}")
        return False
    
    # Conecta ao banco
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Lista usuários admin
    cursor.execute("SELECT id, username, email FROM users WHERE is_admin = 1")
    admins = cursor.fetchall()
    
    if not admins:
        print("⚠️  Nenhum usuário administrador encontrado!")
        print()
        print("Deseja tornar um usuário existente em admin? (s/n): ", end='')
        resposta = input().strip().lower()
        
        if resposta == 's':
            cursor.execute("SELECT id, username, email FROM users ORDER BY id")
            users = cursor.fetchall()
            
            print("\nUsuários disponíveis:")
            for user in users:
                print(f"  {user[0]}. {user[1]} ({user[2]})")
            
            print("\nDigite o ID do usuário: ", end='')
            user_id = input().strip()
            
            try:
                user_id = int(user_id)
                cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
                conn.commit()
                
                cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                username = cursor.fetchone()[0]
                print(f"\n✅ Usuário '{username}' agora é administrador!")
                
                # Continua para resetar a senha
                admins = [(user_id, username, "")]
            except:
                print("\n❌ ID inválido")
                conn.close()
                return False
        else:
            conn.close()
            return False
    
    print("Administradores disponíveis:")
    for admin in admins:
        print(f"  {admin[0]}. {admin[1]} ({admin[2]})")
    print()
    
    # Seleciona o admin
    if len(admins) == 1:
        selected_id, selected_username, selected_email = admins[0]
        print(f"Resetando senha de: {selected_username}")
    else:
        print("Digite o ID do admin para resetar a senha: ", end='')
        try:
            selected_id = int(input().strip())
            cursor.execute("SELECT username, email FROM users WHERE id = ? AND is_admin = 1", (selected_id,))
            result = cursor.fetchone()
            if not result:
                print("❌ Usuário não encontrado ou não é admin")
                conn.close()
                return False
            selected_username, selected_email = result
        except:
            print("❌ ID inválido")
            conn.close()
            return False
    
    print()
    print("-" * 60)
    print(f"Usuário: {selected_username}")
    print(f"Email: {selected_email}")
    print("-" * 60)
    print()
    
    # Solicita nova senha
    while True:
        senha1 = getpass("Nova senha (mínimo 6 caracteres): ")
        
        if len(senha1) < 6:
            print("❌ Senha muito curta! Use no mínimo 6 caracteres.")
            continue
        
        senha2 = getpass("Confirme a nova senha: ")
        
        if senha1 != senha2:
            print("❌ Senhas não conferem! Tente novamente.")
            continue
        
        break
    
    # Criptografa a senha
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
    senha_hash = pwd_context.hash(senha1)
    
    # Atualiza no banco
    cursor.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (senha_hash, selected_id))
    conn.commit()
    conn.close()
    
    print()
    print("=" * 60)
    print("✅ SENHA RESETADA COM SUCESSO!")
    print("=" * 60)
    print()
    print("📋 Credenciais de acesso:")
    print(f"   Username: {selected_username}")
    print(f"   Senha: {senha1}")
    print()
    print("🌐 Acesse o painel admin em:")
    print("   http://localhost:8000/admin-login.html")
    print()
    
    return True

if __name__ == "__main__":
    try:
        reset_admin_password()
    except KeyboardInterrupt:
        print("\n\n❌ Operação cancelada pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro inesperado: {e}")
        sys.exit(1)
