"""
Script de migração para adicionar coluna is_admin na tabela users
Execute este script uma única vez para atualizar o banco de dados existente
"""
import sqlite3
import sys
from pathlib import Path

# Caminho para o banco de dados
DB_PATH = Path(__file__).parent / "security_scanner.db"

def migrate():
    """Adiciona coluna is_admin à tabela users"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verifica se a coluna já existe
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_admin' in columns:
            print("✓ Coluna 'is_admin' já existe. Nenhuma ação necessária.")
            conn.close()
            return True
        
        # Adiciona a coluna is_admin
        print("Adicionando coluna 'is_admin' à tabela users...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
        conn.commit()
        
        print("✓ Coluna 'is_admin' adicionada com sucesso!")
        
        # Pergunta se quer definir um usuário como admin
        print("\n" + "="*50)
        print("CONFIGURAÇÃO DE ADMINISTRADOR")
        print("="*50)
        
        # Lista usuários existentes
        cursor.execute("SELECT id, username, email FROM users ORDER BY id")
        users = cursor.fetchall()
        
        if users:
            print("\nUsuários existentes:")
            for user in users:
                print(f"  ID: {user[0]} | Username: {user[1]} | Email: {user[2]}")
            
            print("\nDeseja definir um usuário como administrador? (s/n): ", end='')
            resposta = input().strip().lower()
            
            if resposta == 's':
                print("Digite o ID do usuário que será administrador: ", end='')
                user_id = input().strip()
                
                try:
                    user_id = int(user_id)
                    cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
                    conn.commit()
                    
                    # Verifica se o update funcionou
                    cursor.execute("SELECT username FROM users WHERE id = ? AND is_admin = 1", (user_id,))
                    admin_user = cursor.fetchone()
                    
                    if admin_user:
                        print(f"\n✓ Usuário '{admin_user[0]}' definido como administrador!")
                    else:
                        print(f"\n✗ Erro: Usuário com ID {user_id} não encontrado.")
                
                except ValueError:
                    print("\n✗ ID inválido. Nenhum usuário foi definido como admin.")
                except Exception as e:
                    print(f"\n✗ Erro ao definir administrador: {e}")
        else:
            print("\nNenhum usuário encontrado no banco de dados.")
            print("Crie uma conta primeiro e depois execute este script novamente.")
        
        conn.close()
        return True
        
    except sqlite3.OperationalError as e:
        print(f"✗ Erro ao acessar banco de dados: {e}")
        print(f"Certifique-se de que o arquivo {DB_PATH} existe.")
        return False
    except Exception as e:
        print(f"✗ Erro inesperado: {e}")
        return False

if __name__ == "__main__":
    print("="*50)
    print("MIGRAÇÃO DO BANCO DE DADOS")
    print("Adicionando suporte para administradores")
    print("="*50)
    print()
    
    if not DB_PATH.exists():
        print(f"✗ Banco de dados não encontrado em: {DB_PATH}")
        print("Execute o backend pelo menos uma vez para criar o banco.")
        sys.exit(1)
    
    success = migrate()
    
    print("\n" + "="*50)
    if success:
        print("✓ MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
        print("="*50)
        print("\nPróximos passos:")
        print("1. Reinicie o backend se estiver rodando")
        print("2. Faça login com a conta admin")
        print("3. Acesse o painel admin em: http://localhost:8000/admin.html")
    else:
        print("✗ MIGRAÇÃO FALHOU")
        print("="*50)
        print("Por favor, corrija os erros acima e tente novamente.")
        sys.exit(1)