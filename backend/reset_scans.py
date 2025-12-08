"""
Script para resetar o contador de scans de um usuário
"""
import sys
sys.path.append('.')

from database import SessionLocal
from models.user import User

def reset_user_scans(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"Usuário '{username}' não encontrado")
            return
        
        print(f"Usuário: {user.username}")
        print(f"Plano: {user.subscription_plan}")
        print(f"Status: {user.subscription_status}")
        print(f"Scans este mês: {user.scans_this_month}")
        print(f"Limite de scans: {user.scans_limit}")
        
        # Resetar contador
        user.scans_this_month = 0
        db.commit()
        
        print(f"\n✅ Contador resetado! Scans este mês agora: {user.scans_this_month}")
        
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python reset_scans.py <username>")
        print("Exemplo: python reset_scans.py teste")
        sys.exit(1)
    
    username = sys.argv[1]
    reset_user_scans(username)
