#!/usr/bin/env python3
"""
Script para criar usuário de teste
"""

from database import SessionLocal
from models.user import User
from auth import get_password_hash

def create_test_user():
    db = SessionLocal()
    
    try:
        # Verifica se o usuário teste já existe
        existing_user = db.query(User).filter(User.username == "teste").first()
        
        if existing_user:
            print("⚠️  Usuário 'teste' já existe. Atualizando senha...")
            existing_user.hashed_password = get_password_hash("teste123")
            existing_user.subscription_plan = "professional"
            existing_user.subscription_status = "active"
            existing_user.scans_limit = -1
            existing_user.scans_this_month = 0
            db.commit()
            print("✅ Senha atualizada com sucesso!")
        else:
            print("Criando novo usuário 'teste'...")
            # Cria novo usuário
            new_user = User(
                username="teste",
                email="teste@example.com",
                hashed_password=get_password_hash("teste123"),
                subscription_plan="professional",
                subscription_status="active",
                scans_limit=-1,
                scans_this_month=0
            )
            db.add(new_user)
            db.commit()
            print("✅ Usuário 'teste' criado com sucesso!")
        
        # Lista todos os usuários
        print("\n=== USUÁRIOS NO BANCO ===")
        users = db.query(User).all()
        for user in users:
            print(f"  • Username: {user.username}, Email: {user.email}")
        print(f"\nTotal: {len(users)} usuários")
        
        print("\n📝 Credenciais de acesso:")
        print("   Username: teste")
        print("   Password: teste123")
        
    except Exception as e:
        print(f"❌ Erro: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_test_user()
