"""
Script para migrar banco de dados adicionando campos de assinatura
"""
import sys
import os

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text
from database import engine, SessionLocal
from models.user import User

def migrate_database():
    """
    Adiciona novos campos de assinatura ao banco de dados existente
    """
    db = SessionLocal()
    
    try:
        print("🔄 Iniciando migração do banco de dados...")
        
        # Lista de colunas a adicionar
        columns_to_add = [
            ("subscription_plan", "VARCHAR DEFAULT 'free'"),
            ("subscription_status", "VARCHAR DEFAULT 'active'"),
            ("subscription_start", "DATETIME"),
            ("subscription_end", "DATETIME"),
            ("scans_this_month", "INTEGER DEFAULT 0"),
            ("scans_limit", "INTEGER DEFAULT 10"),
            ("stripe_customer_id", "VARCHAR"),
            ("stripe_subscription_id", "VARCHAR"),
            ("mercadopago_customer_id", "VARCHAR"),
            ("is_trial", "BOOLEAN DEFAULT 0"),
        ]
        
        for column_name, column_type in columns_to_add:
            try:
                # Tentar adicionar a coluna
                sql = f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"
                db.execute(text(sql))
                db.commit()
                print(f"✅ Coluna '{column_name}' adicionada com sucesso")
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print(f"⚠️  Coluna '{column_name}' já existe, pulando...")
                else:
                    print(f"❌ Erro ao adicionar coluna '{column_name}': {e}")
                db.rollback()
        
        # Atualizar usuários existentes que não têm valores definidos
        print("\n🔄 Atualizando usuários existentes...")
        users = db.query(User).all()
        
        for user in users:
            updated = False
            
            if not hasattr(user, 'subscription_plan') or user.subscription_plan is None:
                user.subscription_plan = 'free'
                updated = True
            
            if not hasattr(user, 'subscription_status') or user.subscription_status is None:
                user.subscription_status = 'active'
                updated = True
            
            if not hasattr(user, 'scans_this_month') or user.scans_this_month is None:
                user.scans_this_month = 0
                updated = True
            
            if not hasattr(user, 'scans_limit') or user.scans_limit is None:
                user.scans_limit = 10
                updated = True
            
            if not hasattr(user, 'is_trial') or user.is_trial is None:
                user.is_trial = False
                updated = True
            
            if updated:
                db.commit()
                print(f"✅ Usuário '{user.username}' atualizado")
        
        print("\n✅ Migração concluída com sucesso!")
        print("\n📊 Status dos usuários:")
        users = db.query(User).all()
        for user in users:
            print(f"  - {user.username}: Plano {user.subscription_plan}, {user.scans_limit} scans/mês")
        
    except Exception as e:
        print(f"\n❌ Erro durante a migração: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    migrate_database()
