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
        datetime_type = "TIMESTAMP" if engine.dialect.name == "postgresql" else "DATETIME"
        
        # Lista de colunas a adicionar
        columns_to_add = [
            ("subscription_plan", "VARCHAR DEFAULT 'starter'"),
            ("subscription_status", "VARCHAR DEFAULT 'active'"),
            ("subscription_start", datetime_type),
            ("subscription_end", datetime_type),
            ("scans_this_month", "INTEGER DEFAULT 0"),
            ("scans_limit", "INTEGER DEFAULT 10"),
            ("stripe_customer_id", "VARCHAR"),
            ("stripe_subscription_id", "VARCHAR"),
            ("mercadopago_customer_id", "VARCHAR"),
            ("is_trial", "BOOLEAN DEFAULT 0"),
            ("trial_started_at", datetime_type),
            ("access_key_hash", "VARCHAR"),
            ("access_key_last4", "VARCHAR"),
            ("access_key_issued_at", datetime_type),
            ("access_key_used_at", datetime_type),
            ("access_key_required", "BOOLEAN DEFAULT FALSE"),
            ("active_session_hash", "VARCHAR"),
            ("active_session_last_activity", datetime_type),
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

        # Contas já existentes antes da validação por chave permanecem válidas
        # e não passam a exigir uma chave retroativamente.
        db.execute(text("UPDATE users SET access_key_required = FALSE WHERE access_key_required IS NULL"))
        db.execute(text(
            "UPDATE users SET access_key_required = 1 "
            "WHERE access_key_hash IS NOT NULL AND access_key_used_at IS NULL AND COALESCE(is_admin, FALSE) = FALSE"
        ))
        db.execute(text("UPDATE users SET access_key_required = FALSE WHERE access_key_used_at IS NOT NULL"))
        db.commit()
        
        for user in users:
            updated = False
            
            if not hasattr(user, 'subscription_plan') or user.subscription_plan is None:
                user.subscription_plan = 'starter'
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

            if not hasattr(user, 'access_key_required') or user.access_key_required is None:
                user.access_key_required = False
                updated = True

            # O plano Free foi removido. Usuários legados ficam sem acesso pago
            # até escolherem um dos planos disponíveis.
            if user.subscription_plan == 'free':
                user.subscription_plan = 'starter'
                user.subscription_status = 'pending'
                user.scans_limit = 100
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
