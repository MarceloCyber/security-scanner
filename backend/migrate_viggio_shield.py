#!/usr/bin/env python3
"""
Migração do banco de dados para adicionar tabelas do Viggio Shield
"""
import sys
import os

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base
from models.monitor import MonitorTarget, MonitorIncident, MonitorLog, BlockedIP
from sqlalchemy import inspect

def check_table_exists(table_name):
    """Verifica se uma tabela já existe"""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()

def migrate():
    """Executa a migração"""
    print("🛡️  Iniciando migração do Viggio Shield...")
    
    tables_to_create = [
        ('monitor_targets', MonitorTarget),
        ('monitor_incidents', MonitorIncident),
        ('monitor_logs', MonitorLog),
        ('blocked_ips', BlockedIP)
    ]
    
    tables_created = []
    tables_existing = []
    
    for table_name, model in tables_to_create:
        if check_table_exists(table_name):
            tables_existing.append(table_name)
            print(f"⏭️  Tabela '{table_name}' já existe, pulando...")
        else:
            print(f"✨ Criando tabela '{table_name}'...")
            model.__table__.create(bind=engine)
            tables_created.append(table_name)
            print(f"✅ Tabela '{table_name}' criada com sucesso!")
    
    print("\n" + "="*60)
    print("📊 RESUMO DA MIGRAÇÃO")
    print("="*60)
    
    if tables_created:
        print(f"\n✅ Tabelas criadas ({len(tables_created)}):")
        for table in tables_created:
            print(f"   • {table}")
    
    if tables_existing:
        print(f"\n⏭️  Tabelas já existentes ({len(tables_existing)}):")
        for table in tables_existing:
            print(f"   • {table}")
    
    print("\n✅ Migração concluída com sucesso!")
    print("\n🚀 Você já pode usar o Viggio Shield!")
    print("   Acesse: /viggio-shield.html\n")

if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"\n❌ Erro durante a migração: {e}")
        sys.exit(1)
