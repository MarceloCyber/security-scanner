#!/usr/bin/env python3
"""
Script para adicionar campos de reset de senha ao banco de dados
"""

import sqlite3
import sys

def migrate_database():
    try:
        # Conecta ao banco de dados
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        print("🔧 Adicionando campos de reset de senha...")
        
        # Adiciona coluna reset_token
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN reset_token TEXT')
            print("✅ Coluna reset_token adicionada")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("⚠️  Coluna reset_token já existe")
            else:
                raise
        
        # Adiciona coluna reset_token_expires
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN reset_token_expires DATETIME')
            print("✅ Coluna reset_token_expires adicionada")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("⚠️  Coluna reset_token_expires já existe")
            else:
                raise
        
        conn.commit()
        print("\n✅ Migração concluída com sucesso!")
        
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Erro durante a migração: {e}")
        sys.exit(1)

if __name__ == "__main__":
    migrate_database()
