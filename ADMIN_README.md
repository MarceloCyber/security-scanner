# 🛡️ Painel Administrativo - Security Scanner

## 📋 Visão Geral

O painel administrativo oferece controle completo sobre a plataforma Security Scanner, permitindo gerenciar usuários, monitorar atividades e visualizar estatísticas em tempo real.

## ✨ Funcionalidades

### 📊 Dashboard
- **Estatísticas em tempo real**
  - Total de usuários e usuários ativos
  - Total de scans realizados
  - Receita mensal estimada
  - Novos usuários nos últimos 7 dias
- **Distribuição de planos**
  - Visualização gráfica de usuários por plano (Free, Starter, Professional, Enterprise)
  - Porcentagem de cada plano
- **Resumo de atividades**
  - Scans realizados nos últimos 7 dias
  - Novos cadastros na semana

### 👥 Gerenciamento de Usuários
- **Listagem completa** com paginação
- **Busca** por username ou email
- **Filtros** por plano de assinatura
- **Ações disponíveis**:
  - ✏️ **Editar usuário**: alterar email, plano, status, limites e privilégios admin
  - 🔄 **Resetar scans**: zerar contador mensal de scans
  - 🗑️ **Excluir usuário**: remover completamente (com proteção contra auto-exclusão)

### 📝 Log de Atividades
- **Monitoramento em tempo real** das últimas 50 atividades
- **Informações detalhadas**:
  - Usuário que executou o scan
  - Tipo de scan realizado
  - Alvo do scan
  - Vulnerabilidades encontradas
  - Data e hora da execução
- **Atualização manual** com botão de refresh

### 🖥️ Informações do Sistema
- **Sistema Operacional**
  - Plataforma (Linux, Windows, macOS)
  - Versão do Python
  - Hostname do servidor
- **Recursos do servidor**
  - Uso de CPU (%)
  - Uso de memória (%)
  - Uso de disco (%)
- **Estatísticas do banco de dados**
  - Total de usuários cadastrados
  - Total de scans realizados
  - Tamanho do banco de dados

## 🚀 Configuração Inicial

### Passo 1: Executar Migração do Banco de Dados

A migração adiciona a coluna `is_admin` à tabela de usuários:

```bash
cd backend
python migrate_add_admin.py
```

O script irá:
1. ✅ Verificar se a coluna `is_admin` já existe
2. ✅ Adicionar a coluna caso não exista
3. ✅ Listar todos os usuários existentes
4. ✅ Perguntar se deseja definir um usuário como administrador
5. ✅ Confirmar a operação

**Exemplo de execução:**

```
==================================================
MIGRAÇÃO DO BANCO DE DADOS
Adicionando suporte para administradores
==================================================

Adicionando coluna 'is_admin' à tabela users...
✓ Coluna 'is_admin' adicionada com sucesso!

==================================================
CONFIGURAÇÃO DE ADMINISTRADOR
==================================================

Usuários existentes:
  ID: 1 | Username: admin | Email: admin@example.com
  ID: 2 | Username: user123 | Email: user@example.com

Deseja definir um usuário como administrador? (s/n): s
Digite o ID do usuário que será administrador: 1

✓ Usuário 'admin' definido como administrador!

==================================================
✓ MIGRAÇÃO CONCLUÍDA COM SUCESSO!
==================================================
```

### Passo 2: Reiniciar o Backend

Após a migração, reinicie o servidor FastAPI:

```bash
# Se estiver rodando, pare com Ctrl+C e reinicie
cd backend
uvicorn main:app --reload
```

### Passo 3: Acessar o Painel Admin

1. **Faça login** com a conta de administrador
2. No **dashboard**, você verá um novo item na sidebar: **"Painel Admin"**
3. Clique para acessar: `http://localhost:8000/admin.html`

## 🔐 Segurança

### Proteções Implementadas

1. **Autenticação JWT obrigatória**
   - Todas as rotas admin requerem token válido
   
2. **Verificação de privilégios**
   - Middleware `require_admin()` valida se `is_admin = True`
   - Resposta 403 (Forbidden) para não-administradores
   
3. **Proteção contra auto-exclusão**
   - Administradores não podem excluir suas próprias contas
   
4. **Validação no frontend e backend**
   - Link do painel admin só aparece para administradores
   - API valida permissões em todas as requisições

### Endpoints Protegidos

Todos os endpoints abaixo requerem `is_admin = True`:

```
GET  /api/admin/stats                    # Estatísticas do dashboard
GET  /api/admin/users                    # Listar usuários
GET  /api/admin/users/{id}               # Detalhes do usuário
PUT  /api/admin/users/{id}               # Atualizar usuário
DEL  /api/admin/users/{id}               # Excluir usuário
POST /api/admin/users/{id}/reset-scans   # Resetar scans
GET  /api/admin/activity                 # Log de atividades
GET  /api/admin/system                   # Informações do sistema
```

## 📖 Manual de Uso

### Gerenciar Usuários

#### Buscar Usuário

1. Digite o **username ou email** no campo de busca
2. A lista será filtrada automaticamente (debounce de 500ms)

#### Filtrar por Plano

1. Selecione o plano no dropdown: **Todos**, **Free**, **Starter**, **Professional** ou **Enterprise**
2. A lista será atualizada instantaneamente

#### Editar Usuário

1. Clique no botão **✏️ Editar** na linha do usuário
2. Altere os campos desejados:
   - **Email**: novo email do usuário
   - **Plano**: Free, Starter, Professional, Enterprise
   - **Status**: Ativo, Cancelado, Expirado
   - **Limite de Scans**: quantidade mensal (0 = ilimitado)
   - **É Admin**: marque para tornar administrador
3. Clique em **Salvar Alterações**

**Nota**: Ao alterar o plano, os limites de scans são ajustados automaticamente:
- Free: 10 scans/mês
- Starter: 100 scans/mês
- Professional: 1000 scans/mês
- Enterprise: ilimitado

#### Resetar Scans

1. Clique no botão **🔄 Resetar** na linha do usuário
2. Confirme a ação
3. O contador `scans_this_month` será zerado

**Uso típico**: início de novo período de faturamento ou resolução de problemas

#### Excluir Usuário

1. Clique no botão **🗑️ Excluir** na linha do usuário
2. Confirme a exclusão no modal
3. O usuário será removido **permanentemente** junto com todos os seus scans

**⚠️ ATENÇÃO**: Esta ação é irreversível e remove:
- Cadastro do usuário
- Todos os scans realizados (cascade delete)
- Histórico completo

### Visualizar Atividades

1. Acesse a página **"Atividades"** na sidebar
2. Veja os últimos 50 scans realizados na plataforma
3. Clique em **"Atualizar"** para refresh manual

Informações exibidas:
- Nome do usuário
- Tipo de scan (port_scan, vulnerability, sql_injection, etc.)
- Alvo do scan
- Vulnerabilidades encontradas
- Data e hora

### Monitorar Sistema

1. Acesse a página **"Sistema"** na sidebar
2. Visualize informações em tempo real:

**Sistema Operacional**:
- Plataforma (Linux, Windows, Darwin)
- Versão do Python
- Nome do host

**Recursos**:
- CPU: % de uso atual
- Memória: % de uso atual
- Disco: % de uso atual

**Banco de Dados**:
- Total de usuários
- Total de scans
- Tamanho do banco

## 🎨 Interface

### Design System

- **Cores primárias**: Gradiente roxo/azul (#667eea → #764ba2)
- **Tipografia**: Inter, -apple-system, segoe UI
- **Ícones**: Font Awesome 6
- **Responsividade**: Mobile-first com breakpoints em 968px e 480px

### Componentes

1. **Header fixo** com logo, nome do admin e botão de logout
2. **Sidebar** com navegação entre páginas
3. **Cards de estatísticas** com ícones coloridos
4. **Tabelas responsivas** com ações inline
5. **Modais** para edição e confirmação
6. **Toast notifications** para feedback das ações

### Responsividade

- **Desktop (>968px)**: Layout completo com sidebar fixa
- **Tablet (768-968px)**: Sidebar colapsável com toggle
- **Mobile (<768px)**: 
  - Sidebar overlay
  - Tabelas com scroll horizontal
  - Cards empilhados verticalmente

## 🛠️ Desenvolvimento

### Estrutura de Arquivos

```
backend/
├── routes/
│   └── admin_routes.py          # API endpoints do admin
├── models/
│   └── user.py                  # Model com campo is_admin
├── middleware/
│   └── auth.py                  # Middleware de autenticação
├── migrate_add_admin.py         # Script de migração
└── main.py                      # Registro das rotas

frontend/
├── admin.html                   # Interface do painel
├── css/
│   └── admin.css                # Estilos do painel
└── js/
    └── admin.js                 # Lógica e API calls
```

### Tecnologias

**Backend**:
- FastAPI 0.104.1
- SQLAlchemy 2.0.23
- psutil 5.9.6 (informações do sistema)
- JWT para autenticação

**Frontend**:
- HTML5 semântico
- CSS3 com variáveis e grid/flexbox
- JavaScript ES6+ (async/await)
- Font Awesome 6.4.0

### Adicionar Novas Funcionalidades

#### Backend (admin_routes.py)

```python
@router.post("/api/admin/new-endpoint")
async def new_admin_function(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    # Seu código aqui
    return {"message": "Success"}
```

#### Frontend (admin.js)

```javascript
async function newAdminFunction() {
    try {
        const response = await fetchAPI('/api/admin/new-endpoint', {
            method: 'POST',
            body: JSON.stringify({ data: 'value' })
        });
        showToast('Operação realizada!', 'success');
    } catch (error) {
        showToast('Erro na operação', 'error');
    }
}
```

## 🐛 Troubleshooting

### Erro: "Acesso negado. Apenas administradores"

**Causa**: Usuário logado não tem `is_admin = True`

**Solução**:
```bash
cd backend
python migrate_add_admin.py
# Selecione seu usuário como admin
```

### Erro: "Token inválido ou expirado"

**Causa**: Token JWT expirou ou foi removido

**Solução**:
1. Faça logout
2. Faça login novamente
3. O token será renovado automaticamente

### Painel não carrega dados

**Causa**: Backend não está rodando ou rota não está registrada

**Solução**:
1. Verifique se o backend está ativo: `http://localhost:8000/docs`
2. Confirme que `admin_routes` está em `main.py`:
```python
from routes import admin_routes
app.include_router(admin_routes.router, tags=["Admin"])
```
3. Reinicie o backend

### Link "Painel Admin" não aparece

**Causa**: Campo `is_admin` não está sendo retornado pela API

**Solução**:
1. Confirme que `/api/user/subscription-info` retorna `is_admin`
2. Verifique o console do navegador (F12) para erros
3. Limpe o cache do navegador

### Erro ao excluir usuário

**Causa**: Tentando excluir a própria conta de admin

**Solução**: Administradores não podem excluir a si mesmos. Use outra conta admin ou faça logout e delete manualmente no banco.

## 📞 Suporte

Para problemas ou dúvidas:
- **Email**: mac526@hotmail.com
- **Documentação**: http://localhost:8000/documentation.html
- **FAQ**: http://localhost:8000/faq.html

## 📝 Changelog

### v1.0.0 (2024)
- ✨ Dashboard com estatísticas em tempo real
- ✨ Gerenciamento completo de usuários (CRUD)
- ✨ Log de atividades com histórico de scans
- ✨ Monitoramento de sistema (CPU, memória, disco)
- ✨ Interface responsiva e moderna
- ✨ Sistema de permissões com is_admin
- ✨ Proteção contra auto-exclusão
- ✨ Toast notifications
- ✨ Paginação e filtros
- ✨ Script de migração automatizado

## 📄 Licença

Este painel administrativo faz parte do Security Scanner Platform.
© 2024 Security Scanner. Todos os direitos reservados.