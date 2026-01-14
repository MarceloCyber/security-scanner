import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()

class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.from_email = os.getenv('FROM_EMAIL', self.smtp_user)
        self.from_name = os.getenv('FROM_NAME', 'Iron Net')

    def send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None):
        """Send an email"""
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = f'{self.from_name} <{self.from_email}>'
            message['To'] = to_email

            # Add plain text version if provided
            if text_content:
                part1 = MIMEText(text_content, 'plain')
                message.attach(part1)

            # Add HTML version
            part2 = MIMEText(html_content, 'html')
            message.attach(part2)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, to_email, message.as_string())

            return True
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False

    def send_welcome_email(self, to_email: str, username: str, plan: str = 'free'):
        """Send welcome email to new user"""
        plan_names = {
            'free': 'Free',
            'starter': 'Starter',
            'professional': 'Professional',
            'enterprise': 'Enterprise'
        }

        subject = f'Bem-vindo à Iron Net - Plano {plan_names.get(plan, "Free")}'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .credentials {{
                    background: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #667eea;
                }}
                .footer {{
                    text-align: center;
                    padding: 20px;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Bem-vindo à Iron Net!</h1>
                </div>
                <div class="content">
                    <h2>Olá, {username}!</h2>
                    <p>Sua conta foi criada com sucesso! Estamos muito felizes em tê-lo conosco.</p>
                    
                    <div class="credentials">
                        <h3>📋 Suas Credenciais de Acesso:</h3>
                        <p><strong>Usuário:</strong> {username}</p>
                        <p><strong>Email:</strong> {to_email}</p>
                        <p><strong>Plano:</strong> {plan_names.get(plan, 'Free')}</p>
                    </p>
                    
                    <div style="margin: 30px 0;">
                        <h3>🚀 Próximos Passos:</h3>
                        <ul>
                            <li>Faça login na plataforma com suas credenciais</li>
                            <li>Configure seu primeiro projeto de segurança</li>
                            <li>Execute suas primeiras varreduras</li>
                            <li>Explore todas as ferramentas disponíveis</li>
                        </ul>
                    </div>

                    <div style="text-align: center;">
                        <a href="http://localhost:8000/index.html" class="button">
                            Acessar Plataforma
                        </a>
                    </div>

                    <p style="margin-top: 30px; color: #666; font-size: 14px;">
                        <strong>💡 Dica:</strong> Mantenha suas credenciais em local seguro. 
                        Nunca compartilhe sua senha com terceiros.
                    </p>
                </div>
                <div class="footer">
                    <p>Iron Net - Proteção Profissional para Suas Aplicações</p>
                    <p>Este é um email automático, por favor não responda.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Bem-vindo à Iron Net!

        Olá, {username}!

        Sua conta foi criada com sucesso!

        Suas Credenciais de Acesso:
        - Usuário: {username}
        - Email: {to_email}
        - Plano: {plan_names.get(plan, 'Free')}

        Próximos Passos:
        1. Faça login na plataforma com suas credenciais
        2. Configure seu primeiro projeto de segurança
        3. Execute suas primeiras varreduras
        4. Explore todas as ferramentas disponíveis

        Acesse: http://localhost:8000/index.html

        Iron Net - Proteção Profissional para Suas Aplicações
        """

        return self.send_email(to_email, subject, html_content, text_content)

    def send_paid_welcome_email(self, to_email: str, username: str, plan: str, manual_url: str):
        plan_names = {
            'starter': 'Starter',
            'professional': 'Professional',
            'enterprise': 'Enterprise'
        }

        subject = f'Bem-vindo à Iron Net - Plano {plan_names.get(plan, "")} Ativado'

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                .details {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #667eea; }}
                .button {{ display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Bem-vindo à Iron Net!</h1>
                </div>
                <div class="content">
                    <h2>Olá, {username}!</h2>
                    <p>Seu pagamento foi confirmado e sua conta foi ativada no plano {plan_names.get(plan, '')}.</p>
                    <div class="details">
                        <h3>📋 Detalhes:</h3>
                        <p><strong>Usuário:</strong> {username}</p>
                        <p><strong>Email:</strong> {to_email}</p>
                        <p><strong>Plano:</strong> {plan_names.get(plan, '')}</p>
                    </div>
                    <p>Para começar, acesse o manual da plataforma com guias e melhores práticas:</p>
                    <div style="text-align: center;">
                        <a href="{manual_url}" class="button">Acessar Manual</a>
                    </div>
                    <p style="margin-top: 24px; color: #666; font-size: 14px;">Você também pode fazer login e explorar o dashboard.</p>
                    <div style="text-align: center;">
                        <a href="{os.getenv('FRONTEND_URL', 'http://localhost:8000')}/index.html" class="button">Entrar na Plataforma</a>
                    </div>
                </div>
                <div class="footer">
                    <p>Iron Net - Proteção Profissional para Suas Aplicações</p>
                    <p>Este é um email automático, por favor não responda.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Bem-vindo à Iron Net!

        Olá, {username}!

        Seu pagamento foi confirmado e sua conta foi ativada no plano {plan_names.get(plan, '')}.

        Detalhes:
        - Usuário: {username}
        - Email: {to_email}
        - Plano: {plan_names.get(plan, '')}

        Manual da plataforma: {manual_url}
        Login: {os.getenv('FRONTEND_URL', 'http://localhost:8000')}/index.html

        Iron Net - Proteção Profissional para Suas Aplicações
        """

        return self.send_email(to_email, subject, html_content, text_content)

    def send_subscription_confirmation(self, to_email: str, username: str, plan: str, amount: float):
        """Send subscription confirmation email"""
        plan_names = {
            'starter': 'Starter',
            'professional': 'Professional',
            'enterprise': 'Enterprise'
        }

        subject = f'Confirmação de Assinatura - Plano {plan_names.get(plan, "")}'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .success-icon {{
                    font-size: 48px;
                    text-align: center;
                    margin: 20px 0;
                }}
                .subscription-details {{
                    background: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #48bb78;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    padding: 20px;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Pagamento Confirmado!</h1>
                </div>
                <div class="content">
                    <div class="success-icon">🎉</div>
                    
                    <h2>Olá, {username}!</h2>
                    <p>Seu pagamento foi processado com sucesso e sua assinatura está ativa!</p>
                    
                    <div class="subscription-details">
                        <h3>📄 Detalhes da Assinatura:</h3>
                        <p><strong>Plano:</strong> {plan_names.get(plan, '')}</p>
                        <p><strong>Valor:</strong> R$ {amount:.2f}/mês</p>
                        <p><strong>Status:</strong> Ativa</p>
                    </div>
                    
                    <div style="margin: 30px 0;">
                        <h3>🎁 O que você ganhou:</h3>
                        <ul>
                            <li>✅ Acesso ilimitado a todas as ferramentas premium</li>
                            <li>✅ Relatórios detalhados e exportação de dados</li>
                            <li>✅ Suporte prioritário 24/7</li>
                            <li>✅ Dashboard analytics avançado</li>
                            <li>✅ Atualizações automáticas</li>
                        </ul>
                    </div>

                    <div style="text-align: center;">
                        <a href="http://localhost:8000/dashboard.html" class="button">
                            Acessar Dashboard
                        </a>
                    </div>

                    <p style="margin-top: 30px; color: #666; font-size: 14px;">
                        Sua assinatura será renovada automaticamente a cada mês. 
                        Você pode cancelar a qualquer momento no painel de controle.
                    </p>
                </div>
                <div class="footer">
                    <p>Iron Net - Proteção Profissional para Suas Aplicações</p>
                    <p>Este é um email automático, por favor não responda.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Pagamento Confirmado!

        Olá, {username}!

        Seu pagamento foi processado com sucesso e sua assinatura está ativa!

        Detalhes da Assinatura:
        - Plano: {plan_names.get(plan, '')}
        - Valor: R$ {amount:.2f}/mês
        - Status: Ativa

        O que você ganhou:
        - Acesso ilimitado a todas as ferramentas premium
        - Relatórios detalhados e exportação de dados
        - Suporte prioritário 24/7
        - Dashboard analytics avançado
        - Atualizações automáticas

        Acesse seu dashboard: http://localhost:8000/dashboard.html

        Iron Net - Proteção Profissional para Suas Aplicações
        """

        return self.send_email(to_email, subject, html_content, text_content)

    def send_password_reset_email(self, to_email: str, username: str, reset_link: str):
        """Send password reset email"""
        subject = 'Reset de Senha - Iron Net Admin'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Reset de Senha</h1>
                </div>
                <div class="content">
                    <p>Olá, <strong>{username}</strong>!</p>
                    
                    <p>Você solicitou o reset de senha para sua conta de administrador na Iron Net.</p>
                    
                    <p>Clique no botão abaixo para criar uma nova senha:</p>
                    
                    <center>
                        <a href="{reset_link}" class="button">Resetar Senha</a>
                    </center>
                    
                    <div class="warning">
                        <strong>⚠️ Importante:</strong>
                        <ul>
                            <li>Este link é válido por apenas 1 hora</li>
                            <li>Se você não solicitou este reset, ignore este email</li>
                            <li>Nunca compartilhe este link com ninguém</li>
                        </ul>
                    </div>
                    
                    <p>Se o botão não funcionar, copie e cole este link no navegador:</p>
                    <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 5px;">
                        {reset_link}
                    </p>
                    
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                    
                    <p style="color: #666; font-size: 12px;">
                        Iron Net - Painel Administrativo<br>
                        Este é um email automático, não responda.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Reset de Senha - Iron Net Admin

        Olá, {username}!

        Você solicitou o reset de senha para sua conta de administrador.

        Acesse o link abaixo para criar uma nova senha:
        {reset_link}

        ⚠️ IMPORTANTE:
        - Este link é válido por apenas 1 hora
        - Se você não solicitou este reset, ignore este email
        - Nunca compartilhe este link com ninguém

        Iron Net - Painel Administrativo
        """

        return self.send_email(to_email, subject, html_content, text_content)

    def send_user_password_reset_email(self, to_email: str, username: str, reset_link: str):
        subject = 'Reset de Senha - Iron Net'
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Reset de Senha</h1>
                </div>
                <div class="content">
                    <p>Olá, <strong>{username}</strong>!</p>
                    <p>Você solicitou o reset de senha para sua conta na Iron Net.</p>
                    <p>Clique no botão abaixo para criar uma nova senha:</p>
                    <center>
                        <a href="{reset_link}" class="button">Resetar Senha</a>
                    </center>
                    <div class="warning">
                        <strong>⚠️ Importante:</strong>
                        <ul>
                            <li>Este link é válido por apenas 1 hora</li>
                            <li>Se você não solicitou este reset, ignore este email</li>
                            <li>Nunca compartilhe este link com ninguém</li>
                        </ul>
                    </div>
                    <p>Se o botão não funcionar, copie e cole este link no navegador:</p>
                    <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 5px;">
                        {reset_link}
                    </p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                    <p style="color: #666; font-size: 12px;">
                        Iron Net - Plataforma<br>
                        Este é um email automático, não responda.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        text_content = f"""
        Reset de Senha - Iron Net

        Olá, {username}!

        Você solicitou o reset de senha para sua conta.

        Acesse o link abaixo para criar uma nova senha:
        {reset_link}

        ⚠️ IMPORTANTE:
        - Este link é válido por apenas 1 hora
        - Se você não solicitou este reset, ignore este email
        - Nunca compartilhe este link com ninguém

        Iron Net - Plataforma
        """
        return self.send_email(to_email, subject, html_content, text_content)

# Create singleton instance
email_service = EmailService()
