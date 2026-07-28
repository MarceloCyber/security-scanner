import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email import encoders
from typing import List
import os
from pathlib import Path
from dotenv import load_dotenv
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# Carrega o .env da raiz do projeto, independentemente do diretório usado
# para iniciar o Uvicorn. Em produção, as variáveis do ambiente continuam
# tendo prioridade quando já estiverem definidas pelo provedor.
project_env = Path(__file__).resolve().parents[2] / '.env'
load_dotenv(dotenv_path=project_env, override=False)

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com').strip()
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER', '').strip()
        # Senhas de app às vezes são copiadas com espaços de formatação.
        # O Gmail espera os 16 caracteres sem espaços.
        self.smtp_password = ''.join(os.getenv('SMTP_PASSWORD', '').split())
        self.from_email = os.getenv('FROM_EMAIL', self.smtp_user).strip()
        self.from_name = os.getenv('FROM_NAME', 'Iron Net').strip()

    def validate_config(self) -> tuple[bool, str]:
        if not self.smtp_host:
            return False, 'SMTP_HOST nao foi configurado'
        if not self.smtp_user:
            return False, 'SMTP_USER nao foi configurado'
        if not self.smtp_password:
            return False, 'SMTP_PASSWORD nao foi configurado'
        if not self.from_email:
            return False, 'FROM_EMAIL nao foi configurado'
        if not 1 <= self.smtp_port <= 65535:
            return False, 'SMTP_PORT deve estar entre 1 e 65535'
        return True, 'Configuracao SMTP valida'

    def test_connection(self) -> tuple[bool, str]:
        is_valid, message = self.validate_config()
        if not is_valid:
            logger.error('Configuracao SMTP invalida: %s', message)
            return False, message

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
            logger.info('Conexao SMTP autenticada com sucesso para %s', self.smtp_user)
            return True, 'Conexao SMTP autenticada com sucesso'
        except (smtplib.SMTPException, OSError) as exc:
            logger.exception('Falha ao autenticar no servidor SMTP %s:%s', self.smtp_host, self.smtp_port)
            return False, str(exc)

    def send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None, attachments: List[tuple] = None):
        """Send an email"""
        is_valid, message = self.validate_config()
        if not is_valid:
            logger.error('Email para %s nao enviado: %s', to_email, message)
            return False
        try:
            message = MIMEMultipart('mixed')
            message['Subject'] = subject
            message['From'] = f'{self.from_name} <{self.from_email}>'
            message['To'] = to_email

            alt = MIMEMultipart('alternative')
            if text_content:
                part1 = MIMEText(text_content, 'plain')
                alt.attach(part1)
            part2 = MIMEText(html_content, 'html')
            alt.attach(part2)
            message.attach(alt)

            if attachments:
                for filename, content_bytes, subtype in attachments:
                    try:
                        maintype = 'application'
                        sub = subtype or 'octet-stream'
                        part = MIMEBase(maintype, sub)
                        part.set_payload(content_bytes)
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
                        message.attach(part)
                    except Exception:
                        # Fallback using MIMEApplication
                        part = MIMEApplication(content_bytes, _subtype=subtype or 'octet-stream')
                        part.add_header('Content-Disposition', 'attachment', filename=filename)
                        message.attach(part)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, to_email, message.as_string())

            logger.info('Email enviado para %s com assunto %r', to_email, subject)
            return True
        except Exception as e:
            error_text = str(e)
            if '535' in error_text or 'BadCredentials' in error_text:
                logger.error(
                    'Autenticacao SMTP recusada ao enviar email para %s. '
                    'Use uma senha de app valida da mesma conta configurada em SMTP_USER.',
                    to_email,
                )
            else:
                logger.exception('Erro ao enviar email para %s: %s', to_email, error_text)
            return False

    def generate_lgpd_contract_pdf(self, plan: str) -> bytes:
        html, text = self.generate_lgpd_contract_content(plan)
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph("Contrato de Prestação de Serviços e Tratamento de Dados (LGPD)", styles['Title']))
        elements.append(Spacer(1, 12))
        for line in text.splitlines():
            if line.strip() == "":
                elements.append(Spacer(1, 10))
            else:
                elements.append(Paragraph(line, styles['Normal']))
        doc.build(elements)
        return buffer.getvalue()

    def generate_lgpd_contract_content(self, plan: str):
        dpo_email = os.getenv('DPO_EMAIL', self.from_email)
        company_name = os.getenv('COMPANY_NAME', 'Iron Net')
        forum_city = os.getenv('FORUM_CITY', 'São Paulo')
        forum_state = os.getenv('FORUM_STATE', 'SP')
        html = f"""
        <div style="margin-top: 30px; background: #ffffff; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea;">
            <h3 style="margin-top: 0;">📄 Contrato de Prestação de Serviços e Tratamento de Dados (LGPD)</h3>
            <p>Este instrumento estabelece os termos da prestação de serviços de segurança e análise oferecidos por {company_name} ao Usuário/Contratante, nos termos da Lei nº 13.709/2018 (LGPD) e demais legislação aplicável.</p>

            <h4>1. Partes e Objeto</h4>
            <p>{company_name} fornece ferramentas para avaliação de segurança, varreduras e relatórios. O Usuário/Contratante declara utilizar os serviços exclusivamente em ativos próprios ou para os quais possua autorização expressa.</p>

            <h4>2. Definições</h4>
            <p>Controlador, Operador, Titular, Dados Pessoais, Dados Sensíveis, Tratamento, Incidente de Segurança, conforme LGPD.</p>

            <h4>3. Aceitação</h4>
            <p>Ao concluir o cadastro ou adquirir o plano {plan}, o Usuário/Contratante concorda integralmente com este contrato e com a Política de Privacidade.</p>

            <h4>4. Tratamento de Dados</h4>
            <p>Coleta e uso de dados estritamente necessários para: criação e gestão de conta, autenticação, faturamento, suporte, geração de relatórios, melhoria de produto e cumprimento de obrigações legais.</p>

            <h4>5. Bases Legais</h4>
            <p>Execução de contrato, cumprimento de obrigação legal/regulatória, legítimo interesse, consentimento quando exigido e proteção ao crédito, conforme aplicável.</p>

            <h4>6. Direitos do Titular</h4>
            <p>Acesso, correção, anonimização, portabilidade, eliminação, revogação de consentimento, informação sobre compartilhamentos e revisão de decisões automatizadas, mediante requisição e comprovação de identidade.</p>

            <h4>7. Compartilhamento</h4>
            <p>Prestadores de serviços estritamente necessários (infraestrutura, email, pagamento), sempre com cláusulas de proteção de dados. Transferências internacionais obedecem aos requisitos da LGPD.</p>

            <h4>8. Retenção</h4>
            <p>Dados mantidos pelo tempo necessário ao cumprimento das finalidades, prazos legais e defesa de direitos. Após esse período, serão eliminados ou anonimizados.</p>

            <h4>9. Segurança</h4>
            <p>Medidas técnicas e administrativas proporcionais ao risco, inclusive controle de acesso, criptografia em repouso/Trânsito quando aplicável, registros de auditoria e resposta a incidentes.</p>

            <h4>10. Registros e Auditoria</h4>
            <p>Logs de uso e de eventos podem ser coletados para segurança, integridade dos serviços e investigação de abusos.</p>

            <h4>11. Uso das Ferramentas</h4>
            <p>É proibida a utilização em sistemas de terceiros sem autorização. O Usuário/Contratante assume responsabilidade integral por cada operação realizada, resultados obtidos e seus efeitos.</p>

            <h4>12. Responsabilidades</h4>
            <p>O Usuário/Contratante é exclusivamente responsável por: licitude das atividades, autorizações, escopo dos testes, impactos gerados e comunicação a terceiros. {company_name} não se responsabiliza por uso indevido, danos diretos, indiretos, lucros cessantes, perdas de dados ou interrupções decorrentes da utilização inadequada das ferramentas.</p>

            <h4>13. Limitação de Responsabilidade</h4>
            <p>Responsabilidade de {company_name} limita-se aos valores efetivamente pagos pelo Usuário/Contratante nos últimos 12 meses, exceto quando vedado pela legislação. Não há garantias de adequação para fins específicos.</p>

            <h4>14. Suporte e Disponibilidade</h4>
            <p>Disponibilidade e níveis de suporte conforme plano contratado. Janelas de manutenção podem ocorrer.</p>

            <h4>15. Rescisão</h4>
            <p>Qualquer parte pode rescindir mediante aviso. Em caso de violação, {company_name} poderá suspender ou encerrar imediatamente.</p>

            <h4>16. Atualizações</h4>
            <p>Este contrato pode ser atualizado. Alterações materiais serão comunicadas. O uso continuado implica concordância.</p>

            <h4>17. Foro</h4>
            <p>Fica eleito o foro da Comarca de {forum_city}/{forum_state}, Brasil, para dirimir controvérsias, com renúncia a qualquer outro, por mais privilegiado que seja.</p>

            <h4>18. Encarregado</h4>
            <p>Contato do Encarregado de Proteção de Dados: {dpo_email}.</p>
        </div>
        """
        text = (
            "CONTRATO DE PRESTAÇÃO DE SERVIÇOS E TRATAMENTO DE DADOS (LGPD)\n"
            f"Este instrumento estabelece os termos da prestação de serviços de segurança oferecidos por {company_name}.\n\n"
            f"1. Partes e Objeto: {company_name} fornece ferramentas para avaliação de segurança. Uso apenas em ativos próprios ou autorizados.\n"
            f"2. Definições: Controlador, Operador, Titular, Dados Pessoais, Sensíveis, Tratamento, Incidente.\n"
            f"3. Aceitação: Ao concluir o cadastro ou adquirir o plano {plan}, você concorda integralmente.\n"
            "4. Tratamento de Dados: Coleta e uso necessários para conta, autenticação, faturamento, suporte, relatórios e obrigações legais.\n"
            "5. Bases Legais: Execução de contrato, obrigação legal, legítimo interesse, consentimento, proteção ao crédito.\n"
            "6. Direitos do Titular: acesso, correção, anonimização, portabilidade, eliminação, revogação de consentimento, informação e revisão de decisões automatizadas.\n"
            "7. Compartilhamento: Prestadores essenciais, com cláusulas de proteção. Transferência internacional conforme LGPD.\n"
            "8. Retenção: Pelo tempo necessário às finalidades, prazos legais e defesa de direitos; após, eliminação ou anonimização.\n"
            "9. Segurança: Medidas técnicas/administrativas proporcionais ao risco; controle de acesso, criptografia, auditoria, resposta a incidentes.\n"
            "10. Registros/Auditoria: Coleta de logs para segurança e investigação de abusos.\n"
            "11. Uso das Ferramentas: Proibido uso sem autorização em sistemas de terceiros; responsabilidade integral do usuário.\n"
            f"12. Responsabilidades: Licitude, autorizações, escopo e impactos são do usuário; {company_name} não responde por uso indevido, danos diretos/indiretos, lucros cessantes, perdas de dados ou interrupções.\n"
            f"13. Limitação de Responsabilidade: Limitada aos valores pagos nos últimos 12 meses, salvo vedação legal; sem garantias de adequação.\n"
            "14. Suporte/Disponibilidade: Conforme plano; janelas de manutenção podem ocorrer.\n"
            "15. Rescisão: Aviso por qualquer parte; violação pode gerar suspensão ou encerramento imediato.\n"
            "16. Atualizações: Contrato pode ser atualizado; uso continuado implica concordância.\n"
            f"17. Foro: Comarca de {forum_city}/{forum_state}, Brasil.\n"
            f"18. Encarregado: {dpo_email}.\n"
        )
        return html, text

    def send_welcome_email(self, to_email: str, username: str, plan: str = 'free'):
        """Send welcome email to new user"""
        plan_names = {
            'free': 'Free',
            'starter': 'Starter',
            'professional': 'Professional',
            'enterprise': 'Enterprise'
        }

        subject = f'Bem-vindo à Iron Net - Plano {plan_names.get(plan, "Free")}'
        base = os.getenv('FRONTEND_URL', 'http://localhost:8000')
        contract_base = os.getenv('BACKEND_URL', base)
        
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
                    </div>
                    
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
                        <a href="{base}/index.html" class="button">
                            Acessar Plataforma
                        </a>
                    </div>

                    <div style="text-align: center;">
                        <a href="{contract_base}/contrato/lgpd?plan={plan_names.get(plan, 'Free')}" class="button">Ver Contrato (LGPD)</a>
                    </div>
                    <p style="text-align:center; margin-top: 8px;">
                        Ver Contrato (LGPD):
                        <a href="{contract_base}/contrato/lgpd?plan={plan_names.get(plan, 'Free')}" style="text-decoration: underline; color: #2c3e50;">
                            {contract_base}/contrato/lgpd?plan={plan_names.get(plan, 'Free')}
                        </a>
                    </p>

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

        Acesse: {base}/index.html

        Iron Net - Proteção Profissional para Suas Aplicações
        """

        text_content = f"{text_content}\n\nContrato (LGPD): {contract_base}/contrato/lgpd?plan={plan_names.get(plan, 'Free')}\nBaixar PDF no link acima."
        return self.send_email(to_email, subject, html_content, text_content)

    def send_paid_welcome_email(self, to_email: str, username: str, plan: str, manual_url: str):
        plan_names = {
            'starter': 'Starter',
            'professional': 'Professional',
            'enterprise': 'Enterprise'
        }

        subject = f'Bem-vindo à Iron Net - Plano {plan_names.get(plan, "")} Ativado'
        base = os.getenv('FRONTEND_URL', 'http://localhost:8000')
        contract_base = os.getenv('BACKEND_URL', base)

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
                    <div style="text-align: center;">
                        <a href="{contract_base}/contrato/lgpd?plan={plan_names.get(plan, '')}" class="button">Ver Contrato (LGPD)</a>
                    </div>
                    <p style="text-align:center; margin-top: 8px;">
                        Ver Contrato (LGPD):
                        <a href="{contract_base}/contrato/lgpd?plan={plan_names.get(plan, '')}" style="text-decoration: underline; color: #2c3e50;">
                            {contract_base}/contrato/lgpd?plan={plan_names.get(plan, '')}
                        </a>
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

        Seu pagamento foi confirmado e sua conta foi ativada no plano {plan_names.get(plan, '')}.

        Detalhes:
        - Usuário: {username}
        - Email: {to_email}
        - Plano: {plan_names.get(plan, '')}

        Manual da plataforma: {manual_url}
        Login: {os.getenv('FRONTEND_URL', 'http://localhost:8000')}/index.html

        Iron Net - Proteção Profissional para Suas Aplicações
        """

        text_content = f"{text_content}\n\nContrato (LGPD): {contract_base}/contrato/lgpd?plan={plan_names.get(plan, '')}\nBaixar PDF no link acima."
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
