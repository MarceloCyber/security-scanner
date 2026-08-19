import argparse
import sys

from utils.email_service import email_service


def main() -> int:
    parser = argparse.ArgumentParser(description='Verifica a configuracao SMTP da Iron AI.')
    parser.add_argument('--to', help='Destinatario para receber um email de teste.')
    args = parser.parse_args()

    is_valid, message = email_service.validate_config()
    if not is_valid:
        print(f'Configuracao SMTP invalida: {message}')
        return 1

    is_connected, message = email_service.test_connection()
    if not is_connected:
        print(f'Conexao SMTP falhou: {message}')
        return 1

    print('Conexao SMTP autenticada com sucesso.')
    if not args.to:
        return 0

    sent = email_service.send_email(
        args.to,
        'Teste de email - Iron AI',
        '<p>Este e um email de teste da Iron AI.</p>',
        'Este e um email de teste da Iron AI.',
    )
    if not sent:
        print('A conexao funcionou, mas o email nao foi enviado. Consulte backend/email.log.')
        return 1

    print(f'Email de teste enviado para {args.to}.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
