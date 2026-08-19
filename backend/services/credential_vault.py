from cryptography.fernet import Fernet, InvalidToken

from config import settings


class CredentialVault:
    def __init__(self):
        try:
            self._cipher = Fernet(settings.CREDENTIAL_ENCRYPTION_KEY.encode())
        except Exception as exc:
            raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key") from exc

    def encrypt(self, secret: str) -> str:
        if not secret:
            raise ValueError("Credential is required")
        return self._cipher.encrypt(secret.encode()).decode()

    def decrypt(self, encrypted_secret: str) -> str:
        try:
            return self._cipher.decrypt(encrypted_secret.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError("Stored credential cannot be decrypted") from exc
