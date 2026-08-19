"""Create missing local secrets without printing their values."""

from pathlib import Path
import secrets

from cryptography.fernet import Fernet


def ensure_value(path: Path, key: str, value: str, invalid_markers=()) -> bool:
    lines = path.read_text().splitlines() if path.exists() else []
    changed = False
    found = False
    output = []
    for line in lines:
        current = line.split("=", 1)[0].strip() if "=" in line else ""
        if current == key:
            found = True
            existing = line.split("=", 1)[1].strip()
            if existing and not any(marker.lower() in existing.lower() for marker in invalid_markers):
                output.append(line)
            else:
                output.append(f"{key}={value}")
                changed = True
        else:
            output.append(line)
    if not found:
        output.extend(["", f"{key}={value}"])
        changed = True
    if changed:
        path.write_text("\n".join(output) + "\n")
    return changed


if __name__ == "__main__":
    env_path = Path(".env")
    jwt_changed = ensure_value(
        env_path,
        "SECRET_KEY",
        secrets.token_urlsafe(64),
        invalid_markers=("change", "replace", "secret-key", "seu_", "..."),
    )
    vault_changed = ensure_value(
        env_path,
        "CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
        invalid_markers=("change", "replace", "fernet-key", "seu_", "..."),
    )
    print("✅ Chave de sessão segura configurada" if jwt_changed else "✅ Chave de sessão já configurada")
    print("✅ Cofre de credenciais configurado" if vault_changed else "✅ Cofre de credenciais já configurado")
