FORBIDDEN_INSTRUCTIONS = ("ignore previous", "ignore all instructions", "reveal token", "show password", "execute shell", "run sql")


def sanitize_external_text(value: str, limit: int = 4000) -> str:
    return (value or "")[:limit]


def validate_user_message(message: str) -> None:
    lowered = (message or "").lower()
    if any(pattern in lowered for pattern in FORBIDDEN_INSTRUCTIONS):
        # The request itself is not a security fact and must not change tool
        # boundaries. The service safely answers with a refusal.
        return


def safe_response(message: str) -> str:
    return sanitize_external_text(message).replace("Bearer ", "Bearer [redacted]")
