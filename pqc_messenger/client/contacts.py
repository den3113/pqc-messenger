"""
Управление контактами.

Вспомогательный модуль для форматирования и отображения контактов.
"""

from __future__ import annotations

from pqc_messenger.crypto.identity import Identity
from pqc_messenger.storage.database import Contact


def format_contact(contact: Contact) -> str:
    """
    Отформатировать контакт для отображения в CLI.

    Args:
        contact: Объект Contact.

    Returns:
        Форматированная строка.
    """
    name = contact.display_name or "Без имени"
    fingerprint = Identity.format_fingerprint(contact.id)
    return f"  {name} [{fingerprint}]"


def format_contact_list(contacts: list[Contact]) -> str:
    """
    Отформатировать список контактов.

    Args:
        contacts: Список Contact.

    Returns:
        Многострочная строка.
    """
    if not contacts:
        return "  (нет контактов)"

    lines = []
    for i, contact in enumerate(contacts, 1):
        name = contact.display_name or "Без имени"
        fp = Identity.format_fingerprint(contact.id)
        lines.append(f"  {i}. {name}")
        lines.append(f"     ID: {fp}")
    return "\n".join(lines)


def parse_public_keys(key_string: str) -> tuple[str, str]:
    """
    Парсить публичные ключи из строки.

    Поддерживаемые форматы:
    - "x25519_hex:kyber_hex" (разделённые двоеточием)
    - JSON-объект с полями "x25519" и "kyber"

    Args:
        key_string: Строка с ключами.

    Returns:
        (x25519_pub_hex, kyber_pub_hex).

    Raises:
        ValueError: При неверном формате.
    """
    key_string = key_string.strip()

    # Формат с двоеточием
    if ":" in key_string:
        parts = key_string.split(":", 1)
        if len(parts) != 2:
            raise ValueError("Ожидается формат: x25519_hex:kyber_hex")
        return parts[0].strip(), parts[1].strip()

    # JSON формат
    if key_string.startswith("{"):
        import json
        try:
            data = json.loads(key_string)
            return data["x25519"], data["kyber"]
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Неверный JSON: {e}") from e

    raise ValueError(
        'Неверный формат ключей. Используйте "x25519_hex:kyber_hex" '
        'или JSON: {"x25519": "...", "kyber": "..."}'
    )
