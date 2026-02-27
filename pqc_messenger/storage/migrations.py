"""
Миграции схемы базы данных.

Обеспечивает обратную совместимость при обновлении версий приложения.
"""

from __future__ import annotations

import sqlite3

from pqc_messenger.common.logging import get_logger

logger = get_logger("storage.migrations")


# Словарь миграций: версия → SQL-скрипт
MIGRATIONS: dict[int, str] = {
    # Версия 1: начальная схема (создаётся в database.py)
    # Здесь могут быть добавлены будущие миграции:
    # 2: "ALTER TABLE contacts ADD COLUMN avatar BLOB;",
}


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Получить текущую версию схемы."""
    try:
        row = conn.execute("PRAGMA user_version").fetchone()
        return row[0] if row else 0
    except sqlite3.Error:
        return 0


def set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    """Установить версию схемы."""
    conn.execute(f"PRAGMA user_version = {version}")


def run_migrations(conn: sqlite3.Connection) -> None:
    """
    Выполнить все необходимые миграции.

    Миграции применяются последовательно от текущей версии до максимальной.
    """
    current = get_schema_version(conn)

    for version in sorted(MIGRATIONS.keys()):
        if version > current:
            logger.info(f"Применение миграции v{version}...")
            conn.executescript(MIGRATIONS[version])
            set_schema_version(conn, version)
            conn.commit()
            logger.info(f"Миграция v{version} применена")

    if MIGRATIONS:
        final = max(MIGRATIONS.keys())
        if current < final:
            logger.info(f"Все миграции применены (v{current} → v{final})")
