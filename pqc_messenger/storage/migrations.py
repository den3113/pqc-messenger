"""
Миграции схемы базы данных.

Обеспечивает обратную совместимость при обновлении версий приложения.
"""

from __future__ import annotations

import hashlib
import sqlite3

from pqc_messenger.common.logging import get_logger

logger = get_logger("storage.migrations")

# Размер публичного ключа настоящего Kyber-768
_KYBER768_PUB_SIZE = 1184

# Словарь миграций: версия -> SQL-скрипт (None = кастомная логика)
MIGRATIONS: dict[int, str | None] = {
    # Версия 1: начальная схема (создаётся в database.py)
    # Версия 2: добавляем kyber_mode для нормализации identity_hash
    2: None,
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


def _migrate_v2(conn: sqlite3.Connection) -> None:
    """
    Миграция v2: добавить столбец kyber_mode в таблицу contacts
    и пересчитать contact.id по новой формуле с mode_byte.

    kyber_mode:
      1 - реальный ML-KEM/Kyber-768 (kyber_public_key == 1184 байт)
      0 - X25519-эмуляция           (kyber_public_key == 32 байт)
    """
    logger.info("Миграция v2: добавляем kyber_mode и пересчитываем contact.id")

    # 1. Добавить столбец kyber_mode если ещё нет
    existing_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(contacts)").fetchall()
    }
    if "kyber_mode" not in existing_cols:
        conn.execute(
            "ALTER TABLE contacts ADD COLUMN kyber_mode INTEGER NOT NULL DEFAULT 0"
        )
        logger.info("Столбец kyber_mode добавлен в таблицу contacts")

    # 2. Считываем все контакты
    rows = conn.execute(
        "SELECT id, x25519_public_key, kyber_public_key FROM contacts"
    ).fetchall()

    # 3. Отключаем FK на время изменения PRIMARY KEY.
    #    При foreign_keys=ON SQLite проверяет ссылочную целостность немедленно
    #    после каждого UPDATE, поэтому обновление PK падает с FOREIGN KEY
    #    constraint failed даже если дочерние строки уже обновлены в той же
    #    транзакции. Отключение FK внутри транзакции — стандартный способ
    #    переименования PK в SQLite (см. https://www.sqlite.org/pragma.html).
    conn.execute("PRAGMA foreign_keys = OFF")

    try:
        for old_id, x25519_pub, kyber_pub in rows:
            mode_byte = b"\x01" if len(kyber_pub) == _KYBER768_PUB_SIZE else b"\x00"
            mode_int  = mode_byte[0]
            new_id    = hashlib.sha256(x25519_pub + mode_byte + kyber_pub).hexdigest()

            conn.execute(
                "UPDATE contacts SET kyber_mode = ? WHERE id = ?",
                (mode_int, old_id),
            )

            if new_id != old_id:
                # Дочерние таблицы сначала, потом PK
                conn.execute(
                    "UPDATE messages SET contact_id = ? WHERE contact_id = ?",
                    (new_id, old_id),
                )
                conn.execute(
                    "UPDATE sessions SET contact_id = ? WHERE contact_id = ?",
                    (new_id, old_id),
                )
                conn.execute(
                    "UPDATE contacts SET id = ? WHERE id = ?",
                    (new_id, old_id),
                )
                logger.info(
                    "Contact id пересчитан: %s... -> %s... (kyber_mode=%d)",
                    old_id[:16], new_id[:16], mode_int,
                )
            else:
                logger.debug(
                    "Contact id не изменился: %s... (kyber_mode=%d)",
                    old_id[:16], mode_int,
                )

        conn.commit()
        logger.info("Миграция v2 завершена (%d контактов обработано)", len(rows))

    except Exception:
        conn.rollback()
        raise
    finally:
        # Всегда восстанавливаем FK — даже при исключении
        conn.execute("PRAGMA foreign_keys = ON")


def run_migrations(conn: sqlite3.Connection) -> None:
    """
    Выполнить все необходимые миграции.

    Миграции применяются последовательно от текущей версии до максимальной.
    """
    current = get_schema_version(conn)

    for version in sorted(MIGRATIONS.keys()):
        if version <= current:
            continue

        logger.info("Применение миграции v%d...", version)

        sql = MIGRATIONS[version]
        if sql is not None:
            conn.executescript(sql)
        elif version == 2:
            _migrate_v2(conn)

        set_schema_version(conn, version)
        conn.commit()
        logger.info("Миграция v%d применена", version)

    if MIGRATIONS:
        final = max(MIGRATIONS.keys())
        if current < final:
            logger.info("Все миграции применены (v%d -> v%d)", current, final)
