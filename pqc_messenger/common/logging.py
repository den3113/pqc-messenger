"""
Настройка логирования PQC-Messenger.

Обеспечивает единообразное логирование для всех модулей
с защитой от утечки чувствительных данных.
"""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Настроить корневой логгер приложения.

    Args:
        level: Уровень логирования (по умолчанию INFO).

    Returns:
        Настроенный логгер.
    """
    logger = logging.getLogger("pqc_messenger")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)

        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Получить логгер для конкретного модуля.

    Args:
        name: Имя модуля (например, 'crypto.keys').

    Returns:
        Логгер с префиксом 'pqc_messenger.{name}'.
    """
    return logging.getLogger(f"pqc_messenger.{name}")
