# PQC-Messenger

Прототип децентрализованного мессенджера с постквантовым оконечным шифрованием.

## Особенности

- **Гибридное шифрование**: X25519 + ML-KEM (Kyber-768)
- **Аутентифицированное шифрование**: AES-256-GCM
- **Прямая секретность (Forward Secrecy)**: Double Ratchet протокол
- **Децентрализация**: «слепой» Relay Server (Mailbox), не имеющий доступа к содержимому
- **Защита ключей**: Argon2id для деривации мастер-ключа из пароля

## Установка

```bash
# Установить зависимости
pip install -e .

# Или через requirements.txt
pip install -r requirements.txt
```

## Запуск

```bash
# Запустить Relay Server
pqc-server --host 0.0.0.0 --port 8765

# Запустить клиент
pqc-client --relay ws://localhost:8765
```

## Тестирование

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Архитектура

```
pqc_messenger/
├── crypto/       # Криптографический модуль (X25519, Kyber, AES-GCM)
├── protocol/     # Протокол обмена (пакеты, handshake, ratchet)
├── network/      # Сетевой уровень (relay server, transport)
├── storage/      # Локальное зашифрованное хранилище (SQLite)
├── client/       # Клиентское приложение (CLI)
└── common/       # Общие утилиты и константы
```
