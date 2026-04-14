# PQC-Messenger

Прототип CLI-мессенджера с оконечным шифрованием, гибридным обменом ключами `X25519 + Kyber-768` и Double Ratchet для прямой секретности.

> [!WARNING]
> Проект находится в стадии прототипа и предназначен для экспериментов и обучения. Перед использованием в реальной среде нужен отдельный аудит криптографии, хранения ключей, сети и модели угроз.

## Что умеет

- Гибридный handshake: `X25519 + Kyber-768`
- Шифрование сообщений: `AES-256-GCM`
- Прямая секретность: `Double Ratchet`
- Relay-server в роли "слепого" ретранслятора
- Локальное хранение контактов, сессий и истории
- Защита локального keystore через `Argon2id`

## Важное по безопасности

- Полноценная постквантовая защита работает только если установлен `liboqs` и доступен Python-пакет `liboqs-python`.
- Без `liboqs` клиент запускается в режиме эмуляции Kyber и прямо предупреждает об этом при `/login`.
- Relay не видит содержимое сообщений, но сетевые метаданные и факт соединения от него не скрыты.

## Требования

- Python `3.13+`
- `pip`
- Для реального Kyber-режима: установленный `liboqs` и пакет `liboqs-python`

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Для разработки и тестов:

```bash
pip install -e ".[dev]"
```

Если нужен именно post-quantum режим, убедитесь, что доступен `liboqs-python`:

```bash
pip install liboqs-python
```

## Быстрый старт

1. Запустите relay-server:

```bash
pqc-server --host 0.0.0.0 --port 8765
```

2. Запустите первого клиента:

```bash
pqc-client
```

3. Выполните в клиенте:

```text
/login
/myid
```

4. Запустите второго клиента.
Если оба клиента работают на одной машине, используйте отдельную директорию данных:

```bash
pqc-client --data-dir ~/.pqc_messenger_bob
```

5. На втором клиенте выполните `/login`, затем обменяйтесь публичными ключами и добавьте контакт:

```text
/add <x25519_hex>:<kyber_hex> Alice
```

6. Подключите клиентов к relay:

```text
/connect ws://localhost:8765
```

7. Откройте чат и отправьте сообщение:

```text
/contacts
/chat 1
Привет!
```

## Основные команды CLI

- `/login` — разблокировать или создать локальное хранилище
- `/myid` — показать fingerprint и публичные ключи
- `/add <x25519_hex>:<kyber_hex> [имя]` — добавить контакт
- `/contacts` — показать список контактов
- `/chat <номер>` — открыть диалог
- `/history` — показать историю активного чата
- `/delete <номер>` — удалить контакт и переписку
- `/connect [url]` — подключиться к relay
- `/wipe` — удалить все локальные данные
- `/help` — показать справку

## Тестирование

Основной набор автотестов:

```bash
python -m pytest tests -v
```

В репозитории также есть отдельные проверочные скрипты:

```bash
python test.py
python test_pfs.py
python test_mitm.py
python test_a2.py
```

## Структура проекта

```text
pqc_messenger/
├── client/      # CLI и прикладная логика клиента
├── common/      # константы, исключения, логирование
├── crypto/      # ключи, KDF, AEAD, гибридный KEM
├── network/     # transport, relay server, wire messages
├── protocol/    # handshake, packets, session, ratchet
└── storage/     # keystore, SQLite, migrations
```

## Полезно знать

- По умолчанию клиент хранит данные в `~/.pqc_messenger`.
- URL relay по умолчанию: `ws://localhost:8765`.
- Для более подробного walkthrough по запуску двух клиентов смотрите [GUIDE.md](/home/underdewota/univer/Individual/GUIDE.md).
