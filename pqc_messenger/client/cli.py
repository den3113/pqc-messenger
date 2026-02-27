"""
Интерактивный CLI-интерфейс PQC-Messenger.

Команды:
    /create         — Создать новую идентичность
    /login          — Разблокировать хранилище паролем
    /myid           — Показать свой ID и публичные ключи
    /add <keys>     — Добавить контакт
    /contacts       — Список контактов
    /chat <номер>   — Начать/продолжить диалог
    /history        — Показать историю сообщений
    /connect [url]  — Подключиться к relay
    /wipe           — Полное удаление данных
    /help           — Справка
    /quit           — Выход
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys

from pqc_messenger.client.app import PQCMessengerApp
from pqc_messenger.client.contacts import (
    format_contact,
    format_contact_list,
    parse_public_keys,
)
from pqc_messenger.common.constants import DEFAULT_RELAY_URL
from pqc_messenger.common.exceptions import PQCError
from pqc_messenger.common.logging import get_logger, setup_logging
from pqc_messenger.crypto.identity import Identity

logger = get_logger("client.cli")

# ANSI-цвета для терминала
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║             PQC-Messenger v0.1.0                 ║
║  Децентрализованный мессенджер с постквантовым   ║
║         оконечным шифрованием (E2EE)             ║
║                                                  ║
║  Шифры: X25519 + Kyber-768 │ AES-256-GCM        ║
║  Протокол: Double Ratchet  │ Forward Secrecy     ║
╚══════════════════════════════════════════════════╝
{Colors.RESET}"""

HELP_TEXT = f"""
{Colors.BOLD}Команды:{Colors.RESET}
  {Colors.GREEN}/login{Colors.RESET}           Разблокировать хранилище (или создать новое)
  {Colors.GREEN}/myid{Colors.RESET}            Показать свой ID и публичные ключи
  {Colors.GREEN}/add{Colors.RESET} <ключи>     Добавить контакт (x25519_hex:kyber_hex)
  {Colors.GREEN}/contacts{Colors.RESET}        Список контактов
  {Colors.GREEN}/chat{Colors.RESET} <номер>    Начать/продолжить диалог с контактом
  {Colors.GREEN}/history{Colors.RESET}         Показать историю текущего чата
  {Colors.GREEN}/connect{Colors.RESET} [url]   Подключиться к relay-серверу
  {Colors.GREEN}/wipe{Colors.RESET}            ⚠ Полное удаление всех данных
  {Colors.GREEN}/help{Colors.RESET}            Эта справка
  {Colors.GREEN}/quit{Colors.RESET}            Выход
"""


class CLI:
    """Интерактивный CLI-интерфейс."""

    def __init__(self, data_dir: str | None = None) -> None:
        self._app = PQCMessengerApp(data_dir)
        self._current_chat: str | None = None  # contact_id текущего чата
        self._running = False

    async def run(self) -> None:
        """Запустить интерактивный CLI."""
        print(BANNER)
        self._running = True

        # Настраиваем callback для входящих сообщений
        self._app.set_message_callback(self._on_message)

        print(f"{Colors.YELLOW}Введите /login для начала работы или /help для справки{Colors.RESET}\n")

        while self._running:
            try:
                prompt = self._get_prompt()
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input(prompt)
                )
                user_input = user_input.strip()

                if not user_input:
                    continue

                if user_input.startswith("/"):
                    await self._handle_command(user_input)
                elif self._current_chat:
                    await self._send_message(user_input)
                else:
                    print(f"{Colors.DIM}Используйте /chat <номер> для начала диалога{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                print(f"\n{Colors.DIM}Используйте /quit для выхода{Colors.RESET}")
                self._running = False
            except Exception as e:
                print(f"{Colors.RED}Ошибка: {e}{Colors.RESET}")

        # Завершение
        self._app.shutdown()

    def _get_prompt(self) -> str:
        """Сформировать prompt для ввода."""
        if self._current_chat:
            contact = self._app._db.get_contact(self._current_chat)
            name = (contact.display_name if contact and contact.display_name
                    else self._current_chat[:8] + "...")
            return f"{Colors.GREEN}[{name}]{Colors.RESET} > "
        return f"{Colors.BLUE}pqc{Colors.RESET} > "

    async def _handle_command(self, cmd: str) -> None:
        """Обработать команду."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handlers = {
            "/login": self._cmd_login,
            "/myid": self._cmd_myid,
            "/add": self._cmd_add,
            "/contacts": self._cmd_contacts,
            "/chat": self._cmd_chat,
            "/history": self._cmd_history,
            "/connect": self._cmd_connect,
            "/wipe": self._cmd_wipe,
            "/help": self._cmd_help,
            "/quit": self._cmd_quit,
        }

        handler = handlers.get(command)
        if handler:
            await handler(args)
        else:
            print(f"{Colors.RED}Неизвестная команда: {command}. Введите /help{Colors.RESET}")

    async def _cmd_login(self, args: str) -> None:
        """Разблокировать или создать хранилище."""
        password = getpass.getpass(f"{Colors.CYAN}Пароль: {Colors.RESET}")
        if not password:
            print(f"{Colors.RED}Пароль не может быть пустым{Colors.RESET}")
            return

        try:
            is_new = self._app.initialize(password)
            if is_new:
                print(f"{Colors.GREEN}✓ Новая идентичность создана!{Colors.RESET}")
                # Подтверждение пароля
                confirm = getpass.getpass(f"{Colors.CYAN}Подтвердите пароль: {Colors.RESET}")
                if confirm != password:
                    print(f"{Colors.RED}Пароли не совпадают!{Colors.RESET}")
                    return
            else:
                print(f"{Colors.GREEN}✓ Хранилище разблокировано{Colors.RESET}")

            # Показываем ID
            print(f"\n{Colors.BOLD}Ваш ID:{Colors.RESET}")
            fp = Identity.format_fingerprint(self._app.identity_id)  # type: ignore
            print(f"  {Colors.CYAN}{fp}{Colors.RESET}\n")

        except PQCError as e:
            print(f"{Colors.RED}✗ {e}{Colors.RESET}")

    async def _cmd_myid(self, args: str) -> None:
        """Показать ID и публичные ключи."""
        if not self._app.is_initialized:
            print(f"{Colors.YELLOW}Сначала выполните /login{Colors.RESET}")
            return

        identity = self._app.identity
        assert identity is not None

        pub_bundle = identity.public_bundle()
        fp = Identity.format_fingerprint(identity.fingerprint())

        print(f"\n{Colors.BOLD}Ваша идентичность:{Colors.RESET}")
        print(f"  Fingerprint: {Colors.CYAN}{fp}{Colors.RESET}")
        print(f"\n{Colors.BOLD}Публичные ключи (для передачи собеседнику):{Colors.RESET}")
        print(f"  X25519: {pub_bundle['x25519'].hex()}")
        print(f"  Kyber:  {pub_bundle['kyber'].hex()}")

        # Компактный формат для копирования
        compact = f"{pub_bundle['x25519'].hex()}:{pub_bundle['kyber'].hex()}"
        print(f"\n{Colors.DIM}Компактный формат (для /add):{Colors.RESET}")
        print(f"  {compact}\n")

    async def _cmd_add(self, args: str) -> None:
        """Добавить контакт."""
        if not self._app.is_initialized:
            print(f"{Colors.YELLOW}Сначала выполните /login{Colors.RESET}")
            return

        if not args:
            print(f"{Colors.YELLOW}Использование: /add x25519_hex:kyber_hex{Colors.RESET}")
            return

        try:
            x25519_hex, kyber_hex = parse_public_keys(args)
            name = input(f"{Colors.CYAN}Имя контакта (Enter для пропуска): {Colors.RESET}").strip()

            contact = self._app.add_contact(x25519_hex, kyber_hex, name)
            fp = Identity.format_fingerprint(contact.id)
            print(f"{Colors.GREEN}✓ Контакт добавлен: {name or 'Без имени'} [{fp}]{Colors.RESET}")

        except ValueError as e:
            print(f"{Colors.RED}✗ {e}{Colors.RESET}")
        except PQCError as e:
            print(f"{Colors.RED}✗ {e}{Colors.RESET}")

    async def _cmd_contacts(self, args: str) -> None:
        """Список контактов."""
        if not self._app.is_initialized:
            print(f"{Colors.YELLOW}Сначала выполните /login{Colors.RESET}")
            return

        contacts = self._app.get_contacts()
        print(f"\n{Colors.BOLD}Контакты:{Colors.RESET}")
        print(format_contact_list(contacts))
        print()

    async def _cmd_chat(self, args: str) -> None:
        """Начать/продолжить чат."""
        if not self._app.is_initialized:
            print(f"{Colors.YELLOW}Сначала выполните /login{Colors.RESET}")
            return

        contacts = self._app.get_contacts()
        if not contacts:
            print(f"{Colors.YELLOW}Нет контактов. Добавьте через /add{Colors.RESET}")
            return

        if not args:
            print(f"{Colors.YELLOW}Использование: /chat <номер контакта>{Colors.RESET}")
            await self._cmd_contacts("")
            return

        try:
            idx = int(args) - 1
            if 0 <= idx < len(contacts):
                contact = contacts[idx]
                self._current_chat = contact.id
                name = contact.display_name or "Без имени"
                print(f"{Colors.GREEN}Чат с {name}. Вводите сообщения:{Colors.RESET}")
                print(f"{Colors.DIM}(Используйте /history для просмотра истории){Colors.RESET}\n")
            else:
                print(f"{Colors.RED}Нет контакта с номером {args}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Введите номер контакта{Colors.RESET}")

    async def _cmd_history(self, args: str) -> None:
        """Показать историю сообщений."""
        if not self._current_chat:
            print(f"{Colors.YELLOW}Сначала выберите чат через /chat{Colors.RESET}")
            return

        messages = self._app.get_messages(self._current_chat)
        if not messages:
            print(f"{Colors.DIM}  (нет сообщений){Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}История сообщений:{Colors.RESET}")
        for msg in messages:
            if msg.direction == "sent":
                print(f"  {Colors.GREEN}→ Вы:{Colors.RESET} {msg.content}")
            else:
                print(f"  {Colors.BLUE}← :{Colors.RESET} {msg.content}")
        print()

    async def _cmd_connect(self, args: str) -> None:
        """Подключиться к relay."""
        if not self._app.is_initialized:
            print(f"{Colors.YELLOW}Сначала выполните /login{Colors.RESET}")
            return

        relay_url = args.strip() or DEFAULT_RELAY_URL
        try:
            await self._app.connect(relay_url)
            print(f"{Colors.GREEN}✓ Подключено к {relay_url}{Colors.RESET}")
        except PQCError as e:
            print(f"{Colors.RED}✗ Ошибка подключения: {e}{Colors.RESET}")

    async def _cmd_wipe(self, args: str) -> None:
        """Полное удаление данных."""
        print(f"\n{Colors.RED}{Colors.BOLD}⚠ ВНИМАНИЕ: Необратимая операция!{Colors.RESET}")
        print(f"{Colors.RED}Все ключи, сообщения и контакты будут удалены.{Colors.RESET}")
        confirm = input(f'{Colors.RED}Введите "УДАЛИТЬ" для подтверждения: {Colors.RESET}')

        if confirm == "УДАЛИТЬ":
            await self._app.wipe_all()
            print(f"{Colors.RED}✓ Все данные уничтожены{Colors.RESET}")
            self._current_chat = None
        else:
            print(f"{Colors.DIM}Отменено{Colors.RESET}")

    async def _cmd_help(self, args: str) -> None:
        """Показать справку."""
        print(HELP_TEXT)

    async def _cmd_quit(self, args: str) -> None:
        """Выход из приложения."""
        self._running = False
        print(f"\n{Colors.DIM}До свидания!{Colors.RESET}")

    async def _send_message(self, text: str) -> None:
        """Отправить сообщение в текущий чат."""
        if not self._app.is_connected:
            print(f"{Colors.YELLOW}Не подключено к relay. Используйте /connect{Colors.RESET}")
            return

        try:
            await self._app.send_message(self._current_chat, text)  # type: ignore
            print(f"  {Colors.GREEN}→ Отправлено{Colors.RESET}")
        except PQCError as e:
            print(f"{Colors.RED}✗ Ошибка: {e}{Colors.RESET}")

    def _on_message(self, contact_id: str, text: str) -> None:
        """Callback для входящих сообщений."""
        if contact_id == self._current_chat:
            print(f"\n  {Colors.BLUE}← {text}{Colors.RESET}")
        else:
            contact = self._app._db.get_contact(contact_id)
            name = (contact.display_name if contact and contact.display_name
                    else contact_id[:8] + "...")
            print(f"\n{Colors.YELLOW}[Новое сообщение от {name}]{Colors.RESET}")


def main() -> None:
    """Точка входа CLI."""
    parser = argparse.ArgumentParser(
        description="PQC-Messenger — защищённый мессенджер"
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="Директория для хранения данных",
    )
    parser.add_argument(
        "--relay",
        default=DEFAULT_RELAY_URL,
        help=f"URL relay-сервера (default: {DEFAULT_RELAY_URL})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Включить отладочное логирование",
    )

    args = parser.parse_args()

    level = logging.DEBUG if args.debug else logging.WARNING
    setup_logging(level)

    cli = CLI(data_dir=args.data_dir)

    try:
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.DIM}Выход...{Colors.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
