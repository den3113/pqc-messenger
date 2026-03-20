"""
Интерактивный CLI-интерфейс PQC-Messenger.

Использует curses для разделения терминала на две зоны:
  - верхняя (прокручиваемая) — история сообщений
  - нижняя (фиксированная)  — строка ввода

Команды:
    /login           — Разблокировать хранилище паролем
    /myid            — Показать свой ID и публичные ключи
    /add <keys>      — Добавить контакт (x25519_hex:kyber_hex)
    /contacts        — Список контактов
    /chat <номер>    — Начать/продолжить диалог
    /history         — Показать историю сообщений
    /connect [url]   — Подключиться к relay
    /wipe            — Полное удаление данных
    /help            — Справка
    /quit            — Выход
"""

from __future__ import annotations

import argparse
import asyncio
import curses
import getpass
import logging
import os
import sys
import textwrap
from datetime import datetime

from pqc_messenger.client.app import PQCMessengerApp
from pqc_messenger.client.contacts import format_contact_list, parse_public_keys
from pqc_messenger.common.constants import DEFAULT_RELAY_URL
from pqc_messenger.common.exceptions import PQCError
from pqc_messenger.common.logging import get_logger, setup_logging
from pqc_messenger.crypto.identity import Identity

logger = get_logger("client.cli")

HELP_TEXT = """\
Команды:
  /login           Разблокировать хранилище (или создать новое)
  /myid            Показать свой ID и публичные ключи
  /add <ключи>     Добавить контакт (x25519_hex:kyber_hex)
  /contacts        Список контактов
  /chat <номер>    Начать/продолжить диалог с контактом
  /history         Показать историю текущего чата
  /connect [url]   Подключиться к relay-серверу
  /wipe            ⚠ Полное удаление всех данных
  /help            Эта справка
  /quit            Выход\
"""

# ─── Цветовые пары (инициализируются в TUI.__init__) ─────────────────────────
# 1 — отправленное сообщение  (зелёный текст)
# 2 — полученное сообщение    (голубой текст)
# 3 — системное уведомление   (жёлтый текст)
# 4 — ошибка                  (красный текст)
# 5 — строка статуса          (белый на синем фоне)
# 6 — приглушённый текст      (серый)
# 7 — жирный заголовок        (белый + bold)


class TUI:
    """
    Терминальный интерфейс с двумя зонами:
      - messages_win  — прокручиваемая область сообщений
      - input_win     — однострочный ввод внизу
      - status_win    — строка статуса между ними
    """

    INPUT_HEIGHT = 3   # высота рамки ввода
    STATUS_HEIGHT = 1  # высота строки статуса

    def __init__(self, stdscr: curses.window) -> None:
        self._scr = stdscr
        self._lines: list[tuple[str, int]] = []  # (text, color_pair)
        self._input_buf = ""
        self._cursor_pos = 0
        self._scroll_offset = 0  # строк от конца (0 = прокрутка в самый низ)

        curses.start_color()
        curses.use_default_colors()
        # Цветовые пары
        curses.init_pair(1, curses.COLOR_GREEN,   -1)  # sent
        curses.init_pair(2, curses.COLOR_CYAN,    -1)  # received
        curses.init_pair(3, curses.COLOR_YELLOW,  -1)  # system
        curses.init_pair(4, curses.COLOR_RED,     -1)  # error
        curses.init_pair(5, curses.COLOR_WHITE,   curses.COLOR_BLUE)  # status bar
        curses.init_pair(6, 8,                    -1)  # dim (color 8 = bright black)
        curses.init_pair(7, curses.COLOR_WHITE,   -1)  # header

        curses.cbreak()
        curses.noecho()
        stdscr.keypad(True)
        stdscr.nodelay(True)  # неблокирующий getch

        self._rebuild_windows()

    # ── Построение окон ───────────────────────────────────────────────────────

    def _rebuild_windows(self) -> None:
        """Пересоздать окна под текущий размер терминала."""
        self._height, self._width = self._scr.getmaxyx()

        msg_height = self._height - self.INPUT_HEIGHT - self.STATUS_HEIGHT
        if msg_height < 1:
            msg_height = 1

        self._msg_win    = curses.newwin(msg_height, self._width, 0, 0)
        self._status_win = curses.newwin(self.STATUS_HEIGHT, self._width,
                                         msg_height, 0)
        self._input_win  = curses.newwin(self.INPUT_HEIGHT, self._width,
                                         msg_height + self.STATUS_HEIGHT, 0)

        self._msg_height    = msg_height
        self._msg_win.scrollok(False)

    # ── Добавление строк ──────────────────────────────────────────────────────

    def add_line(self, text: str, color_pair: int = 0) -> None:
        """Добавить строку в буфер сообщений и перерисовать."""
        # Перенос длинных строк под ширину окна
        wrap_width = max(self._width - 2, 10)
        wrapped = textwrap.wrap(text, wrap_width) or [""]
        for line in wrapped:
            self._lines.append((line, color_pair))

        # Автопрокрутка вниз если пользователь не листал вверх
        if self._scroll_offset == 0:
            pass  # уже в конце, просто перерисуем
        self._draw_messages()
        self._draw_status()
        self._draw_input()

    def add_sent(self, text: str, ts: str = "") -> None:
        prefix = f"  → Вы [{ts}]: " if ts else "  → Вы: "
        self.add_line(prefix + text, 1)

    def add_received(self, sender: str, text: str, ts: str = "") -> None:
        prefix = f"  ← {sender} [{ts}]: " if ts else f"  ← {sender}: "
        self.add_line(prefix + text, 2)

    def add_system(self, text: str) -> None:
        self.add_line(f"  ★ {text}", 3)

    def add_error(self, text: str) -> None:
        self.add_line(f"  ✗ {text}", 4)

    def add_info(self, text: str) -> None:
        self.add_line(f"  {text}", 6)

    def add_header(self, text: str) -> None:
        self.add_line(text, 7)

    # ── Отрисовка ─────────────────────────────────────────────────────────────

    def _draw_messages(self) -> None:
        win = self._msg_win
        win.erase()
        h, w = win.getmaxyx()

        visible_lines = self._lines
        total = len(visible_lines)

        # Определяем срез для отображения
        end = total - self._scroll_offset
        start = max(0, end - h)
        to_show = visible_lines[start:end]

        for row, (text, cp) in enumerate(to_show):
            try:
                if cp:
                    win.addnstr(row, 0, text, w - 1, curses.color_pair(cp))
                else:
                    win.addnstr(row, 0, text, w - 1)
            except curses.error:
                pass

        # Подсказка о прокрутке
        if self._scroll_offset > 0:
            hint = f" ↓ ещё {self._scroll_offset} стр. (PgDn/End) "
            try:
                win.addnstr(h - 1, max(0, w - len(hint) - 1),
                            hint, w - 1, curses.color_pair(3))
            except curses.error:
                pass

        win.noutrefresh()

    def _draw_status(self, status: str = "") -> None:
        win = self._status_win
        win.erase()
        w = self._width
        text = (" " + status).ljust(w)[:w]
        try:
            win.addnstr(0, 0, text, w, curses.color_pair(5))
        except curses.error:
            pass
        win.noutrefresh()
        self._last_status = status

    def _draw_input(self, prompt: str = "") -> None:
        win = self._input_win
        win.erase()
        win.border()
        w = self._width - 2
        display = (prompt + self._input_buf)[-w:]
        cursor_x = min(len(prompt) + self._cursor_pos, w) + 1
        try:
            win.addnstr(1, 1, display, w)
            win.move(1, cursor_x)
        except curses.error:
            pass
        win.noutrefresh()
        self._last_prompt = prompt

    def refresh(self) -> None:
        curses.doupdate()

    def set_status(self, text: str) -> None:
        self._draw_status(text)
        self.refresh()

    def update_prompt(self, prompt: str) -> None:
        self._draw_input(prompt)
        self.refresh()

    # ── Обработка нажатий клавиш ──────────────────────────────────────────────

    def handle_resize(self) -> None:
        curses.endwin()
        self._scr.refresh()
        self._rebuild_windows()
        self._draw_messages()
        self._draw_status(getattr(self, "_last_status", ""))
        self._draw_input(getattr(self, "_last_prompt", ""))
        self.refresh()

    def handle_key(self, key: int) -> str | None:
        """
        Обработать нажатие клавиши.

        Returns:
            Строку если нажат Enter, None иначе.
        """
        if key == curses.KEY_RESIZE:
            self.handle_resize()

        elif key in (curses.KEY_ENTER, 10, 13):  # Enter
            line = self._input_buf
            self._input_buf = ""
            self._cursor_pos = 0
            self._scroll_offset = 0  # сброс прокрутки при отправке
            return line

        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if self._cursor_pos > 0:
                pos = self._cursor_pos
                self._input_buf = self._input_buf[:pos - 1] + self._input_buf[pos:]
                self._cursor_pos -= 1

        elif key == curses.KEY_DC:  # Delete
            pos = self._cursor_pos
            if pos < len(self._input_buf):
                self._input_buf = self._input_buf[:pos] + self._input_buf[pos + 1:]

        elif key == curses.KEY_LEFT:
            if self._cursor_pos > 0:
                self._cursor_pos -= 1

        elif key == curses.KEY_RIGHT:
            if self._cursor_pos < len(self._input_buf):
                self._cursor_pos += 1

        elif key == curses.KEY_HOME:
            self._cursor_pos = 0

        elif key == curses.KEY_END:
            self._cursor_pos = len(self._input_buf)

        elif key == curses.KEY_PPAGE:  # Page Up
            page = max(1, self._msg_height - 2)
            max_scroll = max(0, len(self._lines) - self._msg_height)
            self._scroll_offset = min(self._scroll_offset + page, max_scroll)
            self._draw_messages()

        elif key == curses.KEY_NPAGE:  # Page Down
            page = max(1, self._msg_height - 2)
            self._scroll_offset = max(0, self._scroll_offset - page)
            self._draw_messages()

        elif key == curses.KEY_UP:
            max_scroll = max(0, len(self._lines) - self._msg_height)
            self._scroll_offset = min(self._scroll_offset + 1, max_scroll)
            self._draw_messages()

        elif key == curses.KEY_DOWN:
            self._scroll_offset = max(0, self._scroll_offset - 1)
            self._draw_messages()

        elif 32 <= key <= 126 or key > 127:  # печатаемые символы + Unicode
            char = chr(key)
            pos = self._cursor_pos
            self._input_buf = self._input_buf[:pos] + char + self._input_buf[pos:]
            self._cursor_pos += 1

        return None


# ─── Основной класс CLI ───────────────────────────────────────────────────────


class CLI:
    """Интерактивный CLI-интерфейс с разделённым экраном."""

    def __init__(self, data_dir: str | None = None) -> None:
        self._app = PQCMessengerApp(data_dir)
        self._current_chat: str | None = None
        self._current_chat_name: str = ""
        self._running = False
        self._tui: TUI | None = None
        self._relay_url = DEFAULT_RELAY_URL

    # ── Запуск ────────────────────────────────────────────────────────────────

    def run(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        """Запустить TUI. Синхронная точка входа — сама создаёт event loop."""
        self._relay_url = relay_url
        self._running = True
        self._app.set_message_callback(self._on_message)

        # Инициализируем curses вручную (без wrapper), чтобы управлять
        # жизненным циклом самостоятельно и иметь один asyncio event loop.
        stdscr = curses.initscr()
        try:
            self._tui = TUI(stdscr)
            self._tui.add_header("╔══════════════════════════════════════════╗")
            self._tui.add_header("║         PQC-Messenger v0.1.0             ║")
            self._tui.add_header("║  X25519 + Kyber-768 │ Double Ratchet     ║")
            self._tui.add_header("╚══════════════════════════════════════════╝")
            self._tui.add_system("Введите /login для начала или /help для справки")
            self._tui.add_info("PgUp/PgDn — прокрутка  │  ← → — курсор в строке ввода")
            self._tui.set_status("PQC-Messenger  │  не авторизован")
            self._tui.refresh()

            asyncio.run(self._main_loop())
        finally:
            curses.endwin()
            self._app.shutdown()

    async def _main_loop(self) -> None:
        assert self._tui is not None
        prompt = self._make_prompt()
        self._tui.update_prompt(prompt)

        while self._running:
            key = self._tui._scr.getch()

            if key == curses.ERR:
                # Нет нажатий — отдаём управление событийному циклу
                await asyncio.sleep(0.02)
                continue

            result = self._tui.handle_key(key)

            if result is not None:
                line = result.strip()
                if line:
                    await self._dispatch(line)
                prompt = self._make_prompt()

            self._tui._draw_input(prompt)
            self._tui.refresh()

    # ── Промпт и статус ───────────────────────────────────────────────────────

    def _make_prompt(self) -> str:
        if self._current_chat_name:
            return f"[{self._current_chat_name}] > "
        return "pqc > "

    def _update_status(self) -> None:
        assert self._tui
        parts = ["PQC-Messenger"]
        if self._app.is_initialized:
            parts.append(self._app.identity_id[:12] + "...")  # type: ignore
        else:
            parts.append("не авторизован")
        if self._app.is_connected:
            parts.append(f"relay: {self._relay_url}")
        if self._current_chat_name:
            parts.append(f"чат: {self._current_chat_name}")
        self._tui.set_status("  │  ".join(parts))

    # ── Диспетчер команд ──────────────────────────────────────────────────────

    async def _dispatch(self, line: str) -> None:
        assert self._tui

        if line.startswith("/"):
            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            handlers = {
                "/login":    self._cmd_login,
                "/myid":     self._cmd_myid,
                "/add":      self._cmd_add,
                "/contacts": self._cmd_contacts,
                "/chat":     self._cmd_chat,
                "/history":  self._cmd_history,
                "/connect":  self._cmd_connect,
                "/wipe":     self._cmd_wipe,
                "/help":     self._cmd_help,
                "/quit":     self._cmd_quit,
            }
            handler = handlers.get(cmd)
            if handler:
                await handler(args)
            else:
                self._tui.add_error(f"Неизвестная команда: {cmd}. Введите /help")
        elif self._current_chat:
            await self._send_message(line)
        else:
            self._tui.add_info("Используйте /chat <номер> для начала диалога")

    # ── Команды ───────────────────────────────────────────────────────────────

    async def _cmd_login(self, args: str) -> None:
        assert self._tui

        # Временно выходим из curses для безопасного ввода пароля
        curses.endwin()
        try:
            password = getpass.getpass("Пароль: ")
        except (EOFError, KeyboardInterrupt):
            password = ""
        finally:
            self._tui._scr.refresh()
            self._tui._rebuild_windows()
            self._tui._draw_messages()
            self._tui._draw_status(getattr(self._tui, "_last_status", ""))
            self._tui._draw_input(self._make_prompt())
            self._tui.refresh()

        if not password:
            self._tui.add_error("Пароль не может быть пустым")
            return

        try:
            is_new = self._app.initialize(password)
            if is_new:
                curses.endwin()
                try:
                    confirm = getpass.getpass("Подтвердите пароль: ")
                finally:
                    self._tui._scr.refresh()
                    self._tui._rebuild_windows()
                    self._tui._draw_messages()
                    self._tui._draw_status(getattr(self._tui, "_last_status", ""))
                    self._tui._draw_input(self._make_prompt())
                    self._tui.refresh()

                if confirm != password:
                    self._tui.add_error("Пароли не совпадают!")
                    return
                self._tui.add_system("Новая идентичность создана!")
            else:
                self._tui.add_system("Хранилище разблокировано")

            fp = Identity.format_fingerprint(self._app.identity_id)  # type: ignore
            self._tui.add_info(f"Ваш ID: {fp}")
            self._update_status()

        except PQCError as e:
            self._tui.add_error(str(e))

    async def _cmd_myid(self, args: str) -> None:
        assert self._tui
        if not self._app.is_initialized:
            self._tui.add_error("Сначала выполните /login")
            return
        identity = self._app.identity
        assert identity is not None
        pub = identity.public_bundle()
        fp = Identity.format_fingerprint(identity.fingerprint())
        self._tui.add_info(f"Fingerprint: {fp}")
        self._tui.add_info(f"X25519 : {pub['x25519'].hex()}")
        self._tui.add_info(f"Kyber  : {pub['kyber'].hex()}")
        compact = f"{pub['x25519'].hex()}:{pub['kyber'].hex()}"
        self._tui.add_info(f"Компактно: {compact}")

    async def _cmd_add(self, args: str) -> None:
        assert self._tui
        if not self._app.is_initialized:
            self._tui.add_error("Сначала выполните /login")
            return
        if not args:
            self._tui.add_error("Использование: /add x25519_hex:kyber_hex [имя]")
            return
        try:
            # Поддержка формата "/add ключи Имя Контакта"
            parts = args.split()
            key_str = parts[0]
            name = " ".join(parts[1:]) if len(parts) > 1 else ""
            x25519_hex, kyber_hex = parse_public_keys(key_str)
            contact = self._app.add_contact(x25519_hex, kyber_hex, name)
            fp = Identity.format_fingerprint(contact.id)
            self._tui.add_system(
                f"Контакт добавлен: {contact.display_name or 'Без имени'} [{fp}]"
            )
        except (ValueError, PQCError) as e:
            self._tui.add_error(str(e))

    async def _cmd_contacts(self, args: str) -> None:
        assert self._tui
        if not self._app.is_initialized:
            self._tui.add_error("Сначала выполните /login")
            return
        contacts = self._app.get_contacts()
        if not contacts:
            self._tui.add_info("Нет контактов. Добавьте через /add")
            return
        self._tui.add_info("─── Контакты ───")
        for i, c in enumerate(contacts, 1):
            name = c.display_name or "Без имени"
            fp = Identity.format_fingerprint(c.id)
            self._tui.add_info(f"  {i}. {name}  [{fp}]")

    async def _cmd_chat(self, args: str) -> None:
        assert self._tui
        if not self._app.is_initialized:
            self._tui.add_error("Сначала выполните /login")
            return
        contacts = self._app.get_contacts()
        if not contacts:
            self._tui.add_error("Нет контактов. Добавьте через /add")
            return
        if not args:
            self._tui.add_error("Использование: /chat <номер>")
            await self._cmd_contacts("")
            return
        try:
            idx = int(args) - 1
            if 0 <= idx < len(contacts):
                contact = contacts[idx]
                self._current_chat = contact.id
                self._current_chat_name = contact.display_name or contact.id[:8] + "..."
                self._tui.add_system(
                    f"Чат с {self._current_chat_name}. "
                    f"Вводите сообщения. /history — история."
                )
                self._update_status()
            else:
                self._tui.add_error(f"Нет контакта с номером {args}")
        except ValueError:
            self._tui.add_error("Введите номер контакта")

    async def _cmd_history(self, args: str) -> None:
        assert self._tui
        if not self._current_chat:
            self._tui.add_error("Сначала выберите чат через /chat")
            return
        messages = self._app.get_messages(self._current_chat)
        if not messages:
            self._tui.add_info("(нет сообщений)")
            return
        self._tui.add_info("─── История ───")
        for msg in messages:
            ts = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M")
            if msg.direction == "sent":
                self._tui.add_sent(msg.content, ts)
            else:
                self._tui.add_received(self._current_chat_name, msg.content, ts)

    async def _cmd_connect(self, args: str) -> None:
        assert self._tui
        if not self._app.is_initialized:
            self._tui.add_error("Сначала выполните /login")
            return
        url = args.strip() or self._relay_url
        try:
            self._tui.add_info(f"Подключение к {url}...")
            self._tui.refresh()
            await self._app.connect(url)
            self._relay_url = url
            self._tui.add_system(f"Подключено к {url}")
            self._update_status()
        except PQCError as e:
            self._tui.add_error(f"Ошибка подключения: {e}")

    async def _cmd_wipe(self, args: str) -> None:
        assert self._tui
        self._tui.add_error('⚠ Введите "УДАЛИТЬ" для подтверждения:')
        self._tui.refresh()

        # Временно выходим из curses для ввода подтверждения
        curses.endwin()
        try:
            confirm = input('Введите "УДАЛИТЬ": ')
        except (EOFError, KeyboardInterrupt):
            confirm = ""
        finally:
            self._tui._scr.refresh()
            self._tui._rebuild_windows()
            self._tui._draw_messages()
            self._tui._draw_status(getattr(self._tui, "_last_status", ""))
            self._tui._draw_input(self._make_prompt())
            self._tui.refresh()

        if confirm.strip() == "УДАЛИТЬ":
            await self._app.wipe_all()
            self._current_chat = None
            self._current_chat_name = ""
            self._tui.add_error("Все данные уничтожены")
            self._update_status()
        else:
            self._tui.add_info("Отменено")

    async def _cmd_help(self, args: str) -> None:
        assert self._tui
        for line in HELP_TEXT.splitlines():
            self._tui.add_info(line)

    async def _cmd_quit(self, args: str) -> None:
        self._running = False

    # ── Отправка сообщения ────────────────────────────────────────────────────

    async def _send_message(self, text: str) -> None:
        assert self._tui
        if not self._app.is_connected:
            self._tui.add_error("Не подключено к relay. Используйте /connect")
            return
        try:
            await self._app.send_message(self._current_chat, text)  # type: ignore
            ts = datetime.now().strftime("%H:%M")
            self._tui.add_sent(text, ts)
        except PQCError as e:
            self._tui.add_error(str(e))

    # ── Callback входящих сообщений ───────────────────────────────────────────

    def _on_message(self, contact_id: str, text: str) -> None:
        """Вызывается из фонового asyncio-таска при получении сообщения."""
        if self._tui is None:
            return

        ts = datetime.now().strftime("%H:%M")

        if contact_id == "system":
            self._tui.add_system(text)
        elif contact_id == self._current_chat:
            self._tui.add_received(self._current_chat_name, text, ts)
        else:
            contact = self._app._db.get_contact(contact_id)
            name = (contact.display_name if contact and contact.display_name
                    else contact_id[:8] + "...")
            self._tui.add_system(f"Новое сообщение от {name}: {text}")

        self._tui._draw_messages()
        self._tui._draw_input(self._make_prompt())
        self._tui.refresh()


# ─── Точка входа ─────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="PQC-Messenger")
    parser.add_argument("--data-dir", default=None,
                        help="Директория для хранения данных")
    parser.add_argument("--relay", default=DEFAULT_RELAY_URL,
                        help=f"URL relay-сервера (default: {DEFAULT_RELAY_URL})")
    parser.add_argument("--debug", action="store_true",
                        help="Включить отладочное логирование")
    args = parser.parse_args()

    # При debug-режиме пишем в файл, не в stderr (он сломает curses)
    if args.debug:
        logging.basicConfig(
            filename="/tmp/pqc_debug.log",
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:
        logging.disable(logging.CRITICAL)

    cli = CLI(data_dir=args.data_dir)

    try:
        cli.run(relay_url=args.relay)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            curses.endwin()
        except Exception:
            pass
        sys.exit(0)


if __name__ == "__main__":
    main()
