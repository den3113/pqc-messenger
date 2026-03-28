"""
Интерактивный CLI-интерфейс PQC-Messenger.

Режимы:
  Главное меню  — /команды управляются диспетчером
  Режим чата    — весь текст идёт как сообщение, /back — выход

Команды (только вне чата):
    /login    /myid    /add    /contacts    /chat
    /history  /connect /wipe   /help        /quit

В режиме чата:
    /back  — вернуться в главное меню
    /quit  — выход из программы
    всё остальное — отправляется собеседнику
"""

from __future__ import annotations

import argparse
import asyncio
import curses
import locale
import logging
import sys
import textwrap
import unicodedata
from datetime import datetime

from pqc_messenger.client.app import PQCMessengerApp
from pqc_messenger.client.contacts import parse_public_keys
from pqc_messenger.common.constants import DEFAULT_RELAY_URL
from pqc_messenger.common.exceptions import PQCError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.identity import Identity

logger = get_logger("client.cli")

HELP_TEXT = """\
Команды (доступны вне режима чата):
  /login           Разблокировать хранилище (или создать новое)
  /myid            Показать свой ID и публичные ключи
  /add <ключи>     Добавить контакт (x25519_hex:kyber_hex [имя])
  /contacts        Список контактов
  /chat <номер>    Начать диалог с контактом
  /history         Показать историю последнего чата
  /delete <номер>  Удалить контакт и всю историю переписки
  /connect [url]   Подключиться к relay-серверу
  /wipe            Полное удаление всех данных
  /help            Эта справка
  /quit            Выход

В режиме чата:
  /back            Вернуться в главное меню
  всё остальное    отправляется собеседнику"""


class TUI:
    INPUT_HEIGHT  = 3
    STATUS_HEIGHT = 1

    C_SENT   = 1
    C_RECV   = 2
    C_SYS    = 3
    C_ERR    = 4
    C_STATUS = 5
    C_DIM    = 6
    C_BOLD   = 7

    _ALLOWED_CATEGORIES = frozenset({
        "Lu", "Ll", "Lt", "Lm", "Lo",
        "Nd", "Nl", "No",
        "Pc", "Pd", "Ps", "Pe", "Pi",
        "Pf", "Po",
        "Sm", "Sc", "Sk", "So",
        "Zs",
    })

    @staticmethod
    def _is_printable_char(ch: str) -> bool:
        """Допустим ли символ для ввода?

        Разрешены: латиница, кириллица, цифры, пунктуация и пр.
        Запрещены: управляющие символы, эмодзи, CJK-иероглифы.
        """
        if len(ch) != 1:
            return False
        cp = ord(ch)
        if cp < 32:
            return False
        if 0x4E00 <= cp <= 0x9FFF:   return False
        if 0x3400 <= cp <= 0x4DBF:   return False
        if 0x20000 <= cp <= 0x2A6DF: return False
        if 0x2A700 <= cp <= 0x2CEAF: return False
        if 0xF900 <= cp <= 0xFAFF:   return False
        if 0x1F600 <= cp <= 0x1F64F: return False
        if 0x1F300 <= cp <= 0x1F5FF: return False
        if 0x1F680 <= cp <= 0x1F6FF: return False
        if 0x1F900 <= cp <= 0x1F9FF: return False
        if 0x1FA00 <= cp <= 0x1FA6F: return False
        if 0x1FA70 <= cp <= 0x1FAFF: return False
        if 0x2600 <= cp <= 0x26FF:   return False
        if 0x2700 <= cp <= 0x27BF:   return False
        if 0xFE00 <= cp <= 0xFE0F:   return False
        if 0x200D == cp:             return False
        cat = unicodedata.category(ch)
        return cat in TUI._ALLOWED_CATEGORIES

    def __init__(self, stdscr: curses.window) -> None:
        self._scr        = stdscr
        self._lines: list[tuple[str, int]] = []
        self._input_buf  = ""
        self._cursor_pos = 0
        self._scroll_off = 0
        self._last_status = ""
        self._last_prompt = ""

        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(self.C_SENT,   curses.COLOR_GREEN,  -1)
        curses.init_pair(self.C_RECV,   curses.COLOR_CYAN,   -1)
        curses.init_pair(self.C_SYS,    curses.COLOR_YELLOW, -1)
        curses.init_pair(self.C_ERR,    curses.COLOR_RED,    -1)
        curses.init_pair(self.C_STATUS, curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(self.C_DIM,    8,                   -1)
        curses.init_pair(self.C_BOLD,   curses.COLOR_WHITE,  -1)

        curses.cbreak()
        curses.noecho()
        stdscr.keypad(True)
        stdscr.nodelay(True)
        stdscr.erase()
        stdscr.noutrefresh()
        self._rebuild()

    def _rebuild(self) -> None:
        self._h, self._w = self._scr.getmaxyx()
        msg_h = max(1, self._h - self.INPUT_HEIGHT - self.STATUS_HEIGHT)
        self._msg_h   = msg_h
        self._msg_win = curses.newwin(msg_h,              self._w, 0,       0)
        self._sts_win = curses.newwin(self.STATUS_HEIGHT, self._w, msg_h,   0)
        self._inp_win = curses.newwin(self.INPUT_HEIGHT,  self._w,
                                      msg_h + self.STATUS_HEIGHT, 0)
        self._msg_win.scrollok(False)



    def add_line(self, text: str, cp: int = 0) -> None:
        for line in (textwrap.wrap(text, max(self._w - 2, 10)) or [""]):
            self._lines.append((line, cp))
        self._draw_messages()
        self._draw_status(self._last_status)
        self._draw_input(self._last_prompt)
        curses.doupdate()

    def add_sent    (self, text: str, ts: str = "") -> None:
        self.add_line((f"  → Вы [{ts}]: " if ts else "  → Вы: ") + text, self.C_SENT)

    def add_received(self, sender: str, text: str, ts: str = "") -> None:
        self.add_line((f"  ← {sender} [{ts}]: " if ts else f"  ← {sender}: ") + text, self.C_RECV)

    def add_system  (self, text: str) -> None: self.add_line(f"  ★ {text}", self.C_SYS)
    def add_error   (self, text: str) -> None: self.add_line(f"  ✗ {text}", self.C_ERR)
    def add_info    (self, text: str) -> None: self.add_line(f"  {text}",   self.C_DIM)
    def add_header  (self, text: str) -> None: self.add_line(text,          self.C_BOLD)



    def _draw_messages(self) -> None:
        win = self._msg_win
        win.erase()
        h, w = win.getmaxyx()
        total = len(self._lines)
        end   = total - self._scroll_off
        start = max(0, end - h)
        for row, (text, cp) in enumerate(self._lines[start:end]):
            try:
                win.addnstr(row, 0, text, w - 1,
                            curses.color_pair(cp) if cp else 0)
            except curses.error:
                pass
        if self._scroll_off > 0:
            hint = f" ↓ {self._scroll_off} стр. (PgDn) "
            try:
                win.addnstr(h - 1, max(0, w - len(hint) - 1),
                            hint, w - 1, curses.color_pair(self.C_SYS))
            except curses.error:
                pass
        win.noutrefresh()

    def _draw_status(self, status: str = "") -> None:
        self._last_status = status
        win  = self._sts_win
        win.erase()
        text = (" " + status).ljust(self._w)[:self._w]
        try:
            win.addnstr(0, 0, text, self._w, curses.color_pair(self.C_STATUS))
        except curses.error:
            pass
        win.noutrefresh()

    def _draw_input(self, prompt: str = "", mask: bool = False) -> None:
        self._last_prompt = prompt
        win = self._inp_win
        win.erase()
        win.border()
        w   = self._w - 2
        buf = "*" * len(self._input_buf) if mask else self._input_buf
        display  = (prompt + buf)[-w:]
        cursor_x = min(len(prompt) + self._cursor_pos, w) + 1
        try:
            win.addnstr(1, 1, display, w)
            win.move(1, cursor_x)
        except curses.error:
            pass
        win.noutrefresh()

    def full_refresh(self) -> None:
        self._draw_messages()
        self._draw_status(self._last_status)
        self._draw_input(self._last_prompt)
        curses.doupdate()

    def set_status(self, text: str) -> None:
        self._draw_status(text)
        curses.doupdate()



    def read_password(self, prompt: str) -> str:
        saved_buf, saved_pos = self._input_buf, self._cursor_pos
        self._input_buf, self._cursor_pos = "", 0
        self._draw_input(prompt, mask=True)
        curses.doupdate()

        self._scr.nodelay(False)
        try:
            while True:
                try:
                    wch = self._scr.get_wch()
                except curses.error:
                    continue

                if isinstance(wch, int):
                    if wch in (curses.KEY_ENTER, 10, 13):
                        break
                    elif wch in (curses.KEY_BACKSPACE, 127, 8):
                        p = self._cursor_pos
                        if p > 0:
                            self._input_buf = self._input_buf[:p-1] + self._input_buf[p:]
                            self._cursor_pos -= 1
                    elif wch == curses.KEY_RESIZE:
                        self._rebuild()
                        self._draw_messages()
                        self._draw_status(self._last_status)
                else:
                    if wch in ("\n", "\r"):
                        break
                    elif wch in ("\x7f", "\x08"):
                        p = self._cursor_pos
                        if p > 0:
                            self._input_buf = self._input_buf[:p-1] + self._input_buf[p:]
                            self._cursor_pos -= 1
                    elif self._is_printable_char(wch):
                        p = self._cursor_pos
                        self._input_buf = self._input_buf[:p] + wch + self._input_buf[p:]
                        self._cursor_pos += 1
                self._draw_input(prompt, mask=True)
                curses.doupdate()
        finally:
            self._scr.nodelay(True)

        result = self._input_buf
        self._input_buf, self._cursor_pos = saved_buf, saved_pos
        return result

    def handle_key(self, wch: int | str) -> str | None:
        if isinstance(wch, int):
            if wch == curses.KEY_RESIZE:
                self._rebuild(); self.full_refresh()

            elif wch in (curses.KEY_ENTER,):
                line = self._input_buf
                self._input_buf, self._cursor_pos, self._scroll_off = "", 0, 0
                return line

            elif wch in (curses.KEY_BACKSPACE,):
                p = self._cursor_pos
                if p > 0:
                    self._input_buf = self._input_buf[:p-1] + self._input_buf[p:]
                    self._cursor_pos -= 1

            elif wch == curses.KEY_DC:
                p = self._cursor_pos
                if p < len(self._input_buf):
                    self._input_buf = self._input_buf[:p] + self._input_buf[p+1:]

            elif wch == curses.KEY_LEFT:
                if self._cursor_pos > 0: self._cursor_pos -= 1
            elif wch == curses.KEY_RIGHT:
                if self._cursor_pos < len(self._input_buf): self._cursor_pos += 1
            elif wch == curses.KEY_HOME: self._cursor_pos = 0
            elif wch == curses.KEY_END:  self._cursor_pos = len(self._input_buf)

            elif wch in (curses.KEY_UP, curses.KEY_PPAGE):
                page = max(1, self._msg_h - 2) if wch == curses.KEY_PPAGE else 1
                self._scroll_off = min(self._scroll_off + page,
                                       max(0, len(self._lines) - self._msg_h))
                self._draw_messages()

            elif wch in (curses.KEY_DOWN, curses.KEY_NPAGE):
                page = max(1, self._msg_h - 2) if wch == curses.KEY_NPAGE else 1
                self._scroll_off = max(0, self._scroll_off - page)
                self._draw_messages()

        else:
            if wch in ("\n", "\r"):
                line = self._input_buf
                self._input_buf, self._cursor_pos, self._scroll_off = "", 0, 0
                return line

            elif wch in ("\x7f", "\x08"):
                p = self._cursor_pos
                if p > 0:
                    self._input_buf = self._input_buf[:p-1] + self._input_buf[p:]
                    self._cursor_pos -= 1

            elif self._is_printable_char(wch):
                p = self._cursor_pos
                self._input_buf = self._input_buf[:p] + wch + self._input_buf[p:]
                self._cursor_pos += 1

        return None


class CLI:
    def __init__(self, data_dir: str | None = None) -> None:
        self._app       = PQCMessengerApp(data_dir)
        self._chat_id   = ""
        self._chat_name = ""
        self._running   = False
        self._tui: TUI | None = None
        self._relay_url = DEFAULT_RELAY_URL



    def run(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        self._relay_url = relay_url
        self._running   = True
        self._app.set_message_callback(self._on_message)
        stdscr = curses.initscr()
        try:
            self._tui = TUI(stdscr)
            t = self._tui
            t.add_header("╔══════════════════════════════════════════╗")
            t.add_header("║         PQC-Messenger  v0.5.6            ║")
            t.add_header("║  X25519 + Kyber-768  │  Double Ratchet   ║")
            t.add_header("╚══════════════════════════════════════════╝")
            t.add_system("Введите /login для начала работы")
            t.add_info("PgUp/PgDn — прокрутка  │  ← → Home End — курсор")
            self._update_status()
            t.full_refresh()
            asyncio.run(self._main_loop())
        finally:
            curses.endwin()
            self._app.shutdown()

    async def _main_loop(self) -> None:
        t = self._tui
        assert t
        t._draw_input(self._prompt())
        curses.doupdate()

        while self._running:
            try:
                wch = t._scr.get_wch()
            except curses.error:
                await asyncio.sleep(0.02)
                continue
            result = t.handle_key(wch)
            if result is not None:
                line = result.strip()
                if line:
                    await self._dispatch(line)
            t._draw_input(self._prompt())
            curses.doupdate()



    def _prompt(self) -> str:
        return f"[{self._chat_name}] > " if self._chat_name else "pqc > "

    def _update_status(self) -> None:
        t = self._tui
        assert t
        parts = ["PQC-Messenger"]
        if self._app.is_initialized:
            parts.append(self._app.identity_id[:12] + "...")  # type: ignore
            kyber_label = "Kyber-768✓" if self._app.kyber_is_real else "Kyber-ЭМУЛ⚠"
            parts.append(kyber_label)
        else:
            parts.append("не авторизован")
        if self._app.is_connected:
            parts.append(self._relay_url)
        if self._chat_name:
            parts.append(f"чат: {self._chat_name}  (/back — выйти)")
        t.set_status("  │  ".join(parts))



    async def _dispatch(self, line: str) -> None:
        t = self._tui
        assert t


        if self._chat_id:
            cmd = line.lower()
            if cmd in ("/back", "/exit"):
                self._chat_id = self._chat_name = ""
                t.add_system("Вы вышли из чата. Доступны команды /help")
                self._update_status()
            elif cmd == "/quit":
                self._running = False
            else:
                await self._send_message(line)
            return


        if not line.startswith("/"):
            t.add_info("Используйте /chat <номер> для начала диалога")
            return

        parts = line.split(maxsplit=1)
        cmd   = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ""

        handlers = {
            "/login":    self._cmd_login,
            "/myid":     self._cmd_myid,
            "/add":      self._cmd_add,
            "/contacts": self._cmd_contacts,
            "/chat":     self._cmd_chat,
            "/history":  self._cmd_history,
            "/delete":   self._cmd_delete,
            "/connect":  self._cmd_connect,
            "/wipe":     self._cmd_wipe,
            "/help":     self._cmd_help,
            "/quit":     self._cmd_quit,
        }
        handler = handlers.get(cmd)
        if handler:
            await handler(args)
        else:
            t.add_error(f"Неизвестная команда: {cmd}  (попробуйте /help)")



    async def _cmd_login(self, args: str) -> None:
        t = self._tui
        assert t
        password = t.read_password("Пароль: ")
        if not password:
            t.add_error("Пароль не может быть пустым")
            return
        try:
            is_new = self._app.initialize(password)
        except PQCError as e:
            t.add_error(str(e))
            return
        if is_new:
            confirm = t.read_password("Подтвердите пароль: ")
            if confirm != password:
                t.add_error("Пароли не совпадают!")
                return
            t.add_system("Новая идентичность создана!")
        else:
            t.add_system("Хранилище разблокировано")
        t.add_info(f"Ваш ID: {Identity.format_fingerprint(self._app.identity_id)}")  # type: ignore

        if self._app.kyber_is_real:
            t.add_system("Kyber-768 (liboqs): постквантовая защита АКТИВНА")
        else:
            t.add_error(
                "Kyber-768 работает в режиме ЭМУЛЯЦИИ (liboqs не установлен). "
                "Постквантовая защита НЕ активна!"
            )
        self._update_status()

    async def _cmd_myid(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        identity = self._app.identity
        assert identity
        pub = identity.public_bundle()
        t.add_info(f"Fingerprint : {Identity.format_fingerprint(identity.fingerprint())}")
        t.add_info(f"X25519      : {pub['x25519'].hex()}")
        t.add_info(f"Kyber       : {pub['kyber'].hex()}")
        t.add_info(f"Компактно   : {pub['x25519'].hex()}:{pub['kyber'].hex()}")

    async def _cmd_add(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        if not args:
            t.add_error("Использование: /add x25519_hex:kyber_hex [имя]"); return
        try:
            parts   = args.split(maxsplit=1)
            x, k    = parse_public_keys(parts[0])
            name    = parts[1] if len(parts) > 1 else ""
            contact = self._app.add_contact(x, k, name)
            t.add_system(
                f"Контакт добавлен: {contact.display_name or 'Без имени'}  "
                f"[{Identity.format_fingerprint(contact.id)}]"
            )
        except (ValueError, PQCError) as e:
            t.add_error(str(e))

    async def _cmd_contacts(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        contacts = self._app.get_contacts()
        if not contacts:
            t.add_info("Нет контактов. Добавьте через /add"); return
        t.add_info("─── Контакты ──────────────────────────")
        for i, c in enumerate(contacts, 1):
            t.add_info(f"  {i}.  {c.display_name or 'Без имени'}"
                       f"  [{Identity.format_fingerprint(c.id)}]")

    async def _cmd_chat(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        contacts = self._app.get_contacts()
        if not contacts:
            t.add_error("Нет контактов. Добавьте через /add"); return
        if not args:
            t.add_error("Использование: /chat <номер>")
            await self._cmd_contacts(""); return
        try:
            idx = int(args) - 1
            if 0 <= idx < len(contacts):
                c = contacts[idx]
                self._chat_id   = c.id
                self._chat_name = c.display_name or c.id[:8] + "..."
                t.add_system(f"Чат с {self._chat_name}  —  /back чтобы выйти")
                self._update_status()
            else:
                t.add_error(f"Нет контакта с номером {args}")
        except ValueError:
            t.add_error("Введите номер контакта")

    async def _cmd_delete(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        contacts = self._app.get_contacts()
        if not contacts:
            t.add_error("Нет контактов"); return
        if not args:
            t.add_error("Использование: /delete <номер>")
            await self._cmd_contacts(""); return
        try:
            idx = int(args) - 1
            if not (0 <= idx < len(contacts)):
                t.add_error(f"Нет контакта с номером {args}"); return
            contact = contacts[idx]
            name    = contact.display_name or contact.id[:8] + "..."
            t.add_error(f"Удалить {name} и всю историю? Введите ДА:")
            confirm = t.read_password("Подтверждение: ")
            if confirm.strip() == "ДА":

                if self._chat_id == contact.id:
                    self._chat_id = self._chat_name = ""
                self._app.delete_contact(contact.id)
                t.add_system(f"Контакт {name} удалён")
                self._update_status()
            else:
                t.add_info("Отменено")
        except ValueError:
            t.add_error("Введите номер контакта")

    async def _cmd_history(self, args: str) -> None:
        t = self._tui
        assert t
        chat_id   = self._chat_id
        chat_name = self._chat_name or "контакт"
        if not chat_id:
            t.add_error("Сначала откройте чат через /chat"); return
        messages = self._app.get_messages(chat_id)
        if not messages:
            t.add_info("(нет сообщений)"); return
        t.add_info("─── История ────────────────────────────")
        for msg in messages:
            ts = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M")
            if msg.direction == "sent":
                t.add_sent(msg.content, ts)
            else:
                t.add_received(chat_name, msg.content, ts)

    async def _cmd_connect(self, args: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_initialized:
            t.add_error("Сначала выполните /login"); return
        url = args.strip() or self._relay_url
        t.add_info(f"Подключение к {url}…")
        curses.doupdate()
        try:
            await self._app.connect(url)
            self._relay_url = url
            t.add_system(f"Подключено к {url}")
            self._update_status()
        except PQCError as e:
            t.add_error(f"Ошибка подключения: {e}")

    async def _cmd_wipe(self, args: str) -> None:
        t = self._tui
        assert t
        t.add_error("⚠  Введите  УДАЛИТЬ  для подтверждения:")
        confirm = t.read_password("Подтверждение: ")
        if confirm.strip() == "УДАЛИТЬ":
            await self._app.wipe_all()
            self._chat_id = self._chat_name = ""
            t.add_error("Все данные уничтожены")
            self._update_status()
        else:
            t.add_info("Отменено")

    async def _cmd_help(self, args: str) -> None:
        assert self._tui
        for line in HELP_TEXT.splitlines():
            self._tui.add_info(line)

    async def _cmd_quit(self, args: str) -> None:
        self._running = False



    async def _send_message(self, text: str) -> None:
        t = self._tui
        assert t
        if not self._app.is_connected:
            t.add_error("Не подключено к relay. Выйдите из чата (/back) и выполните /connect")
            return
        try:
            await self._app.send_message(self._chat_id, text)
            t.add_sent(text, datetime.now().strftime("%H:%M"))
        except PQCError as e:
            t.add_error(str(e))



    def _on_message(self, contact_id: str, text: str) -> None:
        t = self._tui
        if t is None:
            return
        ts = datetime.now().strftime("%H:%M")
        if contact_id == "system":
            t.add_system(text)
        elif contact_id == self._chat_id:
            t.add_received(self._chat_name, text, ts)
        else:
            contact = self._app._db.get_contact(contact_id)
            name = (contact.display_name if contact and contact.display_name
                    else contact_id[:8] + "...")
            t.add_system(f"Новое от {name}: {text}")
        t._draw_input(self._prompt())
        curses.doupdate()


def main() -> None:
    locale.setlocale(locale.LC_ALL, "")

    parser = argparse.ArgumentParser(description="PQC-Messenger")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--relay", default=DEFAULT_RELAY_URL)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            filename="/tmp/pqc_debug.log", level=logging.DEBUG,
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
