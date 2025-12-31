import os
import re
import sqlite3
import hashlib
import logging
import threading
import asyncio
import difflib
import textwrap
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup

from telegram.request import HTTPXRequest
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("watch_bot")

STATE_WAIT_URL = 1

ROLE_SUPERADMIN = "superadmin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"


def utcnow():
    return datetime.now(timezone.utc)


def build_reply_menu_kb():
    return ReplyKeyboardMarkup(
        [["Меню"]],
        resize_keyboard=True,
        one_time_keyboard=False,
        input_field_placeholder="Выберите действие",
    )


def dt_to_str(dt):
    return dt.astimezone(timezone.utc).isoformat()


def str_to_dt(s):
    return datetime.fromisoformat(s)


def sha256_text(text):
    h = hashlib.sha256()
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def compact_text(text, limit):
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def normalize_plain_text(text):
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\u00a0", " ")
    lines = []
    for line in text.split("\n"):
        line = " ".join(line.split()).strip()
        if line:
            lines.append(line)
    return "\n".join(lines).strip()


def parse_telegram_public_post(url):
    m = re.search(r"^https?://t\.me/(s/)?([A-Za-z0-9_]{3,})/(\d+)(\?.*)?$", (url or "").strip())
    if not m:
        return None
    if "/c/" in url:
        return None
    channel = m.group(2)
    msg_id = m.group(3)
    public_url = f"https://t.me/s/{channel}/{msg_id}"
    return {"channel": channel, "msg_id": msg_id, "public_url": public_url}


def _soup_drop_noise(soup):
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()


def _extract_title(soup):
    node = soup.select_one('meta[property="og:title"]')
    if node and node.get("content"):
        return normalize_plain_text(node["content"])

    node = soup.select_one('meta[name="twitter:title"]')
    if node and node.get("content"):
        return normalize_plain_text(node["content"])

    h1 = soup.find("h1")
    if h1:
        t = normalize_plain_text(h1.get_text(" ", strip=True))
        if t:
            return t

    t = soup.title.get_text(" ", strip=True) if soup.title else ""
    t = normalize_plain_text(t)
    if t:
        for sep in (" | ", " — ", " - "):
            if sep in t:
                left = t.split(sep, 1)[0].strip()
                if left:
                    return left
    return t


def read_env_bool(name, default):
    v = (os.environ.get(name, "") or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "y", "on")

def _extract_belta_article_body(soup):
    node = soup.select_one('[itemprop="articleBody"]')
    if not node:
        return ""

    # Нетривиальная логика: иногда внутри articleBody бывают "лишние" блоки с промо/шарингом.
    # Но вы просите "доставать всё" — поэтому мы их не выкидываем, просто чистим теги.
    text = node.get_text("\n", strip=True)
    return normalize_plain_text(text)

def _extract_fallback_body(soup):
    # Общий fallback: если articleBody не найден
    body = soup.body if soup.body else soup
    text = body.get_text("\n", strip=True)
    return normalize_plain_text(text)


def extract_news_snapshot_from_html(html, url):
    soup = BeautifulSoup(html or "", "html.parser")
    _soup_drop_noise(soup)

    title = _extract_title(soup)
    body = ""

    if "belta.by" in (url or "").lower():
        body = _extract_belta_article_body(soup)

    if not body:
        body = _extract_fallback_body(soup)

    return {
        "title": normalize_plain_text(title),
        "body": normalize_plain_text(body),
    }


def fetch_news_snapshot_sync(url, user_agent, timeout_sec, verify_ssl=True):
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    r = requests.get(url, headers=headers, timeout=timeout_sec, allow_redirects=True, verify=verify_ssl)
    status = r.status_code
    final_url = r.url
    content_type = (r.headers.get("Content-Type") or "").lower()

    if "text/html" not in content_type and "<html" not in (r.text[:400].lower()):
        text = normalize_plain_text(r.text or "")
        return {"title": "", "body": text, "status": status, "final_url": final_url}

    snap = extract_news_snapshot_from_html(r.text, final_url)
    return {"title": snap["title"], "body": snap["body"], "status": status, "final_url": final_url}



def fetch_telegram_post_snapshot_sync(tg_url, user_agent, timeout_sec, verify_ssl=True):
    info = parse_telegram_public_post(tg_url)
    if not info:
        raise ValueError("Ссылка на Telegram не распознана или это приватный пост (/c/).")

    headers = {"User-Agent": user_agent}
    r = requests.get(info["public_url"], headers=headers, timeout=timeout_sec, allow_redirects=True, verify=verify_ssl)

    soup = BeautifulSoup(r.text, "html.parser")
    node = soup.select_one("div.tgme_widget_message_text")
    if node:
        post_text = node.get_text("\n", strip=True)
        post_text = normalize_plain_text(post_text)
        return {"title": "", "body": post_text, "status": r.status_code, "final_url": r.url}

    text = normalize_plain_text(soup.get_text("\n", strip=True))
    return {"title": "", "body": text, "status": r.status_code, "final_url": r.url}


def compose_snapshot_text(title, body):
    title = normalize_plain_text(title)
    body = normalize_plain_text(body)
    if title and body:
        return title + "\n\n" + body
    return title or body


def split_for_diff(text, width):
    text = normalize_plain_text(text)
    if not text:
        return []
    lines = text.split("\n")
    out = []
    for line in lines:
        if len(line) <= width:
            out.append(line)
            continue
        wrapped = textwrap.wrap(line, width=width, break_long_words=False, break_on_hyphens=False)
        out.extend(wrapped if wrapped else [line])
    return out


def format_unified_diff(old_text, new_text, context_lines, max_lines, max_chars):
    old_lines = split_for_diff(old_text, 120)
    new_lines = split_for_diff(new_text, 120)

    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="before",
            tofile="after",
            lineterm="",
            n=context_lines,
        )
    )

    if not diff_lines:
        return ""

    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ["... (diff обрезан)"]

    text = "\n".join(diff_lines).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "\n... (diff обрезан)"
    return text


def safe_tg_text(text, limit=3800):
    return compact_text(text or "", limit)


class SqliteRepo:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._con = sqlite3.connect(self.path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._setup()

    def _setup(self):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS watches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_hash TEXT,
                    last_title TEXT,
                    last_body TEXT,
                    last_checked_at TEXT,
                    last_status INTEGER,
                    last_error TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(owner_id) REFERENCES users(user_id)
                );
            """)

            cur.execute("CREATE INDEX IF NOT EXISTS idx_watches_active_expires ON watches(is_active, expires_at);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_watches_owner ON watches(owner_id);")

            self._con.commit()

    def close(self):
        with self._lock:
            self._con.close()

    def ensure_user(self, user_id, role):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return
            cur.execute(
                "INSERT INTO users(user_id, role, created_at) VALUES(?,?,?)",
                (user_id, role, dt_to_str(utcnow())),
            )
            self._con.commit()

    def get_role(self, user_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            return row["role"] if row else None

    def upsert_role(self, user_id, role):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, user_id))
            else:
                cur.execute(
                    "INSERT INTO users(user_id, role, created_at) VALUES(?,?,?)",
                    (user_id, role, dt_to_str(utcnow())),
                )
            self._con.commit()

    def delete_user(self, user_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            self._con.commit()

    def list_users(self):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("SELECT user_id, role, created_at FROM users ORDER BY role, user_id")
            return [dict(x) for x in cur.fetchall()]

    def add_watch(self, owner_id, url, kind, expires_at, initial_hash, status, final_url, title, body):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                INSERT INTO watches(owner_id, url, kind, created_at, expires_at, last_hash, last_title, last_body, last_checked_at, last_status, last_error, is_active)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                """,
                (
                    owner_id,
                    final_url or url,
                    kind,
                    dt_to_str(utcnow()),
                    dt_to_str(expires_at),
                    initial_hash,
                    title,
                    body,
                    dt_to_str(utcnow()),
                    int(status) if status is not None else None,
                    None,
                ),
            )
            self._con.commit()
            return cur.lastrowid

    def list_watches_by_owner(self, owner_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                SELECT id, url, kind, created_at, expires_at, last_checked_at, last_status, last_error, is_active
                FROM watches
                WHERE owner_id = ?
                ORDER BY is_active DESC, id DESC
                """,
                (owner_id,),
            )
            return [dict(x) for x in cur.fetchall()]

    def deactivate_watch(self, watch_id, owner_id=None):
        with self._lock:
            cur = self._con.cursor()
            if owner_id is None:
                cur.execute("UPDATE watches SET is_active = 0 WHERE id = ?", (watch_id,))
            else:
                cur.execute("UPDATE watches SET is_active = 0 WHERE id = ? AND owner_id = ?", (watch_id, owner_id))
            self._con.commit()
            return cur.rowcount

    def get_active_watches(self, now_dt):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                SELECT id, owner_id, url, kind, expires_at, last_hash, last_title, last_body
                FROM watches
                WHERE is_active = 1
                """,
            )
            rows = []
            for r in cur.fetchall():
                expires_at = str_to_dt(r["expires_at"])
                rows.append(
                    {
                        "id": r["id"],
                        "owner_id": r["owner_id"],
                        "url": r["url"],
                        "kind": r["kind"],
                        "expires_at": expires_at,
                        "last_hash": r["last_hash"],
                        "last_title": r["last_title"],
                        "last_body": r["last_body"],
                    }
                )
            return rows

    def touch_watch_ok(self, watch_id, new_hash, status, title, body):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                UPDATE watches
                SET last_hash = ?, last_title = ?, last_body = ?, last_checked_at = ?, last_status = ?, last_error = NULL
                WHERE id = ?
                """,
                (new_hash, title, body, dt_to_str(utcnow()), int(status) if status is not None else None, watch_id),
            )
            self._con.commit()

    def touch_watch_error(self, watch_id, err_text, status=None):
        err_text = compact_text(err_text or "unknown error", 700)
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                UPDATE watches
                SET last_checked_at = ?, last_status = ?, last_error = ?
                WHERE id = ?
                """,
                (dt_to_str(utcnow()), int(status) if status is not None else None, err_text, watch_id),
            )
            self._con.commit()

    def expire_watch(self, watch_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("UPDATE watches SET is_active = 0 WHERE id = ?", (watch_id,))
            self._con.commit()


def read_env_int(name, default):
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def read_env_str(name, default):
    v = os.environ.get(name, "").strip()
    return v if v else default


def is_admin(role):
    return role in (ROLE_ADMIN, ROLE_SUPERADMIN)


def is_superadmin(role):
    return role == ROLE_SUPERADMIN


async def require_access(update, context):
    user = update.effective_user
    if not user:
        return False

    repo = context.application.bot_data["repo"]
    superadmin_id = context.application.bot_data["superadmin_id"]

    role = repo.get_role(user.id)

    if user.id == superadmin_id:
        if role != ROLE_SUPERADMIN:
            repo.upsert_role(user.id, ROLE_SUPERADMIN)
        return True

    if role is None:
        await update.effective_message.reply_text(
            "Нет доступа.\n\n"
            "Ваш Telegram ID: {uid}\n"
            "Попросите администратора добавить вас командой:\n"
            "/add_user {uid}".format(uid=user.id)
        )
        return False

    return True


def build_duration_kb():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("1 день", callback_data="dur:1"),
                InlineKeyboardButton("2 дня", callback_data="dur:2"),
                InlineKeyboardButton("3 дня", callback_data="dur:3"),
            ]
        ]
    )


async def on_menu_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    if (update.message.text or "").strip().lower() != "меню":
        return
    await cmd_start(update, context)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    role = repo.get_role(update.effective_user.id)

    await update.message.reply_text(
        "Бот для отслеживания изменений.\n\n"
        "Команды:\n"
        "/watch — добавить отслеживание ссылки\n"
        "/my — мои отслеживания\n"
        "/del <id> — отключить отслеживание\n"
        "/whoami — показать ваш ID и роль\n"
        "\nАдминские:\n"
        "/add_user <user_id> — добавить пользователя\n"
        "/add_admin <user_id> — выдать роль admin (только superadmin)\n"
        "/users — список пользователей (admin+)\n"
        "\nВаша роль: {role}".format(role=role),
        reply_markup=build_reply_menu_kb(),
    )




async def cmd_whoami(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return
    repo = context.application.bot_data["repo"]
    role = repo.get_role(update.effective_user.id)
    await update.message.reply_text(
        "Ваш Telegram ID: {uid}\nРоль: {role}".format(uid=update.effective_user.id, role=role)
    )


async def cmd_add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    role = repo.get_role(update.effective_user.id)
    if not is_admin(role):
        await update.message.reply_text("Недостаточно прав.")
        return

    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.message.reply_text("Использование: /add_user <user_id>")
        return

    uid = int(context.args[0])
    repo.upsert_role(uid, ROLE_USER)
    await update.message.reply_text("Пользователь {uid} добавлен (роль: user).".format(uid=uid))


async def cmd_add_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    role = repo.get_role(update.effective_user.id)
    if not is_superadmin(role):
        await update.message.reply_text("Только superadmin может назначать admin.")
        return

    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.message.reply_text("Использование: /add_admin <user_id>")
        return

    uid = int(context.args[0])
    repo.upsert_role(uid, ROLE_ADMIN)
    await update.message.reply_text("Пользователь {uid} назначен admin.".format(uid=uid))


async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    role = repo.get_role(update.effective_user.id)
    if not is_admin(role):
        await update.message.reply_text("Недостаточно прав.")
        return

    users = repo.list_users()
    if not users:
        await update.message.reply_text("Пользователей нет.")
        return

    lines = []
    for u in users:
        lines.append("{uid} — {role} — {created}".format(uid=u["user_id"], role=u["role"], created=u["created_at"]))
    await update.message.reply_text("Пользователи:\n" + "\n".join(lines))


async def cmd_my(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    items = repo.list_watches_by_owner(update.effective_user.id)
    if not items:
        await update.message.reply_text("У вас нет активных отслеживаний. Добавьте через /watch")
        return

    lines = []
    for it in items:
        status = "active" if it["is_active"] else "off"
        last_err = it["last_error"]
        if last_err:
            last_err = compact_text(last_err, 120)
            tail = " | error: {e}".format(e=last_err)
        else:
            tail = ""
        lines.append(
            "#{id} [{status}] ({kind})\n{url}\nexpires: {exp}{tail}".format(
                id=it["id"],
                status=status,
                kind=it["kind"],
                url=it["url"],
                exp=it["expires_at"],
                tail=tail,
            )
        )

    await update.message.reply_text("\n\n".join(lines))


async def cmd_del(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return

    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.message.reply_text("Использование: /del <id>")
        return

    watch_id = int(context.args[0])
    repo = context.application.bot_data["repo"]

    cnt = repo.deactivate_watch(watch_id, owner_id=update.effective_user.id)
    if cnt:
        await update.message.reply_text("Отключено: #{id}".format(id=watch_id))
    else:
        await update.message.reply_text("Не найдено или нет прав на удаление: #{id}".format(id=watch_id))


async def cmd_watch(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return STATE_WAIT_URL

    await update.message.reply_text(
        "Отправьте ссылку на новость сайта или на публичный пост Telegram.\n"
        "Отслеживаются только заголовок и основной текст (не вся страница целиком).\n\n"
        "Примеры:\n"
        "https://example.com/news/...\n"
        "https://t.me/channel/123\n\n"
        "Отмена: /cancel"
    )
    return STATE_WAIT_URL


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Отменено.")
    context.user_data.pop("pending_watch", None)
    return ConversationHandler.END


def build_snapshot_preview(title, body):
    t = normalize_plain_text(title)
    b = normalize_plain_text(body)
    if t and b:
        return compact_text(t, 240) + "\n\n" + compact_text(b, 900)
    if t:
        return compact_text(t, 1100)
    return compact_text(b, 1100)


async def on_watch_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok = await require_access(update, context)
    if not ok:
        return ConversationHandler.END

    url = (update.message.text or "").strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("Похоже, это не URL. Начните с http:// или https://")
        return STATE_WAIT_URL

    user_agent = context.application.bot_data["user_agent"]
    timeout_sec = context.application.bot_data["timeout_sec"]

    kind = "web"
    if "://t.me/" in url:
        info = parse_telegram_public_post(url)
        if not info:
            await update.message.reply_text(
                "Эта Telegram-ссылка не поддерживается.\n"
                "Поддерживаются только публичные посты вида https://t.me/<channel>/<id>.\n"
                "Приватные ссылки /c/... без авторизации скрапить нельзя."
            )
            return ConversationHandler.END
        kind = "telegram"

    await update.message.reply_text("Принято. Снимаю исходный слепок (заголовок + текст)...")

    try:

        verify_ssl = context.application.bot_data["verify_ssl"]
        if kind == "telegram":
            data = await asyncio.to_thread(fetch_telegram_post_snapshot_sync, url, user_agent, timeout_sec, verify_ssl)
        else:
            data = await asyncio.to_thread(fetch_news_snapshot_sync, url, user_agent, timeout_sec, verify_ssl)

        title = data.get("title") or ""
        body = data.get("body") or ""

        if not (title.strip() or body.strip()):
            await update.message.reply_text(
                "Не удалось извлечь заголовок/текст (пустой результат). Возможно, страница грузится скриптами или блокирует ботов."
            )
            return ConversationHandler.END

        composed = compose_snapshot_text(title, body)
        h = sha256_text(composed)

        context.user_data["pending_watch"] = {
            "url": url,
            "kind": kind,
            "initial_hash": h,
            "status": data.get("status"),
            "final_url": data.get("final_url") or url,
            "title": title,
            "body": body,
            "snapshot_preview": build_snapshot_preview(title, body),
        }

        await update.message.reply_text(
            "Выберите срок отслеживания изменений:",
            reply_markup=build_duration_kb(),
        )
        return ConversationHandler.END

    except Exception as e:
        logger.exception("snapshot failed")
        await update.message.reply_text("Ошибка при чтении ссылки: {e}".format(e=compact_text(str(e), 500)))
        return ConversationHandler.END


async def on_duration_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return

    await query.answer()

    ok = await require_access(update, context)
    if not ok:
        return

    data = (query.data or "").strip()
    if not data.startswith("dur:"):
        return

    pending = context.user_data.get("pending_watch")
    if not pending:
        await query.edit_message_text("Сессия выбора срока устарела. Добавьте заново через /watch")
        return

    try:
        days = int(data.split(":", 1)[1])
    except ValueError:
        await query.edit_message_text("Некорректный выбор срока.")
        context.user_data.pop("pending_watch", None)
        return

    if days not in (1, 2, 3):
        await query.edit_message_text("Доступные сроки: 1/2/3 дня.")
        context.user_data.pop("pending_watch", None)
        return

    repo = context.application.bot_data["repo"]
    owner_id = query.from_user.id
    expires_at = utcnow() + timedelta(days=days)

    watch_id = repo.add_watch(
        owner_id=owner_id,
        url=pending["url"],
        kind=pending["kind"],
        expires_at=expires_at,
        initial_hash=pending["initial_hash"],
        status=pending.get("status"),
        final_url=pending.get("final_url"),
        title=normalize_plain_text(pending.get("title") or ""),
        body=normalize_plain_text(pending.get("body") or ""),
    )

    preview = pending.get("snapshot_preview") or ""
    final_url = pending.get("final_url") or pending.get("url")

    context.user_data.pop("pending_watch", None)

    await query.edit_message_text(
        "Готово.\n"
        "Отслеживание добавлено: #{id}\n"
        "Срок: {days} дн.\n"
        "Ссылка: {url}\n\n"
        "Текущий слепок (фрагмент):\n{p}".format(id=watch_id, days=days, url=final_url, p=preview)
    )


async def check_one_watch(app, w, sem):
    repo = app.bot_data["repo"]
    user_agent = app.bot_data["user_agent"]
    timeout_sec = app.bot_data["timeout_sec"]

    wid = w["id"]
    owner_id = w["owner_id"]
    url = w["url"]
    kind = w["kind"]
    expires_at = w["expires_at"]

    last_hash = w["last_hash"] or ""
    last_title = w.get("last_title")
    last_body = w.get("last_body")

    now = utcnow()
    if now >= expires_at:
        repo.expire_watch(wid)
        try:
            await app.bot.send_message(
                chat_id=owner_id,
                text="Срок отслеживания истёк, отключено: #{id}\n{url}".format(id=wid, url=url),
                reply_markup=build_menu_kb(),
            )

        except Exception:
            pass
        return

    async with sem:
        try:
            verify_ssl = app.bot_data["verify_ssl"]

            if kind == "telegram":
                data = await asyncio.to_thread(fetch_telegram_post_snapshot_sync, url, user_agent, timeout_sec, verify_ssl)
            else:
                data = await asyncio.to_thread(fetch_news_snapshot_sync, url, user_agent, timeout_sec, verify_ssl)

            title = normalize_plain_text(data.get("title") or "")
            body = normalize_plain_text(data.get("body") or "")
            if not (title or body):
                raise RuntimeError("Пустой результат после извлечения заголовка/текста")

            composed = compose_snapshot_text(title, body)
            new_hash = sha256_text(composed)
            status = data.get("status")

            # Нетривиальная логика: “тихая миграция” для старых записей, где last_title/last_body ещё NULL
            if last_title is None and last_body is None:
                repo.touch_watch_ok(wid, new_hash, status, title, body)
                return

            if last_hash and new_hash != last_hash:
                old_title = normalize_plain_text(last_title or "")
                old_body = normalize_plain_text(last_body or "")

                parts = []
                parts.append("Обнаружены изменения.")
                parts.append("ID: #{id}".format(id=wid))
                parts.append("Ссылка: {url}".format(url=url))
                parts.append("Время: {t}".format(t=dt_to_str(utcnow())))

                title_changed = (old_title != title)
                body_changed = (old_body != body)

                if title_changed:
                    parts.append("")
                    parts.append("Изменение заголовка:")
                    parts.append(format_unified_diff(old_title, title, context_lines=0, max_lines=30, max_chars=1200) or "- (не удалось построить diff)")

                if body_changed:
                    parts.append("")
                    parts.append("Изменения в тексте:")
                    diff_text = format_unified_diff(old_body, body, context_lines=2, max_lines=80, max_chars=2400)
                    parts.append(diff_text or "- (не удалось построить diff)")

                parts.append("")
                parts.append("Текущая версия (фрагмент):")
                parts.append(build_snapshot_preview(title, body))

                msg = safe_tg_text("\n".join(parts), limit=3900)

                try:
                    await app.bot.send_message(
                        chat_id=owner_id,
                        text=msg,
                        reply_markup=build_menu_kb(),
                    )

                except Exception:
                    pass

            repo.touch_watch_ok(wid, new_hash, status, title, body)

        except Exception as e:
            repo.touch_watch_error(wid, str(e))
            logger.warning("watch #%s error: %s", wid, compact_text(str(e), 200))


async def job_check_watches(context: ContextTypes.DEFAULT_TYPE):
    app = context.application
    repo = app.bot_data["repo"]

    watches = repo.get_active_watches(utcnow())
    if not watches:
        return

    sem = asyncio.Semaphore(app.bot_data["max_concurrency"])
    tasks = [check_one_watch(app, w, sem) for w in watches]
    await asyncio.gather(*tasks, return_exceptions=True)


async def on_menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return

    await query.answer()

    ok = await require_access(update, context)
    if not ok:
        return

    repo = context.application.bot_data["repo"]
    role = repo.get_role(query.from_user.id)

    text = (
        "Бот для отслеживания изменений.\n\n"
        "Команды:\n"
        "/watch — добавить отслеживание ссылки\n"
        "/my — мои отслеживания\n"
        "/del <id> — отключить отслеживание\n"
        "/whoami — показать ваш ID и роль\n"
        "\nАдминские:\n"
        "/add_user <user_id> — добавить пользователя\n"
        "/add_admin <user_id> — выдать роль admin (только superadmin)\n"
        "/users — список пользователей (admin+)\n"
        "\nВаша роль: {role}".format(role=role)
    )

    # Если это нажатие кнопки под сообщением — удобнее редактировать это сообщение.
    # Если редактирование не получится (например, сообщение старое) — fallback отправит новое.
    try:
        await query.edit_message_text(text=text, reply_markup=build_menu_kb())
    except Exception:
        await context.application.bot.send_message(
            chat_id=query.from_user.id,
            text=text,
            reply_markup=build_menu_kb(),
        )


def build_menu_kb():
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("МЕНЮ", callback_data="menu:open")]]
    )

def build_app():
    token = read_env_str("BOT_TOKEN", "")
    if not token:
        raise RuntimeError("Не задан BOT_TOKEN")

    superadmin_id = read_env_int("SUPERADMIN_ID", 0)
    if superadmin_id <= 0:
        raise RuntimeError("Не задан SUPERADMIN_ID (целое число)")

    db_path = read_env_str("DB_PATH", "watch_bot.sqlite3")
    check_interval = read_env_int("CHECK_INTERVAL_SEC", 300)
    timeout_sec = read_env_int("REQUEST_TIMEOUT_SEC", 20)
    max_concurrency = read_env_int("MAX_CONCURRENCY", 10)

    user_agent = read_env_str(
        "USER_AGENT",
        "Mozilla/5.0 (compatible; WatchBot/1.0; +https://example.local/bot)",
    )

    repo = SqliteRepo(db_path)
    repo.ensure_user(superadmin_id, ROLE_SUPERADMIN)

    http_request_bot = HTTPXRequest(
    httpx_kwargs={"verify": False},
    connection_pool_size=20,
    pool_timeout=30,
    connect_timeout=10,
    read_timeout=30,
    write_timeout=30,
)

    http_request_updates = HTTPXRequest(
        httpx_kwargs={"verify": False},
        connection_pool_size=5,
        pool_timeout=30,
        connect_timeout=10,
        read_timeout=60,
        write_timeout=30,
    )

    app = (
        Application.builder()
        .token(token)
        .request(http_request_bot)
        .get_updates_request(http_request_updates)
        .build()
    )


    app.bot_data["repo"] = repo
    app.bot_data["superadmin_id"] = superadmin_id
    app.bot_data["check_interval"] = check_interval
    app.bot_data["timeout_sec"] = timeout_sec
    app.bot_data["user_agent"] = user_agent
    app.bot_data["max_concurrency"] = max_concurrency
    verify_ssl = read_env_bool("REQUEST_VERIFY_SSL", True)
    app.bot_data["verify_ssl"] = verify_ssl


    conv = ConversationHandler(
        entry_points=[CommandHandler("watch", cmd_watch)],
        states={
            STATE_WAIT_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_watch_url)],
        },
        fallbacks=[CommandHandler("cancel", cmd_cancel)],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("whoami", cmd_whoami))
    app.add_handler(CommandHandler("my", cmd_my))
    app.add_handler(CommandHandler("del", cmd_del))
    app.add_handler(CommandHandler("add_user", cmd_add_user))
    app.add_handler(CommandHandler("add_admin", cmd_add_admin))
    app.add_handler(CommandHandler("users", cmd_users))

    app.add_handler(conv)
    app.add_handler(CallbackQueryHandler(on_duration_choice, pattern=r"^dur:\d+$"))
    app.add_handler(CallbackQueryHandler(on_menu_button, pattern=r"^menu:open$"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_menu_text))


    app.job_queue.run_repeating(job_check_watches, interval=check_interval, first=10)

    return app


def main():
    app = build_app()
    logger.info("Bot started")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
