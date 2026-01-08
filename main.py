import os
import re
import sqlite3
import hashlib
import logging
import threading
import asyncio
from datetime import datetime, timedelta, timezone
import html

import requests
import urllib3
from bs4 import BeautifulSoup
from dotenv import load_dotenv

from telegram import Update, ReplyKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.request import HTTPXRequest


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)
logger = logging.getLogger("watch_bot")


def utcnow():
    return datetime.now(timezone.utc)


def dt_to_str(dt):
    return dt.astimezone(timezone.utc).isoformat()


def str_to_dt(s):
    return datetime.fromisoformat(s)


def read_env_int(name, default):
    v = (os.environ.get(name, "") or "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def read_env_str(name, default):
    v = (os.environ.get(name, "") or "").strip()
    return v if v else default


def read_env_bool(name, default):
    v = (os.environ.get(name, "") or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "y", "on")


def sha256_text(text):
    h = hashlib.sha256()
    h.update((text or "").encode("utf-8", errors="ignore"))
    return h.hexdigest()


def compact_text(text, limit):
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def normalize_plain_text(text):
    text = (text or "").replace("\r", "\n").replace("\u00a0", " ")
    lines = []
    for line in text.splitlines():
        line = " ".join(line.split()).strip()
        if line:
            lines.append(line)
    return "\n".join(lines).strip()


def is_url(text):
    t = (text or "").strip()
    return t.startswith("http://") or t.startswith("https://")


def build_reply_kb():
    return ReplyKeyboardMarkup(
        [["Меню", "Мои отслеживания"]],
        resize_keyboard=True,
        one_time_keyboard=False,
        input_field_placeholder="Вставьте ссылку на новость",
    )


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

    if soup.title:
        t = normalize_plain_text(soup.title.get_text(" ", strip=True))
        if t:
            for sep in (" | ", " — ", " - "):
                if sep in t:
                    left = t.split(sep, 1)[0].strip()
                    if left:
                        return left
            return t

    return ""


def _extract_belta_article_body(soup):
    node = soup.select_one('[itemprop="articleBody"]')
    if not node:
        return ""

    # Нетривиальная логика: чистим шум внутри articleBody, но не режем контент.
    _soup_drop_noise(node)

    text = node.get_text("\n", strip=True)
    return normalize_plain_text(text)


def _extract_fallback_body(soup):
    body = soup.body if soup.body else soup
    _soup_drop_noise(body)
    text = body.get_text("\n", strip=True)
    return normalize_plain_text(text)


def extract_news_snapshot_from_html(html_text, url):
    soup = BeautifulSoup(html_text or "", "html.parser")
    _soup_drop_noise(soup)

    title = _extract_title(soup)

    low = (url or "").lower()
    if "belta.by" in low:
        body = _extract_belta_article_body(soup)
    else:
        body = _extract_fallback_body(soup)

    return {
        "title": normalize_plain_text(title),
        "body": normalize_plain_text(body),
    }


def parse_telegram_public_post(url):
    m = re.search(r"^https?://t\.me/(s/)?([A-Za-z0-9_]{3,})/(\d+)(\?.*)?$", (url or "").strip())
    if not m:
        return None
    if "/c/" in url:
        return None
    channel = m.group(2)
    msg_id = m.group(3)
    public_url = f"https://t.me/s/{channel}/{msg_id}"
    return {"public_url": public_url}


def fetch_html_sync(url, user_agent, timeout_sec, verify_ssl):
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    r = requests.get(
        url,
        headers=headers,
        timeout=timeout_sec,
        allow_redirects=True,
        verify=verify_ssl,
    )

    return {
        "html": r.text or "",
        "status": r.status_code,
        "final_url": r.url,
        "content_type": (r.headers.get("Content-Type") or "").lower(),
    }


def fetch_telegram_post_snapshot_sync(tg_url, user_agent, timeout_sec, verify_ssl):
    info = parse_telegram_public_post(tg_url)
    if not info:
        raise ValueError("Ссылка Telegram не поддерживается (нужна публичная: https://t.me/<channel>/<id>).")

    headers = {"User-Agent": user_agent}
    r = requests.get(info["public_url"], headers=headers, timeout=timeout_sec, allow_redirects=True, verify=verify_ssl)

    soup = BeautifulSoup(r.text or "", "html.parser")
    _soup_drop_noise(soup)

    node = soup.select_one("div.tgme_widget_message_text")
    if node:
        text = normalize_plain_text(node.get_text("\n", strip=True))
        return {"title": "", "body": text, "status": r.status_code, "final_url": r.url}

    text = normalize_plain_text(soup.get_text("\n", strip=True))
    return {"title": "", "body": text, "status": r.status_code, "final_url": r.url}


def fetch_snapshot_sync(url, user_agent, timeout_sec, verify_ssl):
    if "://t.me/" in (url or "").lower():
        return fetch_telegram_post_snapshot_sync(url, user_agent, timeout_sec, verify_ssl)

    data = fetch_html_sync(url, user_agent, timeout_sec, verify_ssl)
    html_text = data.get("html") or ""
    final_url = data.get("final_url") or url
    content_type = data.get("content_type") or ""

    if "text/html" not in content_type and "<html" not in (html_text[:500].lower()):
        text = normalize_plain_text(html_text)
        return {"title": "", "body": text, "status": data.get("status"), "final_url": final_url}

    snap = extract_news_snapshot_from_html(html_text, final_url)
    return {"title": snap["title"], "body": snap["body"], "status": data.get("status"), "final_url": final_url}


def build_snapshot_hash(title, body):
    base = normalize_plain_text((title or "").strip()) + "\n\n" + normalize_plain_text((body or "").strip())
    return sha256_text(base)


def _tokenize_for_diff(text):
    text = normalize_plain_text(text or "")
    if not text:
        return []
    return re.findall(r"\s+|[^\s]+", text, flags=re.UNICODE)


def build_diff_merged_html(old_text, new_text):
    old_tokens = _tokenize_for_diff(old_text)
    new_tokens = _tokenize_for_diff(new_text)

    import difflib

    sm = difflib.SequenceMatcher(a=old_tokens, b=new_tokens)
    out = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for t in old_tokens[i1:i2]:
                out.append(html.escape(t))
            continue

        if tag == "delete":
            deleted = "".join(old_tokens[i1:i2])
            if deleted.strip():
                out.append("<s>{}</s>".format(html.escape(deleted)))
            else:
                out.append(html.escape(deleted))
            continue

        if tag == "insert":
            inserted = "".join(new_tokens[j1:j2])
            if inserted.strip():
                out.append("<b>{}</b>".format(html.escape(inserted)))
            else:
                out.append(html.escape(inserted))
            continue

        if tag == "replace":
            deleted = "".join(old_tokens[i1:i2])
            inserted = "".join(new_tokens[j1:j2])

            if deleted:
                if deleted.strip():
                    out.append("<s>{}</s>".format(html.escape(deleted)))
                else:
                    out.append(html.escape(deleted))

            if inserted:
                if inserted.strip():
                    out.append("<b>{}</b>".format(html.escape(inserted)))
                else:
                    out.append(html.escape(inserted))
            continue

    return "".join(out).strip()


def _safe_entity_cut(text, max_len):
    if max_len <= 0:
        return 0
    if max_len >= len(text):
        return len(text)

    chunk = text[:max_len]

    last_amp = chunk.rfind("&")
    last_semi = chunk.rfind(";")

    # Если в конце чанка остался "хвост" незакрытой HTML-сущности (&...),
    # режем до последнего '&', чтобы не ломать ParseMode.HTML.
    if last_amp != -1 and (last_semi == -1 or last_semi < last_amp):
        if last_amp == 0:
            return max_len
        return last_amp

    return max_len


def _split_html_message(html_text, limit):
    html_text = (html_text or "").strip()
    if not html_text:
        return []

    # Мы используем только <b>, </b>, <s>, </s>
    tag_re = re.compile(r"(</?b>|</?s>)", flags=re.IGNORECASE)
    parts = tag_re.split(html_text)

    chunks = []
    buf = []
    buf_len = 0
    open_tags = []

    def close_tags():
        closing = []
        for t in reversed(open_tags):
            if t == "b":
                closing.append("</b>")
            elif t == "s":
                closing.append("</s>")
        return "".join(closing)

    def open_tags_prefix():
        opening = []
        for t in open_tags:
            if t == "b":
                opening.append("<b>")
            elif t == "s":
                opening.append("<s>")
        return "".join(opening)

    def flush():
        nonlocal buf, buf_len
        if not buf:
            return
        chunk = "".join(buf) + close_tags()
        chunk = chunk.strip()
        if chunk:
            chunks.append(chunk)
        buf = []
        buf_len = 0
        prefix = open_tags_prefix()
        if prefix:
            buf.append(prefix)
            buf_len = len(prefix)

    def push_piece(piece):
        nonlocal buf_len

        if not piece:
            return

        while piece:
            space = limit - buf_len
            if space <= 0:
                flush()
                space = limit - buf_len
                if space <= 0:
                    break

            if len(piece) <= space:
                buf.append(piece)
                buf_len += len(piece)
                return

            cut = _safe_entity_cut(piece, space)
            if cut <= 0:
                flush()
                continue

            buf.append(piece[:cut])
            buf_len += cut
            piece = piece[cut:]
            flush()

    for p in parts:
        if not p:
            continue

        low = p.lower()

        if low in ("<b>", "<s>"):
            tag = "b" if low == "<b>" else "s"
            open_tags.append(tag)
            push_piece(low)
            continue

        if low in ("</b>", "</s>"):
            tag = "b" if low == "</b>" else "s"
            for i in range(len(open_tags) - 1, -1, -1):
                if open_tags[i] == tag:
                    open_tags.pop(i)
                    break
            push_piece(low)
            continue

        push_piece(p)

    if buf:
        chunk = "".join(buf) + close_tags()
        chunk = chunk.strip()
        if chunk:
            chunks.append(chunk)

    return chunks


async def send_html_long(bot, chat_id, html_text, reply_markup=None, disable_preview=True):
    chunks = _split_html_message(html_text, limit=3800)
    if not chunks:
        return

    for idx, chunk in enumerate(chunks):
        kb = reply_markup if idx == 0 else None
        await bot.send_message(
            chat_id=chat_id,
            text=chunk,
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
            disable_web_page_preview=disable_preview,
        )


class SqliteRepo:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._con = sqlite3.connect(self.path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._setup()

    def close(self):
        with self._lock:
            self._con.close()

    def _setup(self):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")

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
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_watches_owner ON watches(owner_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_watches_active_expires ON watches(is_active, expires_at);")
            self._con.commit()

    def add_or_refresh_watch(self, owner_id, url, kind, expires_at, snapshot_hash, title, body, status, final_url):
        final_url = final_url or url
        now_s = dt_to_str(utcnow())

        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                SELECT id FROM watches
                WHERE owner_id = ? AND url = ? AND is_active = 1
                ORDER BY id DESC
                LIMIT 1
                """,
                (owner_id, final_url),
            )
            row = cur.fetchone()

            if row:
                wid = row["id"]
                cur.execute(
                    """
                    UPDATE watches
                    SET kind = ?, expires_at = ?, last_hash = ?, last_title = ?, last_body = ?,
                        last_checked_at = ?, last_status = ?, last_error = NULL
                    WHERE id = ?
                    """,
                    (
                        kind,
                        dt_to_str(expires_at),
                        snapshot_hash,
                        title,
                        body,
                        now_s,
                        int(status) if status is not None else None,
                        wid,
                    ),
                )
                self._con.commit()
                return wid, True

            cur.execute(
                """
                INSERT INTO watches(owner_id, url, kind, created_at, expires_at, last_hash, last_title, last_body,
                                    last_checked_at, last_status, last_error, is_active)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                """,
                (
                    owner_id,
                    final_url,
                    kind,
                    now_s,
                    dt_to_str(expires_at),
                    snapshot_hash,
                    title,
                    body,
                    now_s,
                    int(status) if status is not None else None,
                    None,
                ),
            )
            self._con.commit()
            return cur.lastrowid, False

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

    def deactivate_watch(self, watch_id, owner_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                "UPDATE watches SET is_active = 0 WHERE id = ? AND owner_id = ?",
                (watch_id, owner_id),
            )
            self._con.commit()
            return cur.rowcount

    def get_active_watches(self):
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
                rows.append(
                    {
                        "id": r["id"],
                        "owner_id": r["owner_id"],
                        "url": r["url"],
                        "kind": r["kind"],
                        "expires_at": str_to_dt(r["expires_at"]),
                        "last_hash": r["last_hash"] or "",
                        "last_title": r["last_title"] or "",
                        "last_body": r["last_body"] or "",
                    }
                )
            return rows

    def touch_watch_ok(self, watch_id, snapshot_hash, title, body, status):
        with self._lock:
            cur = self._con.cursor()
            cur.execute(
                """
                UPDATE watches
                SET last_hash = ?, last_title = ?, last_body = ?, last_checked_at = ?, last_status = ?, last_error = NULL
                WHERE id = ?
                """,
                (
                    snapshot_hash,
                    title,
                    body,
                    dt_to_str(utcnow()),
                    int(status) if status is not None else None,
                    watch_id,
                ),
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
                (
                    dt_to_str(utcnow()),
                    int(status) if status is not None else None,
                    err_text,
                    watch_id,
                ),
            )
            self._con.commit()

    def expire_watch(self, watch_id):
        with self._lock:
            cur = self._con.cursor()
            cur.execute("UPDATE watches SET is_active = 0 WHERE id = ?", (watch_id,))
            self._con.commit()


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "Отправьте ссылку на новость — бот начнёт отслеживание на 24 часа.\n"
        "При изменениях пришлёт уведомление с полным текстом и подсветкой правок.",
        reply_markup=build_reply_kb(),
    )


async def cmd_my(update: Update, context: ContextTypes.DEFAULT_TYPE):
    repo = context.application.bot_data["repo"]
    items = repo.list_watches_by_owner(update.effective_user.id)

    if not items:
        await update.effective_message.reply_text(
            "У вас нет отслеживаний. Просто отправьте ссылку на новость.",
            reply_markup=build_reply_kb(),
        )
        return

    lines = []
    for it in items:
        status = "active" if it["is_active"] else "off"
        tail = ""
        if it.get("last_error"):
            tail = " | error: {e}".format(e=compact_text(it["last_error"], 120))

        lines.append(
            "#{id} [{status}] ({kind})\n{url}\nexpires: {exp}{tail}".format(
                id=it["id"],
                status=status,
                kind=it.get("kind") or "web",
                url=it["url"],
                exp=it["expires_at"],
                tail=tail,
            )
        )

    await update.effective_message.reply_text("\n\n".join(lines), reply_markup=build_reply_kb())


async def cmd_del(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Использование: /del <id>", reply_markup=build_reply_kb())
        return

    watch_id = int(context.args[0])
    repo = context.application.bot_data["repo"]
    cnt = repo.deactivate_watch(watch_id, owner_id=update.effective_user.id)

    if cnt:
        await update.effective_message.reply_text("Отключено: #{id}".format(id=watch_id), reply_markup=build_reply_kb())
    else:
        await update.effective_message.reply_text(
            "Не найдено или нет прав: #{id}".format(id=watch_id),
            reply_markup=build_reply_kb(),
        )


async def on_error(update, context):
    logger.exception("Unhandled error: %s", context.error)


async def on_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    txt = (update.message.text or "").strip()

    if txt.lower() == "меню":
        await cmd_start(update, context)
        return

    if txt.lower() == "мои отслеживания":
        await cmd_my(update, context)
        return

    if not is_url(txt):
        await update.message.reply_text(
            "Вставьте ссылку на новость (http/https).",
            reply_markup=build_reply_kb(),
        )
        return

    user_agent = context.application.bot_data["user_agent"]
    timeout_sec = context.application.bot_data["timeout_sec"]
    verify_ssl = context.application.bot_data["verify_ssl"]

    kind = "telegram" if "://t.me/" in txt.lower() else "web"

    try:
        data = await asyncio.to_thread(fetch_snapshot_sync, txt, user_agent, timeout_sec, verify_ssl)
        title = normalize_plain_text(data.get("title") or "")
        body = normalize_plain_text(data.get("body") or "")
        status = data.get("status")
        final_url = data.get("final_url") or txt

        if not (title.strip() or body.strip()):
            raise RuntimeError("Не удалось извлечь заголовок/текст (пустой результат).")

        snapshot_hash = build_snapshot_hash(title, body)
        expires_at = utcnow() + timedelta(hours=24)

        repo = context.application.bot_data["repo"]
        repo.add_or_refresh_watch(
            owner_id=update.effective_user.id,
            url=txt,
            kind=kind,
            expires_at=expires_at,
            snapshot_hash=snapshot_hash,
            title=title,
            body=body,
            status=status,
            final_url=final_url,
        )

        # Ничего не отправляем пользователю.

    except Exception as e:
        logger.exception("snapshot failed")
        await update.message.reply_text(
            "Ошибка при чтении ссылки: {e}".format(e=compact_text(str(e), 500)),
            reply_markup=build_reply_kb(),
        )


async def check_one_watch(app, w, sem):
    repo = app.bot_data["repo"]
    user_agent = app.bot_data["user_agent"]
    timeout_sec = app.bot_data["timeout_sec"]
    verify_ssl = app.bot_data["verify_ssl"]

    wid = w["id"]
    owner_id = w["owner_id"]
    url = w["url"]
    expires_at = w["expires_at"]

    last_hash = w["last_hash"] or ""
    last_title = w["last_title"] or ""
    last_body = w["last_body"] or ""

    now = utcnow()
    if now >= expires_at:
        repo.expire_watch(wid)
        return

    async with sem:
        try:
            data = await asyncio.to_thread(fetch_snapshot_sync, url, user_agent, timeout_sec, verify_ssl)
            title = normalize_plain_text(data.get("title") or "")
            body = normalize_plain_text(data.get("body") or "")
            status = data.get("status")

            if not (title.strip() or body.strip()):
                raise RuntimeError("Пустой результат после извлечения текста")

            new_hash = build_snapshot_hash(title, body)

            if last_hash and new_hash != last_hash:
                shown_title = title.strip() or last_title.strip() or "Изменения"
                diff_body_html = build_diff_merged_html(last_body, body)

                header_html = "<b>{}</b>\n{}\n\n".format(html.escape(shown_title), html.escape(url))
                message_html = (header_html + (diff_body_html or "")).strip()

                await send_html_long(
                    bot=app.bot,
                    chat_id=owner_id,
                    html_text=message_html,
                    reply_markup=build_reply_kb(),
                    disable_preview=True,
                )

            repo.touch_watch_ok(wid, new_hash, title, body, status)

        except Exception as e:
            repo.touch_watch_error(wid, str(e))
            logger.warning("watch #%s error: %s", wid, compact_text(str(e), 200))


async def job_check_watches(context: ContextTypes.DEFAULT_TYPE):
    app = context.application
    repo = app.bot_data["repo"]

    watches = repo.get_active_watches()
    if not watches:
        return

    sem = asyncio.Semaphore(app.bot_data["max_concurrency"])
    tasks = [check_one_watch(app, w, sem) for w in watches]
    await asyncio.gather(*tasks, return_exceptions=True)


def build_app():
    token = read_env_str("BOT_TOKEN", "")
    if not token:
        raise RuntimeError("Не задан BOT_TOKEN")

    db_path = read_env_str("DB_PATH", "watch_bot.sqlite3")
    check_interval = read_env_int("CHECK_INTERVAL_SEC", 300)
    timeout_sec = read_env_int("REQUEST_TIMEOUT_SEC", 20)
    max_concurrency = read_env_int("MAX_CONCURRENCY", 5)

    verify_ssl = read_env_bool("REQUEST_VERIFY_SSL", True)
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    user_agent = read_env_str(
        "USER_AGENT",
        "Mozilla/5.0 (compatible; WatchBot/1.0; +https://example.local/bot)",
    )

    repo = SqliteRepo(db_path)

    telegram_verify_ssl = read_env_bool("TELEGRAM_VERIFY_SSL", True)

    http_request_bot = HTTPXRequest(
        httpx_kwargs={"verify": telegram_verify_ssl},
        connection_pool_size=30,
        pool_timeout=30,
        connect_timeout=10,
        read_timeout=30,
        write_timeout=30,
    )

    http_request_updates = HTTPXRequest(
        httpx_kwargs={"verify": telegram_verify_ssl},
        connection_pool_size=10,
        pool_timeout=30,
        connect_timeout=10,
        read_timeout=60,
        write_timeout=30,
    )

    async def post_init(app):
        await app.bot.delete_webhook(drop_pending_updates=True)
        me = await app.bot.get_me()
        logger.info("Connected as @%s (id=%s)", me.username, me.id)

    async def post_shutdown(app):
        try:
            app.bot_data["repo"].close()
        except Exception:
            pass

    app = (
        Application.builder()
        .token(token)
        .request(http_request_bot)
        .get_updates_request(http_request_updates)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.bot_data["repo"] = repo
    app.bot_data["check_interval"] = check_interval
    app.bot_data["timeout_sec"] = timeout_sec
    app.bot_data["user_agent"] = user_agent
    app.bot_data["max_concurrency"] = max_concurrency
    app.bot_data["verify_ssl"] = verify_ssl

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("my", cmd_my))
    app.add_handler(CommandHandler("del", cmd_del))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text_message))

    app.add_error_handler(on_error)

    app.job_queue.run_repeating(job_check_watches, interval=check_interval, first=10)

    return app


def main():
    app = build_app()
    logger.info("Bot started")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
