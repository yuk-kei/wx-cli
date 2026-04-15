"""
wx-daemon: 微信数据访问守护进程

启动后常驻后台，通过 Unix socket 响应 CLI 查询，持续监听 WAL 变化推送实时消息。

Socket : ~/.wechat-cli/daemon.sock
PID    : ~/.wechat-cli/daemon.pid
Log    : ~/.wechat-cli/daemon.log
Cache  : ~/.wechat-cli/cache/
"""

import hashlib
import hmac as hmac_mod
import json
import os
import queue
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from contextlib import closing
from datetime import datetime

from Crypto.Cipher import AES
import zstandard as zstd

# ─── 路径常量 ─────────────────────────────────────────────────────────────────
CLI_DIR   = os.path.join(os.path.expanduser("~"), ".wechat-cli")
SOCK_PATH = os.path.join(CLI_DIR, "daemon.sock")
PID_PATH  = os.path.join(CLI_DIR, "daemon.pid")
LOG_PATH  = os.path.join(CLI_DIR, "daemon.log")
CACHE_DIR = os.path.join(CLI_DIR, "cache")
MTIME_FILE = os.path.join(CACHE_DIR, "_mtimes.json")

os.makedirs(CLI_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# ─── 加密常量 ─────────────────────────────────────────────────────────────────
PAGE_SZ        = 4096
SALT_SZ        = 16
RESERVE_SZ     = 80
SQLITE_HDR     = b'SQLite format 3\x00'
WAL_HDR_SZ     = 32
WAL_FRAME_HDR  = 24

# ─── 配置加载 ─────────────────────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from config import load_config
from key_utils import get_key_info, strip_key_metadata

_cfg     = load_config()
DB_DIR   = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]

with open(KEYS_FILE, encoding="utf-8") as _f:
    ALL_KEYS = strip_key_metadata(json.load(_f))

_zstd = zstd.ZstdDecompressor()

# ─── 日志 ─────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)

# ─── 解密 ─────────────────────────────────────────────────────────────────────

def _decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        enc = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(enc)
        return bytes(SQLITE_HDR + dec + b'\x00' * RESERVE_SZ)
    enc = page_data[:PAGE_SZ - RESERVE_SZ]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(enc)
    return dec + b'\x00' * RESERVE_SZ


def _full_decrypt(db_path: str, out_path: str, enc_key: bytes) -> None:
    size = os.path.getsize(db_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, size // PAGE_SZ + 1):
            page = fin.read(PAGE_SZ)
            if not page:
                break
            if len(page) < PAGE_SZ:
                page = page + b'\x00' * (PAGE_SZ - len(page))
            fout.write(_decrypt_page(enc_key, page, pgno))


def _apply_wal(wal_path: str, out_path: str, enc_key: bytes) -> None:
    if not os.path.exists(wal_path):
        return
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HDR_SZ:
        return
    frame_size = WAL_FRAME_HDR + PAGE_SZ
    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        hdr = wf.read(WAL_HDR_SZ)
        s1 = struct.unpack('>I', hdr[16:20])[0]
        s2 = struct.unpack('>I', hdr[20:24])[0]
        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HDR)
            if len(fh) < WAL_FRAME_HDR:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            fs1  = struct.unpack('>I', fh[8:12])[0]
            fs2  = struct.unpack('>I', fh[12:16])[0]
            ep   = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break
            if pgno == 0 or pgno > 1_000_000:
                continue
            if fs1 != s1 or fs2 != s2:
                continue
            dec = _decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)

# ─── DB 缓存（mtime 感知，跨进程重启可复用）────────────────────────────────────

class DBCache:
    def __init__(self):
        self._cache: dict[str, tuple[float, float, str]] = {}  # rel -> (db_mt, wal_mt, path)
        self._lock = threading.Lock()
        self._load_persistent()

    def _cache_path(self, rel_key: str) -> str:
        h = hashlib.md5(rel_key.encode()).hexdigest()[:12]
        return os.path.join(CACHE_DIR, f"{h}.db")

    def _load_persistent(self) -> None:
        if not os.path.exists(MTIME_FILE):
            return
        try:
            saved = json.loads(open(MTIME_FILE, encoding='utf-8').read())
        except Exception:
            return
        reused = 0
        for rel_key, info in saved.items():
            path = info.get("path", "")
            if not os.path.exists(path):
                continue
            db_path  = os.path.join(DB_DIR, rel_key.replace('\\', os.sep).replace('/', os.sep))
            wal_path = db_path + "-wal"
            try:
                db_mt  = os.path.getmtime(db_path)
                wal_mt = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0.0
            except OSError:
                continue
            if db_mt == info.get("db_mt") and wal_mt == info.get("wal_mt"):
                self._cache[rel_key] = (db_mt, wal_mt, path)
                reused += 1
        if reused:
            _log(f"DBCache: 复用 {reused} 个已解密 DB")

    def _save_persistent(self) -> None:
        data = {k: {"db_mt": v[0], "wal_mt": v[1], "path": v[2]} for k, v in self._cache.items()}
        try:
            with open(MTIME_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except OSError:
            pass

    def get(self, rel_key: str) -> str | None:
        key_info = get_key_info(ALL_KEYS, rel_key)
        if not key_info:
            return None
        db_path  = os.path.join(DB_DIR, rel_key.replace('\\', os.sep).replace('/', os.sep))
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return None
        try:
            db_mt  = os.path.getmtime(db_path)
            wal_mt = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0.0
        except OSError:
            return None

        with self._lock:
            cached = self._cache.get(rel_key)
            if cached and cached[0] == db_mt and cached[1] == wal_mt and os.path.exists(cached[2]):
                return cached[2]
            out = self._cache_path(rel_key)
            enc_key = bytes.fromhex(key_info["enc_key"])
            t0 = time.perf_counter()
            _full_decrypt(db_path, out, enc_key)
            _apply_wal(wal_path, out, enc_key)
            ms = (time.perf_counter() - t0) * 1000
            _log(f"解密 {rel_key} ({ms:.0f}ms)")
            self._cache[rel_key] = (db_mt, wal_mt, out)
            self._save_persistent()
            return out


_db = DBCache()

# ─── 消息 DB 列表 ─────────────────────────────────────────────────────────────

MSG_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if re.search(r'message[/\\]message_\d+\.db$', k)
])

# ─── 联系人缓存 ───────────────────────────────────────────────────────────────

_names: dict[str, str] | None = None
_names_lock = threading.Lock()
_md5_to_uname: dict[str, str] | None = None
_md5_lock = threading.Lock()


def _load_names() -> dict[str, str]:
    global _names
    with _names_lock:
        if _names is not None:
            return _names
        path = _db.get(os.path.join("contact", "contact.db"))
        if not path:
            _names = {}
            return _names
        try:
            with closing(sqlite3.connect(path)) as conn:
                rows = conn.execute(
                    "SELECT username, nick_name, remark FROM contact"
                ).fetchall()
            _names = {u: (r if r else (n if n else u)) for u, n, r in rows}
        except Exception:
            _names = {}
        return _names


def _get_md5_lookup() -> dict[str, str]:
    """返回 {md5(username): username}，用于全局搜索时从表名反推联系人。"""
    global _md5_to_uname
    with _md5_lock:
        if _md5_to_uname is not None:
            return _md5_to_uname
        names = _load_names()
        _md5_to_uname = {hashlib.md5(u.encode()).hexdigest(): u for u in names}
        return _md5_to_uname


def _refresh_names() -> None:
    """强制刷新联系人缓存（新联系人/新群加入时调用）"""
    global _names, _md5_to_uname
    with _names_lock:
        _names = None
    with _md5_lock:
        _md5_to_uname = None
    _load_names()
    _get_md5_lookup()

# ─── 辅助 ─────────────────────────────────────────────────────────────────────

_XML_BAD = re.compile(r'<!DOCTYPE|<!ENTITY', re.IGNORECASE)


def _fmt_type(t) -> str:
    try:
        base = int(t) & 0xFFFFFFFF if int(t) > 0xFFFFFFFF else int(t)
    except (TypeError, ValueError):
        return f'type={t}'
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片', 43: '视频',
        47: '表情', 48: '位置', 49: '链接/文件', 50: '通话',
        10000: '系统', 10002: '撤回',
    }.get(base, f'type={base}')


def _decompress(content, ct) -> str | None:
    if ct == 4 and isinstance(content, bytes):
        try:
            return _zstd.decompress(content).decode('utf-8', errors='replace')
        except Exception:
            return None
    if isinstance(content, bytes):
        return content.decode('utf-8', errors='replace')
    return content


def _fmt_content(local_id: int, local_type, content: str | None, is_group: bool) -> str:
    try:
        base = int(local_type) & 0xFFFFFFFF if int(local_type) > 0xFFFFFFFF else int(local_type)
    except (TypeError, ValueError):
        base = 0
    if base == 3:
        return f"[图片] local_id={local_id}"
    if base == 47:
        return "[表情]"
    if base == 50:
        return "[通话]"
    # 群聊消息内容带 "sender:\n" 前缀，解析 XML 前先剥离
    text = content or ''
    if is_group and ':\n' in text:
        text = text.split(':\n', 1)[1]
    if base == 49 and text and '<appmsg' in text and not _XML_BAD.search(text):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            appmsg = root.find('.//appmsg')
            if appmsg is not None:
                title = (appmsg.findtext('title') or '').strip()
                atype = (appmsg.findtext('type') or '').strip()
                if atype == '6':
                    return f"[文件] {title}" if title else "[文件]"
                if atype == '57':
                    ref = appmsg.find('.//refermsg')
                    ref_content = ''
                    if ref is not None:
                        ref_content = re.sub(r'\s+', ' ', (ref.findtext('content') or '')).strip()
                        if len(ref_content) > 80:
                            ref_content = ref_content[:80] + '...'
                    quote = f"[引用] {title}" if title else "[引用]"
                    return f"{quote}\n  ↳ {ref_content}" if ref_content else quote
                if atype in ('33', '36', '44'):
                    return f"[小程序] {title}" if title else "[小程序]"
                return f"[链接] {title}" if title else "[链接/文件]"
        except Exception:
            pass
    return text


def _resolve_username(chat_name: str) -> str | None:
    names = _load_names()
    if chat_name in names or '@chatroom' in chat_name or chat_name.startswith('wxid_'):
        return chat_name
    low = chat_name.lower()
    for uname, display in names.items():
        if low == display.lower():
            return uname
    for uname, display in names.items():
        if low in display.lower():
            return uname
    return None


def _load_id2u(conn: sqlite3.Connection) -> dict[int, str]:
    try:
        return {r: u for r, u in conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall() if u}
    except Exception:
        return {}


def _sender_label(real_sender_id, content, is_group, chat_username, id2u, names) -> str:
    sender_uname = id2u.get(real_sender_id, '')
    if is_group:
        if sender_uname and sender_uname != chat_username:
            return names.get(sender_uname, sender_uname)
        if content and ':\n' in content:
            raw = content.split(':\n', 1)[0]
            return names.get(raw, raw)
        return ''
    return names.get(sender_uname, '') if sender_uname and sender_uname != chat_username else ''


def _find_msg_tables(username: str) -> list[dict]:
    table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
    if not re.fullmatch(r'Msg_[0-9a-f]{32}', table_name):
        return []
    results = []
    for rel_key in MSG_DB_KEYS:
        path = _db.get(rel_key)
        if not path:
            continue
        try:
            with closing(sqlite3.connect(path)) as conn:
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
                ).fetchone()
                if not exists:
                    continue
                max_ts = conn.execute(f"SELECT MAX(create_time) FROM [{table_name}]").fetchone()[0] or 0
                results.append({'path': path, 'table': table_name, 'max_ts': max_ts})
        except Exception:
            continue
    results.sort(key=lambda x: x['max_ts'], reverse=True)
    return results

# ─── 查询函数 ─────────────────────────────────────────────────────────────────

def q_sessions(limit: int = 20) -> dict:
    path = _db.get(os.path.join("session", "session.db"))
    if not path:
        return {"error": "无法解密 session.db"}
    names = _load_names()
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
            ORDER BY last_timestamp DESC LIMIT ?
        """, (limit,)).fetchall()

    results = []
    for username, unread, summary, ts, msg_type, sender, sender_name in rows:
        display  = names.get(username, username)
        is_group = '@chatroom' in username
        if isinstance(summary, bytes):
            try:
                summary = _zstd.decompress(summary).decode('utf-8', errors='replace')
            except Exception:
                summary = '(压缩内容)'
        if isinstance(summary, str) and ':\n' in summary:
            summary = summary.split(':\n', 1)[1]
        sender_display = ''
        if is_group and sender:
            sender_display = names.get(sender, sender_name or sender)
        results.append({
            "chat":          display,
            "username":      username,
            "is_group":      is_group,
            "unread":        unread or 0,
            "last_msg_type": _fmt_type(msg_type),
            "last_sender":   sender_display,
            "summary":       str(summary or ''),
            "timestamp":     ts,
            "time":          datetime.fromtimestamp(ts).strftime('%m-%d %H:%M'),
        })
    return {"sessions": results}


def q_history(chat_name: str, limit: int = 50, offset: int = 0,
              since: int | None = None, until: int | None = None) -> dict:
    username = _resolve_username(chat_name)
    if not username:
        return {"error": f"找不到联系人: {chat_name}"}
    names    = _load_names()
    display  = names.get(username, username)
    is_group = '@chatroom' in username
    tables   = _find_msg_tables(username)
    if not tables:
        return {"error": f"找不到 {display} 的消息记录"}

    all_msgs: list[dict] = []
    for tbl in tables:
        try:
            with closing(sqlite3.connect(tbl['path'])) as conn:
                id2u = _load_id2u(conn)
                clauses, params = [], []
                if since:
                    clauses.append('create_time >= ?'); params.append(since)
                if until:
                    clauses.append('create_time <= ?'); params.append(until)
                where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
                rows = conn.execute(
                    f"SELECT local_id, local_type, create_time, real_sender_id,"
                    f" message_content, WCDB_CT_message_content"
                    f" FROM [{tbl['table']}] {where}"
                    f" ORDER BY create_time DESC LIMIT ? OFFSET ?",
                    (*params, limit + offset, 0)
                ).fetchall()
            for local_id, local_type, ts, real_sender_id, content, ct in rows:
                content = _decompress(content, ct)
                if content is None:
                    content = '(无法解压)'
                sender = _sender_label(real_sender_id, content, is_group, username, id2u, names)
                text   = _fmt_content(local_id, local_type, content, is_group)
                all_msgs.append({
                    "timestamp": ts,
                    "time":      datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
                    "sender":    sender,
                    "content":   text,
                    "type":      _fmt_type(local_type),
                    "local_id":  local_id,
                })
        except Exception:
            continue

    all_msgs.sort(key=lambda m: m['timestamp'], reverse=True)
    paged = all_msgs[offset: offset + limit]
    paged.sort(key=lambda m: m['timestamp'])
    return {
        "chat":     display,
        "username": username,
        "is_group": is_group,
        "count":    len(paged),
        "messages": paged,
    }


def q_search(keyword: str, chats: list[str] | None = None,
             limit: int = 20, since: int | None = None, until: int | None = None) -> dict:
    names = _load_names()
    results: list[dict] = []

    # 构建搜索目标 (db_path, table_name, chat_display, username)
    targets: list[tuple[str, str, str, str]] = []

    if chats:
        for chat_name in chats:
            uname = _resolve_username(chat_name)
            if not uname:
                continue
            for tbl in _find_msg_tables(uname):
                targets.append((tbl['path'], tbl['table'], names.get(uname, uname), uname))
    else:
        md5_lookup = _get_md5_lookup()
        for rel_key in MSG_DB_KEYS:
            path = _db.get(rel_key)
            if not path:
                continue
            try:
                with closing(sqlite3.connect(path)) as conn:
                    table_rows = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                    ).fetchall()
                for (tname,) in table_rows:
                    if not re.fullmatch(r'Msg_[0-9a-f]{32}', tname):
                        continue
                    uname = md5_lookup.get(tname[4:], '')
                    display = names.get(uname, uname) if uname else ''
                    targets.append((path, tname, display, uname))
            except Exception:
                continue

    # 按 db_path 分组，减少重复打开
    by_path: dict[str, list[tuple[str, str, str]]] = {}
    for db_path, table, display, uname in targets:
        by_path.setdefault(db_path, []).append((table, display, uname))

    for db_path, table_list in by_path.items():
        try:
            with closing(sqlite3.connect(db_path)) as conn:
                id2u = _load_id2u(conn)
                for table, display, uname in table_list:
                    clauses = ['message_content LIKE ?']
                    params  = [f'%{keyword}%']
                    if since:
                        clauses.append('create_time >= ?'); params.append(since)
                    if until:
                        clauses.append('create_time <= ?'); params.append(until)
                    where = f"WHERE {' AND '.join(clauses)}"
                    rows = conn.execute(
                        f"SELECT local_id, local_type, create_time, real_sender_id,"
                        f" message_content, WCDB_CT_message_content"
                        f" FROM [{table}] {where}"
                        f" ORDER BY create_time DESC LIMIT ?",
                        (*params, limit * 3)
                    ).fetchall()
                    is_group = uname and '@chatroom' in uname
                    for local_id, local_type, ts, real_sender_id, content, ct in rows:
                        content = _decompress(content, ct)
                        if content is None:
                            continue
                        sender = _sender_label(real_sender_id, content, is_group or False,
                                               uname or '', id2u, names)
                        text = _fmt_content(local_id, local_type, content, is_group or False)
                        chat_display = display or uname or table
                        results.append({
                            "timestamp": ts,
                            "time":      datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
                            "chat":      chat_display,
                            "sender":    sender,
                            "content":   text,
                            "type":      _fmt_type(local_type),
                        })
        except Exception:
            continue

    results.sort(key=lambda r: r['timestamp'], reverse=True)
    paged = results[:limit]
    return {"keyword": keyword, "count": len(paged), "results": paged}


def q_contacts(query: str | None = None, limit: int = 50) -> dict:
    names = _load_names()
    contacts = [
        {"username": u, "display": d}
        for u, d in names.items()
        if not u.startswith('gh_')   # 排除公众号
        and not u.startswith('biz_') # 排除服务号
    ]
    if query:
        low = query.lower()
        contacts = [c for c in contacts
                    if low in c['display'].lower() or low in c['username'].lower()]
    contacts.sort(key=lambda c: c['display'])
    return {"contacts": contacts[:limit], "total": len(contacts)}

# ─── 实时推送（watch）────────────────────────────────────────────────────────

_watch_clients: list[queue.Queue] = []
_watch_lock    = threading.Lock()


def _broadcast(event: dict) -> None:
    line = json.dumps(event, ensure_ascii=False)
    with _watch_lock:
        dead = []
        for q in _watch_clients:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _watch_clients.remove(q)


def _wal_watcher() -> None:
    """后台线程：每 500ms 检测 session.db-wal 的 mtime，有变化时推送新消息"""
    last_mtime: dict[str, float] = {}
    last_ts:    dict[str, int]   = {}  # username -> last pushed timestamp
    initialized = False

    while True:
        time.sleep(0.5)
        with _watch_lock:
            if not _watch_clients:
                continue

        session_wal = os.path.join(DB_DIR, "session", "session.db-wal")
        try:
            mtime = os.path.getmtime(session_wal)
        except OSError:
            continue

        prev = last_mtime.get(session_wal, 0.0)
        if mtime == prev:
            continue
        last_mtime[session_wal] = mtime

        # 解密 session.db（缓存会处理 mtime，只有真的变了才重新解密）
        path = _db.get(os.path.join("session", "session.db"))
        if not path:
            continue
        names = _load_names()
        try:
            with closing(sqlite3.connect(path)) as conn:
                rows = conn.execute("""
                    SELECT username, summary, last_timestamp, last_msg_type, last_msg_sender
                    FROM SessionTable WHERE last_timestamp > 0
                    ORDER BY last_timestamp DESC LIMIT 50
                """).fetchall()
        except Exception:
            continue

        for username, summary, ts, msg_type, sender in rows:
            if not initialized:
                # 第一轮只建立基线，不推送
                last_ts[username] = ts
                continue
            prev_ts = last_ts.get(username, 0)
            if ts <= prev_ts:
                continue
            last_ts[username] = ts

            display  = names.get(username, username)
            is_group = '@chatroom' in username
            if isinstance(summary, bytes):
                try:
                    summary = _zstd.decompress(summary).decode('utf-8', errors='replace')
                except Exception:
                    summary = '(压缩内容)'
            if isinstance(summary, str) and ':\n' in summary:
                summary = summary.split(':\n', 1)[1]
            sender_display = names.get(sender, sender) if sender else ''

            _broadcast({
                "event":     "message",
                "time":      datetime.fromtimestamp(ts).strftime('%H:%M'),
                "chat":      display,
                "username":  username,
                "is_group":  is_group,
                "sender":    sender_display,
                "content":   str(summary or ''),
                "type":      _fmt_type(msg_type),
                "timestamp": ts,
            })

        if not initialized:
            initialized = True

# ─── 命令路由 ─────────────────────────────────────────────────────────────────

def _dispatch(req: dict) -> dict:
    cmd = req.get("cmd", "")
    try:
        if cmd == "ping":
            return {"ok": True, "pong": True}
        if cmd == "sessions":
            return {"ok": True, **q_sessions(int(req.get("limit", 20)))}
        if cmd == "history":
            return {"ok": True, **q_history(
                req["chat"],
                limit=int(req.get("limit", 50)),
                offset=int(req.get("offset", 0)),
                since=req.get("since"),
                until=req.get("until"),
            )}
        if cmd == "search":
            return {"ok": True, **q_search(
                req["keyword"],
                chats=req.get("chats"),
                limit=int(req.get("limit", 20)),
                since=req.get("since"),
                until=req.get("until"),
            )}
        if cmd == "contacts":
            return {"ok": True, **q_contacts(req.get("query"), int(req.get("limit", 50)))}
        return {"ok": False, "error": f"未知命令: {cmd}"}
    except KeyError as e:
        return {"ok": False, "error": f"缺少参数: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ─── Unix Socket Server ───────────────────────────────────────────────────────

def _handle_client(conn: socket.socket) -> None:
    try:
        f = conn.makefile('rwb', buffering=0)
        line = f.readline()
        if not line:
            return
        req = json.loads(line.decode('utf-8'))

        if req.get("cmd") == "watch":
            # 流式模式：daemon 持续推事件，直到客户端断开
            q: queue.Queue = queue.Queue(maxsize=500)
            with _watch_lock:
                _watch_clients.append(q)
            _write_line(f, {"event": "connected"})
            try:
                while True:
                    try:
                        event_line = q.get(timeout=30)
                        f.write((event_line + '\n').encode())
                        f.flush()
                    except queue.Empty:
                        _write_line(f, {"event": "heartbeat"})
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                with _watch_lock:
                    try:
                        _watch_clients.remove(q)
                    except ValueError:
                        pass
        else:
            resp = _dispatch(req)
            _write_line(f, resp)
    except Exception as e:
        try:
            _write_line(conn.makefile('rwb', buffering=0), {"ok": False, "error": str(e)})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _write_line(f, obj: dict) -> None:
    f.write((json.dumps(obj, ensure_ascii=False) + '\n').encode())
    f.flush()


def _serve() -> None:
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o600)
    server.listen(64)
    _log(f"监听 {SOCK_PATH}")
    while True:
        try:
            conn, _ = server.accept()
            threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
        except Exception:
            pass

# ─── 守护进程化 ───────────────────────────────────────────────────────────────

def _daemonize() -> None:
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdin  = open(os.devnull, 'r')
    log_file   = open(LOG_PATH, 'a', buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file

# ─── 入口 ─────────────────────────────────────────────────────────────────────

def main(foreground: bool = False) -> None:
    if not foreground:
        _daemonize()

    with open(PID_PATH, 'w') as f:
        f.write(str(os.getpid()))

    def _cleanup(sig=None, frame=None):
        for p in (SOCK_PATH, PID_PATH):
            try:
                os.unlink(p)
            except OSError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    _log("wx-daemon 启动")
    _log(f"DB_DIR: {DB_DIR}")
    _log(f"密钥数量: {len(ALL_KEYS)}")

    # 预热：加载联系人 + 解密 session.db（最常用的两个）
    _load_names()
    _db.get(os.path.join("session", "session.db"))
    _log(f"预热完成，联系人 {len(_names or {})} 个")

    # WAL 监听线程
    threading.Thread(target=_wal_watcher, daemon=True, name='wal-watcher').start()

    # Socket server（阻塞）
    _serve()


if __name__ == "__main__":
    main(foreground='--fg' in sys.argv)
