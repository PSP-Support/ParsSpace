import asyncio
import json
import os
import re
import random
import sys
import hashlib
import socket
import signal
from typing import Dict, Optional

# Ensure the app directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secrets
import time
import uuid
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
import base64
import io
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Spider-Gateway")

try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    logger.warning("qrcode/PIL not installed -- QR endpoints will return 501")

from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx

# Import xhttp_siz10 router (must come after app is created)
# xhttp_siz10 does `from main import ...`. When run as `python main.py` this
# module is named `__main__`; alias ourselves as `main` so submodule imports
# resolve to THIS module (prevents a second, circular copy of main).
import sys as _sys
_sys.modules.setdefault("main", _sys.modules[__name__])

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="Spider Gateway", docs_url=None, redoc_url=None)

# Import and include xhttp_siz10 router - deferred until globals are defined
xhttp_router = None

PANEL_PORT = 8080


def _env_port(default: int = PANEL_PORT) -> int:
    """Return the canonical SpiderPanel listen port.

    Provider-injected PORT values are intentionally ignored. The panel itself
    always listens on 8080; a platform reverse proxy may still expose another
    public port/domain in front of it.
    """
    return PANEL_PORT


CONFIG = {
    "port": PANEL_PORT,
    "secret": os.environ.get("SECRET_KEY", "spider-panel-secret-key-v2"),
    # Public host is discovered at runtime. Never use localhost as a public
    # endpoint or as a value embedded in client configs.
    "host": "",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "spider_state.json"
SAVE_LOCK = asyncio.Lock()

# ── Official MTProxy runtime paths/settings ──────────────────────────────────
# Every Telegram inbound owns one MTProxy process. The process listens on the
# inbound's Internal Port (-H). Its statistics socket is localhost-only and
# must be unique per inbound so multiple Telegram inbounds cannot collide.
TG_DIR = DATA_DIR / "mtproxy"
BIN = Path(os.environ.get("MTPROXY_BIN", "/usr/local/bin/mtproto-proxy"))
if not BIN.exists():
    _project_mtproxy = Path(os.path.dirname(os.path.abspath(__file__))) / "mtproto-proxy"
    if _project_mtproxy.exists():
        BIN = _project_mtproxy
SECRET_RE = re.compile(r"^[0-9a-fA-F]{32}$")
WORKERS = max(1, int(os.environ.get("MTPROXY_WORKERS", "1") or "1"))
STATS_BASE = max(1024, int(os.environ.get("MTPROXY_STATS_BASE", "18080") or "18080"))

def _mtproxy_bin_path() -> Path:
    """Resolve MTProxy binary at runtime so post-import installs are honored."""
    configured = Path(os.environ.get("MTPROXY_BIN", "")).expanduser() if os.environ.get("MTPROXY_BIN") else None
    candidates = [
        configured,
        Path("/usr/local/bin/mtproto-proxy"),
        Path(os.path.dirname(os.path.abspath(__file__))) / "mtproto-proxy",
    ]
    for candidate in candidates:
        if candidate and candidate.exists() and candidate.is_file():
            return candidate
    return BIN

# ── IP scanner live-saved files (first 10 working IPs per source) ─────────────
SCANNED_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "data" / "scanned"
# Fallback to DATA_DIR if the project-local dir doesn't exist (e.g. /data on Railway)
if not SCANNED_DIR.exists():
    SCANNED_DIR = DATA_DIR / "scanned"
_SCANNED_TYPES = {"cf", "railway", "spf-ip", "spf-sni"}
_SCANNED_MAX = 10
# Monotonic per-type sequence number for /api/scanner/save. Every write carries
# the seq it last saw; the server rejects stale writes (seq mismatch) so a
# clear() can never be overwritten by a scan save that was already in flight.
SCANNED_SEQ: dict = {}


def _read_scanned_ips(ctype: str) -> list:
    """Return the saved ip:port entries for a scanned source (first 10)."""
    if ctype not in _SCANNED_TYPES:
        return []
    f = SCANNED_DIR / f"{ctype}.txt"
    if not f.is_file():
        return []
    out, seen = [], set()
    for line in f.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            ip, _, port = line.rpartition(":")
        elif " " in line:
            ip, _, port = line.partition(" ")
        elif "|" in line:
            # spf-sni format: sni|ip:port
            continue
        else:
            ip, port = line, "443"
        ip, port = ip.strip(), port.strip()
        if not ip or not port:
            continue
        tok = f"{ip}:{port}"
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= _SCANNED_MAX:
            break
    return out


def _save_scanned_ips(ctype: str, entries: list, replace: bool = False) -> list:
    """Persist ip:port entries to the source file, capped at first 10.

    merge=True keeps existing entries and appends new ones (used when saving
    one newly-found IP); replace=True writes entries as the new list (used by
    the scanner to keep the file in sync with the current best-10).
    """
    if ctype not in _SCANNED_TYPES:
        return []
    try:
        SCANNED_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return _read_scanned_ips(ctype)
    merged, seen = [], set()
    if not replace:
        merged = list(_read_scanned_ips(ctype))
        seen = set(merged)
    for e in entries:
        e = str(e).strip()
        if not e or e in seen:
            continue
        seen.add(e)
        merged.append(e)
    merged = merged[:_SCANNED_MAX]
    try:
        f = SCANNED_DIR / f"{ctype}.txt"
        f.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not save scanned ips: {e}")
    return merged

def _is_real_listener_inbound(ib: dict) -> bool:
    proto = str(ib.get("protocol") or "").lower()
    sec = str(ib.get("security") or "").lower()
    return proto == "telegram" or proto == "reality" or sec == "reality"


def _listener_port_in_use(port: int, exclude_id: str | None = None) -> str | None:
    try:
        port = int(port)
    except Exception:
        return "invalid"
    if port == int(CONFIG.get("port") or 8080):
        return "panel"
    for iid, ib in INBOUNDS.items():
        if exclude_id is not None and str(iid) == str(exclude_id):
            continue
        if not _is_real_listener_inbound(ib):
            continue
        try:
            ip = int(ib.get("port") or 0)
        except Exception:
            continue
        if ip == port:
            return str(iid)
    return None


def _validate_listener_port(port: int, exclude_id: str | None = None) -> None:
    try:
        port = int(port)
    except Exception:
        raise HTTPException(status_code=400, detail="Internal Port must be a number")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="Internal Port must be between 1 and 65535")
    owner = _listener_port_in_use(port, exclude_id=exclude_id)
    if owner == "panel":
        raise HTTPException(status_code=409, detail=f"Internal Port {port} is already used by the SpiderPanel HTTP server")
    if owner and owner != "invalid":
        raise HTTPException(status_code=409, detail=f"Internal Port {port} is already used by inbound {owner}")


async def load_state():
    global LINKS, AUTH, SUBS, USERS, SETTINGS, GROUPS, IP_POOL, IP_BLACKLIST, INBOUNDS, NODES, PENDING_NODE_DELETIONS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            USERS.update(data.get("users", {}))
            # Always load saved password hash (no secret-key guard — causes password reset bugs)
            if "username" in data and str(data.get("username") or "").strip():
                AUTH["username"] = str(data.get("username")).strip()
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            # Also store saved_secret so future saves remain consistent
            if "saved_secret" in data:
                CONFIG["secret"] = data["saved_secret"]
            if "settings" in data:
                SETTINGS.update(data["settings"])
            if SETTINGS.get("domain") and not SETTINGS.get("domain_source"):
                SETTINGS["domain_source"] = "saved"
            # Accept both the current nested settings format and the canonical
            # top-level state keys used by the Node replication architecture.
            if data.get("panel_api_key"):
                SETTINGS["panel_api_key"] = str(data.get("panel_api_key") or "").strip()
            if isinstance(data.get("server_info"), dict):
                SETTINGS.update({
                    k: v for k, v in data["server_info"].items()
                    if k in {"server_ip", "public_ip", "country", "country_code", "country_flag", "server_info_detected_at", "detected_at"}
                })
                if data["server_info"].get("public_ip") and not SETTINGS.get("server_ip"):
                    SETTINGS["server_ip"] = data["server_info"]["public_ip"]
                if data["server_info"].get("detected_at") and not SETTINGS.get("server_info_detected_at"):
                    SETTINGS["server_info_detected_at"] = data["server_info"]["detected_at"]
            # Migrate legacy `security_token` into the canonical panel API key.
            legacy_key = str(SETTINGS.get("security_token") or "").strip()
            panel_key = str(SETTINGS.get("panel_api_key") or legacy_key or "").strip()
            if not panel_key:
                panel_key = "spdr_" + secrets.token_urlsafe(24)
            if not panel_key.startswith("spdr_"):
                panel_key = "spdr_" + panel_key
            SETTINGS["panel_api_key"] = panel_key
            SETTINGS["security_token"] = panel_key
            GROUPS.update(data.get("groups", {}))
            INBOUNDS.update(data.get("inbounds", {}))
            NODES.update(data.get("nodes", {}))
            PENDING_NODE_DELETIONS.update(data.get("pending_node_deletions", {}))
            BOT_ORDERS.update(data.get("bot_orders", {}))
            IP_POOL.clear()
            IP_POOL.extend(data.get("ip_pool", []))
            IP_BLACKLIST.clear()
            IP_BLACKLIST.update(data.get("ip_blacklist", []))
            if isinstance(data.get("worker"), dict):
                # Preserve connected=True state from saved state; don't let startup logic reset it.
                was_connected = data["worker"].get("connected", False)
                WORKER.update(data["worker"])
                if was_connected:
                    WORKER["connected"] = True
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs, {len(USERS)} users, {len(GROUPS)} groups, {len(IP_POOL)} ips, {len(INBOUNDS)} inbounds, {len(NODES)} nodes")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")
    # Rebuild path index from all users and links
    _rebuild_path_index()
    # Migrate: auto-create links for users that have config_uuid but no link
    _migrate_user_links()
    # Migrate: legacy bare-hex config UUIDs → proper hyphenated UUIDs
    _migrate_user_uuids()
    # Rebuild again so the re-keyed links/paths are indexed.
    _rebuild_path_index()
    if normalize_relay_links():
        asyncio.create_task(save_state())


def _migrate_user_links():
    """Ensure every user with a config_uuid has a corresponding link in LINKS."""
    created = 0
    for uid, u in USERS.items():
        cuuid = u.get("config_uuid")
        if not cuuid:
            continue
        if cuuid in LINKS:
            continue
        LINKS[cuuid] = {
            "label": u.get("username", uid),
            "limit_bytes": u.get("traffic_limit_bytes", 0),
            "used_bytes": u.get("traffic_used_bytes", 0),
            "created_at": u.get("created_at", datetime.now().isoformat()),
            "active": (u.get("status", "active") == "active"),
            "expires_at": u.get("expire_at"),
            "note": f"لینک کاربر {u.get('username', uid)}",
            "is_default": False,
            "sub_id": None,
            "protocol": u.get("protocol", "vless"),
            "path": (u.get("path") or "").strip().lstrip("/"),
            "user_id": uid,
        }
        created += 1
    if created:
        logger.info(f"_migrate_user_links: created {created} missing links for existing users")


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _is_valid_uuid(s) -> bool:
    return bool(s and _UUID_RE.match(str(s)))


def _migrate_user_uuids():
    """Migrate legacy 32-char (bare-hex) config UUIDs to proper hyphenated UUIDs.

    Old generate_uuid() returned secrets.token_hex(16) with no dashes, which VLESS
    clients and the worker's uuid validation both reject. This rekeys the user,
    its stored path, the synced link, and PATH_INDEX to a valid UUID.
    """
    migrated = 0
    for uid, u in USERS.items():
        cuuid = u.get("config_uuid") or ""
        if _is_valid_uuid(cuuid):
            continue
        new_uuid = str(uuid.uuid4())
        u["config_uuid"] = new_uuid
        # Rewrite any stored path that embeds the old uuid (e.g. /ws/{uuid}).
        old_path = str(u.get("path") or "").strip()
        if old_path:
            u["path"] = old_path.replace(cuuid, new_uuid)
        # Re-key the synced link (keyed by config_uuid) and fix its path.
        if cuuid and cuuid in LINKS:
            link = LINKS.pop(cuuid)
            link_path = str(link.get("path") or "")
            if cuuid and link_path:
                link["path"] = link_path.replace(cuuid, new_uuid)
            LINKS[new_uuid] = link
        # Drop stale PATH_INDEX entries that pointed at the old uuid.
        for k in list(PATH_INDEX.keys()):
            if PATH_INDEX[k] == cuuid:
                PATH_INDEX.pop(k)
        PATH_INDEX[new_uuid] = new_uuid
        migrated += 1
    if migrated:
        logger.info(f"_migrate_user_uuids: migrated {migrated} user UUIDs to hyphenated format")
        asyncio.create_task(save_state())


def _rebuild_path_index():
    """Rebuild PATH_INDEX from all USERS and LINKS with stored paths."""
    PATH_INDEX.clear()
    # From users — store clean path (no /ws/ prefix)
    for uid, u in USERS.items():
        path = (u.get("path") or "").strip().lstrip("/")
        # Strip any old /ws/ prefix from stored paths
        if path.startswith("ws/"):
            path = path[3:]
        config_uuid = u.get("config_uuid") or uid
        if path:
            PATH_INDEX[path] = config_uuid
    # From legacy links
    for lid, link in LINKS.items():
        link_path = (link.get("path") or "").strip().lstrip("/")
        if link_path.startswith("ws/"):
            link_path = link_path[3:]
        if link_path:
            PATH_INDEX[link_path] = lid
    # Backward compat: index by config_uuid for old /ws/{uuid} clients
    for uid, u in USERS.items():
        config_uuid = u.get("config_uuid") or uid
        PATH_INDEX[config_uuid] = config_uuid
    logger.info(f"PATH_INDEX rebuilt: {len(PATH_INDEX)} entries")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            _panel_key = _get_panel_api_key_sync() if "_get_panel_api_key_sync" in globals() else str(SETTINGS.get("panel_api_key") or SETTINGS.get("security_token") or "")
            _server_info = {
                "public_ip": str(SETTINGS.get("server_ip") or ""),
                "country": str(SETTINGS.get("country") or ""),
                "country_code": str(SETTINGS.get("country_code") or "").upper(),
                "country_flag": str(SETTINGS.get("country_flag") or "🌐"),
                "detected_at": SETTINGS.get("server_info_detected_at") or None,
            }
            data = {
                "links": dict(LINKS),
                "users": dict(USERS),
                "subs": dict(SUBS),
                "settings": dict(SETTINGS),
                "panel_api_key": _panel_key,
                "server_info": _server_info,
                "groups": dict(GROUPS),
                "inbounds": dict(INBOUNDS),
                "ip_pool": list(IP_POOL),
                "ip_blacklist": list(IP_BLACKLIST),
                "worker": dict(WORKER),
                "nodes": dict(NODES),
                "pending_node_deletions": dict(PENDING_NODE_DELETIONS),
                "bot_orders": dict(BOT_ORDERS),
                "username": AUTH.get("username", "admin"),
                "password_hash": AUTH["password_hash"],
                "saved_secret": CONFIG["secret"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
            try:
                os.chmod(DATA_FILE, 0o600)
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
PATH_INDEX: dict = {}          # random_path -> uuid
PATH_INDEX_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()
USERS: dict = {}
USERS_LOCK = asyncio.Lock()

# ── Remote nodes (other SpiderPanel instances we sync configs to) ──────────────
# node_id -> {domain, api_key, name, added_at, last_status, last_checked,
#             latency_ms, user_count, error}
NODES: dict = {}
NODES_LOCK = asyncio.Lock()
PENDING_NODE_DELETIONS: dict = {}  # node_id -> [{"config_uuid", "queued_at", "username"}]
PENDING_NODE_DELETIONS_LOCK = asyncio.Lock()
NODE_HEARTBEAT_TASK = None

# ── Settings ──────────────────────────────────────────────────────────────
SETTINGS = {
    # Canonical SpiderPanel-to-SpiderPanel API credential. `security_token`
    # remains as a backwards-compatible alias for older features.
    "panel_api_key": "spdr_" + secrets.token_urlsafe(24),
    "server_ip": "",
    "country": "",
    "country_code": "",
    "country_flag": "",
    "server_info_detected_at": "",
    "panel_api_key_rotated_at": "",
    "websocket_mode": True,
    "xhttp_mode": True,
    "default_connection_mode": "ws",  # ws, xhttp, tcp
    "max_ip_per_user": 3,
    "bandwidth_limit_mbps": 100,
    "live_monitoring": True,
    "auto_ip_rotation": False,
    "security_token": "spdr_" + secrets.token_urlsafe(24),
    # Custom backgrounds (uploaded by admin)
    "bg_login": "",
    "bg_dashboard": "",
    "bg_sub": "",
    # Panel audio (uploaded by admin)
    "panel_audio": "",
    "panel_audio_enabled": False,
    # Telegram bot automation. The token is stored server-side only and never
    # returned to the browser in full. Channel Bot is scheduled/push-only;
    # Sell Bot reuses the same token for private-chat commands and approvals.
    "telegram_bot": {
        "token": "",
        "channel": {
            "enabled": False,
            "channel": "",
            "interval_minutes": 60,
            "username_prefix": "spider",
            "traffic_limit_gb": 0,
            "expire_days": 30,
            "inbound_id": "",
            "last_run_at": "",
            "last_user_id": "",
            "last_message_id": 0,
            "success_count": 0,
            "error_count": 0,
            "last_error": "",
            "next_run_at": "",
        },
        "sell": {
            "enabled": False,
            "admin_chat_id": "",
            "support_username": "",
            "plan_name": "1 ماهه",
            "price": "",
            "traffic_gb": 50,
            "expire_days": 30,
            "payment_url": "",
            "required_channels": [],
            "welcome_text": "سلام 👋\nبرای مشاهده پلن‌ها /plans را بفرستید.",
            "last_update_at": "",
            "last_error": "",
            "offset": 0,
        },
    },
    # Reality defaults (3x-ui style)
    "reality": {
        "port": 1234,
        "dest": "is1-ssl.mzstatic.com:443",
        "sni": "is1-ssl.mzstatic.com",
        "public_key": "",
        "private_key": "",
        "short_id": "5a3ff5a13d",
        "spiderx": "/",
        "fingerprint": "chrome",
        "external_domain": "",
        "external_port": 443,
    },
    # XHTTP settings (3x-ui style)
    "xhttp": {
        "path": "/",
        "host": "",
        "mode": "auto",
        "xPaddingBytes": "100-1000",
        "scMaxEachPostBytes": "1000000",
        "scMaxBufferedPosts": 30,
        "scStreamUpServerSecs": "20-80",
    },
}
SETTINGS_LOCK = asyncio.Lock()

# ── Inbounds (for user config generation) ────────────────────────────────
INBOUNDS: dict = {}  # inbound_id → {name, protocol, port, network, security, domain, sni, external_port, fingerprint, reality_settings, xhttp_settings, created_at}
INBOUNDS_LOCK = asyncio.Lock()

# ── Groups ─────────────────────────────────────────────────────────────────
GROUPS: dict = {}  # group_id → {name, description, user_ids, ip_pool, rules, created_at}
GROUPS_LOCK = asyncio.Lock()

# ── IP Pool & Blacklist ────────────────────────────────────────────────────
IP_POOL: list = []  # list of {ip, status, latency_ms, location, assigned_user, last_check}
IP_POOL_LOCK = asyncio.Lock()
IP_BLACKLIST: set = set()
IP_BLACKLIST_LOCK = asyncio.Lock()

# ── IP per user tracking ───────────────────────────────────────────────────
USER_IP_MAP: dict = defaultdict(set)  # user_id → set of IPs used
USER_IP_MAP_LOCK = asyncio.Lock()

# ── Cloudflare Worker manager ──────────────────────────────────────────────
# Railway only hosts the panel; user traffic flows Client → Worker → Proxy IP.
# The API token lives ONLY here (server-side, persisted to /data state), never
# sent to the frontend. `proxies` maps a country code → {country, proxy, port}.
WORKER: dict = {
    "connected": False,
    "account_id": "",
    "worker_name": "",
    "worker_domain": "",
    "worker_url": "",
    "pages_project_name": "",
    "pages_project_id": "",
    "pages_url": "",
    "token": "",
    # Cloudflare auth email (for Global API Key auth: cfk_... tokens).
    # Control token: a random secret baked into the deployed worker. The panel
    # uses it to call the worker's admin API (update proxy map, etc.) after
    # deploy — the worker only accepts calls carrying this Bearer token.
    "control_token": "",
    # Panel domain injected into the worker so it can expose panel info.
    "panel_domain": "",
    # KV namespace id + title for the worker's dedicated SPIDER_KV binding
    # ({worker_name}-db — one namespace per worker, never shared).
    "kv_namespace_id": "",
    "kv_namespace_title": "",
    # Remote-control status pulled from the worker's /panel/status API.
    "remote_status": "",
    "last_heartbeat": "",
    "worker_users_online": 0,
    "worker_traffic_bytes": 0,
    "worker_user_count": 0,
    "proxies": {},
    "last_sync": "",
    "last_error": "",
    "source_url": "https://raw.githubusercontent.com/NiREvil/vless/main/sub/ProxyIP-Daily.md",
    "auto_sync": True,
    "sync_error": "",
    "sync_count": 0,
    "routing_status": {},
    # Tunnel: dedicated KV + inbound (user → Railway → Worker → site)
    "tunnel_kv_namespace_id": "",
    "tunnel_kv_namespace_title": "",
    "tunnel_enabled": False,
    "tunnel_created_at": "",
    "tunnel_logs": [],
    # Reverse: dedicated KV + mode flag (user → Worker → Railway → site)
    "reverse_kv_namespace_id": "",
    "reverse_kv_namespace_title": "",
}
WORKER_LOCK = asyncio.Lock()
# Serialize source syncs (hourly loop + manual button can't overlap).
WORKER_SYNC_LOCK = asyncio.Lock()

# ── Telegram Bot automation ─────────────────────────────────────────────────
# One scheduler handles channel publishing. One long-poller handles Sell Bot
# commands. They intentionally share the configured Telegram bot token so a
# single BotFather bot can do both jobs without update-stream conflicts.
BOT_SCHEDULER_TASK = None
BOT_POLL_TASK = None
BOT_WAKE = asyncio.Event()
BOT_ORDERS: dict = {}  # order_id -> {chat_id, username, plan, status, created_at, ...}
BOT_ADMIN_WIZARD: dict = {}  # admin_id -> {mode, step, plan, started_at}
BOT_ADMIN_WIZARD_LOCK = asyncio.Lock()
BOT_ORDERS_LOCK = asyncio.Lock()
BOT_LAST_UPDATE_LOCK = asyncio.Lock()
BOT_CUSTOMER_UI: dict = {}  # chat_id -> {menu_message_id, section, updated_at}
BOT_CUSTOMER_UI_LOCK = asyncio.Lock()
BOT_EXPIRY_TASK = None

# ── Telegram Proxy Instances ────────────────────────────────────────────────
# Maps inbound_id → MTProtoProxyServer instance
TG_PROXY_INSTANCES: dict = {}

# پروتکل‌های پشتیبانی‌شده برای هر کانفیگ
PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")

USER_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "reality")
DEFAULT_PROTOCOL = "vless-ws"

def log_activity(kind: str, message: str, level: str = "info"):
    """ثبت یک رخداد در لاگ فعالیت‌ها (ساخت/حذف/ویرایش کانفیگ، ورود، و...)."""
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "spider_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"username": os.environ.get("ADMIN_USERNAME", "admin"), "password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def require_replication_auth(request: Request):
    """Authenticate local admins with the session cookie or remote SpiderPanels
    with X-API-Key. The API-key path is intentionally used only on replication
    endpoints, never as a blanket replacement for the browser session."""
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return {"kind": "session", "token": token}
    key = str(request.headers.get("X-API-Key") or "").strip()
    if not key:
        # Backward compatibility with older SpiderPanel peers. New clients use X-API-Key.
        key = str(request.headers.get("X-Node-Key") or "").strip()
    async with SETTINGS_LOCK:
        expected = str(SETTINGS.get("panel_api_key") or SETTINGS.get("security_token") or "")
    if key and expected and secrets.compare_digest(key, expected):
        return {"kind": "api_key"}
    raise HTTPException(status_code=401, detail="unauthorized")

async def require_session_or_api_key(request: Request):
    return await require_replication_auth(request)

# ── Reality + Xray helpers ─────────────────────────────────────────────────────
def _valid_mldsa65_seed(value: str) -> bool:
    """Return True only for an ML-DSA-65 seed with Xray's expected 32-byte size."""
    import base64 as b64
    if not value:
        return False
    raw = str(value).strip().replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        return len(b64.b64decode(raw, validate=True)) == 32
    except Exception:
        return False


def _sanitize_mldsa65_settings(rs: dict) -> bool:
    """Drop stale/invalid post-quantum Reality material instead of breaking Xray startup.

    Xray documents mldsa65Seed as optional and generated by `xray mldsa65`.
    Older panel state could contain a 64-byte placeholder seed and a fabricated
    verify key; those values are not a valid ML-DSA-65 keypair.
    """
    changed = False
    seed = str(rs.get("mldsa65_seed") or "").strip()
    if seed and not _valid_mldsa65_seed(seed):
        rs.pop("mldsa65_seed", None)
        changed = True
        logger.warning("Removed invalid Reality mldsa65 seed from persisted state")
    # The verify key is optional too. The previous fallback generated a
    # synthetic value that cannot verify an ML-DSA signature. Remove it unless
    # it has the exact encoded ML-DSA-65 public-key size.
    verify = str(rs.get("mldsa65_verify") or "").strip()
    if verify:
        raw = verify.replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)
        try:
            verify_len = len(__import__("base64").b64decode(raw, validate=True))
        except Exception:
            verify_len = 0
        if verify_len != 1952:
            rs.pop("mldsa65_verify", None)
            changed = True
            logger.warning("Removed invalid Reality mldsa65 verify key")
    if not rs.get("mldsa65_seed") and rs.pop("mldsa65_verify", None) is not None:
        changed = True
        logger.warning("Removed stale Reality mldsa65 verify key")
    return changed


def _xray_gen_keypair(cmd: str, timeout: float = 5.0) -> dict:
    """Run an Xray key-generation command (x25519 | mldsa65) and parse the
    'Name: value' lines. Keys are produced by the Xray binary itself so they
    always match what the running Xray instance expects."""
    import subprocess
    bin_path = _xray_bin_path()
    if not bin_path.exists():
        return {}
    try:
        proc = subprocess.run([str(bin_path), cmd], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        logger.warning(f"xray {cmd} keygen failed: {e}")
        return {}
    out = {}
    for line in (proc.stdout or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def _gen_reality_settings() -> dict:
    """Generate REALITY keys using the Xray binary itself: the x25519 key pair
    (private + public) via `xray x25519` and the ML-DSA-65 seed/verify via
    `xray mldsa65`. Falls back to the cryptography lib only if Xray is missing.
    short_id is a random hex string (Xray accepts any hex short id)."""
    import base64 as b64
    xk = _xray_gen_keypair("x25519")
    mk = _xray_gen_keypair("mldsa65")
    priv = xk.get("privatekey", "")
    pub = xk.get("password (publickey)", "")
    seed = mk.get("seed", "")
    verify = mk.get("verify", "")
    if priv and pub:
        return {
            "private_key": priv,
            "public_key": pub,
            "short_id": secrets.token_hex(5)[:10],
            "spiderx": "/",
            "dest": "is1-ssl.mzstatic.com:443",
            "mldsa65_seed": seed,
            "mldsa65_verify": verify,
        }
    # Xray not available: fall back to a Python x25519 keypair so the panel
    # still produces a working config shape.
    mldsa_seed = secrets.token_bytes(64)
    try:
        priv_key, pub_key = _xray_x25519_keypair()
        return {
            "private_key": priv_key,
            "public_key": pub_key,
            "short_id": secrets.token_hex(5)[:10],
            "spiderx": "/",
            "dest": "is1-ssl.mzstatic.com:443",
            # ML-DSA is optional; do not persist a synthetic keypair.
        }
    except ImportError:
        return {
            "private_key": "", "public_key": "", "short_id": "5a3ff5a13d",
            "spiderx": "/", "dest": "is1-ssl.mzstatic.com:443",
            # ML-DSA is optional; do not persist a synthetic keypair.
        }


def _xray_x25519_public_key(private_key_b64: str) -> str:
    """Derive the X25519 public key from a base64-encoded private key.

    This ensures the public key in config matches what Xray derives from the
    private key, so Reality handshake works."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64 as b64
        key = private_key_b64.strip()
        # Xray emits unpadded URL-safe base64 (e.g. "uMbq3TC3..."). Padding is
        # required by the decoder, and "-"/"_" are the URL-safe alphabet.
        priv_bytes = b64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        if len(priv_bytes) != 32:
            return ""
        p = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_bytes = p.public_key().public_bytes_raw()
        return b64.urlsafe_b64encode(pub_bytes).decode().rstrip("=")
    except Exception:
        return ""


def _xray_x25519_keypair() -> tuple:
    """Generate a fresh X25519 keypair as urlsafe base64 WITHOUT padding — the
    exact format Xray's `x25519` emits and the only format Xray-core accepts for
    Reality privateKey (standard padded base64 is rejected: 'invalid privateKey')."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64 as b64
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes = priv.public_key().public_bytes_raw()
        return (
            b64.urlsafe_b64encode(priv_bytes).decode().rstrip("="),
            b64.urlsafe_b64encode(pub_bytes).decode().rstrip("="),
        )
    except ImportError:
        return "", ""


def _xray_x25519_privkey_norm(private_key: str) -> str:
    """Re-encode a private key as urlsafe base64 without padding (same raw bytes).
    Fixes keys that were stored as standard padded base64, which Xray rejects."""
    try:
        import base64 as b64
        key = (private_key or "").strip()
        if not key:
            return ""
        decoded = b64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        if len(decoded) != 32:
            return ""
        return b64.urlsafe_b64encode(decoded).decode().rstrip("=")
    except Exception:
        return ""



def _railway_tcp_info() -> dict:
    """Return Railway TCP Proxy routing metadata when TCP Proxy is enabled.

    Railway exposes the externally reachable hostname/port separately from the
    service's internal application port. Telegram MTProto must listen on the
    internal TCP application port, while user links must use the public TCP
    proxy domain/port.
    """
    domain = str(os.getenv("RAILWAY_TCP_PROXY_DOMAIN") or "").strip()
    try:
        public_port = int(str(os.getenv("RAILWAY_TCP_PROXY_PORT") or "0").strip() or 0)
    except Exception:
        public_port = 0
    try:
        app_port = int(str(os.getenv("RAILWAY_TCP_APPLICATION_PORT") or "0").strip() or 0)
    except Exception:
        app_port = 0
    return {"domain": domain, "public_port": public_port, "application_port": app_port,
            "enabled": bool(domain and public_port and app_port)}


@app.get("/api/telegram/railway-info")
async def telegram_railway_info(_=Depends(require_auth)):
    info = _railway_tcp_info()
    return {"ok": True, "advisory": True, "message": "Railway TCP variables are informational only; inbound External Domain/Port are authoritative.", **info}


def generate_telegram_proxy_link(user_id: str, user: dict, inbound: dict, remark_tag: str = None) -> str:
    """Generate a Telegram Proxy link for a user based on the inbound settings.

    The secret is deterministic per user (derived from config_uuid) and stored
    on the user record so it remains stable across config regenerations.
    """
    # telegram_proxy merged into main.py

    username = user.get("username", user_id)
    config_uuid = user.get("config_uuid", user_id)
    tg = inbound.get("telegram_settings") or {}

    # Telegram inbound settings are authoritative. Railway TCP variables are
    # advisory only and must not override what the user entered in the inbound.
    external_domain = str(tg.get("external_domain") or inbound.get("external_domain") or "").strip()
    try:
        external_port = int(tg.get("external_port") or inbound.get("external_port") or 0)
    except Exception:
        external_port = 0
    if not external_domain or not external_port:
        return ""

    # Use a stored, validated secret. Older users are migrated lazily here and
    # the value is written back to the in-memory record before the link is sent.
    secret = str(user.get("telegram_secret") or "").strip().lower()
    if not SECRET_RE.fullmatch(secret):
        secret = derive_secret_from_uuid(config_uuid)
        user["telegram_secret"] = secret
        global_user = USERS.get(user_id)
        if global_user is not None:
            global_user["telegram_secret"] = secret
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(save_state())
        except RuntimeError:
            pass

    # Note: Telegram t.me/proxy links don't support #remark fragment like VLESS links
    # The name is set by the user in the Telegram app after adding the proxy
    link = f"https://t.me/proxy?server={external_domain}&port={external_port}&secret={secret}"
    return link


XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"


async def _ensure_xray() -> bool:
    """Download + unzip the Xray binary once into BASE/xray so a Reality/xhttp
    inbound can actually be served (the panel's own relay only handles VLESS
    ws/xhttp; Reality needs the real Xray). Safe to call on every startup —
    it no-ops when the binary already exists."""
    import subprocess, zipfile, shutil
    xray_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "xray"
    bin_path = xray_dir / "xray"
    if bin_path.exists() and bin_path.stat().st_size > 100000:
        return True
    try:
        xray_dir.mkdir(parents=True, exist_ok=True)
        zip_path = xray_dir / "xray.zip"
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as c:
            r = await c.get(XRAY_URL)
            if r.status_code != 200:
                logger.warning(f"Xray download failed: HTTP {r.status_code}")
                return False
            zip_path.write_bytes(r.content)
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
            target = "xray" if "xray" in names else (names[0] if names else None)
            if not target:
                return False
            z.extract(target, xray_dir)
        shutil.move(xray_dir / target, bin_path)
        os.chmod(bin_path, 0o755)
        zip_path.unlink(missing_ok=True)
        logger.info(f"Xray installed at {bin_path}")
        return True
    except Exception as e:
        logger.warning(f"Xray install failed: {e}")
        return False


# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    # Learn the public endpoint from platform variables before generating any
    # default inbound/config. If the platform has not exposed a domain yet,
    # the background resolver keeps retrying until one becomes available.
    await _discover_public_endpoint()
    # Ensure the exact default TLS+WS inbound exists. It is the ONLY inbound
    # served by the FastAPI /ws/{uuid} relay.
    async with INBOUNDS_LOCK:
        default_iid = find_default_tls_ws_inbound_id()
        if not default_iid:
            default_iid = "default" if "default" not in INBOUNDS else generate_short_id()
            INBOUNDS[default_iid] = {
                "name": DEFAULT_TLS_WS_INBOUND_NAME,
                "protocol": "vless", "inbound_type": "transport", "port": 443, "network": "ws", "security": "tls",
                "domain": _safe_host(SETTINGS.get("domain"), get_host()),
                "external_domain": "", "sni": "", "external_port": "",
                "fingerprint": "chrome", "reality_settings": {}, "xhttp_settings": {},
                "ws_settings": {"path": "/ws/{uuid}"},
                "created_at": datetime.now().isoformat(),
            }
            asyncio.create_task(save_state())
            log_activity("inbound", f"اینباند {DEFAULT_TLS_WS_INBOUND_NAME} ساخته شد", "ok")
        else:
            ib = INBOUNDS[default_iid]
            ib["name"] = DEFAULT_TLS_WS_INBOUND_NAME
            ib["protocol"] = "vless"
            ib["inbound_type"] = "transport"
            ib["network"] = "ws"
            ib["security"] = "tls"
            ib["domain"] = _safe_host(ib.get("domain"), SETTINGS.get("domain"), get_host())
            ib["external_domain"] = ""
            ib["external_port"] = ""
            ib.setdefault("ws_settings", {"path": "/ws/{uuid}"})
        # Auto-create a default Reality+xhttp inbound (needs real Xray to serve)
        has_reality = any(
            ib.get("network") == "xhttp" and ib.get("protocol") == "reality"
            for ib in INBOUNDS.values()
        )
        if not has_reality:
            rs = _gen_reality_settings()
            # Reality inbound: domain + ports are LEFT EMPTY — the admin fills
            # them in (external domain + external port + listen port). The pbk
            # keypair is auto-generated here so it's always ready.
            INBOUNDS["default-reality"] = {
                "name": "Reality+XHTTP پیش‌فرض",
                "protocol": "reality",
                "port": 8443,
                "network": "xhttp",
                "security": "reality",
                "domain": "",
                "external_domain": "",
                "sni": "is1-ssl.mzstatic.com",
                "external_port": "",
                "fingerprint": "chrome",
                "reality_settings": rs,
                "xhttp_settings": {
                    "path": "/",
                    "xPaddingBytes": "100-1000",
                    "mode": "stream-up",
                    "scMaxEachPostBytes": "1000000",
                },
                "created_at": datetime.now().isoformat(),
            }
            asyncio.create_task(save_state())
            log_activity("inbound", "اینباند پیش‌فرض Reality+XHTTP ساخته شد", "ok")
        # Auto-create / migrate the system Node selector inbound. It is NOT an
        # Xray listener: it only stores the Node relationship.
        node_selector = None
        for _iid, _ib in INBOUNDS.items():
            if _ib.get("system") is True or _iid == "Node":
                node_selector = (_iid, _ib)
                break
        if node_selector is None:
            INBOUNDS["Node"] = {
                "name": "Node",
                "protocol": "node",
                "inbound_type": "node",
                "network": "",
                "security": "",
                "node_ids": [],
                "enabled_node_ids": [],
                "system": True,
                "created_at": datetime.now().isoformat(),
            }
            asyncio.create_task(save_state())
            log_activity("inbound", "اینباند سیستمی Node ساخته شد", "ok")
        else:
            _niid, _nib = node_selector
            if _niid != "Node":
                INBOUNDS["Node"] = dict(_nib)
                INBOUNDS.pop(_niid, None)
            _nib = INBOUNDS.get("Node")
            if _nib is not None:
                _nib["name"] = "Node"
                _nib["protocol"] = "node"
                _nib["inbound_type"] = "node"
                _nib["system"] = True
                current_ids = _nib.get("enabled_node_ids")
                if not isinstance(current_ids, list):
                    current_ids = _nib.get("node_ids") if isinstance(_nib.get("node_ids"), list) else []
                current_ids = [str(x).strip() for x in current_ids if str(x).strip()]
                _nib["enabled_node_ids"] = list(dict.fromkeys(current_ids))
                _nib["node_ids"] = list(dict.fromkeys(current_ids))
                for _obsolete in ("port", "network", "security", "domain", "external_domain", "external_port", "sni", "reality_settings", "xhttp_settings"):
                    _nib.pop(_obsolete, None)
        # Any deployed Cloudflare Worker domain (address/host/sni auto-filled),
        # with BPB snispoofing. Only created once a worker is actually connected.
        has_worker = any((ib.get("protocol") or "").lower() == "worker" for ib in INBOUNDS.values())
        _wdom_now = _worker_safe_domain(WORKER.get("worker_domain"))
        if not has_worker and _wdom_now:
            INBOUNDS["default-worker"] = {
                "name": "Worker (Multi-Location)",
                "protocol": "worker",
                "port": 443,
                "network": "ws",
                "security": "tls",
                "domain": _wdom_now,
                "external_domain": _wdom_now,
                "sni": "www.hcaptcha.com",
                "spoof_ip": "8.6.112.4",
                "external_port": 443,
                "fingerprint": "chrome",
                "reality_settings": {},
                "xhttp_settings": {},
                "ws_settings": {"path": "/ws/{uuid}"},
                "grpc_settings": {},
                "created_at": datetime.now().isoformat(),
            }
            asyncio.create_task(save_state())
            log_activity("inbound", "اینباند پیش‌فرض Worker ساخته شد", "ok")

    if normalize_relay_links():
        await save_state()

    _changed = False

    # Normalize existing Telegram inbounds: only internal/external Telegram fields
    # are meaningful. Remove legacy SNI/Destination/Server Name state.
    for _tg_ib in INBOUNDS.values():
        if (_tg_ib.get("protocol") or "").lower() == "telegram":
            _tg = _tg_ib.setdefault("telegram_settings", {})
            try:
                _tg["internal_port"] = int(_tg.get("internal_port") or _tg_ib.get("port") or 44344)
            except Exception:
                _tg["internal_port"] = 44344
            try:
                _tg["external_port"] = int(_tg.get("external_port") or _tg_ib.get("external_port") or 443)
            except Exception:
                _tg["external_port"] = 443
            _tg["external_domain"] = str(_tg.get("external_domain") or _tg_ib.get("external_domain") or "").strip()
            _tg_ib["port"] = _tg["internal_port"]
            _tg_ib["external_port"] = _tg["external_port"]
            _tg_ib["external_domain"] = _tg["external_domain"]
            _tg_ib.pop("sni", None)
            _tg_ib.pop("destination", None)
            _tg_ib.pop("server_name", None)

    # Persist a real per-user 16-byte/32-hex MTProxy secret. This repairs users
    # created by older builds where the secret was only derived at link time.
    for _uid, _u in USERS.items():
        if not str(_u.get("config_uuid") or "").strip():
            _u["config_uuid"] = str(uuid.uuid4())
            _changed = True
        _iids = _u.get("inbound_ids") or ([_u.get("inbound_id")] if _u.get("inbound_id") else [])
        _has_tg = any((INBOUNDS.get(iid, {}).get("protocol") or "").lower() == "telegram" for iid in _iids)
        if _has_tg:
            _tg_secret = str(_u.get("telegram_secret") or "").strip().lower()
            if not SECRET_RE.fullmatch(_tg_secret):
                _u["telegram_secret"] = derive_secret_from_uuid(_u.get("config_uuid"))
                _changed = True

    # Backfill placeholder domains on any pre-existing inbounds so configs never
    # carry localhost/SERVER_IP when a real domain is available.
    _real = _safe_host(SETTINGS.get("domain"), get_host())
    _real_is_rlwy = ".rlwy.net" in _real or ".up.railway.app" in _real
    for _ib in INBOUNDS.values():
        _proto = (_ib.get("protocol") or "").lower()
        _sec = (_ib.get("security") or "").lower()
        _is_reality = _proto == "reality" or _sec == "reality"
        _cur = str(_ib.get("domain") or "")
        _cext = str(_ib.get("external_domain") or "")
        # Railway rotates its public domain (sakura... → production-221d...).
        # If an inbound points at an OLD rlwy/railway domain, refresh it to the
        # current reachable domain. This applies to EVERY inbound (reality too),
        # but only when the domain is already filled — an empty reality inbound
        # (waiting for the admin) stays empty.
        if _real_is_rlwy and _cext and (".rlwy.net" in _cext or ".up.railway.app" in _cext) and _cext != _real:
            _ib["external_domain"] = _real
            if _is_reality or _cur in ("", "0.0.0.0", "127.0.0.1", "localhost", "SERVER_IP"):
                _ib["domain"] = _real
            _changed = True
            logger.info("Inbound «%s» external domain refreshed %s → %s", _ib.get("name"), _cext, _real)
        # Fill placeholder/empty domains (non-reality only; reality stays empty
        # until the admin configures it).
        elif not _is_reality:
            if _cur in ("", "0.0.0.0", "127.0.0.1", "localhost", "SERVER_IP"):
                _ib["domain"] = _real
                _changed = True
            # For TLS WS/XHTTP inbounds: external_domain should be empty (panel domain used via SETTINGS["domain"])
            # For Worker inbounds: external_domain should be the worker domain (set by _ensure_worker_inbound)
            if _proto != "worker" and _cext in ("", "0.0.0.0", "127.0.0.1", "localhost", "SERVER_IP"):
                _ib["external_domain"] = ""
                _changed = True
    if _changed:
        asyncio.create_task(save_state())
        logger.info("Backfilled placeholder inbound domains with %s", _real)

    # Deduplicate only real OS listeners. The FastAPI panel itself owns its
    # configured port, while the system Node selector is not a listener.
    _seen_ports: dict[int, str] = {}
    _panel_port = int(CONFIG.get("port") or 8080)
    _seen_ports[_panel_port] = "panel"
    for _iid, _ib in INBOUNDS.items():
        _proto = (_ib.get("protocol") or "").lower()
        if _proto == "node" or _ib.get("system") is True or _proto == "worker":
            continue
        if _proto not in {"reality", "telegram"} and (_ib.get("security") or "").lower() != "reality":
            continue
        try:
            _p = int(_ib.get("port") or 0)
        except Exception:
            _p = 0
        if not 1 <= _p <= 65535 or _p in _seen_ports:
            _np = max(10000, _p + 1 if _p else 10000)
            while _np in _seen_ports or _np == _panel_port:
                _np += 1
                if _np > 65535:
                    raise RuntimeError("No free internal listener port remains for inbound %s" % _iid)
            old_port = _p
            _ib["port"] = _np
            if _proto == "telegram":
                _ib.setdefault("telegram_settings", {})["internal_port"] = _np
            if not _ib.get("external_port"):
                _ib["external_port"] = _np
            _changed = True
            logger.info("Inbound «%s» moved to free internal port %s (was %s)", _ib.get("name"), _np, old_port or "unset")
            _p = _np
        _seen_ports[_p] = _iid

    # Reality migration: every reality inbound must carry a WORKING pbk/sid —
    # a pbk that is actually the public half of the private key Xray will use.
    # Old inbounds created before the key-gen fix have empty or mismatched keys;
    # backfill by deriving pbk from the private key, or generate a fresh pair.
    _gs_rs = SETTINGS.get("reality", {}) or {}
    if _sanitize_mldsa65_settings(_gs_rs):
        SETTINGS["reality"] = _gs_rs
        _changed = True
    # Normalize the global Reality keys too (they backfill into inbounds).
    for _fld in ("private_key", "public_key"):
        if _fld == "private_key":
            _nv = _xray_x25519_privkey_norm(str(_gs_rs.get("private_key") or ""))
            if _nv and _nv != _gs_rs.get("private_key"):
                _gs_rs["private_key"] = _nv
                _changed = True
    if _gs_rs.get("private_key"):
        _gp = _xray_x25519_public_key(str(_gs_rs.get("private_key")))
        if _gp and _gp != _gs_rs.get("public_key"):
            _gs_rs["public_key"] = _gp
            _changed = True
    for _ib in INBOUNDS.values():
        if (_ib.get("protocol") or "").lower() != "reality" and (_ib.get("security") or "").lower() != "reality":
            continue
        _rs = _ib.setdefault("reality_settings", {})
        if _sanitize_mldsa65_settings(_rs):
            _changed = True
        _priv = str(_rs.get("private_key") or "")
        _pub = str(_rs.get("public_key") or "")
        # Keys must be urlsafe base64 without padding (what Xray emits and accepts).
        # Standard padded base64 makes Xray fail with 'invalid "privateKey"' — re-encode
        # the same raw bytes so existing clients keep working.
        _norm = _xray_x25519_privkey_norm(_priv) if _priv else ""
        if _norm and _norm != _priv:
            _rs["private_key"] = _norm
            _changed = True
            logger.info("Reality inbound «%s» private key re-encoded to urlsafe base64", _ib.get("name"))
            _priv = _norm
        # If we have a private key, derive its public key — that is the ONLY
        # pbk that works with Xray (which uses the same private key).
        _derived = _xray_x25519_public_key(_priv) if _priv else ""
        if _derived and _derived != _pub:
            _rs["public_key"] = _derived
            _changed = True
            logger.info("Reality inbound «%s» pbk re-derived from private key", _ib.get("name"))
        if not _rs.get("public_key") or not _rs.get("private_key"):
            if _gs_rs.get("public_key") and _gs_rs.get("private_key"):
                _rs.setdefault("public_key", _gs_rs.get("public_key"))
                _rs.setdefault("private_key", _gs_rs.get("private_key"))
            else:
                _fresh = _gen_reality_settings()
                _rs.setdefault("private_key", _fresh.get("private_key", ""))
                _rs.setdefault("public_key", _fresh.get("public_key", ""))
            _changed = True
            logger.info("Reality inbound «%s» backfilled with pbk", _ib.get("name"))
        _rs.setdefault("short_id", _gs_rs.get("short_id") or secrets.token_hex(5)[:10])
        _sid = str(_rs.get("short_id") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2,16}", _sid or "") or len(_sid) % 2:
            _rs["short_id"] = secrets.token_hex(5)
            _changed = True
        else:
            _rs["short_id"] = _sid
        _rs.setdefault("spiderx", "/")
        _rs.setdefault("dest", "is1-ssl.mzstatic.com:443")
        _rs.setdefault("sni", "is1-ssl.mzstatic.com")
        # Internal and external ports are intentionally separate.
        # Xray MUST listen on internal `port`; the client connects to
        # external_domain:external_port (for example a Railway TCP proxy).
        # Never overwrite one with the other.

    # WS/XHTTP-TLS inbounds are served by the FastAPI relay on the panel's own
    # port (CONFIG["port"]); the client-facing port stays 443 (Railway TLS).
    # Syncing port→CONFIG["port"] ensures the relay and config agree.
    _relay_port = int(CONFIG.get("port") or 8080)
    for _ib in INBOUNDS.values():
        _proto = (_ib.get("protocol") or "").lower()
        _sec = (_ib.get("security") or "").lower()
        if _proto == "worker" or _proto == "reality" or _sec == "reality":
            continue
        if int(_ib.get("port") or 0) != _relay_port:
            _ib["port"] = _relay_port
            _changed = True
            logger.info("TLS inbound «%s» relay port synced to %s", _ib.get("name"), _relay_port)
    if _changed:
        asyncio.create_task(save_state())

    # If a worker is connected, make sure the default Worker inbound exists and
    # points at the worker domain (address/host/sni auto-filled at boot too).
    if WORKER.get("connected"):
        await _ensure_worker_inbound()

    # User path migration: each user's path must match their WS inbound. A user
    # who has a WS (or worker) inbound must have path /ws/{config_uuid} so the
    # FastAPI relay (/ws/{uuid}) can tunnel it. Old users created when reality
    # was the primary inbound may carry /xhttp-siz10/... paths that break WS.
    _up_changed = False
    for _uid, _u in USERS.items():
        _cuuid = _u.get("config_uuid") or _uid
        _iids = _u.get("inbound_ids") or ([_u.get("inbound_id")] if _u.get("inbound_id") else [])
        # A user path is /ws/{uuid} if any EXISTING inbound is a WS/TLS inbound.
        # Missing inbounds (deleted) don't force WS.
        _has_ws = any(
            (lambda _ib: bool(_ib) and _ib.get("protocol") == "vless" and _ib.get("network") == "ws")(INBOUNDS.get(i))
            for i in _iids
        )
        _cur = str(_u.get("path") or "").strip()
        if _has_ws and "/ws/" not in _cur:
            _u["path"] = f"/ws/{_cuuid}"
            _up_changed = True
            logger.info("User «%s» path fixed to /ws/%s", _u.get("username", _uid), _cuuid)

        # Native Reality+XHTTP uses the inbound's shared XHTTP base path.
        # Do not retain the old relay-style /xhttp-siz10/.../{uuid} path.
        for _iid in _iids:
            _rib = INBOUNDS.get(_iid)
            if not _rib:
                continue
            if str(_rib.get("protocol") or "").lower() == "reality" and str(_rib.get("network") or "").lower() == "xhttp":
                _wanted = str((_rib.get("xhttp_settings") or {}).get("path") or "/").strip()
                if not _wanted.startswith("/") or "?" in _wanted or "#" in _wanted:
                    _wanted = "/"
                if _u.get("path") != _wanted:
                    _u["path"] = _wanted
                    _up_changed = True
                    logger.info("User «%s» Reality+XHTTP path fixed to %s", _u.get("username", _uid), _wanted)
                break
    if _up_changed:
        asyncio.create_task(save_state())

    # Ensure Xray is installed and serving reality BEFORE the panel is fully up,
    # so reality configs work immediately (not in a background task).
    await _ensure_xray()
    if _xray_bin_path().exists():
        try:
            await _xray_apply()
        except Exception as e:
            logger.warning(f"Xray apply on boot failed: {e}")
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"Spider Panel v8 (commit 24d7594) started on port {CONFIG['port']}")
    # Include XHTTP router for xhttp-siz10 endpoints (already merged into main.py)
    global xhttp_router
    # router is already defined in this module
    app.include_router(router)
    global PUBLIC_ENDPOINT_TASK
    if PUBLIC_ENDPOINT_TASK is None or PUBLIC_ENDPOINT_TASK.done():
        PUBLIC_ENDPOINT_TASK = asyncio.create_task(_public_endpoint_resolver_loop())
    asyncio.create_task(_worker_proxy_sync_loop())
    asyncio.create_task(_worker_auto_sync_loop())
    asyncio.create_task(_xray_client_audit_loop())
    global BOT_SCHEDULER_TASK, BOT_POLL_TASK, BOT_EXPIRY_TASK
    if BOT_SCHEDULER_TASK is None or BOT_SCHEDULER_TASK.done():
        BOT_SCHEDULER_TASK = asyncio.create_task(_channel_bot_loop(), name="spider-channel-bot")
    if BOT_POLL_TASK is None or BOT_POLL_TASK.done():
        BOT_POLL_TASK = asyncio.create_task(_sell_bot_loop(), name="spider-sell-bot")
    if BOT_EXPIRY_TASK is None or BOT_EXPIRY_TASK.done():
        BOT_EXPIRY_TASK = asyncio.create_task(_sell_bot_expiry_loop(), name="spider-expiry-sweeper")

    # Start Telegram Proxy instances for all existing TG inbounds
    await _start_all_telegram_proxies()
    global NODE_HEARTBEAT_TASK
    if NODE_HEARTBEAT_TASK is None or NODE_HEARTBEAT_TASK.done():
        NODE_HEARTBEAT_TASK = asyncio.create_task(_node_heartbeat_loop(), name="spider-node-heartbeat")


# ── Telegram Proxy Lifecycle ────────────────────────────────────────────────
async def _start_all_telegram_proxies():
    """Start MTProto proxy servers for all Telegram inbounds."""
    # telegram_proxy merged into main.py
    async with INBOUNDS_LOCK:
        snap = dict(INBOUNDS)
    for iid, ib in snap.items():
        if (ib.get("protocol") or "").lower() == "telegram":
            await _start_telegram_proxy(iid, ib)


async def _start_telegram_proxy(inbound_id: str, inbound: dict):
    """Start one MTProto listener on the inbound internal port.

    The built-in implementation is used because a single listener must accept
    all user secrets assigned to this inbound; spawning one Docker process per
    user would require different host ports. The listener therefore belongs to
    the Telegram inbound itself, while credentials remain per-user.
    """
    # telegram_proxy merged into main.py

    await _stop_telegram_proxy(inbound_id)
    tg = inbound.get("telegram_settings") or {}
    # The inbound values are the single source of truth. Railway environment
    # variables are informational only and must never silently rewrite them.
    try:
        int_port = int(tg.get("internal_port") or inbound.get("port") or 44344)
    except Exception:
        int_port = 44344
    try:
        ext_port = int(tg.get("external_port") or inbound.get("external_port") or 0)
    except Exception:
        ext_port = 0
    ext_domain = str(tg.get("external_domain") or inbound.get("external_domain") or "").strip()
    inbound["telegram_settings"] = {
        "internal_port": int_port,
        "external_port": ext_port,
        "external_domain": ext_domain,
    }
    inbound["port"] = int_port
    inbound["external_port"] = ext_port
    inbound["external_domain"] = ext_domain

    secrets_map = {}
    async with USERS_LOCK:
        for uid, u in USERS.items():
            iids = u.get("inbound_ids") or []
            if inbound_id in iids:
                config_uuid = u.get("config_uuid", uid)
                secret = str(u.get("telegram_secret") or "").strip().lower()
                if not SECRET_RE.fullmatch(secret):
                    secret = derive_secret_from_uuid(config_uuid)
                    u["telegram_secret"] = secret
                secrets_map[secret] = {"user_id": uid, "config_uuid": config_uuid, "label": u.get("username", uid)}

    await save_state()
    server = MTProtoProxyServer(inbound_id=inbound_id, port=int_port)
    server.update_secrets(secrets_map)
    if not secrets_map:
        logger.info(f"[TG Proxy {inbound_id}] no users yet; listener will start after a Telegram user is assigned")
        return

    def on_traffic(user_id: str, nbytes: int):
        asyncio.create_task(_sync_tg_traffic(user_id, nbytes))
    server.on_traffic = on_traffic

    try:
        await server.start()
        TG_PROXY_INSTANCES[inbound_id] = server
        log_activity("telegram-proxy", f"Telegram MTProto listening on internal port {int_port}", "ok")
    except Exception as e:
        logger.error(f"Failed to start Telegram MTProto for {inbound_id}: {e}")


async def _stop_telegram_proxy(inbound_id: str):
    """Stop the Telegram proxy server for a Telegram inbound (both Python and Docker)."""
    # Stop Python proxy if running
    server = TG_PROXY_INSTANCES.pop(inbound_id, None)
    if server:
        await server.stop()

    # Stop Docker containers if any
    # telegram_proxy merged into main.py
    if is_docker_available():
        # Stop all containers for this inbound_id
        for i in range(10):  # Try up to 10 possible container names (for different secrets)
            container_name = f"spider-tg-proxy-{inbound_id}-"
            # We can't know the exact secret suffix, so we'll stop any matching
            import subprocess
            try:
                result = subprocess.run(
                    ["docker", "ps", "-a", "--filter", f"name=spider-tg-proxy-{inbound_id}-", "--format", "{{.Names}}"],
                    capture_output=True, text=True, timeout=10
                )
                for name in result.stdout.strip().split('\n'):
                    if name:
                        subprocess.run(["docker", "stop", name], capture_output=True, timeout=10)
                        subprocess.run(["docker", "rm", name], capture_output=True, timeout=10)
                        logger.info(f"Stopped Docker Telegram proxy: {name}")
            except Exception as e:
                logger.error(f"Failed to stop Docker Telegram proxy: {e}")


async def _restart_telegram_proxy(inbound_id: str):
    """Restart the MTProto proxy for an inbound (e.g. after settings change)."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
    if ib and (ib.get("protocol") or "").lower() == "telegram":
        await _start_telegram_proxy(inbound_id, ib)


async def _sync_tg_traffic(user_id: str, nbytes: int):
    """Sync Telegram proxy traffic back to the user record."""
    try:
        async with USERS_LOCK:
            u = USERS.get(user_id)
            if u:
                u["traffic_used_bytes"] = u.get("traffic_used_bytes", 0) + nbytes
        asyncio.create_task(save_state())
    except Exception:
        pass


# Worker proxy source sync — hourly pull from the daily GitHub list and push to
# the deployed Cloudflare Worker (Railway is the control plane; the Worker gets
# a fresh country → proxy map without the user doing anything).
WORKER_SYNC_INTERVAL = int(os.environ.get("WORKER_SYNC_INTERVAL", 3600))  # seconds


async def _worker_proxy_sync_loop():
    """Background loop: every hour, if the worker is connected and auto-sync is
    on, fetch the daily proxy source, parse it into country → proxy and re-deploy
    the worker. Failures are recorded and retried next tick."""
    # First tick quickly so the panel starts with fresh proxies.
    await asyncio.sleep(30)
    while True:
        try:
            if WORKER.get("connected"):
                if WORKER.get("auto_sync"):
                    await _sync_worker_proxies_from_source()
                # Worker owns runtime traffic counters; pull them back to Railway
                # so the panel dashboard/subscription always reflects reality.
                await _worker_pull_all_users()
        except Exception as e:
            logger.warning(f"worker sync failed: {e}")
        await asyncio.sleep(min(WORKER_SYNC_INTERVAL, 30))

WORKER_AUTO_SYNC_INTERVAL = int(os.environ.get("WORKER_AUTO_SYNC_INTERVAL", 300))  # seconds

async def _worker_auto_sync_loop():
    """Background loop: keeps panel and worker in sync without any manual action.

    Every WORKER_AUTO_SYNC_INTERVAL seconds (default 5 min), while a worker is
    connected:
      1. push users/routes/settings → worker (POST /panel/config),
      2. pull live usage + worker-generated configs back (GET /api/user/{uuid}),
      3. refresh the remote status/heartbeat shown in the Worker tab.
    Failures (e.g. KV daily limit) are logged and retried next tick."""
    await asyncio.sleep(20)  # let startup finish
    while True:
        try:
            if WORKER.get("connected"):
                push = await _worker_push_config()
                if not push.get("ok"):
                    logger.warning(f"worker auto-push failed: {push.get('detail')}")
                await _worker_pull_all_users()
                await _worker_pull_status()
        except Exception as e:
            logger.warning(f"worker auto-sync failed: {e}")
        await asyncio.sleep(WORKER_AUTO_SYNC_INTERVAL)


@app.on_event("shutdown")
async def shutdown():
    global BOT_SCHEDULER_TASK, BOT_POLL_TASK
    for _task_name in ("BOT_SCHEDULER_TASK", "BOT_POLL_TASK"):
        _task = globals().get(_task_name)
        if _task and not _task.done():
            _task.cancel()
    for _task_name in ("BOT_SCHEDULER_TASK", "BOT_POLL_TASK"):
        _task = globals().get(_task_name)
        if _task:
            try:
                await _task
            except asyncio.CancelledError:
                pass
    global NODE_HEARTBEAT_TASK, PUBLIC_ENDPOINT_TASK, PUBLIC_ENDPOINT_WORKER_SYNC_TASK
    if PUBLIC_ENDPOINT_WORKER_SYNC_TASK is not None and not PUBLIC_ENDPOINT_WORKER_SYNC_TASK.done():
        PUBLIC_ENDPOINT_WORKER_SYNC_TASK.cancel()
        try:
            await PUBLIC_ENDPOINT_WORKER_SYNC_TASK
        except asyncio.CancelledError:
            pass
        PUBLIC_ENDPOINT_WORKER_SYNC_TASK = None
    if PUBLIC_ENDPOINT_TASK is not None and not PUBLIC_ENDPOINT_TASK.done():
        PUBLIC_ENDPOINT_TASK.cancel()
        try:
            await PUBLIC_ENDPOINT_TASK
        except asyncio.CancelledError:
            pass
        PUBLIC_ENDPOINT_TASK = None
    if NODE_HEARTBEAT_TASK is not None and not NODE_HEARTBEAT_TASK.done():
        NODE_HEARTBEAT_TASK.cancel()
        try:
            await NODE_HEARTBEAT_TASK
        except asyncio.CancelledError:
            pass
        NODE_HEARTBEAT_TASK = None
    # Stop all Telegram Proxy instances
    for iid in list(TG_PROXY_INSTANCES.keys()):
        await _stop_telegram_proxy(iid)
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
# ── Public endpoint discovery ────────────────────────────────────────────────
# A container cannot query "the internet" to magically learn a hostname that a
# deployer has not assigned. The portable strategy is:
#   1) explicit SpiderPanel public URL/domain env vars,
#   2) deployer-provided public URL/domain env vars,
#   3) the real external Host/X-Forwarded-Host seen on an incoming request,
#   4) a persisted value from a previous successful discovery.
#
# The resolver keeps running until a valid public endpoint is available and then
# refreshes it periodically so provider-generated domains can rotate safely.
PUBLIC_ENDPOINT_LOCK = asyncio.Lock()
PUBLIC_ENDPOINT_TASK = None
PUBLIC_ENDPOINT_WORKER_SYNC_TASK = None
PUBLIC_ENDPOINT = {
    "host": "",
    "scheme": "https",
    "port": 443,
    "url": "",
    "source": "",
    "ready": False,
    "attempts": 0,
    "last_checked_at": "",
    "last_error": "",
}
try:
    PUBLIC_ENDPOINT_RETRY_SECONDS = max(
        3.0, float(os.environ.get("PUBLIC_ENDPOINT_RETRY_SECONDS", "5") or "5")
    )
except ValueError:
    PUBLIC_ENDPOINT_RETRY_SECONDS = 5.0
try:
    PUBLIC_ENDPOINT_REFRESH_SECONDS = max(
        15.0, float(os.environ.get("PUBLIC_ENDPOINT_REFRESH_SECONDS", "60") or "60")
    )
except ValueError:
    PUBLIC_ENDPOINT_REFRESH_SECONDS = 60.0

PUBLIC_ENDPOINT_ENV_VARS = (
    "SPIDER_PANEL_PUBLIC_URL",
    "SPIDER_PANEL_PUBLIC_DOMAIN",
    "PUBLIC_URL",
    "PUBLIC_DOMAIN",
    "PUBLIC_HOST",
    "APP_URL",
    "APP_DOMAIN",
    "EXTERNAL_URL",
    "EXTERNAL_DOMAIN",
    "SERVICE_URL",
    "SERVICE_DOMAIN",
    "RENDER_EXTERNAL_URL",
    "RENDER_EXTERNAL_HOSTNAME",
    "KOYEB_PUBLIC_DOMAIN",
    "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_STATIC_URL",
    "VERCEL_URL",
    "VERCEL_BRANCH_URL",
    "NETLIFY_URL",
    "DEPLOY_PRIME_URL",
    "URL",
    "REPLIT_DEV_DOMAIN",
    "REPLIT_DOMAINS",
    "HEROKU_APP_NAME",
)


def _is_placeholder_host(host: str) -> bool:
    h = str(host or "").strip().lower().strip("[]").rstrip(".")
    return h in {
        "",
        "localhost",
        "localhost.localdomain",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "server_ip",
        "server-ip",
    } or h.endswith((".localhost", ".local", ".internal", ".svc", ".cluster.local"))


def _is_public_host(host: str) -> bool:
    """Return True for a plausible public DNS name or globally routable IP."""
    import ipaddress

    h = str(host or "").strip().strip("[]").rstrip(".")
    if not h or _is_placeholder_host(h):
        return False

    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "." in h and " " not in h
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _normalize_public_endpoint(raw: str, default_scheme: str = "https") -> dict | None:
    """Normalize a URL/host[:port] into a safe public endpoint record."""
    from urllib.parse import urlsplit

    value = str(raw or "").strip().strip("`'\"")
    if not value:
        return None

    if "," in value and "://" not in value:
        value = next((x.strip() for x in value.split(",") if x.strip()), "")
    if not value:
        return None

    if "://" not in value:
        value = f"{default_scheme}://{value}"

    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").strip().rstrip(".")
        scheme = (parsed.scheme or default_scheme).lower()
        port = parsed.port
    except (TypeError, ValueError):
        return None

    if not _is_public_host(host):
        return None
    if scheme not in ("http", "https"):
        scheme = default_scheme if default_scheme in ("http", "https") else "https"
    if port is None:
        port = 443 if scheme == "https" else 80

    default_port = 443 if scheme == "https" else 80
    url = f"{scheme}://{host}" + (f":{port}" if port != default_port else "")
    return {"host": host, "scheme": scheme, "port": int(port), "url": url}


def _deployer_env_candidates() -> list[tuple[str, str, str]]:
    """Return (raw_value, source, variable_name) candidates."""
    out = []

    # Explicit SpiderPanel configuration wins over provider defaults.
    for var in ("SPIDER_PANEL_PUBLIC_URL", "SPIDER_PANEL_PUBLIC_DOMAIN"):
        val = str(os.environ.get(var) or "").strip()
        if val:
            out.append((val, "spider-env", var))

    # Provider-native values. These are intentionally independent of Railway.
    provider_vars = (
        "RENDER_EXTERNAL_URL",
        "RENDER_EXTERNAL_HOSTNAME",
        "KOYEB_PUBLIC_DOMAIN",
        "RAILWAY_PUBLIC_DOMAIN",
        "RAILWAY_STATIC_URL",
        "VERCEL_URL",
        "VERCEL_BRANCH_URL",
        "NETLIFY_URL",
        "DEPLOY_PRIME_URL",
        "URL",
        "REPLIT_DEV_DOMAIN",
        "REPLIT_DOMAINS",
        "HEROKU_APP_NAME",
    )
    for var in provider_vars:
        val = str(os.environ.get(var) or "").strip()
        if val:
            if var == "HEROKU_APP_NAME":
                val = f"https://{val}.herokuapp.com"
            out.append((val, "platform-env", var))

    # Generic names cover platforms that do not expose a canonical variable.
    for var in (
        "PUBLIC_URL",
        "PUBLIC_DOMAIN",
        "PUBLIC_HOST",
        "APP_URL",
        "APP_DOMAIN",
        "EXTERNAL_URL",
        "EXTERNAL_DOMAIN",
        "SERVICE_URL",
        "SERVICE_DOMAIN",
    ):
        val = str(os.environ.get(var) or "").strip()
        if val:
            out.append((val, "platform-env", var))

    # Fly.io: the default public hostname is deterministic from FLY_APP_NAME.
    fly_name = str(os.environ.get("FLY_APP_NAME") or "").strip()
    if fly_name:
        out.append((f"https://{fly_name}.fly.dev", "platform-env", "FLY_APP_NAME"))

    # GitHub Codespaces: public forwarded-port hostname.
    cs_name = str(os.environ.get("CODESPACE_NAME") or "").strip()
    cs_suffix = str(os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN") or "").strip()
    if cs_name and cs_suffix:
        out.append((
            f"https://{cs_name}-{_env_port()}.{cs_suffix}",
            "platform-env",
            "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN",
        ))

    return out


def _request_endpoint_candidates(request: Request) -> list[tuple[str, str, str]]:
    """Read the external endpoint reflected by a reverse proxy/request."""
    candidates = []

    forwarded = str(request.headers.get("forwarded") or "").strip()
    if forwarded:
        first = forwarded.split(",", 1)[0]
        host_match = re.search(r"(?:^|;)\s*host=([^;]+)", first, re.I)
        proto_match = re.search(r"(?:^|;)\s*proto=([^;]+)", first, re.I)
        if host_match:
            raw_host = host_match.group(1).strip().strip("\"")
            proto = proto_match.group(1).strip().strip("\"") if proto_match else "https"
            candidates.append((f"{proto}://{raw_host}", "request", "Forwarded"))

    forwarded_proto = str(request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    if forwarded_proto not in ("http", "https"):
        forwarded_proto = "https" if request.url.scheme == "https" else "http"

    for header in ("x-forwarded-host", "host"):
        raw = str(request.headers.get(header) or "").strip()
        if raw:
            candidates.append((f"{forwarded_proto}://{raw}", "request", header))

    try:
        if request.base_url:
            candidates.append((str(request.base_url), "request", "base_url"))
    except Exception:
        pass

    return candidates


def _saved_public_endpoint() -> dict | None:
    raw = str(SETTINGS.get("domain") or CONFIG.get("host") or "").strip()
    endpoint = _normalize_public_endpoint(raw)
    if endpoint:
        endpoint["source"] = "saved"
        return endpoint
    return None


def _apply_public_endpoint(endpoint: dict, source: str) -> bool:
    """Publish a newly discovered endpoint into runtime state."""
    global PUBLIC_ENDPOINT

    host = endpoint["host"]
    old_host = str(PUBLIC_ENDPOINT.get("host") or "")
    old_source = str(PUBLIC_ENDPOINT.get("source") or "")

    # A manually configured domain is authoritative.
    if str(SETTINGS.get("domain_source") or "") == "manual" and old_host and old_host != host:
        return False

    PUBLIC_ENDPOINT.update({
        **endpoint,
        "source": source,
        "ready": True,
        "last_error": "",
    })
    changed = old_host != host or old_source != source

    if str(SETTINGS.get("domain") or "") != host:
        SETTINGS["domain"] = host
        changed = True
    CONFIG["host"] = host
    SETTINGS["domain_source"] = source.split(":", 1)[0]

    # Keep derived panel-transport inbounds synchronized. Reality and Worker
    # have independent external endpoints and must never be overwritten here.
    for ib in INBOUNDS.values():
        proto = str(ib.get("protocol") or "").lower()
        sec = str(ib.get("security") or "").lower()
        if proto == "worker" or proto == "reality" or sec == "reality":
            continue
        cur = str(ib.get("domain") or "").strip()
        if not cur or _is_placeholder_host(cur) or cur == old_host:
            if cur != host:
                ib["domain"] = host
                changed = True

    worker_domain_changed = False
    if WORKER.get("connected"):
        panel_domain = str(WORKER.get("panel_domain") or "").strip()
        if not panel_domain or _is_placeholder_host(panel_domain) or panel_domain == old_host:
            if panel_domain != host:
                WORKER["panel_domain"] = host
                worker_domain_changed = True
                changed = True

    # The Worker source contains PANEL_DOMAIN as an injected constant. If the
    # panel domain becomes known/changes after the Worker was already deployed,
    # schedule exactly one redeploy so the Worker stays in sync.
    if worker_domain_changed:
        try:
            global PUBLIC_ENDPOINT_WORKER_SYNC_TASK
            if PUBLIC_ENDPOINT_WORKER_SYNC_TASK is None or PUBLIC_ENDPOINT_WORKER_SYNC_TASK.done():
                PUBLIC_ENDPOINT_WORKER_SYNC_TASK = asyncio.create_task(_worker_deploy())
        except (NameError, RuntimeError):
            pass

    return changed


async def _discover_public_endpoint(request: Request | None = None) -> bool:
    """Try portable sources once; never fall back to localhost."""
    try:
        candidates = _deployer_env_candidates()
        if request is not None:
            # A real external request is the strongest portable signal for
            # custom domains, so put it ahead of generic provider fallbacks.
            candidates = _request_endpoint_candidates(request) + candidates

        saved = _saved_public_endpoint()
        if saved:
            candidates.append((saved["url"], "saved", "state"))

        endpoint = None
        source = ""
        current_host = str(PUBLIC_ENDPOINT.get("host") or "")
        current_source = str(PUBLIC_ENDPOINT.get("source") or "")

        for raw, src, label in candidates:
            ep = _normalize_public_endpoint(raw)
            if not ep:
                continue

            # Once a custom/request domain is known, do not flap back to a
            # provider hostname on every resolver tick.
            if current_host and current_source.startswith("request:") and src == "platform-env":
                if ep["host"] != current_host:
                    continue

            ep["source"] = f"{src}:{label}"
            endpoint, source = ep, ep["source"]
            break

        async with PUBLIC_ENDPOINT_LOCK:
            PUBLIC_ENDPOINT["attempts"] = int(PUBLIC_ENDPOINT.get("attempts") or 0) + 1
            PUBLIC_ENDPOINT["last_checked_at"] = datetime.now().isoformat(timespec="seconds")

        if endpoint:
            changed = _apply_public_endpoint(endpoint, source)
            if changed:
                logger.info("Public endpoint discovered: %s (source=%s)", endpoint["url"], source)
                try:
                    asyncio.create_task(save_state())
                except RuntimeError:
                    pass
            return True

        async with PUBLIC_ENDPOINT_LOCK:
            PUBLIC_ENDPOINT["ready"] = False
            PUBLIC_ENDPOINT["last_error"] = "No public domain has been exposed yet"
        return False
    except Exception as exc:
        async with PUBLIC_ENDPOINT_LOCK:
            PUBLIC_ENDPOINT["last_error"] = str(exc)
        logger.debug("Public endpoint discovery failed: %s", exc)
        return False


async def _public_endpoint_resolver_loop():
    """Keep checking until a public endpoint exists and refresh periodically."""
    while True:
        try:
            ready = await _discover_public_endpoint()
            await asyncio.sleep(
                PUBLIC_ENDPOINT_REFRESH_SECONDS if ready else PUBLIC_ENDPOINT_RETRY_SECONDS
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Public endpoint resolver loop error: %s", exc)
            await asyncio.sleep(PUBLIC_ENDPOINT_RETRY_SECONDS)


def get_host() -> str:
    # Environment-based refresh is synchronous and cheap; request-based
    # discovery is performed by middleware below.
    endpoint, source = _choose_public_endpoint()
    if endpoint:
        current_source = str(PUBLIC_ENDPOINT.get("source") or "")
        current_host = str(PUBLIC_ENDPOINT.get("host") or "")
        if not (
            current_host
            and current_source.startswith("request:")
            and source.startswith("platform-env:")
            and endpoint["host"] != current_host
        ):
            _apply_public_endpoint(endpoint, source)
    return str(PUBLIC_ENDPOINT.get("host") or SETTINGS.get("domain") or CONFIG.get("host") or "").strip()


def _choose_public_endpoint(request: Request | None = None) -> tuple[dict | None, str]:
    # A domain explicitly entered by the operator must stay authoritative and
    # must not be replaced by a provider hostname discovered later.
    if str(SETTINGS.get("domain_source") or "") == "manual":
        manual = _saved_public_endpoint()
        if manual:
            manual["source"] = "manual:settings"
            return manual, "manual:settings"

    candidates = _deployer_env_candidates()
    if request is not None:
        candidates = _request_endpoint_candidates(request) + candidates

    saved = _saved_public_endpoint()
    if saved:
        candidates.append((saved["url"], "saved", "state"))

    for raw, src, label in candidates:
        endpoint = _normalize_public_endpoint(raw)
        if endpoint:
            return endpoint, f"{src}:{label}"
    return None, ""


def get_public_endpoint() -> dict:
    """Return the known public endpoint without inventing localhost."""
    endpoint = dict(PUBLIC_ENDPOINT)
    host = str(endpoint.get("host") or get_host() or "").strip()
    if host:
        endpoint["host"] = host
        if not endpoint.get("url"):
            endpoint["url"] = f"https://{host}"
        endpoint["ready"] = True
    return endpoint


def _safe_host(*candidates: str) -> str:
    """Return a normalized real public hostname; never return localhost."""
    for c in candidates:
        if c is None:
            continue
        endpoint = _normalize_public_endpoint(str(c))
        if endpoint:
            return endpoint["host"]
    return get_host()


def _is_ip_address(value: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(str(value or '').strip())
        return True
    except Exception:
        return False


def _client_public_domain() -> str:
    """Return a hostname suitable for client configs, never a literal IP.

    The panel may know its public IP for diagnostics, but connection profiles
    should use the operator's configured/public hostname. If no hostname exists
    yet, fail closed instead of leaking the panel IP into a share link.
    """
    candidates = [
        SETTINGS.get("domain"),
        os.environ.get("SPIDER_PANEL_PUBLIC_DOMAIN"),
        os.environ.get("SPIDER_PANEL_PUBLIC_URL"),
    ]
    for raw in candidates:
        ep = _normalize_public_endpoint(str(raw or ""))
        if ep and not _is_ip_address(ep.get("host", "")):
            return ep["host"]
    return ""


DEFAULT_TLS_WS_INBOUND_NAME = "پیش‌فرض TLS + WS"
LEGACY_TLS_WS_NAMES = {"VLESS+WS پیش‌فرض", "VLESS + WS پیش‌فرض", "پیش‌فرض VLESS+WS", "پیش‌فرض VLESS + WS"}


def is_default_tls_ws_inbound(inbound: dict | None) -> bool:
    if not inbound:
        return False
    return (str(inbound.get("name") or "").strip() == DEFAULT_TLS_WS_INBOUND_NAME
            and str(inbound.get("protocol") or "").lower() == "vless"
            and str(inbound.get("network") or "").lower() == "ws"
            and str(inbound.get("security") or "").lower() == "tls")


def find_default_tls_ws_inbound_id() -> str | None:
    for iid, ib in INBOUNDS.items():
        if is_default_tls_ws_inbound(ib):
            return iid
    for iid, ib in INBOUNDS.items():
        name = str(ib.get("name") or "").strip()
        if (name in LEGACY_TLS_WS_NAMES
                and str(ib.get("protocol") or "").lower() == "vless"
                and str(ib.get("network") or "").lower() == "ws"
                and str(ib.get("security") or "").lower() == "tls"):
            ib["name"] = DEFAULT_TLS_WS_INBOUND_NAME
            return iid
    return None


def normalize_relay_links() -> int:
    default_iid = find_default_tls_ws_inbound_id()
    changed = 0
    for uid, user in USERS.items():
        cuuid = user.get("config_uuid") or uid
        inbound_ids = list(user.get("inbound_ids") or [])
        if not inbound_ids and user.get("inbound_id"):
            inbound_ids = [user.get("inbound_id")]
        primary = user.get("inbound_id") or (inbound_ids[0] if inbound_ids else None)
        # Relay is enabled if the user selected the exact default TLS+WS inbound
        # anywhere in the selected inbound list, not only as primary inbound.
        relay = bool(default_iid and default_iid in inbound_ids)
        link = LINKS.get(cuuid)
        if link is None:
            continue
        desired = {
            "user_id": uid,
            "inbound_id": primary,
            "relay_enabled": relay,
            "relay_inbound_id": default_iid if relay else None,
        }
        if relay:
            desired["protocol"] = "vless-ws"
        for key, value in desired.items():
            if link.get(key) != value:
                link[key] = value
                changed += 1
        if relay and link.get("path") != f"/ws/{cuuid}":
            link["path"] = f"/ws/{cuuid}"
            changed += 1
    return changed


def remote_node_config(node: dict, user: dict, remark_tag: str | None = None) -> str:
    """Build the client config from the remote panel's actual managed TLS+WS data."""
    from urllib.parse import urlsplit
    config_uuid = str(user.get("config_uuid") or "").strip()
    if not config_uuid:
        return ""
    raw = str(node.get("domain") or "").strip().rstrip("/")
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlsplit(raw)
    remote_ib = dict(node.get("remote_tls_ws") or {})
    host = str(remote_ib.get("domain") or node.get("remote_host") or parsed.hostname or "").strip()
    if not host:
        return ""
    try:
        port = int(remote_ib.get("external_port") or remote_ib.get("port") or parsed.port or 443)
    except Exception:
        port = 443
    path_template = str(remote_ib.get("path") or ((remote_ib.get("ws_settings") or {}).get("path") or "/ws/{uuid}"))
    path = path_template.replace("{uuid}", config_uuid)
    if not path.startswith("/"):
        path = "/" + path
    network = str(remote_ib.get("network") or "ws").lower()
    security = str(remote_ib.get("security") or "tls").lower()
    fingerprint = str(remote_ib.get("fingerprint") or "chrome")
    sni = str(remote_ib.get("sni") or host)
    node_label = str(node.get("name") or node.get("remote_host") or "node").strip()
    node_flag = str(node.get("country_flag") or node.get("remote_flag") or "🌐").strip() or "🌐"
    node_country = str(node.get("country") or "").strip()
    node_ip = str(node.get("public_ip") or node.get("remote_ip") or "").strip()
    node_identity = " ".join(x for x in (node_flag, node_country, node_ip) if x).strip()
    remark = f"Pars Space - {user.get('username', 'user')} {node_identity}".strip()
    if node_label and node_label not in remark:
        remark += f" · {node_label}"
    if remark_tag and remark_tag not in remark:
        remark += f" {remark_tag}"
    if network == "ws":
        params = (f"encryption=none&security={security}&type=ws"
                  f"&host={quote(host)}&path={quote(path, safe='')}"
                  f"&sni={quote(sni)}&fp={quote(fingerprint)}&alpn=http/1.1")
    else:
        # Managed Node selection currently requires TLS+WS. Refuse to generate a
        # misleading VLESS config when the remote server reports another transport.
        return ""
    return f"vless://{config_uuid}@{host}:{port}?{params}#{quote(remark)}"


def is_node_control_inbound(inbound_id: str, inbound: dict | None = None) -> bool:
    """The local Node inbound is a management selector, not a remote VLESS endpoint."""
    ib = inbound if inbound is not None else INBOUNDS.get(inbound_id)
    if inbound_id == "Node":
        return True
    if not ib:
        return False
    return bool((ib.get("system") or str(ib.get("inbound_type") or "").lower() == "node"
                 or str(ib.get("protocol") or "").lower() == "node")
                and str(ib.get("name") or "").strip() == "Node")


def node_subscription_configs(user: dict) -> list[str]:
    """Return the deduplicated configs for the union of Node selections.

    Any inbound may carry enabled_node_ids; the user's Node assignments are the
    union of those selections. Stored node_configs are authoritative once a sync
    has run, while a safe local regeneration is used as a fallback.
    """
    selected_node_ids = _selected_node_ids_for_user(user) if "_selected_node_ids_for_user" in globals() else []
    if not selected_node_ids:
        return []
    stored = user.get("node_configs") or {}
    out, seen = [], set()
    for nid in selected_node_ids:
        cfg = stored.get(nid)
        if not cfg:
            node = NODES.get(nid)
            if node:
                cfg = remote_node_config(node, user, f"Node-{node.get('name') or node.get('remote_host') or nid}")
        if cfg:
            cfg = str(cfg).strip()
            if cfg and cfg not in seen:
                out.append(cfg)
                seen.add(cfg)
    return out


def generate_uuid() -> str:
    """Generate a standard hyphenated UUID (RFC 4122) — required by VLESS clients
    and the worker's uuid validation (the worker rejects 32-char bare hex)."""
    return str(uuid.uuid4())


def generate_random_path(prefix: str = "", length: int = 6) -> str:
    """Generate a URL-safe random path segment once per user.

    Returns a path like /a83d91c5, /api-f7a29c, /cdn-91ad3b2f.
    Called ONCE at user creation time then stored permanently.
    """
    if prefix:
        return f"/{prefix}-{secrets.token_hex(length)}"
    return f"/{secrets.token_hex(length)}"


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(uuid: str, host: str, remark: str = "Pars Space", protocol: str = DEFAULT_PROTOCOL) -> str:
    """می‌سازد VLESS share-link متناسب با پروتکل انتخاب‌شده."""
    host = _safe_host(host)
    if not host:
        return ""
    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "http/1.1",
        }
    else:
        # xhttp-packet-up / xhttp-stream-up / xhttp-stream-one
        mode = protocol.replace("xhttp-", "")  # packet-up | stream-up | stream-one
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "h2,http/1.1",
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def uptime_secs():
    return max(time.time() - stats["start_time"], 1)

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.2f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    if b < 1024**4: return f"{b/1024**3:.2f} GB"
    return f"{b/1024**4:.2f} TB"

def client_ip(request: Request) -> str:
    """آی‌پی واقعی کلاینت رو با احتساب هدرهای پراکسی (Railway/Cloudflare) برمی‌گردونه."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


# ── User helper functions ────────────────────────────────────────────────────
def is_user_allowed(user: dict | None) -> bool:
    """Check if a user is active and not expired."""
    if user is None:
        return False
    if user.get("status") == "disabled":
        return False
    if user.get("status") == "expired":
        return False
    exp = user.get("expire_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(exp):
                user["status"] = "expired"
                return False
        except Exception:
            pass
    lb = user.get("traffic_limit_bytes", 0)
    if lb > 0 and user.get("traffic_used_bytes", 0) >= lb:
        return False
    return True

def auto_check_user_expiry(user: dict):
    """Auto-mark user as expired if past expire_at."""
    if not user:
        return
    exp = user.get("expire_at")
    if not exp:
        return
    try:
        if datetime.now() > datetime.fromisoformat(exp):
            if user.get("status") not in ("expired", "disabled"):
                user["status"] = "expired"
    except Exception:
        pass

def generate_short_id() -> str:
    """Generate a shorter ID for user management."""
    return secrets.token_hex(6)

def _generate_protocol_share_link(config_uuid: str, username: str, password: str, proto: str, host: str, port: str, transport: str, security: str, inbound: dict | None, user: dict, addr_ip: str | None = None, addr_port: str | None = None, alpn: str = "http/1.1") -> str:
    """Generate a client share link matching the selected protocol/transport.

    This deliberately emits VMess/Trojan links instead of pretending every
    protocol is VLESS. The old implementation did exactly that, which is a
    particularly creative way to make a protocol selector decorative.
    """
    host = addr_ip or host
    port = addr_port or port
    remark = quote(f"Pars Space - {username}")
    fp = str((inbound or {}).get("fingerprint") or "chrome")
    if transport == "ws":
        ws = (inbound or {}).get("ws_settings") or {}
        path = str(ws.get("path") or (inbound or {}).get("path") or f"/ws/{config_uuid}").strip()
        if not path.startswith("/"): path = "/" + path
        host_header = str(ws.get("host") or host).strip()
        if proto == "vmess":
            obj = {"v":"2","ps":f"Pars Space - {username}","add":host,"port":int(port or 443),"id":config_uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host_header,"path":path,"tls":"tls" if security=="tls" else "","sni":host,"alpn":alpn}
            return "vmess://" + base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
        if proto == "trojan":
            pw = str(password or user.get("trojan_password") or config_uuid)
            q = f"security={quote(security)}&type=ws&host={quote(host_header)}&path={quote(path,safe='')}&sni={quote(host)}&fp={quote(fp)}&alpn={quote(alpn)}"
            return f"trojan://{quote(pw,safe='')}@{host}:{port}?{q}#{remark}"
    elif transport == "grpc":
        gs = (inbound or {}).get("grpc_settings") or {}
        service = str(gs.get("serviceName") or gs.get("service_name") or "pars-space").strip()
        if proto == "vmess":
            obj = {"v":"2","ps":f"Pars Space - {username}","add":host,"port":int(port or 443),"id":config_uuid,"aid":0,"scy":"auto","net":"grpc","type":"none","host":host,"path":service,"tls":"tls" if security=="tls" else "","sni":host,"alpn":alpn}
            return "vmess://" + base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
        if proto == "trojan":
            pw = str(password or user.get("trojan_password") or config_uuid)
            q = f"security={quote(security)}&type=grpc&serviceName={quote(service)}&sni={quote(host)}&fp={quote(fp)}&alpn={quote(alpn)}"
            return f"trojan://{quote(pw,safe='')}@{host}:{port}?{q}#{remark}"
    elif transport == "tcp":
        if proto == "vmess":
            obj = {"v":"2","ps":f"Pars Space - {username}","add":host,"port":int(port or 443),"id":config_uuid,"aid":0,"scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"tls" if security=="tls" else "","sni":host,"alpn":alpn}
            return "vmess://" + base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
        if proto == "trojan":
            pw = str(password or user.get("trojan_password") or config_uuid)
            q = f"security={quote(security)}&type=tcp&sni={quote(host)}&fp={quote(fp)}&alpn={quote(alpn)}"
            return f"trojan://{quote(pw,safe='')}@{host}:{port}?{q}#{remark}"
    # Fallback for protocols not covered above.
    return ""

def _finalmask_query(inbound: dict | None) -> str:
    fm = (inbound or {}).get("finalmask") or {}
    if not isinstance(fm, dict) or not fm:
        return ""
    try:
        return "&fm=" + quote(json.dumps(fm, separators=(",", ":"), ensure_ascii=False), safe="")
    except Exception:
        return ""


def generate_user_config(user_id: str, user: dict, inbound_id: str = None, addr: str = None, remark_tag: str = None) -> str:
    """Build a VLESS config string for one inbound of a user.

    Three config families (one per inbound type):
      - Reality  → served by Xray core (address/host/port/pbk/sid come from the
                   inbound's reality settings + external domain/port)
      - TLS WS/XHTTP → served by the FastAPI relay; address/host/sni = the
                   panel's main domain, port 443. ws is the default transport,
                   xhttp is selectable per inbound.
      - Worker   → served by the Cloudflare Worker; address/host/sni = worker
                   domain, canonical path /ws/{uuid}.

    addr (scanned custom IP) overrides only the connect address; host/sni stay
    on the real domain so the TLS handshake reaches the service.
    """
    inbound = INBOUNDS.get(inbound_id) if inbound_id else None
    proto = (inbound.get("protocol") if inbound else None) or (user.get("protocol") or "vless")
    proto = proto.lower()
    sec = (inbound.get("security") if inbound else None) or "tls"
    sec = sec.lower()
    tls_cfg = (inbound.get("tls_settings") or {}) if inbound else {}
    alpn = str(tls_cfg.get("alpn") or "http/1.1").strip() or "http/1.1"

    config_uuid = str(user.get("config_uuid", "") or user_id).strip()
    if not _is_valid_uuid(config_uuid):
        logger.warning("Skipping config for user %s: invalid config UUID %r", user_id, config_uuid)
        return ""
    username = user.get("username", user_id)
    rem = f"Pars Space - {username}"
    if remark_tag:
        rem = f"{rem} {remark_tag}"
    remark = quote(rem)

    # Never generate a client-facing config until a real public hostname is known.
    # Returning an empty config lets the caller/UI retry while the resolver works.
    panel_domain = _client_public_domain()
    if not panel_domain and proto not in ("worker", "reality", "telegram"):
        return ""

    # Optional custom-IP address override (only the connect address changes).
    addr_ip, addr_port = None, None
    if addr:
        addr = addr.strip()
        if ":" in addr:
            addr_ip, _, addr_port = addr.rpartition(":")
        else:
            addr_ip, addr_port = addr, "443"
        addr_ip, addr_port = addr_ip.strip(), addr_port.strip()

    # ── WORKER (multi-location via Cloudflare Worker) ──
    if proto == "worker":
        wcfgs = _worker_configs(user_id, user, inbound, "", remark_tag, addr_ip, addr_port)
        if wcfgs:
            return wcfgs[0]
        return ""

    # ── TELEGRAM PROXY ──
    if proto == "telegram":
        if not inbound:
            return ""
        return generate_telegram_proxy_link(user_id, user, inbound, remark_tag)

    # ── REALITY (served by Xray core) ──
    if proto == "reality" or sec == "reality":
        # Not configured yet (admin must fill domain + port) → no config.
        if not inbound:
            return ""
        ext_domain = str(inbound.get("external_domain") or "").strip()
        ext_port = str(inbound.get("external_port") or "").strip()
        if not ext_domain or not ext_port:
            return ""
        rs = inbound.get("reality_settings") or SETTINGS.get("reality") or {}
        gs = SETTINGS.get("reality") or {}
        # Use the private key from inbound, derive public key from it (this is the ONLY
        # public key that works with Xray — Xray derives it from the same private key).
        priv_key = _xray_x25519_privkey_norm(str(rs.get("private_key") or gs.get("private_key") or ""))
        if not priv_key:
            logger.warning("Skipping Reality config for user %s: missing/invalid private key", user_id)
            return ""
        pbk = _xray_x25519_public_key(priv_key)
        if not pbk:
            logger.warning("Skipping Reality config for user %s: failed to derive public key", user_id)
            return ""
        sid = str(rs.get("short_id") or gs.get("short_id") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2,16}", sid or "") or len(sid) % 2:
            logger.warning("Skipping Reality config for user %s: invalid short_id %r", user_id, sid)
            return ""
        spx = str(rs.get("spiderx") or gs.get("spiderx") or "/").strip() or "/"
        fp = inbound.get("fingerprint") or rs.get("fingerprint") or gs.get("fingerprint") or "chrome"
        sni = inbound.get("sni") or rs.get("sni") or gs.get("sni") or "is1-ssl.mzstatic.com"
        xs = inbound.get("xhttp_settings") or {}
        # XHTTP path is a shared transport base path: the client and server
        # must use the exact same value. Xray adds its per-session UUID path
        # internally; do not manually append the VLESS UUID here.
        rpath = str(xs.get("path") or "/").strip()
        if not rpath.startswith("/"):
            rpath = "/" + rpath
        if "#" in rpath or "?" in rpath or rpath == "":
            rpath = "/"
        host = addr_ip or ext_domain
        port = addr_port or ext_port
        if not host or _is_ip_address(host):
            return ""
        # xhttp (default for reality inbound) or tcp
        if (inbound.get("network") or "xhttp") == "tcp":
            params = (f"encryption=none&security=reality&type=tcp"
                      f"&sni={quote(sni)}&fp={fp}&alpn={quote(alpn)}"
                      f"&pbk={pbk}&sid={sid}&spx={spx}")
        else:
            xpb = xs.get("xPaddingBytes", "100-1000")
            xmod = str(xs.get("mode") or "stream-up").strip().lower()
            if xmod not in ("auto", "packet-up", "stream-up", "stream-one"):
                xmod = "stream-up"
            if xmod == "auto":
                # Keep client/server mode deterministic. Recent Xray builds have
                # compatibility issues when one side forces a concrete mode and
                # the other advertises auto.
                xmod = "stream-up"
            extra_obj = {"xPaddingBytes": xpb}
            if xmod == "packet-up":
                extra_obj["scMaxEachPostBytes"] = xs.get("scMaxEachPostBytes", "1000000")
            extra = quote(json.dumps(extra_obj, separators=(",", ":"), ensure_ascii=False), safe='')
            xh_host = str(xs.get("host") or "").strip()
            host_q = f"&host={quote(xh_host)}" if xh_host else ""
            params = (f"encryption=none&security=reality"
                      f"&sni={quote(sni)}&fp={quote(str(fp), safe='')}"
                      f"&pbk={quote(pbk, safe='')}&sid={sid}&spx={quote(spx, safe='')}"
                      f"&type=xhttp{host_q}&path={quote(rpath, safe='')}&mode={xmod}&extra={extra}")
        # VMess/Trojan can also run over Reality natively in Xray. Keep their
        # protocol-specific share links instead of silently downgrading to VLESS.
        if proto in ("vmess", "trojan"):
            pw = str(user.get("trojan_password") or user.get("password") or config_uuid)
            if proto == "trojan":
                q = (f"security=reality&type=tcp&sni={quote(sni)}&fp={quote(str(fp), safe='')}"
                     f"&pbk={quote(pbk, safe='')}&sid={sid}&spx={quote(spx, safe='')}")
                return f"trojan://{quote(pw, safe='')}@{host}:{port}?{q}#{remark}"
            obj = {"v":"2","ps":f"Pars Space - {username}","add":host,"port":int(port or 443),"id":config_uuid,"aid":0,"scy":"auto","net":"tcp","type":"none","tls":"reality","sni":sni,"fp":str(fp),"pbk":pbk,"sid":sid,"spx":spx}
            return "vmess://" + base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
        return f"vless://{config_uuid}@{host}:{port}?{params}{_finalmask_query(inbound)}#{remark}"

    # ── TLS (WS default / XHTTP selectable) — served by the FastAPI relay ──
    # address/host/sni always = the panel main domain; port 443 (Railway TLS).
    panel_domain = _client_public_domain()

    # ── TUNNEL (user → Railway → CF Worker → site) — path /tunnel/{uuid} ──
    if proto == "tunnel":
        wdom = _worker_safe_domain(WORKER.get("worker_domain"))
        if not wdom or not WORKER.get("connected"):
            return ""
        # Reverse switch ON: user → Worker → Railway → site. The config is
        # addressed to the WORKER domain with path /reverse/{uuid} and the
        # user's record lives in REVERSE_KV.
        if inbound and inbound.get("reverse_enabled"):
            rpath = f"/reverse/{config_uuid}"
            params = ("encryption=none&security=tls&type=ws"
                      f"&host={quote(wdom)}&path={quote(rpath, safe='')}&sni={quote(wdom)}"
                      f"&fp=chrome&alpn={quote(alpn)}")
            rev_rem = quote(f"Pars Space - {username} Reverse".strip())
            return f"vless://{config_uuid}@{wdom}:443?{params}{_finalmask_query(inbound)}#{rev_rem}"
        # Plain tunnel: user → Railway → Worker → site (path /tunnel/{uuid},
        # addressed to the panel/Railway domain).
        tpath = f"/tunnel/{config_uuid}"
        params = ("encryption=none&security=tls&type=ws"
                  f"&host={quote(panel_domain)}&path={quote(tpath, safe='')}&sni={quote(panel_domain)}"
                  f"&fp=chrome&alpn={quote(alpn)}")
        tun_rem = quote(f"Pars Space - {username} Tunnel".strip())
        return f"vless://{config_uuid}@{panel_domain}:443?{params}{_finalmask_query(inbound)}#{tun_rem}"

    # The exact default TLS+WS inbound is the only inbound served by the FastAPI
    # WebSocket relay. Other inbounds must use their own stored transport/domain/port.
    if is_default_tls_ws_inbound(inbound):
        panel_domain = _client_public_domain()
        host = addr_ip or panel_domain
        port = addr_port or "443"
        transport = "ws"
        security = "tls"
    else:
        inbound_domain = str((inbound or {}).get("external_domain") or (inbound or {}).get("domain") or "").strip()
        host = addr_ip or _client_public_domain() or inbound_domain
        if not host or (_is_ip_address(host) and not addr_ip):
            return ""
        port = addr_port or str((inbound or {}).get("external_port") or (inbound or {}).get("port") or 443)
        network = str((inbound or {}).get("network") or "").strip().lower()
        # Use the selected inbound's transport first. The user's global transport_type
        # is only a legacy fallback and must not override another selected inbound.
        transport = network or str(user.get("transport_type") or "ws").strip().lower()
        if transport not in ("ws", "xhttp", "tcp", "grpc"):
            transport = "ws"
        security = sec if sec in ("tls", "none") else "tls"

    if transport == "xhttp":
        xs = (inbound.get("xhttp_settings") or {}) if inbound else {}
        xpb = xs.get("xPaddingBytes", "100-1000")
        xmode = str(xs.get("mode", "auto")).strip().lower()
        if xmode not in ("packet-up", "stream-up"):
            xmode = "stream-up"
        xsc = xs.get("scMaxEachPostBytes", "1000000")
        extra_obj = {"xPaddingBytes": xpb}
        if xmode == "packet-up":
            extra_obj["scMaxEachPostBytes"] = xsc
        extra = quote(json.dumps(extra_obj, separators=(",", ":"), ensure_ascii=False), safe='')
        xpath = f"/xhttp-siz10/{xmode}/{config_uuid}"
        params = (f"encryption=none&security={security}&type=xhttp"
                  f"&host={quote(host)}&path={quote(xpath, safe='')}&sni={quote(host)}"
                  f"&fp=chrome&alpn={quote(alpn)}&mode={xmode}&extra={extra}")
    elif transport == "grpc":
        gs = (inbound.get("grpc_settings") or {}) if inbound else {}
        service = str(gs.get("serviceName") or gs.get("service_name") or "pars-space").strip() or "spider"
        params = (f"encryption=none&security={security}&type=grpc"
                  f"&serviceName={quote(service)}&sni={quote(host)}"
                  f"&fp=chrome&alpn={quote(alpn)}")
    elif transport == "tcp":
        params = (f"encryption=none&security={security}&type=tcp"
                  f"&sni={quote(host)}&fp=chrome&alpn={quote(alpn)}")
    else:  # ws
        # Only the exact default TLS+WS inbound may use /ws/{uuid}; other WS
        # inbounds keep their own configured path if present.
        configured_path = str((inbound or {}).get("path") or "").strip()
        if is_default_tls_ws_inbound(inbound) or not configured_path:
            ws_path = f"/ws/{config_uuid}"
        else:
            ws_path = configured_path if configured_path.startswith("/") else f"/{configured_path}"
        params = (f"encryption=none&security={security}&type=ws"
                  f"&host={quote(host)}&path={quote(ws_path, safe='')}&sni={quote(host)}"
                  f"&fp=chrome&alpn={quote(alpn)}")
    if proto in ("vmess", "trojan"):
        generated = _generate_protocol_share_link(
            config_uuid, username, str(user.get("password") or user.get("trojan_password") or ""),
            proto, host, port, transport, security, inbound, user, addr_ip, addr_port, alpn
        )
        if generated:
            return generated
    return f"vless://{config_uuid}@{host}:{port}?{params}{_finalmask_query(inbound)}#{remark}"


def generate_custom_ip_configs(user_id: str, user: dict) -> dict:
    """Build extra configs from scanned IPs — ONLY for VLESS/WS/Worker inbounds.

    Telegram inbounds are SKIPPED because:
    - Telegram proxy works on its own dedicated port, not on CF/Railway IPs

    Per-inbound rules:
    - worker inbound → scanned Cloudflare IPs (host/sni stay on worker domain)
    - tls (ws/xhttp) inbound → scanned Railway IPs (host/sni stay on panel domain)
    - telegram → SKIPPED (not compatible with scanned IPs)
    - reality → SKIPPED (can't swap address)

    Returns {"railway": [...], "cf": [...]}
    """
    cii = user.get("custom_ip_inbounds") or {}
    cf_ids = [str(x) for x in (cii.get("cf") or [])]
    rw_ids = [str(x) for x in (cii.get("railway") or [])]
    out = {"railway": [], "cf": []}

    # Cloudflare scanned IPs → worker inbounds only
    cf_ips = _read_scanned_ips("cf")
    if cf_ips:
        for iid_ in cf_ids:
            ib = INBOUNDS.get(iid_)
            if not ib:
                continue
            if (ib.get("protocol") or "").lower() in ("telegram",):
                continue
            for i, ip in enumerate(cf_ips[:10], 1):
                try:
                    cfg = generate_user_config(user_id, user, iid_, addr=ip, remark_tag=f"Cloudflare{i}")
                except Exception as e:
                    logger.warning(f"cf custom-ip config gen failed for {ip}: {e}")
                    continue
                if cfg:
                    out["cf"].append(cfg)

    # Railway scanned IPs → TLS inbounds only
    rw_ips = _read_scanned_ips("railway")
    if rw_ips:
        for iid_ in rw_ids:
            ib = INBOUNDS.get(iid_)
            if not ib:
                continue
            if (ib.get("protocol") or "").lower() in ("telegram",):
                continue
            if not ib:
                continue
            for i, ip in enumerate(rw_ips[:10], 1):
                try:
                    cfg = generate_user_config(user_id, user, iid_, addr=ip, remark_tag=f"Railway{i}")
                except Exception as e:
                    logger.warning(f"railway custom-ip config gen failed for {ip}: {e}")
                    continue
                if cfg:
                    out["railway"].append(cfg)
    return out


def generate_status_config(user: dict, configs: list) -> str:
    """Generate a status config (config-status) with fake random stats.

    This config is placed FIRST in the subscription so clients display it as
    the status/overview config. It uses the panel's main domain and carries
    fake volume/time/user-count in the remark for easy reading.

    The address is the panel domain (not external_domain) and host/sni are
    also the panel domain so TLS handshake reaches the panel.
    """
    import random

    # Get user info
    username = user.get("username", "user")
    user_id = user.get("user_id", "")
    config_uuid = user.get("config_uuid", "") or user_id

    # Use panel domain from discovery (required for TLS WS/XHTTP).
    panel_domain = _client_public_domain()
    if not panel_domain:
        return ""

    # Generate fake stats for the status config
    # Random volume: 100GB - 500GB total, 10GB - 100GB used
    total_gb = random.randint(100, 500)
    used_gb = random.randint(10, min(100, total_gb - 1))

    # Random expiry: 30-365 days
    expire_days = random.randint(30, 365)

    # Random concurrent users: 1-10
    online_users = random.randint(1, 10)

    # Build remark with fake stats (status config identifier)
    # Format: "📊 Status | User: {username} | Used: {used}GB/{total}GB | Days: {days} | Online: {online}"
    remark_text = f"📊 Status | User: {username} | Used: {used_gb}GB/{total_gb}GB | Days: {expire_days} | Online: {online_users}"
    remark = quote(remark_text)

    # Try to find a TLS WS/XHTTP config to copy transport from
    transport = "ws"
    ws_path = f"/ws/{config_uuid}"
    params = (f"encryption=none&security=tls&type=ws"
              f"&host={quote(panel_domain)}&path={quote(ws_path, safe='')}&sni={quote(panel_domain)}"
              f"&fp=chrome&alpn=http/1.1")

    for c in configs:
        if c and "type=ws" in c:
            transport = "ws"
            # Already set ws_path and params above; break if desired
            break
        elif c and "type=xhttp" in c:
            transport = "xhttp"
            # Build xhttp parameters using settings from user's inbound
            inbound_ids = user.get("inbound_ids") or []
            xpb = "100-1000"
            xsc = "1000000"
            xmode = "stream-up"
            for iid_ in inbound_ids:
                ib = INBOUNDS.get(iid_)
                if ib:
                    _p = (ib.get("protocol") or "").lower()
                    _s = (ib.get("security") or "").lower()
                    if _p != "reality" and _s != "reality" and _p != "worker":
                        xs = ib.get("xhttp_settings") or {}
                        xpb = xs.get("xPaddingBytes", "100-1000")
                        xmode = str(xs.get("mode", "auto")).strip().lower()
                        if xmode not in ("packet-up", "stream-up"):
                            xmode = "stream-up"
                        xsc = xs.get("scMaxEachPostBytes", "1000000")
                        break
            extra = quote('{{"xPaddingBytes":"{}","mode":"{}","scMaxEachPostBytes":"{}"}}'.format(xpb, xmode, xsc), safe='')
            ws_path = f"/xhttp-siz10/{xmode}/{config_uuid}"
            params = (f"encryption=none&security=tls&type=xhttp"
                      f"&host={quote(panel_domain)}&path={quote(ws_path, safe='')}&sni={quote(panel_domain)}"
                      f"&fp=chrome&mode={xmode}&extra={extra}")
            break

    # Address is panel domain, port 443
    host = panel_domain
    port = "443"

    return f"vless://{config_uuid}@{host}:{port}?{params}#{remark}"




def _worker_configs(user_id: str, user: dict, inbound: dict, stored_path: str, base_remark: str, addr_ip: str = None, addr_port: str = None) -> list:
    """Build one canonical VLESS/TCP/WS/TLS config for the managed Worker.

    The Worker accepts exactly /ws/{UUID}; the same UUID is embedded in the
    VLESS user-id and in the KV record pushed by the panel. Never invent a
    second UUID or reuse a legacy bare-hex identifier here.
    """
    wdomain = _worker_safe_domain(WORKER.get("worker_domain"))
    if not wdomain:
        return []

    cfg_uuid = str(user.get("config_uuid") or "").strip().lower()
    if not _is_valid_uuid(cfg_uuid):
        logger.warning("worker config skipped: invalid config_uuid user=%s uuid=%s", user_id, cfg_uuid)
        return []

    # Default Worker endpoint is HTTPS/WSS on 443. A scanned Cloudflare IP
    # may replace only the TCP connect address; TLS SNI/Host stay on the real
    # Pages domain so the edge certificate and routing remain correct.
    raw_port = ((inbound or {}).get("external_port") or (inbound or {}).get("port") or 443)
    try:
        wport = int(raw_port)
    except Exception:
        wport = 443
    if not 1 <= wport <= 65535:
        wport = 443

    address = str(addr_ip or wdomain).strip()
    try:
        port = int(addr_port or wport)
    except Exception:
        port = wport
    if not address or not (1 <= port <= 65535):
        return []

    # Canonical route shared by the generator, Worker and every subscription.
    wpath = f"/ws/{cfg_uuid}"
    uname = str(user.get("username") or user_id)
    remark = quote(f"Pars Space - {uname}{(' ' + str(base_remark)) if base_remark and not str(base_remark).startswith('Pars Space -') else ''}")

    params = (
        "encryption=none"
        "&security=tls"
        "&type=ws"
        f"&host={quote(wdomain, safe='')}"
        f"&path={quote(wpath, safe='')}"
        f"&sni={quote(wdomain, safe='')}"
        "&fp=chrome"
        "&alpn=http%2F1.1"
    )
    return [f"vless://{cfg_uuid}@{address}:{port}?{params}#{remark}"]


# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                }
                asyncio.create_task(save_state())
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT UI FIXES (MIGRATED FROM app.py)
# ══════════════════════════════════════════════════════════════════════════════
_HIDDEN_TABS = """
<style>
  [onclick*="switchTab('autoconfig'"] ,
  [onclick*="switchTab('tunnel'"] ,
  #tab-autoconfig,
  #tab-tunnel { display: none !important; }
</style>
"""

_SETTINGS_TOOLS = """
<div id="copilot-settings-tools" class="panel" style="margin-top:14px">
  <div class="panel-h"><span class="glow">Domain / IP / API Key</span></div>
  <div class="set-row"><span class="set-lbl">Panel Domain</span><span id="copilot-panel-domain" dir="ltr">در انتظار دامنه عمومی...</span></div>
  <div class="set-row"><span class="set-lbl">Domain Source</span><span id="copilot-domain-source" dir="ltr">pending</span></div>
  <div class="set-row"><span class="set-lbl">Public IP</span><span id="copilot-public-ip" dir="ltr">در حال دریافت...</span></div>
  <div class="set-row"><span class="set-lbl">API Key</span><code id="copilot-api-key" dir="ltr">--</code></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
    <button class="btn btn-g" type="button" id="copilot-refresh-ip">دریافت IP</button>
    <button class="btn btn-p" type="button" id="copilot-rotate-key">ساخت API Key جدید</button>
    <button class="btn btn-g" type="button" id="copilot-copy-key">کپی API Key</button>
  </div>
  <div id="copilot-tools-message" style="margin-top:10px;color:var(--txt2);font-size:11px"></div>
</div>
<script>
(function(){
  function authFetch(url, opts){ return fetch(url, opts || {}).then(function(r){
    if(r.status === 401){ location.href='/login'; throw new Error('نشست منقضی شده است'); }
    return r;
  }); }
  function msg(t){ var e=document.getElementById('copilot-tools-message'); if(e)e.textContent=t; }
  function loadIp(){
    authFetch('/api/tools/my-ip').then(function(r){return r.json()}).then(function(d){
      var e=document.getElementById('copilot-public-ip');
      var v=d.ips && (d.ips.ipify || d.ips.icanhazip || d.ips.ipinfo) || 'نامشخص';
      if(e)e.textContent=v;
    }).catch(function(e){msg(e.message || 'دریافت IP ناموفق بود');});
  }
  function loadKey(){
    authFetch('/api/settings/security-token/rotate',{method:'POST'}).then(function(r){return r.json()}).then(function(d){
      var e=document.getElementById('copilot-api-key'); if(e)e.textContent=d.security_token || '--';
      msg('API Key ساخته شد و در تنظیمات ذخیره شد.');
    }).catch(function(e){msg(e.message || 'ساخت API Key ناموفق بود');});
  }
  var domainPoll = null;
  function loadPublicEndpoint(){
    authFetch('/api/runtime/public-endpoint').then(function(r){return r.json()}).then(function(d){
      var de=document.getElementById('copilot-panel-domain');
      var se=document.getElementById('copilot-domain-source');
      if(de) de.textContent=d.ready && d.host ? d.host : 'در انتظار دامنه عمومی...';
      if(se) se.textContent=d.ready ? (d.source || 'discovered') : 'pending';
      if(d.ready && domainPoll){ clearInterval(domainPoll); domainPoll=null; }
      if(!d.ready) msg('دامنه عمومی هنوز منتشر نشده؛ پنل به‌صورت خودکار دوباره بررسی می‌کند.');
    }).catch(function(e){ msg(e.message || 'بررسی دامنه ناموفق بود'); });
  }
  document.addEventListener('DOMContentLoaded',function(){
    var ip=document.getElementById('copilot-refresh-ip'), key=document.getElementById('copilot-rotate-key'), copy=document.getElementById('copilot-copy-key');
    if(ip)ip.onclick=loadIp; if(key)key.onclick=loadKey;
    if(copy)copy.onclick=function(){var v=document.getElementById('copilot-api-key').textContent; navigator.clipboard.writeText(v).then(function(){msg('API Key کپی شد.');});};
    loadIp();
    loadPublicEndpoint();
    domainPoll = setInterval(loadPublicEndpoint, 5000);
  });
})();
</script>
"""

@app.middleware("http")
async def deployment_ui_fixes(request: Request, call_next):
    # Every public request is a portable source of truth for custom domains.
    # This runs before route handlers so config/subscription generation in the
    # same request already sees the discovered host.
    try:
        await _discover_public_endpoint(request)
    except Exception as exc:
        logger.debug("Request public-endpoint discovery failed: %s", exc)

    if request.url.path == "/":
        return RedirectResponse("/dashboard", status_code=307)
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return response
    body = b""
    async for chunk in response.body_iterator:
        body += chunk
    html = body.decode("utf-8", errors="replace")
    html = html.replace("</head>", _HIDDEN_TABS + "</head>", 1)
    if 'id="tab-settings"' in html:
        html = html.replace("</div>\n</body>", _SETTINGS_TOOLS + "</div>\n</body>", 1)
    safe_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in {"content-length", "content-encoding", "etag", "transfer-encoding"}
    }
    return HTMLResponse(html, status_code=response.status_code, headers=safe_headers, media_type="text/html")





# ── Telegram Proxy Module (merged from telegram_proxy.py) ──
def derive_secret_from_uuid(config_uuid: str, salt: str = "spider-tg-proxy") -> str:
    """Return the exact 16-byte / 32-hex client secret expected by official MTProxy."""
    return hashlib.sha256(f"{salt}:{config_uuid}".encode()).hexdigest()[:32]


def validate_secret(secret: str) -> str:
    secret = str(secret or "").strip().lower()
    # Railway sample uses plain 32-hex secrets. Do not add an implicit dd prefix.
    if not SECRET_RE.fullmatch(secret):
        raise ValueError("MTProxy secret must be exactly 32 hexadecimal characters")
    return secret


def is_docker_available() -> bool:
    return False


def run_docker_telegram_proxy(*args, **kwargs):
    return None


def stop_docker_telegram_proxy(*args, **kwargs):
    return None




def _get_public_ip() -> str:
    # NAT-info must use the instance's real outbound/public IPv4.
    # Do NOT resolve RAILWAY_TCP_PROXY_DOMAIN here: that is the inbound TCP
    # proxy endpoint and is not necessarily the egress/NAT address used by
    # MTProxy when it connects to Telegram DCs.
    try:
        import urllib.request
        for url in ("https://api.ipify.org", "https://digitalresistance.dog/myIp"):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    ip = r.read().decode().strip()
                if ip:
                    return ip
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _get_internal_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


async def _download_official_files() -> tuple[Path, Path]:
    """Download Telegram's proxy secret/config files, refreshing the config daily."""
    TG_DIR.mkdir(parents=True, exist_ok=True)
    secret_file = TG_DIR / "proxy-secret"
    config_file = TG_DIR / "proxy-multi.conf"
    import urllib.request

    if not secret_file.exists() or secret_file.stat().st_size == 0:
        await asyncio.to_thread(urllib.request.urlretrieve, "https://core.telegram.org/getProxySecret", secret_file)
    if not config_file.exists() or (asyncio.get_running_loop().time() - config_file.stat().st_mtime) > 86400:
        await asyncio.to_thread(urllib.request.urlretrieve, "https://core.telegram.org/getProxyConfig", config_file)
    return secret_file, config_file


class MTProtoProxyServer:
    """Wrapper around the official Telegram MTProxy binary.

    Railway exposes TCP separately from the HTTP service. Therefore MTProxy listens
    on RAILWAY_TCP_APPLICATION_PORT while Uvicorn continues using PORT.
    """

    def __init__(self, inbound_id: str, port: int, sni: str = "", destination: str = "", server_name: str = ""):
        self.inbound_id = inbound_id
        _railway = _railway_tcp_info()
        self.railway_domain = str(_railway.get("domain") or "")
        self.railway_public_port = int(_railway.get("public_port") or 0)
        railway_app_port = int(_railway.get("application_port") or 0)
        # The inbound's Internal Port is authoritative for the MTProxy listener.
        # Railway's TCP application port must be configured to the same value.
        self.port = int(port)
        if railway_app_port and int(railway_app_port) != self.port:
            logger.warning(
                "[TG Proxy %s] Railway TCP application port (%s) differs from inbound Internal Port (%s); "
                "set RAILWAY_TCP_APPLICATION_PORT/TCP Proxy target to the Internal Port.",
                inbound_id, railway_app_port, self.port,
            )
        self.sni = self.destination = self.server_name = ""
        self._secrets_map: Dict[str, dict] = {}
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False
        self._stdout_task: Optional[asyncio.Task] = None
        self._stats_port_value: Optional[int] = None

    def update_secrets(self, secrets_map: dict):
        cleaned = {}
        for secret, info in (secrets_map or {}).items():
            try:
                cleaned[validate_secret(secret)] = dict(info or {})
            except Exception:
                logger.warning("Skipping invalid MTProxy secret for inbound %s", self.inbound_id)
        self._secrets_map = cleaned
        logger.info("[TG Proxy %s] Secrets updated: %d users", self.inbound_id, len(cleaned))

    def get_traffic(self) -> dict:
        return {}

    def _stats_port(self) -> int:
        # Stable localhost-only stats port, avoiding both active stats ports and
        # every actual inbound/panel listener. Cache the choice to prevent recursion.
        if self._stats_port_value is not None:
            return self._stats_port_value
        digest = hashlib.sha256(self.inbound_id.encode("utf-8")).digest()
        offset = int.from_bytes(digest[:2], "big") % 1000
        port = STATS_BASE + offset
        used = {getattr(s, "_stats_port_value", None) for iid, s in TG_PROXY_INSTANCES.items() if iid != self.inbound_id}
        used.update(
            int(ib.get("port") or 0) for iid, ib in INBOUNDS.items()
            if iid != self.inbound_id and _is_real_listener_inbound(ib)
        )
        used.add(int(CONFIG.get("port") or 8080))
        while port in used or not 1024 <= port <= 65535:
            port += 1
            if port > 65535:
                port = 1024
        self._stats_port_value = port
        return port

    async def start(self):
        if self._running:
            return
        if not self._secrets_map:
            logger.info("[TG Proxy %s] no users/secrets yet; listener not started", self.inbound_id)
            return
        bin_path = _mtproxy_bin_path()
        if not bin_path.exists():
            raise RuntimeError(f"official mtproto-proxy binary not found at {bin_path}")

        secret_file, config_file = await _download_official_files()
        internal_ip = _get_internal_ip()
        public_ip = _get_public_ip()
        secret_args = []
        for secret in self._secrets_map:
            secret_args.extend(["-S", secret])

        # The exact structure is based on the official Telegram MTProxy runner:
        # -p = local stats port, -H = client-facing listener port.
        cmd = [
            str(bin_path),
            "-p", str(self._stats_port()),
            "-H", str(self.port),
            "-M", str(WORKERS),
            "--aes-pwd", str(secret_file),
            "-u", "nobody",
            str(config_file),
            "--allow-skip-dh",
        ]
        if internal_ip and public_ip:
            cmd += ["--nat-info", f"{internal_ip}:{public_ip}"]
        cmd += secret_args

        _railway = _railway_tcp_info()
        domain = str(_railway.get("domain") or "")
        public_port = int(_railway.get("public_port") or 0)
        logger.info("[TG Proxy %s] Starting official MTProxy", self.inbound_id)
        logger.info("[TG Proxy %s] client listener: 0.0.0.0:%s", self.inbound_id, self.port)
        if domain and public_port:
            logger.info("[TG Proxy %s] Railway public endpoint: %s:%s", self.inbound_id, domain, public_port)
        logger.info("[TG Proxy %s] command: %s", self.inbound_id, " ".join(cmd[:-2]) + " <secrets>")

        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._running = True
        self._stdout_task = asyncio.create_task(self._watch_output())
        await asyncio.sleep(0.8)
        if self._process and self._process.returncode is not None:
            rc = self._process.returncode
            self._process = None
            self._running = False
            raise RuntimeError(f"mtproto-proxy exited immediately with code {rc}")
        logger.info("[TG Proxy %s] MTProxy is listening on internal port %s", self.inbound_id, self.port)

    async def _watch_output(self):
        proc = self._process
        if not proc or not proc.stdout:
            return
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                logger.info("[TG Proxy %s] %s", self.inbound_id, line.decode(errors="replace").rstrip())
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("MTProxy log watcher stopped: %s", exc)

    async def stop(self):
        self._running = False
        proc = self._process
        self._process = None
        if self._stdout_task:
            self._stdout_task.cancel()
            self._stdout_task = None
        if not proc:
            return
        if proc.returncode is None:
            try:
                proc.send_signal(signal.SIGTERM)
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
        logger.info("[TG Proxy %s] stopped", self.inbound_id)

    async def restart(self):
        await self.stop()
        await self.start()


TGProxy = MTProtoProxyServer


@app.get("/")
async def root(request: Request):
    return RedirectResponse(url="/dashboard")


@app.get("/healthz")
async def healthz():
    """Provider-neutral health check endpoint; never blocks on public-domain discovery."""
    return {
        "ok": True,
        "service": "SpiderPanel",
        "port": CONFIG.get("port", 8080),
        "public_domain_ready": bool(get_host()),
    }


@app.get("/api/runtime/public-endpoint")
async def runtime_public_endpoint(request: Request):
    """Expose discovery state so the UI/deployer can poll until a domain exists."""
    await _discover_public_endpoint(request)
    return get_public_endpoint()


# ── Public subscription endpoint (link/uuid) ────────────────────────────────
async def _find_user_by_config_uuid(config_uuid: str):
    async with USERS_LOCK:
        for uid, u in USERS.items():
            if str(u.get("config_uuid") or "") == config_uuid:
                user = dict(u)
                user["user_id"] = uid
                return uid, user
    return None, None


async def _build_subscription_data_by_uuid(config_uuid: str):
    """Build the public subscription data for a config UUID only.

    Username-based public subscription addressing is intentionally not supported.
    The UUID is the only public identifier for an individual subscription.
    """
    uid, user = await _find_user_by_config_uuid(config_uuid)
    if not user:
        async with LINKS_LOCK:
            link = LINKS.get(config_uuid)
        if link and is_link_allowed(link):
            host = SETTINGS.get("domain") or get_host()
            proto = link.get("protocol", DEFAULT_PROTOCOL)
            vless = generate_vless_link(
                config_uuid,
                host,
                remark=f"Pars Space - {link['label']}",
                protocol=proto,
            )
            return {
                "username": link.get("label", config_uuid),
                "config_uuid": config_uuid,
                "configs": [vless],
                "config": vless,
                "status": "active",
                "is_active": True,
                "traffic_used_bytes": link.get("used_bytes", 0),
                "traffic_limit_bytes": link.get("limit_bytes", 0),
                "traffic_used_fmt": fmt_bytes(link.get("used_bytes", 0)),
                "traffic_limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link.get("limit_bytes", 0)),
                "inbound_ids": [],
                "path": "",
                "sni": "",
                "protocol": proto,
            }
        raise HTTPException(status_code=404, detail="subscription not found")

    if _user_uses_worker_inbound(user):
        user = await _worker_pull_user(uid, user)
        async with USERS_LOCK:
            if uid in USERS:
                USERS[uid].update(user)

    auto_check_user_expiry(user)

    expire_days = None
    expire_at_ts = None
    if user.get("expire_at"):
        try:
            exp = datetime.fromisoformat(user["expire_at"])
            expire_at_ts = int(exp.timestamp())
            expire_days = max(0, (exp - datetime.now()).days)
        except Exception:
            pass

    created_at_ts = None
    if user.get("created_at"):
        try:
            created_at_ts = int(datetime.fromisoformat(user["created_at"]).timestamp())
        except Exception:
            pass

    status = str(user.get("status") or "active").lower()
    if status not in ("active", "disabled", "expired"):
        status = "active"
    if status == "disabled":
        is_active = False
    elif status == "expired":
        is_active = False
    else:
        is_active = is_user_allowed(user)
        if not is_active:
            if user.get("traffic_limit_bytes", 0) > 0 and user.get("traffic_used_bytes", 0) >= user.get("traffic_limit_bytes", 0):
                status = "expired"
            else:
                status = "active"
                is_active = True

    used = user.get("traffic_used_bytes", 0)
    limit = user.get("traffic_limit_bytes", 0)
    traffic_pct = round(used / max(limit, 1) * 100, 1) if limit > 0 else 0

    configs = []
    inbound_ids = user.get("inbound_ids") or []
    stored_path_user = (user.get("path") or "").strip()

    for iid_ in inbound_ids:
        ib = INBOUNDS.get(iid_)
        try:
            if is_node_control_inbound(iid_, ib):
                continue
            p_ = (ib.get("protocol") if ib else "").lower()
            sec_ = (ib.get("security") if ib else "").lower()
            if ib and (p_ == "reality" or sec_ == "reality"):
                if not str(ib.get("external_domain") or "").strip() or not str(ib.get("external_port") or "").strip():
                    continue
            if ib and p_ == "worker":
                configs.extend(_worker_configs(uid, user, ib, stored_path_user, f"Pars Space - {user.get('username', uid)}"))
            else:
                cfg = generate_user_config(uid, user, iid_)
                if cfg:
                    configs.append(cfg)
        except Exception as exc:
            logger.warning(
                "subscription config generation failed user=%s inbound=%s: %s",
                user.get("username", uid), iid_, exc,
            )

    # Node is a management selector; its public configs come from the exact
    # existing `پیش‌فرض TLS + WS` inbound on each selected remote panel.
    configs.extend(node_subscription_configs(user))

    if not configs:
        fallback_iid = find_default_tls_ws_inbound_id()
        selected = set(inbound_ids)
        if not fallback_iid or fallback_iid not in selected:
            fallback_iid = next((iid for iid in inbound_ids if not is_node_control_inbound(iid)), None)
        if fallback_iid:
            fallback_config = generate_user_config(uid, user, fallback_iid)
            if fallback_config:
                configs = [fallback_config]

    custom_cfgs = generate_custom_ip_configs(uid, user)
    all_custom = custom_cfgs.get("railway", []) + custom_cfgs.get("cf", [])
    if all_custom:
        configs.extend(all_custom)

    if not configs:
        raise HTTPException(status_code=404, detail="no configs found")

    status_config = generate_status_config(user, configs)
    all_configs = [status_config] + configs if status_config else configs

    config = None
    for c in all_configs[1:]:
        if c and ("type=ws" in c or "type=xhttp" in c):
            config = c
            break
    if not config and len(all_configs) > 1:
        config = all_configs[1]
    elif not config and all_configs:
        config = all_configs[0]

    return {
        "username": user.get("username"),
        "config_uuid": user.get("config_uuid", config_uuid),
        "protocol": user.get("protocol", "vless"),
        "custom_ip_type": user.get("custom_ip_type", ""),
        "custom_ip_count": len(all_custom),
        "custom_configs": all_custom,
        "custom_railway_configs": custom_cfgs.get("railway", []),
        "custom_cf_configs": custom_cfgs.get("cf", []),
        "traffic_used_bytes": used,
        "traffic_used_fmt": fmt_bytes(used),
        "traffic_limit_bytes": limit,
        "traffic_limit_fmt": "∞" if limit == 0 else fmt_bytes(limit),
        "traffic_percent": traffic_pct,
        "expire_days": expire_days,
        "expire_at": user.get("expire_at"),
        "expire_at_ts": expire_at_ts,
        "created_at": user.get("created_at"),
        "created_at_ts": created_at_ts,
        "status": status,
        "is_active": is_active,
        "vless_link": config,
        "config": config,
        "configs": all_configs,
        "links": [{
            "label": f"Pars Space - {user.get('username', uid)}" if i == 0 else f"Pars Space - {user.get('username', uid)} #{i+1}",
            "protocol": str(c).split("://",1)[0] if "://" in str(c) else user.get("protocol", "vless"),
            "active": is_active,
            "used_fmt": fmt_bytes(used),
            "limit_fmt": "∞" if limit == 0 else fmt_bytes(limit),
            "vless_link": c,
        } for i, c in enumerate(all_configs[1:] if len(all_configs) > 1 else all_configs) if c],
        "sub_url": f"https://{SETTINGS.get('domain') or get_host()}/link/{user.get('config_uuid', config_uuid)}",
        "worker_configs": list(user.get("worker_configs") or []),
        "worker_countries": [],
        "inbound_ids": inbound_ids,
        "sni": user.get("sni", ""),
        "path": user.get("path", ""),
        "transport_type": user.get("transport_type", "ws"),
        "concurrent_connections": user.get("concurrent_connections", 0),
        "server": user.get("server", ""),
        "proxy_ips": user.get("proxy_ips", []),
        "proxy_country": "",
        "proxy_countries": [],
        "proxy_ip_enabled": user.get("proxy_ip_enabled", False),
        "max_ip_per_user": int(user.get("concurrent_connections") if user.get("concurrent_connections") is not None else 0),
        "used_ips": len(USER_IP_MAP.get(uid, set())),
    }


@app.get("/link/{uuid}")
async def link_page(uuid: str, request: Request):
    """Single public subscription URL.

    Browser requests receive the graphical subscription page. Non-browser
    subscription clients receive the base64-encoded subscription payload.
    The public identifier is UUID-only; username URLs are not supported.
    """
    data = await _build_subscription_data_by_uuid(uuid)
    accept = (request.headers.get("accept") or "").lower()
    user_agent = (request.headers.get("user-agent") or "").lower()

    wants_html = (
        "text/html" in accept
        or "application/xhtml+xml" in accept
        or "mozilla" in user_agent
    )

    if wants_html:
        return FileResponse(_os.path.join(_STATIC_DIR, "sub.html"))

    content = base64.b64encode("\n".join(data["configs"]).encode()).decode()
    username = data.get("username") or uuid
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(username),
            "profile-update-interval": "12",
            "support-url": "Pars Space",
        },
    )


@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = SETTINGS.get("domain") or get_host()
    async with LINKS_LOCK:
        lines = [
            generate_vless_link(uid, host, remark=f"Pars Space - {d['label']}", protocol=d.get("protocol", DEFAULT_PROTOCOL))
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ══════════════════════════════════════════════════════════════════════════════
# SUB GROUP endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    desc = (body.get("desc") or body.get("description") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = SETTINGS.get("domain") or get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    host = SETTINGS.get("domain") or get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return {"ok": True}

# ── Public sub-group subscription file ───────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = SETTINGS.get("domain") or get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    async with USERS_LOCK:
        snap_users = dict(USERS)
    lines = []
    for lid in link_ids:
        link = snap_links.get(lid)
        if not link or not is_link_allowed(link):
            continue
        uid = link.get("user_id")
        user = snap_users.get(uid) if uid else None
        cfg = generate_user_config(uid, user, link.get("inbound_id") or user.get("inbound_id")) if uid and user else ""
        if not cfg:
            cfg = generate_vless_link(lid, host, remark=f"Pars-{link.get('label','user')}", protocol=link.get('protocol', DEFAULT_PROTOCOL))
        if cfg:
            lines.append(cfg)

    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "support-url": "Pars Space",
            "profile-update-interval": "12",
        }
    )

@app.get("/sub/{uuid_key}")
async def pars_subscription_alias(uuid_key: str, request: Request):
    return await sub_group_subscription(uuid_key, request)


# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    username = str(body.get("username", "")).strip()
    if username != str(AUTH.get("username") or "admin") or hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

async def _get_external_ip() -> str:
    """Fetch server's external/public IP address."""
    try:
        import urllib.request
        import socket
        # Try to get external IP from public service
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                return r.read().decode().strip()
        except:
            pass
        # Fallback to socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except:
        return ""

async def _build_server_info(refresh: bool = True) -> dict:
    """Return the canonical panel identity used by Settings and remote Nodes."""
    async with SETTINGS_LOCK:
        stored_ip = str(SETTINGS.get("server_ip") or "").strip()
        stored_country = str(SETTINGS.get("country") or "").strip()
        stored_code = str(SETTINGS.get("country_code") or "").strip().upper()
        stored_flag = str(SETTINGS.get("country_flag") or "").strip()
        detected_at = str(SETTINGS.get("server_info_detected_at") or "").strip()
        panel_key = _get_panel_api_key_sync()
    ip = stored_ip
    country = stored_country
    country_code = stored_code
    flag = stored_flag or ("🌐" if not stored_code else _code_to_flag(stored_code))
    if refresh or not ip or not country_code:
        try:
            detected_ip = await _get_external_ip()
            if detected_ip:
                ip = detected_ip
            ident = await _node_identity(ip or (SETTINGS.get("domain") or get_host()))
            if ident.get("ip"):
                ip = ident.get("ip")
            country_code = str(ident.get("country_code") or country_code or "").upper()
            country = str(ident.get("country_name") or country or "")
            flag = str(ident.get("flag") or flag or "🌐")
        except Exception:
            pass
    if not flag and country_code:
        flag = _code_to_flag(country_code)
    detected_at = datetime.now().isoformat()
    host = _safe_host(SETTINGS.get("domain"), get_host())
    default_iid = find_default_tls_ws_inbound_id()
    default_ib = dict(INBOUNDS.get(default_iid, {})) if default_iid else {}
    async with USERS_LOCK:
        users_count = len(USERS)
    async with SETTINGS_LOCK:
        SETTINGS["server_ip"] = ip
        SETTINGS["country"] = country
        SETTINGS["country_code"] = country_code
        SETTINGS["country_flag"] = flag or "🌐"
        SETTINGS["server_info_detected_at"] = detected_at
        SETTINGS["panel_api_key"] = panel_key
        SETTINGS["security_token"] = panel_key
    return {
        "public_ip": ip,
        "country": country,
        "country_code": country_code,
        "country_flag": flag or "🌐",
        "detected_at": detected_at,
        "host": host,
        "users": users_count,
        "default_tls_ws": {
            "id": default_iid or "",
            "name": default_ib.get("name", ""),
            "domain": default_ib.get("external_domain") or default_ib.get("domain") or host,
            "port": default_ib.get("port") or 443,
            "external_port": default_ib.get("external_port") or 443,
            "network": default_ib.get("network", "ws"),
            "security": default_ib.get("security", "tls"),
            "path": str((default_ib.get("ws_settings") or {}).get("path") or "/ws/{uuid}"),
            "fingerprint": default_ib.get("fingerprint") or "chrome",
            "sni": default_ib.get("sni") or default_ib.get("domain") or host,
        },
    }


@app.get("/api/server-info")
async def server_info(_=Depends(require_replication_auth)):
    info = await _build_server_info(refresh=True)
    return info


@app.get("/api/panel-api-key")
async def get_panel_api_key(_=Depends(require_auth)):
    async with SETTINGS_LOCK:
        key = _get_panel_api_key_sync()
    return {"ok": True, "api_key": key, "prefix": "spdr_"}


@app.post("/api/panel-api-key/regenerate")
async def regenerate_panel_api_key(_=Depends(require_auth)):
    new_key = "spdr_" + secrets.token_urlsafe(24)
    async with SETTINGS_LOCK:
        SETTINGS["panel_api_key"] = new_key
        SETTINGS["security_token"] = new_key
        SETTINGS["panel_api_key_rotated_at"] = datetime.now().isoformat()
    await save_state()
    log_activity("auth", "SpiderPanel API Key regenerated", "warn")
    return {"ok": True, "api_key": new_key, "prefix": "spdr_", "rotated_at": SETTINGS.get("panel_api_key_rotated_at")}


@app.post("/api/panel-api-key/verify")
async def verify_panel_api_key(request: Request, _=Depends(require_auth)):
    body = await request.json()
    candidate = str(body.get("api_key") or "").strip()
    async with SETTINGS_LOCK:
        expected = _get_panel_api_key_sync()
    return {"ok": bool(candidate and secrets.compare_digest(candidate, expected)), "valid": bool(candidate and secrets.compare_digest(candidate, expected))}


@app.get("/api/me")
async def api_me(request: Request):
    """Return browser authentication and non-secret server identity."""
    auth = await is_valid_session(request.cookies.get(SESSION_COOKIE))
    info = await _build_server_info(refresh=auth)
    async with SETTINGS_LOCK:
        key = _get_panel_api_key_sync()
    return {"authenticated": auth, "username": AUTH.get("username", "admin"), **info, "api_key": key}


@app.patch("/api/me")
async def update_api_key(request: Request, token=Depends(require_auth)):
    body = await request.json()
    new_key = _normalize_node_key(body.get("api_key") or "")
    if not new_key or not new_key.startswith("spdr_") or len(new_key) < 12:
        raise HTTPException(status_code=400, detail="API key must use the spdr_ prefix")
    async with SETTINGS_LOCK:
        SETTINGS["panel_api_key"] = new_key
        SETTINGS["security_token"] = new_key
        SETTINGS["panel_api_key_rotated_at"] = datetime.now().isoformat()
    await save_state()
    log_activity("auth", "API key updated", "warn")
    return {"ok": True, "api_key": new_key}


@app.post("/api/me/generate-key")
async def generate_api_key(_=Depends(require_auth)):
    # Legacy alias used by older UI builds.
    return await regenerate_panel_api_key()

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}

@app.post("/api/change-credentials")
async def api_change_credentials(request: Request, token=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    username = str(body.get("username") or AUTH.get("username") or "admin").strip()
    if not re.fullmatch(r"(?=(?:.*[A-Za-z]){2,})[A-Za-z0-9_-]+", username):
        raise HTTPException(status_code=400, detail="نام کاربری باید حداقل دو حرف انگلیسی و فقط شامل A-Z، 0-9، _ یا - باشد")
    new = str(body.get("new_password") or "")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["username"] = username
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok":True,"username":username}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    async with USERS_LOCK:
        snap_users = dict(USERS)
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)

    # Auto-check user expiry
    for user in snap_users.values():
        auto_check_user_expiry(user)

    # Count active users
    active_users = sum(1 for u in snap_users.values() if u.get("status") == "active")
    total_users = len(snap_users)

    # Traffic across all links
    total_bytes = stats["total_bytes"]
    traffic_usage_gb = round(total_bytes / (1024 ** 3), 3)

    # Connection-based health simulation
    conn_count = len(connections)
    if conn_count > 400:
        server_status = "down"
    elif conn_count > 200:
        server_status = "degraded"
    else:
        server_status = "healthy"

    # Simulated system metrics
    cpu_percent = round(min(conn_count * 0.3 + 5, 95), 1)
    ram_percent = round(min(45 + (total_users * 0.5) + (conn_count * 0.1), 95), 1)
    disk_percent = round(min(25 + (len(snap) * 0.02) + (total_users * 0.1), 90), 1)
    uptime_secs = max(time.time() - stats["start_time"], 1)
    network_mbps = round(total_bytes / uptime_secs * 8 / 1000000, 2)

    return {
        "active_connections": len(connections),
        "traffic_usage_gb": traffic_usage_gb,
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
        # Enhanced stats
        "active_users": active_users,
        "total_configs": len(snap),
        "total_users": total_users,
        "traffic_usage_gb": traffic_usage_gb,
        "server_status": server_status,
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "disk_percent": disk_percent,
        "network_mbps": network_mbps,
        "recent_activity": list(activity_logs)[-10:],
    }

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections (with IP) ────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    """
    خروجی این endpoint حالا بر اساس IP گروه‌بندی شده:
    هر آی‌پی فقط یک آیتم نمایش داده می‌شود، با جمع بایت‌های تمام سشن‌های
    باز روی همان آی‌پی و تعداد سشن‌های فعال آن آی‌پی.
    raw_count همچنان تعداد واقعی اتصالات باز (سشن‌های خام، مثلاً ۴۰ تا
    اتصال هم‌زمان یک موبایل) را برمی‌گرداند.
    """
    async with LINKS_LOCK:
        snap = dict(LINKS)

    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca

    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "connections": result,
        "count": len(result),          # تعداد آی‌پی‌های یکتا
        "raw_count": len(connections), # تعداد کل اتصالات باز (بدون گروه‌بندی)
    }

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
        }

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = SETTINGS.get("domain") or get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=f"Pars Space - {label}", protocol=protocol),
        "sub_url": f"https://{host}/link/{uid}",
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = SETTINGS.get("domain") or get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": generate_vless_link(uid, host, remark=f"Pars Space - {d['label']}", protocol=proto),
            "sub_url": f"https://{host}/link/{uid}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if any(k in body for k in ("label", "note", "limit_value", "expires_days")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}


# WebSocket route: /ws/{uuid} — config_uuid IS the path.
# Registered directly (like the RVG reference) so it is never swallowed by a
# try/except — this is the only route serving WS TLS configs.
@app.websocket("/ws/{uuid}")
async def ws_uuid_handler(ws: WebSocket, uuid: str):
    # /ws/live is registered later — handle it here since param route matches first
    if uuid == "live":
        await websocket_live_stats(ws)
        return
    await websocket_tunnel(ws, uuid)


# Tunnel path: /tunnel/{uuid} — user → Railway (here) → Cloudflare Worker → site.
# Railway accepts the client's TLS+WS, then relays raw VLESS bytes to the Worker
# over an outbound WSS connection to /{uuid} on the worker domain. The Worker
# authenticates the user from its TUNNEL_KV and connects out to the target.
@app.websocket("/tunnel/{uuid}")
async def tunnel_ws_handler(ws: WebSocket, uuid: str):
    wdom = _worker_safe_domain(WORKER.get("worker_domain"))
    if not wdom or not WORKER.get("connected"):
        await ws.close(code=1014, reason="worker not connected")
        return
    await _tunnel_relay(ws, uuid, wdom)


# Reverse chain leg on Railway: user → Worker → HERE (Railway) → site.
# The client connects to the Worker domain with /reverse/{uuid}; the Worker
# relays the raw VLESS stream over WSS to this endpoint, which forwards it to
# the real destination through the normal proxy_connect pipeline.
@app.websocket("/reverse/{uuid}")
async def reverse_ws_handler(ws: WebSocket, uuid: str):
    await websocket_tunnel(ws, uuid)


async def _tunnel_relay(ws: WebSocket, uuid: str, worker_domain: str):
    """Bridge panel-WS ⇄ worker-WSS bidirectionally."""
    import websockets as _websockets
    await ws.accept()
    link = None
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        await ws.close(code=1008, reason="not authorized")
        return
    ip = ws.headers.get("x-forwarded-for", "").split(",")[0].strip() or (ws.client.host if ws.client else "?")
    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {"uuid": uuid, "ip": ip, "transport": "tunnel-ws", "connected_at": datetime.now().isoformat(), "bytes": 0}
    log_activity("connection", f"Tunnel اتصال جدید از {ip}", "info")
    worker_ws = None
    try:
        wss_url = f"wss://{worker_domain}/{uuid}"
        headers = {"User-Agent": "Spider-Tunnel"}
        worker_ws = await asyncio.wait_for(
            _websockets.connect(wss_url, extra_headers=headers, max_size=None), timeout=10.0)

        async def panel_to_worker():
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                if data:
                    connections[conn_id]["bytes"] += len(data)
                    stats["total_bytes"] += len(data)
                    await worker_ws.send(data)

        async def worker_to_panel():
            async for data in worker_ws:
                if isinstance(data, str):
                    data = data.encode()
                await ws.send_bytes(data)

        done, pending = await asyncio.wait(
            {asyncio.create_task(panel_to_worker()), asyncio.create_task(worker_to_panel())},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        logger.warning(f"tunnel relay [{conn_id}] error: {exc}")
    finally:
        if worker_ws:
            try: await worker_ws.close()
            except Exception: pass
        connections.pop(conn_id, None)

logger.info("VLESS Relay module loaded (WS: /ws/{uuid}, tunnel: /tunnel/{uuid})")

# ══════════════════════════════════════════════════════════════════════════════
# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# INBOUNDS MANAGEMENT endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/inbounds")
async def list_inbounds(auth=Depends(require_replication_auth)):
    """List local inbounds for admins; remote API-key calls only need the
    managed TLS+WS transport metadata required for replication."""
    async with INBOUNDS_LOCK:
        snap = dict(INBOUNDS)
    if auth.get("kind") == "api_key":
        iid = find_default_tls_ws_inbound_id()
        ib = dict(snap.get(iid, {})) if iid else {}
        return {"inbounds": ([{
            "inbound_id": iid,
            "name": ib.get("name", DEFAULT_TLS_WS_INBOUND_NAME),
            "protocol": "vless",
            "inbound_type": "transport",
            "network": ib.get("network", "ws"),
            "security": ib.get("security", "tls"),
            "domain": ib.get("domain") or _safe_host(SETTINGS.get("domain"), get_host()),
            "external_port": ib.get("external_port") or 443,
            "port": ib.get("port") or 443,
            "ws_settings": ib.get("ws_settings") or {"path": "/ws/{uuid}"},
            "fingerprint": ib.get("fingerprint") or "chrome",
        }] if iid else [])}
    result = []
    for iid, ib in snap.items():
        iids = {str(iid)}
        result.append({
            "inbound_id": iid,
            **ib,
            "enabled_node_ids": list(ib.get("enabled_node_ids") or ib.get("node_ids") or []),
            "users_count": sum(1 for u in USERS.values() if str(iid) in [str(x) for x in (u.get("inbound_ids") or [])]),
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"inbounds": result}


@app.post("/api/inbounds")
async def create_inbound(request: Request, auth=Depends(require_replication_auth)):
    """Create an inbound locally, or ensure the managed default inbound for a remote Node."""
    body = await request.json()
    if auth.get("kind") == "api_key":
        # Remote SpiderPanels only need the managed TLS+WS transport. Never let
        # an API key create arbitrary admin inbounds on the target panel.
        async with INBOUNDS_LOCK:
            iid = find_default_tls_ws_inbound_id()
            if not iid:
                iid = "default" if "default" not in INBOUNDS else generate_short_id()
                INBOUNDS[iid] = {
                    "name": DEFAULT_TLS_WS_INBOUND_NAME,
                    "protocol": "vless", "inbound_type": "transport",
                    "port": 443, "network": "ws", "security": "tls",
                    "domain": _safe_host(SETTINGS.get("domain"), get_host()),
                    "external_domain": "", "sni": "", "external_port": "",
                    "fingerprint": "chrome", "ws_settings": {"path": "/ws/{uuid}"},
                    "reality_settings": {}, "xhttp_settings": {},
                    "created_at": datetime.now().isoformat(),
                }
            ib = INBOUNDS[iid]
        await save_state()
        return {"ok": True, "inbound_id": iid, **ib}
    _raw_ib = (body.get("name") or "").strip()[:60]
    name = _raw_ib or f"inbound-{secrets.token_hex(3)}"
    protocol = str(body.get("protocol") or "vless").lower()
    if protocol not in ("vless", "vmess", "trojan", "reality", "worker", "telegram", "node"):
        raise HTTPException(status_code=400, detail="Invalid protocol")
    if protocol == "node":
        selected = [str(x).strip() for x in (body.get("enabled_node_ids") or body.get("node_ids") or []) if str(x).strip()]
        selected = list(dict.fromkeys(selected))
        async with INBOUNDS_LOCK:
            ib = INBOUNDS.get("Node")
            if ib is None:
                ib = {"name": "Node", "system": True, "created_at": datetime.now().isoformat()}
                INBOUNDS["Node"] = ib
            ib.update({"name": "Node", "protocol": "node", "inbound_type": "node", "system": True,
                       "enabled_node_ids": selected, "node_ids": selected})
        await save_state()
        asyncio.create_task(refresh_node_inbound_configs("Node"))
        return {"ok": True, "inbound_id": "Node", **ib}

    network = str(body.get("network") or "ws").lower()
    security = str(body.get("security") or "tls").lower()
    domain = str(body.get("domain") or "").strip()
    external_domain = str(body.get("external_domain") or "").strip()
    sni = str(body.get("sni") or "").strip()
    destination = str(body.get("destination") or "").strip()
    server_name = str(body.get("server_name") or "").strip()
    # A "worker" inbound is a special type: it is addressed to the deployed
    # Cloudflare Worker domain; Railway only controls it and is not in the
    # client traffic path.
    if protocol == "worker":
        wdom = _worker_safe_domain(WORKER.get("worker_domain"))
        if not wdom:
            raise HTTPException(status_code=400, detail="Worker هنوز متصل نیست — ابتدا Worker را در تب Worker متصل کنید")
        network = "ws"
        security = "tls"
        domain = wdom
        external_domain = wdom
        sni = wdom

    # Telegram uses the explicit internal listener from telegram_settings.
    if protocol == "telegram":
        port = int(body.get("port") or 0)
        external_port = int(body.get("external_port") or 443)
    else:
        port = int(body.get("port") or 443)
        external_port = int(body.get("external_port") or 443)

    fingerprint = str(body.get("fingerprint") or "chrome").strip()
    spoof_ip = str(body.get("spoof_ip") or "").strip()
    reality_settings = body.get("reality_settings", {}) if isinstance(body.get("reality_settings"), dict) else {}
    xhttp_settings = body.get("xhttp_settings", {}) if isinstance(body.get("xhttp_settings"), dict) else {}
    finalmask = body.get("finalmask") if isinstance(body.get("finalmask"), dict) else {}
    ws_settings = body.get("ws_settings", {}) if isinstance(body.get("ws_settings"), dict) else {}
    grpc_settings = body.get("grpc_settings", {}) if isinstance(body.get("grpc_settings"), dict) else {}
    telegram_settings = body.get("telegram_settings", {}) if isinstance(body.get("telegram_settings"), dict) else {}
    tls_settings = body.get("tls_settings", {}) if isinstance(body.get("tls_settings"), dict) else {}
    if protocol == "telegram":
        # Telegram Proxy does not use Xray Reality fields.
        sni = ""
        destination = ""
        server_name = ""
        telegram_settings = {
            "internal_port": int(telegram_settings.get("internal_port") or port or 44344),
            "external_port": int(telegram_settings.get("external_port") or external_port or 443),
            "external_domain": str(telegram_settings.get("external_domain") or external_domain or "").strip(),
        }
        port = telegram_settings["internal_port"]
        external_port = telegram_settings["external_port"]
        external_domain = telegram_settings["external_domain"]
        _validate_listener_port(port)
        if not 1 <= external_port <= 65535:
            raise HTTPException(status_code=400, detail="Telegram External Port must be between 1 and 65535")
    elif protocol == "reality" or security == "reality":
        _validate_listener_port(port)
        if not 1 <= external_port <= 65535:
            raise HTTPException(status_code=400, detail="External Port must be between 1 and 65535")

    # Auto-generate Reality keys (x25519 pbk/priv + short_id + mldsa65 seed)
    # fresh for every reality inbound. SNI target is fixed.
    if protocol == "reality" or security == "reality":
        fresh = _gen_reality_settings()
        if not reality_settings.get("private_key"):
            reality_settings["private_key"] = fresh["private_key"]
        if not reality_settings.get("public_key"):
            reality_settings["public_key"] = fresh["public_key"]
        if not reality_settings.get("short_id") and reality_settings.get("short_ids"):
            reality_settings["short_id"] = reality_settings.get("short_ids")
        _sid = str(reality_settings.get("short_id") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2,16}", _sid or "") or len(_sid) % 2:
            reality_settings["short_id"] = fresh["short_id"]
        else:
            reality_settings["short_id"] = _sid
        _pub = _xray_x25519_public_key(str(reality_settings.get("private_key") or ""))
        if _pub:
            reality_settings["public_key"] = _pub
        reality_settings.setdefault("spiderx", "/")
        if fresh.get("mldsa65_seed"):
            reality_settings.setdefault("mldsa65_seed", fresh["mldsa65_seed"])
        if fresh.get("mldsa65_verify"):
            reality_settings.setdefault("mldsa65_verify", fresh["mldsa65_verify"])
        # SNI from frontend is used as dest, server_names, and sni
        if not reality_settings.get("dest"):
            reality_settings["dest"] = (sni or "is1-ssl.mzstatic.com") + ":443"
        if not reality_settings.get("server_names"):
            reality_settings["server_names"] = [sni or "is1-ssl.mzstatic.com"]
        if not reality_settings.get("sni"):
            reality_settings["sni"] = sni or "is1-ssl.mzstatic.com"
        security = "reality"
        if not external_domain:
            external_domain = domain or CONFIG.get("host", "")
        if network not in ("tcp", "xhttp", "grpc"):
            network = "tcp"
    else:
        # For TLS WS/XHTTP (non-reality, non-worker): external_domain and external_port should be empty
        # The panel domain is used via SETTINGS["domain"] in generate_user_config
        external_domain = ""
        external_port = ""

    inbound_id = generate_short_id()
    async with INBOUNDS_LOCK:
        if any(ib.get("name") == name for ib in INBOUNDS.values()):
            if not _raw_ib:
                for _ in range(5):
                    name = f"inbound-{secrets.token_hex(3)}"
                    if not any(ib.get("name") == name for ib in INBOUNDS.values()):
                        break
                else:
                    raise HTTPException(status_code=409, detail="Inbound name already exists")
            else:
                raise HTTPException(status_code=409, detail="Inbound name already exists")
        INBOUNDS[inbound_id] = {
            "name": name,
            "protocol": protocol,
            "inbound_type": "transport",
            "port": port,
            "network": network,
            "security": security,
            "domain": domain,
            "external_domain": external_domain,
            "sni": sni,
            "destination": destination,
            "server_name": server_name,
            "spoof_ip": spoof_ip,
            "external_port": external_port,
            "fingerprint": fingerprint,
            "reality_settings": reality_settings,
            "xhttp_settings": xhttp_settings,
            "finalmask": finalmask,
            "ws_settings": ws_settings,
            "grpc_settings": grpc_settings,
            "telegram_settings": telegram_settings,
            "tls_settings": tls_settings,
            "node_ids": [str(x).strip() for x in (body.get("node_ids") or []) if str(x).strip()],
            "enabled_node_ids": [str(x).strip() for x in (body.get("enabled_node_ids") or body.get("node_ids") or []) if str(x).strip()],
            "created_at": datetime.now().isoformat(),
        }
    if protocol == "reality" and network == "xhttp":
        _xp = str(xhttp_settings.get("path") or "/").strip()
        if not _xp.startswith("/") or "?" in _xp or "#" in _xp:
            _xp = "/"
        xhttp_settings["path"] = _xp
        _xm = str(xhttp_settings.get("mode") or "stream-up").strip().lower()
        if _xm not in ("packet-up", "stream-up", "stream-one"):
            _xm = "stream-up"
        xhttp_settings["mode"] = _xm
        xhttp_settings.setdefault("xPaddingBytes", "100-1000")
        xhttp_settings.setdefault("scMaxEachPostBytes", "1000000")
    await save_state()
    log_activity("inbound", f"اینباند «{name}» با پروتکل {protocol.upper()} ساخته شد", "ok")
    asyncio.create_task(_xray_apply())  # (re)start Xray with the new inbound
    # Start Telegram Proxy if this is a telegram inbound
    if protocol == "telegram":
        asyncio.create_task(_start_telegram_proxy(inbound_id, INBOUNDS[inbound_id]))
    return {"ok": True, "inbound_id": inbound_id, **INBOUNDS[inbound_id]}


@app.patch("/api/inbounds/{inbound_id}")
async def update_inbound(inbound_id: str, request: Request, _=Depends(require_auth)):
    """Update an existing inbound."""
    body = await request.json()
    old_protocol = ""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        old_protocol = str(ib.get("protocol") or "").lower()
        if "name" in body:
            _nn = str(body["name"]).strip()[:60]
            if _nn:
                ib["name"] = _nn
        if "protocol" in body:
            p = str(body["protocol"]).lower()
            if p in ("vless", "vmess", "trojan", "reality", "worker", "telegram", "node"): 
                ib["protocol"] = p
        if ib.get("protocol") == "node":
            if inbound_id != "Node" and not ib.get("system"):
                raise HTTPException(status_code=400, detail="Node selector فقط روی inbound سیستمی Node مجاز است")
            ib["name"] = "Node"
            ib["inbound_type"] = "node"
            ib["system"] = True
            selected = body.get("enabled_node_ids") if "enabled_node_ids" in body else body.get("node_ids")
            if selected is not None:
                ids = [str(x).strip() for x in (selected or []) if str(x).strip()]
                ids = list(dict.fromkeys(ids))
                ib["enabled_node_ids"] = ids
                ib["node_ids"] = ids
            await save_state()
            asyncio.create_task(refresh_node_inbound_configs(inbound_id))
            return {"ok": True, "inbound_id": inbound_id, "enabled_node_ids": list(ib.get("enabled_node_ids") or [])}
        # A worker inbound always targets the connected worker domain; if the
        # inbound's domain is stale/empty, refresh it automatically.
        if ib.get("protocol") == "worker":
            wdom = _worker_safe_domain(WORKER.get("worker_domain"))
            if wdom:
                ib["domain"] = wdom
                ib["external_domain"] = wdom
                ib["sni"] = ib.get("sni") or "www.hcaptcha.com"
        if "port" in body:
            _pv = str(body["port"] or "").strip()
            ib["port"] = int(_pv) if _pv else ""  # "" = unconfigured (reality)
        if "network" in body:
            ib["network"] = str(body["network"]).lower()
        if "security" in body:
            ib["security"] = str(body["security"]).lower()
        # Reality security must always be "reality" + have fresh keys
        if ib.get("protocol") == "reality" or ib.get("security") == "reality":
            ib["security"] = "reality"
            # Auto-generate the full reality key set if missing (x25519 pbk/priv,
            # short_id, mldsa65) so the config always carries a working pbk/sid.
            rs = ib.setdefault("reality_settings", {})
            if not rs.get("public_key") or not rs.get("private_key"):
                fresh = _gen_reality_settings()
                rs.setdefault("private_key", fresh["private_key"])
                rs.setdefault("public_key", fresh["public_key"])
                rs.setdefault("mldsa65_seed", fresh["mldsa65_seed"])
                rs.setdefault("mldsa65_verify", fresh["mldsa65_verify"])
            if not rs.get("short_id"):
                rs["short_id"] = secrets.token_hex(5)[:10]
            rs.setdefault("spiderx", "/")
            rs.setdefault("dest", "is1-ssl.mzstatic.com:443")
            rs.setdefault("sni", "is1-ssl.mzstatic.com")
            ib["sni"] = "is1-ssl.mzstatic.com"
            if ib.get("network") not in ("tcp", "xhttp", "grpc"):
                ib["network"] = "tcp"
        if "domain" in body:
            ib["domain"] = str(body["domain"]).strip()
        if "external_domain" in body:
            ib["external_domain"] = str(body["external_domain"]).strip()
        if "sni" in body:
            ib["sni"] = str(body["sni"]).strip()
        if "spoof_ip" in body:
            ib["spoof_ip"] = str(body["spoof_ip"]).strip()
        if "external_port" in body:
            _ev = str(body["external_port"] or "").strip()
            ib["external_port"] = int(_ev) if _ev else ""
        if "fingerprint" in body:
            ib["fingerprint"] = str(body["fingerprint"]).strip()
        if "reality_settings" in body and isinstance(body["reality_settings"], dict):
            incoming_rs = dict(body["reality_settings"])
            if incoming_rs.get("short_id") in (None, "") and incoming_rs.get("short_ids") not in (None, ""):
                incoming_rs["short_id"] = incoming_rs.get("short_ids")
            current_rs = dict(ib.get("reality_settings") or {})
            current_rs.update(incoming_rs)
            _priv = _xray_x25519_privkey_norm(str(current_rs.get("private_key") or ""))
            if _priv:
                current_rs["private_key"] = _priv
                _pub = _xray_x25519_public_key(_priv)
                if _pub:
                    current_rs["public_key"] = _pub
            _sid = str(current_rs.get("short_id") or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{2,16}", _sid or "") or len(_sid) % 2:
                current_rs["short_id"] = secrets.token_hex(5)
            else:
                current_rs["short_id"] = _sid
            ib["reality_settings"] = current_rs
        if "xhttp_settings" in body and isinstance(body["xhttp_settings"], dict):
            ib["xhttp_settings"] = body["xhttp_settings"]
        if "finalmask" in body:
            if isinstance(body["finalmask"], dict):
                ib["finalmask"] = body["finalmask"]
            elif body["finalmask"] in (None, "", False):
                ib["finalmask"] = {}
        if "ws_settings" in body and isinstance(body["ws_settings"], dict):
            ib["ws_settings"] = body["ws_settings"]
        if "grpc_settings" in body and isinstance(body["grpc_settings"], dict):
            ib["grpc_settings"] = body["grpc_settings"]
        if "telegram_settings" in body and isinstance(body["telegram_settings"], dict):
            ib["telegram_settings"] = body["telegram_settings"]

        if (ib.get("protocol") or "").lower() == "reality" or (ib.get("security") or "").lower() == "reality":
            rs = ib.setdefault("reality_settings", {})
            _priv = _xray_x25519_privkey_norm(str(rs.get("private_key") or ""))
            if not _priv:
                fresh = _gen_reality_settings()
                _priv = _xray_x25519_privkey_norm(str(fresh.get("private_key") or ""))
                if _priv:
                    rs["private_key"] = _priv
                    rs["public_key"] = _xray_x25519_public_key(_priv) or str(fresh.get("public_key") or "")
            else:
                rs["private_key"] = _priv
                rs["public_key"] = _xray_x25519_public_key(_priv) or rs.get("public_key", "")
            _sid = str(rs.get("short_id") or rs.get("short_ids") or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{2,16}", _sid or "") or len(_sid) % 2:
                rs["short_id"] = secrets.token_hex(5)
            else:
                rs["short_id"] = _sid
            rs.setdefault("spiderx", "/")
            _sni_final = str(ib.get("sni") or rs.get("sni") or "is1-ssl.mzstatic.com").strip() or "is1-ssl.mzstatic.com"
            rs["sni"] = _sni_final
            if not str(rs.get("dest") or "").strip() or "sni" in body:
                rs["dest"] = _sni_final + ":443"
            if not rs.get("server_names") or "sni" in body:
                rs["server_names"] = [_sni_final]
            if (ib.get("network") or "").lower() == "xhttp":
                xs = ib.setdefault("xhttp_settings", {})
                _xp = str(xs.get("path") or "/").strip()
                if not _xp.startswith("/") or "?" in _xp or "#" in _xp:
                    _xp = "/"
                _xm = str(xs.get("mode") or "stream-up").strip().lower()
                if _xm not in ("packet-up", "stream-up", "stream-one"):
                    _xm = "stream-up"
                xs["path"] = _xp
                xs["mode"] = _xm
                xs.setdefault("xPaddingBytes", "100-1000")
                xs.setdefault("scMaxEachPostBytes", "1000000")

        if ("node_ids" in body or "enabled_node_ids" in body) and ib.get("system"):
            selected = body.get("enabled_node_ids") if "enabled_node_ids" in body else body.get("node_ids")
            ids = [str(x).strip() for x in (selected or []) if str(x).strip()]
            ids = list(dict.fromkeys(ids))
            ib["enabled_node_ids"] = ids
            ib["node_ids"] = ids

        if (ib.get("protocol") or "").lower() == "telegram":
            # Telegram Proxy: inbound settings are authoritative. Railway TCP
            # variables are advisory and must never overwrite user-entered
            # External Domain / External Port / Internal Port.
            ib["sni"] = ""
            ib["destination"] = ""
            ib["server_name"] = ""
            tg = ib.setdefault("telegram_settings", {})
            incoming_tg = body.get("telegram_settings") or {}
            tg["internal_port"] = int(incoming_tg.get("internal_port") or body.get("port") or tg.get("internal_port") or ib.get("port") or 44344)
            tg["external_port"] = int(incoming_tg.get("external_port") or body.get("external_port") or tg.get("external_port") or ib.get("external_port") or 443)
            tg["external_domain"] = str(incoming_tg.get("external_domain") or body.get("external_domain") or tg.get("external_domain") or ib.get("external_domain") or "").strip()
            if not 1 <= tg["external_port"] <= 65535:
                raise HTTPException(status_code=400, detail="Telegram External Port must be between 1 and 65535")
            ib.pop("sni", None)
            ib.pop("destination", None)
            ib.pop("server_name", None)
            ib["port"] = tg["internal_port"]
            ib["external_port"] = tg["external_port"]
            ib["external_domain"] = tg["external_domain"]
        if "destination" in body:
            ib["destination"] = str(body["destination"]).strip()
        if "server_name" in body:
            ib["server_name"] = str(body["server_name"]).strip()
        if (ib.get("protocol") or "").lower() == "telegram":
            ib.pop("sni", None)
            ib.pop("destination", None)
            ib.pop("server_name", None)
    if (ib.get("protocol") or "").lower() not in ("telegram", "worker", "reality") and (ib.get("security") or "").lower() != "reality":
        ib["external_domain"] = ""
        ib["external_port"] = ""

    if (ib.get("protocol") or "").lower() == "telegram":
        _validate_listener_port(int(ib.get("port") or 0), exclude_id=inbound_id)
    elif (ib.get("protocol") or "").lower() == "reality" or (ib.get("security") or "").lower() == "reality":
        _validate_listener_port(int(ib.get("port") or 0), exclude_id=inbound_id)

    await save_state()
    log_activity("inbound", f"اینباند «{ib.get('name', inbound_id)}» ویرایش شد", "info")
    # The Node inbound is a selector, never an Xray listener. Selection changes
    # are authoritative and immediately reconcile all dependent users.
    if inbound_id == "Node" and ib.get("system"):
        asyncio.create_task(refresh_node_inbound_configs(inbound_id))
    if (ib.get("protocol") or "").lower() != "node":
        asyncio.create_task(_xray_apply())
    # Telegram process lifecycle follows the final protocol, while also
    # shutting down a listener when an existing Telegram inbound is converted
    # into another protocol.
    _new_protocol = (ib.get("protocol") or "").lower()
    if _new_protocol == "telegram":
        asyncio.create_task(_restart_telegram_proxy(inbound_id))
    elif old_protocol == "telegram":
        asyncio.create_task(_stop_telegram_proxy(inbound_id))
    return {"ok": True}


@app.post("/api/inbounds/{inbound_id}/generate-reality-keys")
async def generate_inbound_reality_keys(inbound_id: str, _=Depends(require_auth)):
    """Generate Reality x25519 key pair + short_id + spiderx for an inbound."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        try:
            rs = ib.setdefault("reality_settings", {})
            rs["private_key"], rs["public_key"] = _xray_x25519_keypair()
            rs["short_id"] = secrets.token_hex(5)[:10]
            rs.setdefault("spiderx", "/")
            rs.setdefault("dest", "is1-ssl.mzstatic.com:443")
            ib["security"] = "reality"
            ib["protocol"] = "reality"
            if ib.get("network") not in ("tcp", "xhttp", "grpc"):
                ib["network"] = "tcp"
            if not rs.get("private_key") or not rs.get("public_key"):
                raise HTTPException(status_code=503, detail="X25519 Reality key generation failed")
        except ImportError:
            raise HTTPException(status_code=503, detail="cryptography not installed: pip install cryptography")
    await save_state()
    return {
        "ok": True,
        "public_key": rs["public_key"],
        "private_key": rs["private_key"],
        "short_id": rs["short_id"],
        "spiderx": rs.get("spiderx", "/"),
    }


@app.post("/api/inbounds/{inbound_id}/generate-short-id")
async def generate_inbound_short_id(inbound_id: str, _=Depends(require_auth)):
    """Generate only a new short_id for a Reality inbound (no key regeneration)."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        if ib.get("protocol") != "reality":
            raise HTTPException(status_code=400, detail="inbound is not Reality protocol")
        rs = ib.setdefault("reality_settings", {})
        rs["short_id"] = secrets.token_hex(5)[:10]
    await save_state()
    return {"ok": True, "short_id": rs["short_id"]}


@app.delete("/api/inbounds/{inbound_id}")
async def delete_inbound(inbound_id: str, _=Depends(require_auth)):
    """Delete an inbound."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.pop(inbound_id, None)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        # Protect system Inbound "Node" from deletion
        if inbound_id == "Node" or ib.get("system") is True:
            INBOUNDS[inbound_id] = ib
            raise HTTPException(status_code=400, detail="سیستمی قابل حذف نیست")
        name = ib.get("name", inbound_id)
    # Stop Telegram Proxy if this was a telegram inbound
    if (ib.get("protocol") or "").lower() == "telegram":
        await _stop_telegram_proxy(inbound_id)
    asyncio.create_task(save_state())
    log_activity("inbound", f"اینباند «{name}» حذف شد", "err")
    return {"ok": True, "deleted": inbound_id}


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
async def list_users(_=Depends(require_auth)):
    """List all users with traffic stats and status."""
    host = SETTINGS.get("domain") or get_host()
    async with USERS_LOCK:
        snap = dict(USERS)

    result = []
    for uid, u in snap.items():
        auto_check_user_expiry(u)
        protocol = u.get("protocol", "vless")
        result.append({
            "user_id": uid,
            "username": u.get("username"),
            "protocol": protocol,
            "transport_type": u.get("transport_type", "ws"),
            "path": u.get("path", ""),
            "proxy_ip": u.get("proxy_ip", ""),
            "proxy_country": "",
            "proxy_ips": u.get("proxy_ips", []),
            "proxy_countries": [],
            "proxy_ip_enabled": u.get("proxy_ip_enabled", False),
            "custom_ip_type": u.get("custom_ip_type", ""),
            "traffic_limit_bytes": u.get("traffic_limit_bytes", 0),
            "traffic_limit_fmt": "∞" if u.get("traffic_limit_bytes", 0) == 0 else fmt_bytes(u["traffic_limit_bytes"]),
            "traffic_used_bytes": u.get("traffic_used_bytes", 0),
            "traffic_used_fmt": fmt_bytes(u.get("traffic_used_bytes", 0)),
            "traffic_percent": round(u.get("traffic_used_bytes", 0) / max(u.get("traffic_limit_bytes", 1), 1) * 100, 1) if u.get("traffic_limit_bytes", 0) > 0 else 0,
            "expire_at": u.get("expire_at"),
            "concurrent_connections": u.get("concurrent_connections", 0),
            "created_at": u.get("created_at"),
            "status": u.get("status", "active"),
            "server": u.get("server", ""),
            "config_uuid": u.get("config_uuid"),
            "subscription_uuid": u.get("subscription_uuid"),
            "inbound_id": u.get("inbound_id"),
            "inbound_ids": u.get("inbound_ids") or (([u.get("inbound_id")] if u.get("inbound_id") else [])),
            "inbound_name": INBOUNDS.get(u.get("inbound_id", ""), {}).get("name", "") if u.get("inbound_id") else "",
            "config_url": f"https://{host}/api/users/{uid}/config",
            "qr_url": f"https://{host}/api/users/{uid}/qr",
            "subscription_url": f"https://{host}/link/{u.get('config_uuid')}",
            "subscription_type": "per-user",
            "connections": sum(1 for c in connections.values() if c.get("uuid") == u.get("config_uuid")),
            "node_configs": dict(u.get("node_configs") or {}),
            "node_sync_state": dict(u.get("node_sync_state") or {}),
            "node_traffic": dict(u.get("node_traffic") or {}),
            "node_traffic_used_bytes": int(u.get("node_traffic_used_bytes") or 0),
            "node_assignments": [
                {
                    "node_id": str(nid),
                    "name": (NODES.get(str(nid), {}) or {}).get("name") or str(nid),
                    "country": (NODES.get(str(nid), {}) or {}).get("country") or "",
                    "country_code": (NODES.get(str(nid), {}) or {}).get("country_code") or "",
                    "country_flag": _node_country_flag(NODES.get(str(nid), {}) or {}),
                    "public_ip": (NODES.get(str(nid), {}) or {}).get("public_ip") or (NODES.get(str(nid), {}) or {}).get("remote_ip") or "",
                    "status": _node_status(NODES.get(str(nid), {}) or {}),
                    "config": cfg,
                }
                for nid, cfg in (u.get("node_configs") or {}).items()
            ],
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"users": result}

async def _upsert_remote_user(body: dict) -> dict:
    """Create/update a replica user from a trusted SpiderPanel API-key call."""
    username = str(body.get("username") or "").strip()[:40]
    config_uuid = str(body.get("config_uuid") or "").strip()
    if not username or not config_uuid or not _is_valid_uuid(config_uuid):
        raise HTTPException(status_code=400, detail="username و valid config_uuid الزامی است")
    default_iid = find_default_tls_ws_inbound_id()
    if not default_iid:
        async with INBOUNDS_LOCK:
            default_iid = find_default_tls_ws_inbound_id()
            if not default_iid:
                default_iid = "default" if "default" not in INBOUNDS else generate_short_id()
                INBOUNDS[default_iid] = {
                    "name": DEFAULT_TLS_WS_INBOUND_NAME,
                    "protocol": "vless", "inbound_type": "transport",
                    "port": 443, "network": "ws", "security": "tls",
                    "domain": _safe_host(SETTINGS.get("domain"), get_host()),
                    "external_domain": "", "sni": "", "external_port": "",
                    "fingerprint": "chrome", "ws_settings": {"path": "/ws/{uuid}"},
                    "reality_settings": {}, "xhttp_settings": {},
                    "created_at": datetime.now().isoformat(),
                }
                asyncio.create_task(_xray_apply())
    traffic_limit_gb = float(body.get("traffic_limit_gb") or 0)
    traffic_limit_bytes = int(traffic_limit_gb * 1024 ** 3) if traffic_limit_gb > 0 else 0
    expire_at = body.get("expire_at")
    if expire_at is None:
        expire_days = int(body.get("expire_days") or 0)
        expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
    concurrent = max(0, int(body.get("concurrent_connections") or 0))
    status = str(body.get("status") or "active").lower()
    if status not in ("active", "disabled", "expired"):
        status = "active"
    path = f"/ws/{config_uuid}"
    subscription_uuid = str(body.get("subscription_uuid") or secrets.token_urlsafe(16))
    password = str(body.get("password") or secrets.token_urlsafe(18))
    reset_traffic = bool(body.get("reset_traffic"))
    from_node = str(body.get("from_node") or "").strip()

    async with USERS_LOCK:
        target_uid = next((uid for uid, u in USERS.items() if u.get("config_uuid") == config_uuid), None)
        if target_uid is None:
            target_uid = generate_short_id()
        existing = dict(USERS.get(target_uid) or {})
        traffic_used = 0 if reset_traffic else int(existing.get("traffic_used_bytes") or 0)
        USERS[target_uid] = {
            **existing,
            "username": username,
            "password_hash": hash_password(password),
            "protocol": "vless",
            "traffic_limit_bytes": traffic_limit_bytes,
            "traffic_used_bytes": traffic_used,
            "expire_at": expire_at,
            "concurrent_connections": concurrent,
            "created_at": existing.get("created_at") or datetime.now().isoformat(),
            "status": status,
            "server": existing.get("server") or "remote-node",
            "config_uuid": config_uuid,
            "subscription_uuid": subscription_uuid,
            "sni": "",
            "path": path,
            "transport_type": "ws",
            "inbound_id": default_iid,
            "inbound_ids": [default_iid],
            "node_sync_password": existing.get("node_sync_password") or secrets.token_urlsafe(18),
            "from_node": from_node,
            "synced_at": datetime.now().isoformat(),
            "node_configs": {},
            "node_sync_state": {},
            "node_traffic": {},
            "node_traffic_used_bytes": 0,
        }
    async with LINKS_LOCK:
        LINKS.setdefault(config_uuid, {})
        LINKS[config_uuid].update({
            "label": username,
            "limit_bytes": traffic_limit_bytes,
            "used_bytes": traffic_used,
            "created_at": USERS[target_uid]["created_at"],
            "active": status == "active",
            "expires_at": expire_at,
            "note": f"Remote Node: {from_node or 'unknown'}",
            "is_default": False,
            "sub_id": None,
            "protocol": "vless-ws",
            "path": path,
            "user_id": target_uid,
            "inbound_id": default_iid,
            "relay_enabled": True,
            "relay_inbound_id": default_iid,
        })
        PATH_INDEX[config_uuid] = config_uuid
        PATH_INDEX[path.lstrip("/")] = config_uuid
    await save_state()
    asyncio.create_task(_xray_apply())
    node_user = dict(USERS[target_uid])
    cfg = generate_user_config(target_uid, node_user, default_iid)
    host = SETTINGS.get("domain") or get_host()
    return {
        "ok": True,
        "user_id": target_uid,
        "username": username,
        "config_uuid": config_uuid,
        "subscription_uuid": subscription_uuid,
        "inbound_id": default_iid,
        "inbound_name": DEFAULT_TLS_WS_INBOUND_NAME,
        "traffic_used_bytes": traffic_used,
        "traffic_limit_bytes": traffic_limit_bytes,
        "status": status,
        "config": cfg,
        "config_url": f"https://{host}/api/users/{target_uid}/config",
    }


@app.post("/api/users")
async def create_user(request: Request, auth=Depends(require_replication_auth)):

    """Create a local user, or upsert a replica user for a trusted Node."""
    body = await request.json()
    if auth.get("kind") == "api_key":
        return await _upsert_remote_user(body)
    _raw_name = (body.get("username") or "").strip()[:40]
    _auto_name = not _raw_name
    username = _raw_name or f"user-{secrets.token_hex(3)}"
    password = str(body.get("password") or secrets.token_urlsafe(12))
    traffic_limit_gb = float(body.get("traffic_limit_gb") or 0)
    expire_days = int(body.get("expire_days") or 0)
    protocol = str(body.get("protocol") or "vless").lower()
    trojan_password = str(body.get("trojan_password") or (password if protocol == "trojan" else ""))
    _cc_raw = body.get("concurrent_connections")
    concurrent_connections = int(_cc_raw) if _cc_raw is not None else 0
    server = (body.get("server") or "IR-Tehran-01").strip()[:40]
    sni = str(body.get("sni") or "").strip()
    path_custom = str(body.get("path") or "").strip()
    transport_type = str(body.get("transport_type") or "").strip().lower()
    inbound_id = str(body.get("inbound_id") or "").strip() or None
    # Multi-inbound support: accept an array of inbound ids; keep the first as
    # the "primary" inbound_id for backward compatibility.
    raw_ids = body.get("inbound_ids") or []
    if isinstance(raw_ids, str):
        raw_ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
    inbound_ids = [str(x).strip() for x in raw_ids if str(x).strip()]
    if inbound_id and inbound_id not in inbound_ids:
        inbound_ids.insert(0, inbound_id)
    if inbound_ids:
        inbound_id = inbound_ids[0]
    proxy_ip = str(body.get("proxy_ip") or "").strip()
    proxy_ips = [str(x).strip() for x in (body.get("proxy_ips") or []) if str(x).strip()][:3]
    # Cloudflare Worker routing: when enabled + worker connected, the user's
    # configs are addressed to the worker domain with a /ws/{uuid} path.
    proxy_ip_enabled = bool(body.get("proxy_ip_enabled"))
    if proxy_ip_enabled and not WORKER.get("connected"):
        proxy_ip_enabled = False
    # Scanned custom-IP source: cf | railway ("" = off). Adds up to 10 extra
    # configs in the sub, addressed by scanned IPs on non-Reality inbounds.
    custom_ip_type = str(body.get("custom_ip_type") or "").strip().lower()
    if custom_ip_type not in _SCANNED_TYPES:
        custom_ip_type = ""
    # Per-inbound scanned-IP switches: {cf: [inboundIds], railway: [inboundIds]}
    # chosen in the create-user modal. Only these inbounds get scanned-IP configs.
    cii = body.get("custom_ip_inbounds") or {}
    if isinstance(cii, dict):
        custom_ip_inbounds = {
            "cf": [str(x) for x in (cii.get("cf") or [])],
            "railway": [str(x) for x in (cii.get("railway") or [])],
        }
    else:
        custom_ip_inbounds = {"cf": [], "railway": []}
    # Sni spoof for v2box: when enabled, TLS WS and Worker configs include
    # snispoofing JSON parameter. Does not apply to Reality/XHTTP Reality.
    sni_spoof_v2box = bool(body.get("sni_spoof_v2box"))

    # If transport_type not given explicitly, derive it from the primary inbound
    # (so an xhttp inbound produces an xhttp user).
    if not transport_type and inbound_id:
        async with INBOUNDS_LOCK:
            ib = INBOUNDS.get(inbound_id) or {}
        # For Reality inbounds, transport_type should be "reality" regardless of network
        if (ib.get("protocol") or "").lower() == "reality" or (ib.get("security") or "").lower() == "reality":
            transport_type = "reality"
        else:
            transport_type = str(ib.get("network") or "").strip().lower()
    if not transport_type:
        transport_type = "ws"

    if transport_type not in ("ws", "grpc", "tcp", "xhttp", "reality"):
        transport_type = "ws"

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol. Must be one of: {', '.join(USER_PROTOCOLS)}")
    if len(username) < 1:
        raise HTTPException(status_code=400, detail="Username is required")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if concurrent_connections < 0:
        concurrent_connections = 0

    user_id = generate_short_id()
    config_uuid = generate_uuid()
    subscription_uuid = secrets.token_urlsafe(16)
    traffic_limit_bytes = int(traffic_limit_gb * 1024 ** 3) if traffic_limit_gb > 0 else 0
    expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None

    # Auto-generate Reality key pair if protocol is reality and no key exists
    if protocol == "reality":
        async with SETTINGS_LOCK:
            reality = SETTINGS.get("reality", {})
            if not reality.get("public_key"):
                try:
                    reality["private_key"], reality["public_key"] = _xray_x25519_keypair()
                    reality.setdefault("short_id", secrets.token_hex(4)[:10])
                    reality.setdefault("dest", "is1-ssl.mzstatic.com:443")
                    reality.setdefault("sni", "is1-ssl.mzstatic.com")
                    reality.setdefault("spiderx", "/")
                    reality.setdefault("fingerprint", "chrome")
                    reality.setdefault("external_port", 443)
                    SETTINGS["reality"] = reality
                    asyncio.create_task(save_state())
                    log_activity("settings", "کلیدهای Reality خودکار ساخته شد", "ok")
                except ImportError:
                    pass

    async with USERS_LOCK:
        # Check for duplicate username (retry auto-generated names on collision)
        for existing in USERS.values():
            if existing.get("username") == username:
                if _auto_name:
                    for _ in range(5):
                        username = f"user-{secrets.token_hex(3)}"
                        if not any(u.get("username") == username for u in USERS.values()):
                            break
                    else:
                        raise HTTPException(status_code=409, detail="Username already exists")
                    break
                raise HTTPException(status_code=409, detail="Username already exists")

        # Determine the path based on the inbound type, not just transport_type
        # WS/Worker inbound -> /ws/{config_uuid}; XHTTP/Reality use their own path.
        primary_inbound = INBOUNDS.get(inbound_id) if inbound_id else None
        primary_inbound_proto = (primary_inbound.get("protocol") if primary_inbound else "").lower()
        primary_inbound_network = (primary_inbound.get("network") if primary_inbound else "").lower()
        worker_selected = any(((INBOUNDS.get(iid) or {}).get("protocol") or "").lower() == "worker" for iid in inbound_ids)
        relay_default_id = find_default_tls_ws_inbound_id()
        relay_enabled = bool(relay_default_id and relay_default_id in inbound_ids)

        if primary_inbound_proto == "worker" or worker_selected:
            # Managed Worker owns this exact route; never let a custom/legacy path diverge.
            path = f"/ws/{config_uuid}"
        elif primary_inbound_proto == "reality" and primary_inbound_network == "xhttp":
            # Native Xray XHTTP has one shared base path on the inbound. Xray
            # handles the per-session UUID suffix internally; never synthesize
            # /uuid here because it would diverge from xhttpSettings.path.
            path = str((primary_inbound.get("xhttp_settings") or {}).get("path") or "/").strip()
            if not path.startswith("/") or "?" in path or "#" in path:
                path = "/"
        elif primary_inbound_network == "xhttp":
            # FastAPI XHTTP relay uses a UUID-bearing route.
            path = f"/xhttp-siz10/stream-up/{config_uuid}"
        else:
            # Default WS TLS inbound uses /ws/{config_uuid}
            path = f"/ws/{config_uuid}"

        path = path_custom if path_custom else path
        if relay_enabled:
            # The FastAPI relay is registered only at /ws/{config_uuid}.
            # Never allow a custom/legacy path to break the exact default TLS+WS link.
            path = f"/ws/{config_uuid}"

        USERS[user_id] = {
            "username": username,
            "password_hash": hash_password(password),
            "protocol": protocol,
            "traffic_limit_bytes": traffic_limit_bytes,
            "traffic_used_bytes": 0,
            "expire_at": expire_at,
            "concurrent_connections": concurrent_connections,
            "created_at": datetime.now().isoformat(),
            "status": "active",
            "server": server,
            "config_uuid": config_uuid,
            "subscription_uuid": subscription_uuid,
            "trojan_password": trojan_password,
            "sni": sni,
            "proxy_ip": proxy_ip,
            "proxy_ips": proxy_ips,
            "proxy_ip_enabled": proxy_ip_enabled,
            "custom_ip_type": custom_ip_type,
            "custom_ip_inbounds": custom_ip_inbounds,
            "sni_spoof_v2box": sni_spoof_v2box,
            "inbound_id": inbound_id,
            "inbound_ids": inbound_ids,
            "path": path,
            "transport_type": transport_type,
            "telegram_secret": (
                derive_secret_from_uuid(config_uuid)
                if any((INBOUNDS.get(_iid, {}).get("protocol") or "").lower() == "telegram" for _iid in inbound_ids)
                else ""
            ),
            "node_sync_password": secrets.token_urlsafe(18),
            "node_configs": {},
            "node_sync_state": {},
            "node_traffic": {},
            "node_traffic_used_bytes": 0,
        }
        _path = USERS[user_id].get("path", "").strip().lstrip("/")

    # Auto-create matching link so relay can find it
    async with LINKS_LOCK:
        link_xhttp = {}
        # Determine the link protocol based on transport_type for correct config generation
        # vless-ws for WS, xhttp-{mode} for XHTTP
        link_protocol = protocol
        if transport_type == "ws" or transport_type == "vless-ws":
            link_protocol = "vless-ws"
        elif transport_type == "xhttp":
            link_protocol = "xhttp-stream-up"  # default mode
        elif transport_type == "reality":
            link_protocol = "reality"
        elif transport_type == "worker":
            link_protocol = "worker"

        if transport_type == "xhttp":
            link_xhttp = {
                "xPaddingBytes": "100-1000",
                "mode": "auto",
                "scMaxEachPostBytes": "1000000",
            }
        LINKS[config_uuid] = {
            "label": username, "limit_bytes": traffic_limit_bytes, "used_bytes": 0,
            "created_at": datetime.now().isoformat(), "active": True, "expires_at": expire_at,
            "note": f"لینک کاربر {username}", "is_default": False, "sub_id": None,
            "protocol": "vless-ws" if relay_enabled else link_protocol,
            "transport_type": transport_type, "xhttp_settings": link_xhttp, "path": _path,
            "user_id": user_id, "inbound_id": inbound_id, "relay_enabled": relay_enabled,
            "relay_inbound_id": relay_default_id if relay_enabled else None,
        }
        # Register uuid in PATH_INDEX for backward compat (old random-path clients)
        # config_uuid IS the path under /ws/{config_uuid}
        PATH_INDEX[config_uuid] = config_uuid
        if _path:
            PATH_INDEX[_path.lstrip("/")] = config_uuid

    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{username}» با پروتکل {protocol} ساخته شد", "ok")
    # If the user picked the worker inbound, sync them to the worker so VLESS
    # auth + quotas work on the Cloudflare side too.
    if WORKER.get("connected") and inbound_ids:
        wid = next((i for i, ib in INBOUNDS.items() if (ib.get("protocol") or "").lower() == "worker"), None)
        if wid and wid in inbound_ids:
            asyncio.create_task(_worker_sync_users())
    # Generate and persist telegram_secret if user has a Telegram inbound
    if inbound_ids:
        has_tg = any(
            (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"
            for i in inbound_ids
        )
        if has_tg:
            # telegram_proxy merged into main.py
            async with USERS_LOCK:
                u = USERS.get(user_id)
                if u:
                    current = str(u.get("telegram_secret") or "").strip().lower()
                    # mtprotoproxy 1.0.6 expects exactly 32 hex characters.
                    if not re.fullmatch(r"[0-9a-f]{32}", current):
                        u["telegram_secret"] = derive_secret_from_uuid(config_uuid)
            asyncio.create_task(save_state())
            # The inbound may have been created before this user existed.
            # Rebuild its secret list and restart the listener now.
            for _tg_iid in [i for i in inbound_ids if (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"]:
                asyncio.create_task(_restart_telegram_proxy(_tg_iid))
    # Reconcile the authoritative union of Node selections across all user inbounds.
    if _selected_node_ids_for_user(USERS[user_id]):
        asyncio.create_task(_sync_user_to_selected_nodes(user_id, dict(USERS[user_id])))
    host = SETTINGS.get("domain") or get_host()
    asyncio.create_task(_xray_apply())  # refresh Xray clients after user change
    return {
        "user_id": user_id,
        **USERS[user_id],
        "password_hash": None,
        "config_url": f"https://{host}/api/users/{user_id}/config",
        "qr_url": f"https://{host}/api/users/{user_id}/qr",
        "subscription_url": f"https://{host}/link/{USERS[user_id].get('config_uuid')}",
        "config": generate_user_config(user_id, USERS[user_id], inbound_id),
    }

@app.patch("/api/users/{user_id}/toggle")
async def toggle_user(user_id: str, _=Depends(require_auth)):
    """Enable or disable a user."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        old = u.get("status", "active")
        if old == "disabled":
            u["status"] = "active"
        else:
            u["status"] = "disabled"
        new_status = u["status"]

    # Sync link active state
    config_uuid = u.get("config_uuid")
    if config_uuid:
        async with LINKS_LOCK:
            if config_uuid in LINKS:
                LINKS[config_uuid]["active"] = (new_status == "active")

    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{u['username']}» {'غیرفعال' if new_status == 'disabled' else 'فعال'} شد", "ok" if new_status == "active" else "warn")
    # Reflect enable/disable on the worker side too.
    if WORKER.get("connected") and _user_uses_worker_inbound(u):
        asyncio.create_task(_worker_sync_users())
    if _selected_node_ids_for_user(u):
        asyncio.create_task(_sync_user_to_selected_nodes(user_id, dict(u)))
    return {"ok": True, "user_id": user_id, "status": new_status}

@app.patch("/api/users/{user_id}/reset")
async def reset_user_traffic(user_id: str, _=Depends(require_auth)):
    """Reset a user's traffic usage to zero."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        u["traffic_used_bytes"] = 0
        username = u.get("username", user_id)
    # Reset the worker-side usage too, so the quota reflects the reset immediately.
    if WORKER.get("connected") and _user_uses_worker_inbound(u):
        asyncio.create_task(_worker_sync_users())
    for _tg_iid in [i for i in (u.get("inbound_ids") or []) if (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"]:
        asyncio.create_task(_restart_telegram_proxy(_tg_iid))
    asyncio.create_task(save_state())
    if _selected_node_ids_for_user(u):
        asyncio.create_task(_sync_user_to_selected_nodes(user_id, dict(u), force_reset=True))
    log_activity("user", f"مصرف کاربر «{username}» ریست شد", "info")
    return {"ok": True, "user_id": user_id, "traffic_used_bytes": 0}

@app.patch("/api/users/{user_id}")
async def edit_user(user_id: str, request: Request, _=Depends(require_auth)):
    """Edit an existing user."""
    body = await request.json()
    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")
        u = USERS[user_id]
        old_telegram_inbound_ids = {
            str(i) for i in (u.get("inbound_ids") or [])
            if (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"
        }
        if "username" in body:
            _new_name = str(body["username"]).strip()[:40]
            if not _new_name:
                raise HTTPException(status_code=400, detail="Username cannot be empty")
            if any(oid != user_id and ou.get("username") == _new_name for oid, ou in USERS.items()):
                raise HTTPException(status_code=409, detail="Username already exists")
            u["username"] = _new_name
        if "traffic_limit_gb" in body:
            gb = float(body["traffic_limit_gb"])
            u["traffic_limit_bytes"] = int(gb * 1024**3) if gb > 0 else 0
        if "expire_days" in body:
            days = int(body["expire_days"])
            u["expire_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
        if "protocol" in body:
            p = str(body["protocol"]).lower()
            if p in USER_PROTOCOLS:
                u["protocol"] = p
        if "status" in body:
            u["status"] = str(body["status"])
        if "sni" in body:
            u["sni"] = str(body["sni"]).strip()
        if "path" in body:
            # Update PATH_INDEX when path changes. The exact default TLS+WS relay
            # always uses /ws/{config_uuid}, regardless of a custom legacy path.
            old_path = (u.get("path") or "").strip().lstrip("/")
            new_path = str(body["path"]).strip().lstrip("/")
            u["path"] = new_path
            if old_path:
                PATH_INDEX.pop(old_path, None)
            if new_path:
                PATH_INDEX[new_path] = u.get("config_uuid", user_id)
        if "transport_type" in body:
            u["transport_type"] = str(body["transport_type"]).strip().lower()
        if "concurrent_connections" in body:
            u["concurrent_connections"] = max(0, int(body["concurrent_connections"]))
        if "reset_traffic" in body and body["reset_traffic"]:
            u["traffic_used_bytes"] = 0
        if "custom_ip_type" in body:
            ct = str(body["custom_ip_type"] or "").strip().lower()
            u["custom_ip_type"] = ct if ct in _SCANNED_TYPES else ""
        if "sni_spoof_v2box" in body:
            u["sni_spoof_v2box"] = bool(body["sni_spoof_v2box"])
        if "fake_sni" in body:
            u["fake_sni"] = str(body["fake_sni"] or "").strip()
        if "spoof_ip" in body:
            u["spoof_ip"] = str(body["spoof_ip"] or "").strip()
        if "proxy_ip_enabled" in body:
            en = bool(body["proxy_ip_enabled"])
            u["proxy_ip_enabled"] = en and WORKER.get("connected")
        # proxy_country/proxy_countries removed - no longer used
        if "inbound_ids" in body:
            raw_ids = [str(x).strip() for x in (body["inbound_ids"] or []) if str(x).strip()]
            valid = [i for i in raw_ids if i in INBOUNDS]
            u["inbound_ids"] = valid
            if valid:
                u["inbound_id"] = valid[0]
            else:
                u.pop("inbound_id", None)
        # Ensure a Telegram secret exists whenever the edited user has a Telegram inbound.
        if any((INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram" for i in (u.get("inbound_ids") or [])):
            # telegram_proxy merged into main.py
            cur_secret = str(u.get("telegram_secret") or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{32}", cur_secret):
                u["telegram_secret"] = derive_secret_from_uuid(u.get("config_uuid", user_id))

        # Keep the relay link exactly in sync with the selected inbound list.
        _relay_iid = find_default_tls_ws_inbound_id()
        _selected_iids = list(u.get("inbound_ids") or [])
        _relay_on = bool(_relay_iid and _relay_iid in _selected_iids)
        _link = LINKS.get(u.get("config_uuid"))
        if _link is not None:
            _link["user_id"] = user_id
            _link["inbound_id"] = (u.get("inbound_id") or (_selected_iids[0] if _selected_iids else None))
            _link["relay_enabled"] = _relay_on
            _link["relay_inbound_id"] = _relay_iid if _relay_on else None
            if _relay_on:
                _link["protocol"] = "vless-ws"
                _link["path"] = f"/ws/{u.get('config_uuid')}"
                u["path"] = f"/ws/{u.get('config_uuid')}"
    # If the user uses the worker inbound, push updated volume/expiry to the worker.
    if WORKER.get("connected") and _user_uses_worker_inbound(u):
        asyncio.create_task(_worker_sync_users())
    if _selected_node_ids_for_user(u) or u.get("node_configs"):
        asyncio.create_task(_sync_user_to_selected_nodes(user_id, dict(u)))
    asyncio.create_task(save_state())
    new_telegram_inbound_ids = {
        str(i) for i in (u.get("inbound_ids") or [])
        if (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"
    }
    # Restart all affected listeners, including a Telegram inbound the user
    # was removed from; otherwise the old secret remains live until reboot.
    for _tg_iid in sorted(old_telegram_inbound_ids | new_telegram_inbound_ids):
        asyncio.create_task(_restart_telegram_proxy(_tg_iid))
    asyncio.create_task(_xray_apply())
    return {"ok": True, "user_id": user_id}

@app.get("/api/users/config/{config_uuid}")
async def get_user_config_metadata(config_uuid: str, _=Depends(require_auth)):
    """Return non-secret config metadata, including per-Node generated configs."""
    async with USERS_LOCK:
        user = next((dict(u) for u in USERS.values() if str(u.get("config_uuid") or "") == str(config_uuid)), None)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    node_configs = dict(user.get("node_configs") or {})
    node_details = []
    for nid, cfg in node_configs.items():
        node = NODES.get(str(nid)) or {}
        node_details.append({
            "node_id": str(nid),
            "name": node.get("name") or str(nid),
            "country": node.get("country") or "",
            "country_code": node.get("country_code") or "",
            "country_flag": _node_country_flag(node),
            "public_ip": node.get("public_ip") or node.get("remote_ip") or "",
            "status": _node_status(node),
            "config": cfg,
            "sync": (user.get("node_sync_state") or {}).get(str(nid)) or {},
        })
    return {"ok": True, "config_uuid": config_uuid, "node_configs": node_configs, "nodes": node_details}


@app.get("/api/users/{user_id}")
async def get_user(user_id: str, auth=Depends(require_replication_auth)):
    """Get user details locally or a minimal traffic/config snapshot for a Node."""
    async with USERS_LOCK:
        target_id = user_id if user_id in USERS else next((uid for uid, u in USERS.items() if str(u.get("config_uuid") or "") == str(user_id)), None)
        if target_id is None:
            raise HTTPException(status_code=404, detail="user not found")
        u = dict(USERS[target_id])
    if auth.get("kind") == "api_key":
        return {
            "ok": True, "user_id": target_id, "username": u.get("username"),
            "config_uuid": u.get("config_uuid"), "status": u.get("status", "active"),
            "traffic_used_bytes": int(u.get("traffic_used_bytes") or 0),
            "traffic_limit_bytes": int(u.get("traffic_limit_bytes") or 0),
            "expire_at": u.get("expire_at"), "concurrent_connections": int(u.get("concurrent_connections") or 0),
        }
    u["user_id"] = target_id
    u["password_hash"] = None
    host = SETTINGS.get("domain") or get_host()
    u["config"] = generate_user_config(target_id, u, u.get("inbound_id"))
    u["config_url"] = f"https://{host}/api/users/{target_id}/config"
    u["qr_url"] = f"https://{host}/api/users/{target_id}/qr"
    u["subscription_url"] = f"https://{host}/link/{u.get('config_uuid')}"
    u["traffic_used_fmt"] = fmt_bytes(u.get("traffic_used_bytes", 0))
    u["traffic_limit_fmt"] = "∞" if u.get("traffic_limit_bytes", 0) == 0 else fmt_bytes(u.get("traffic_limit_bytes", 0))
    return u


async def _delete_user_from_nodes_after_local_delete(user: dict, node_ids: list[str]) -> dict:
    cuuid = str(user.get("config_uuid") or "")
    if not cuuid:
        return {"ok": True, "results": []}
    async with NODES_LOCK:
        nodes = {nid: dict(NODES[nid]) for nid in node_ids if nid in NODES}
    results = []
    for nid, node in nodes.items():
        ok, detail = await _remote_delete_user(node, cuuid)
        if not ok:
            _pending_delete_add(nid, cuuid, str(user.get("username") or ""))
        else:
            _pending_delete_remove(nid, cuuid)
        results.append({"node_id": nid, "ok": ok, "detail": detail})
    await save_state()
    return {"ok": True, "results": results}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, auth=Depends(require_replication_auth)):
    """Delete a user locally and best-effort from every previously-synced Node."""
    async with USERS_LOCK:
        target_uid = user_id if user_id in USERS else next((uid for uid, u in USERS.items() if str(u.get("config_uuid") or "") == str(user_id)), None)
        if target_uid is None:
            raise HTTPException(status_code=404, detail="user not found")
        u = dict(USERS[target_uid])
        username = u.get("username", target_uid)
        config_uuid = u.get("config_uuid")
        node_ids = set(str(x) for x in (u.get("node_configs") or {}).keys())
        node_ids.update(_selected_node_ids_for_user(u))
        telegram_inbound_ids = [
            str(i) for i in (u.get("inbound_ids") or [])
            if (INBOUNDS.get(i, {}).get("protocol") or "").lower() == "telegram"
        ]
        if auth.get("kind") == "api_key":
            # A remote Node deletion must not cascade back to this panel's other Nodes.
            node_ids = set()
        old_path = (u.get("path") or "").strip().lstrip("/")
        if old_path:
            PATH_INDEX.pop(old_path, None)
        if config_uuid:
            PATH_INDEX.pop(config_uuid, None)
        USERS.pop(target_uid, None)
    if config_uuid:
        async with LINKS_LOCK:
            LINKS.pop(config_uuid, None)
    if auth.get("kind") == "session" and config_uuid:
        # Best-effort remote cleanup; local deletion never waits for remote success.
        asyncio.create_task(_delete_user_from_nodes_after_local_delete(dict(u), list(node_ids)))
    if WORKER.get("connected") and _user_uses_worker_inbound(u):
        asyncio.create_task(_worker_sync_users())
    # Remove the deleted user's MTProxy secret from the live listener immediately.
    for _tg_iid in telegram_inbound_ids:
        asyncio.create_task(_restart_telegram_proxy(_tg_iid))
    asyncio.create_task(save_state())
    asyncio.create_task(_xray_apply())
    log_activity("user", f"کاربر «{username}» حذف شد", "err")
    return {"ok": True, "deleted": target_uid, "config_uuid": config_uuid}

@app.get("/api/users/{user_id}/config")
async def get_user_config(user_id: str, _=Depends(require_auth)):
    """Return the protocol config string for a user."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        _selected = list(u.get("inbound_ids") or [])
        _default = find_default_tls_ws_inbound_id()
        _config_iid = _default if _default in _selected else (u.get("inbound_id") if u.get("inbound_id") in _selected else (_selected[0] if _selected else u.get("inbound_id")))
        config = generate_user_config(user_id, u, _config_iid)
        username = u.get("username")
        protocol = u.get("protocol")
    host = SETTINGS.get("domain") or get_host()
    return {
        "user_id": user_id,
        "username": username,
        "protocol": protocol,
        "config": config,
        "config_url": f"https://{host}/api/users/{user_id}/config",
        "qr_url": f"https://{host}/api/users/{user_id}/qr",
        "subscription_url": f"https://{host}/link/{u.get('config_uuid')}",
            "subscription_type": "per-user",
    }

@app.get("/api/users/{user_id}/qr")
async def get_user_qr(user_id: str, _=Depends(require_auth)):
    """Return a QR code PNG for the user's subscription URL (domain/link/uuid)."""
    if not QR_AVAILABLE:
        raise HTTPException(status_code=501, detail="QR code generation not available (install qrcode and Pillow)")

    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        config_uuid = u.get("config_uuid", "")
        username = u.get("username", user_id)

    if not config_uuid:
        raise HTTPException(status_code=404, detail="user has no config_uuid")

    host = SETTINGS.get("domain") or get_host()
    sub_url = f"https://{host}/link/{config_uuid}"

    qr = qrcode.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(sub_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png",
                    headers={"Content-Disposition": f"inline; filename={username}.png"})

@app.get("/api/users/{user_id}/subscription")
async def get_user_subscription(user_id: str, _=Depends(require_auth)):
    """Return the subscription URL for a user."""
    host = SETTINGS.get("domain") or get_host()
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        sub_uuid = u.get("config_uuid") or u.get("subscription_uuid")
        username = u.get("username")

    if not sub_uuid:
        raise HTTPException(status_code=404, detail="no subscription configured")

    selected_ids = list(u.get("inbound_ids") or [])
    configs = []
    for iid in selected_ids:
        if is_node_control_inbound(iid):
            continue
        cfg = generate_user_config(user_id, u, iid)
        if cfg:
            configs.append(cfg)
    configs.extend(node_subscription_configs(u))
    if not configs:
        fallback_iid = find_default_tls_ws_inbound_id() if find_default_tls_ws_inbound_id() in selected_ids else (u.get("inbound_id") if u.get("inbound_id") and not is_node_control_inbound(u.get("inbound_id")) else None)
        cfg = generate_user_config(user_id, u, fallback_iid) if fallback_iid else ""
        if cfg:
            configs.append(cfg)
    content = base64.b64encode("\n".join(configs).encode()).decode()

    return {
        "user_id": user_id,
        "username": username,
        "subscription_uuid": sub_uuid,
        "subscription_url": f"https://{host}/link/{sub_uuid}",
        "encoded_config": content,
        "configs": configs,
    }


# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    """Pars Space branded public subscription page.

    The page is static and reads its live data from /api/public/sub/{uuid_key}.
    Keeping the HTML here avoids a fragile optional public_page.py dependency.
    """
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>اشتراک پیدا نشد</h2>", status_code=404)
    static_sub = _os.path.join(_STATIC_DIR, "sub.html")
    return FileResponse(static_sub)

@app.post("/api/tools/test-config")
async def test_config(request: Request, _=Depends(require_auth)):
    """Basic reachability test for a generated client config.

    This validates the URL shape and checks the configured host/port from the
    server side. It does not claim that a full Xray handshake succeeded.
    """
    from urllib.parse import urlparse
    import ssl as _ssl
    body = await request.json()
    raw = str(body.get("config") or "").strip()
    if not raw or not re.match(r"^(vless|vmess|trojan)://", raw, re.I):
        raise HTTPException(status_code=400, detail="A generated VLESS/VMess/Trojan config is required")
    u = urlparse(raw)
    host = u.hostname
    port = int(u.port or 443)
    if not host or not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Config host/port is invalid")
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        latency = round((time.perf_counter() - start) * 1000, 1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"ok": True, "host": host, "port": port, "latency_ms": latency, "message": f"TCP reachable · {latency} ms"}
    except Exception as exc:
        latency = round((time.perf_counter() - start) * 1000, 1)
        return {"ok": False, "host": host, "port": port, "latency_ms": latency, "message": f"TCP check failed: {str(exc)[:180]}"}

@app.get("/api/tools/speed-test")
async def speed_test(bytes: int = 524288, _=Depends(require_auth)):
    """Return a bounded uncached payload for a browser-side throughput test."""
    size = max(65536, min(int(bytes or 524288), 2 * 1024 * 1024))
    return Response(content=b"0" * size, media_type="application/octet-stream", headers={"Cache-Control":"no-store, no-cache, must-revalidate", "X-Pars-Space-Speed-Test":str(size)})


# ── Authenticated Linux terminal ────────────────────────────────────────────
@app.get("/api/terminal/info")
async def terminal_info(_=Depends(require_auth)):
    import getpass, platform, shutil
    return {
        "ok": True,
        "enabled": os.environ.get("PARS_TERMINAL_ENABLED", "1").lower() not in ("0", "false", "no"),
        "shell": "/bin/bash" if Path("/bin/bash").exists() else "/bin/sh",
        "user": getpass.getuser(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "bash": shutil.which("bash") or "",
    }

@app.post("/api/terminal/exec")
async def terminal_exec(request: Request, _=Depends(require_auth)):
    """Run an authenticated Linux shell command as the panel service user.

    This is deliberately an admin-only terminal, not an anonymous remote shell.
    It never grants sudo/root and caps execution/output so a forgotten command
    cannot pin the web worker indefinitely.
    """
    if os.environ.get("PARS_TERMINAL_ENABLED", "1").lower() in ("0", "false", "no"):
        raise HTTPException(status_code=403, detail="terminal disabled")
    body = await request.json()
    command = str(body.get("command") or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="command is required")
    if len(command) > 4000:
        raise HTTPException(status_code=400, detail="command too long")
    cwd = str(body.get("cwd") or os.getcwd()).strip()
    if not Path(cwd).is_dir():
        cwd = os.getcwd()
    shell = "/bin/bash" if Path("/bin/bash").exists() else "/bin/sh"
    try:
        proc = await asyncio.create_subprocess_exec(
            shell, "-lc", command, cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            raw = await asyncio.wait_for(proc.stdout.read(24000), timeout=30)
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
            except Exception:
                pass
            raw = await proc.stdout.read(24000)
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except Exception:
            pass
        text_out = raw.decode("utf-8", errors="replace")
        if len(text_out) > 24000:
            text_out = text_out[:24000] + "\n… output truncated …"
        return {"ok": proc.returncode == 0 and not timed_out, "code": proc.returncode, "timed_out": timed_out, "cwd": cwd, "output": text_out}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)[:300])

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        # /link/{config_uuid} is also a real per-user subscription. The same
        # graphical Pars Space page is used for both group and personal links.
        try:
            data = await _build_subscription_data_by_uuid(uuid_key)
            data["name"] = data.get("username") or "Pars Space"
            data["desc"] = "Personal Pars Space subscription"
            data["sub_url"] = f"https://{SETTINGS.get('domain') or get_host()}/link/{uuid_key}"
            data["total_used_fmt"] = data.get("traffic_used_fmt", "0 B")
            data["active_connections"] = sum(1 for c in connections.values() if c.get("uuid") == uuid_key)
            return data
        except HTTPException:
            raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = SETTINGS.get("domain") or get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)
    async with USERS_LOCK:
        snap_users = dict(USERS)

    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
            "expires_at": link.get("expires_at"),
            "vless_link": (generate_user_config(link.get("user_id"), snap_users.get(link.get("user_id"), {}), link.get("inbound_id")) if link.get("user_id") and snap_users.get(link.get("user_id")) else generate_vless_link(lid, host, remark=f"Pars-{link['label']}", protocol=proto)),
            "sub_url": f"https://{host}/link/{lid}",
            "connections": conn_count,
        })

    total_used = sum(l["used_bytes"] for l in links_out)
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
    }

# ══════════════════════════════════════════════════════════════════════════════
# PARS SPACE API v1
# Thin public contract over the existing local data model. The dashboard uses
# this namespace only, so its frontend no longer depends on Spider-named routes.
# ══════════════════════════════════════════════════════════════════════════════
PARS_API_KEY = str(SETTINGS.get("pars_api_key") or "").strip()
if not PARS_API_KEY.startswith("psp_"):
    PARS_API_KEY = "psp_" + secrets.token_urlsafe(24)
    SETTINGS["pars_api_key"] = PARS_API_KEY
    SETTINGS.setdefault("pars_panel_id", "pars_" + secrets.token_hex(6))

async def _pars_v1_auth(request: Request):
    key = str(request.headers.get("x-pars-key") or "").strip()
    authz = str(request.headers.get("authorization") or "")
    if authz.lower().startswith("bearer "):
        key = authz[7:].strip()
    if key and secrets.compare_digest(key, str(SETTINGS.get("pars_api_key") or PARS_API_KEY)):
        return {"kind":"api_key"}
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return {"kind":"session"}
    raise HTTPException(status_code=401, detail="Pars API authentication required")

def _pars_host():
    return SETTINGS.get("domain") or get_host()

@app.get("/api/pars/v1/identity")
async def pars_identity(request: Request):
    await _pars_v1_auth(request)
    return {"panel_id": SETTINGS.get("pars_panel_id") or "pars-local", "name":"Pars Space", "version":"1.0"}

@app.get("/api/pars/v1/health")
async def pars_health(request: Request):
    await _pars_v1_auth(request)
    return {"ok":True,"status":"online","host":_pars_host(),"uptime":uptime()}

@app.get("/api/pars/v1/stats")
async def pars_stats(request: Request):
    await _pars_v1_auth(request)
    async with USERS_LOCK: users=list(USERS.values())
    async with INBOUNDS_LOCK: ibs=list(INBOUNDS.values())
    async with LINKS_LOCK: links=list(LINKS.values())
    return {"active_users":sum(1 for u in users if is_user_allowed(u)),"connections":len(connections),"inbounds":len(ibs),"total_traffic":sum(int(u.get("traffic_used_bytes") or 0) for u in users),"total_traffic_fmt":fmt_bytes(sum(int(u.get("traffic_used_bytes") or 0) for u in users)),"subscriptions":len(links)}

@app.get("/api/pars/v1/users")
async def pars_users(request: Request):
    await _pars_v1_auth(request)
    return await list_users()

@app.post("/api/pars/v1/users")
async def pars_create_user(request: Request):
    await _pars_v1_auth(request)
    return await create_user(request, {"kind":"session"})

@app.get("/api/pars/v1/inbounds")
async def pars_inbounds(request: Request):
    await _pars_v1_auth(request)
    return await list_inbounds({"kind":"session"})

@app.post("/api/pars/v1/inbounds")
async def pars_create_inbound(request: Request):
    await _pars_v1_auth(request)
    return await create_inbound(request, {"kind":"session"})

@app.get("/api/pars/v1/subscriptions")
async def pars_subscriptions(request: Request):
    await _pars_v1_auth(request)
    return await list_subs()

@app.post("/api/pars/v1/subscriptions")
async def pars_create_subscription(request: Request):
    await _pars_v1_auth(request)
    return await create_sub(request, {"kind":"session"})

@app.get("/api/pars/v1/activity")
async def pars_activity(request: Request):
    await _pars_v1_auth(request)
    rows = list(error_logs)[-50:]
    return {"activity":[{"message":str(x.get("message") or x.get("error") or x),"created_at":x.get("time") or x.get("created_at") or ""} for x in reversed(rows)]}

@app.get("/api/pars/v1/nodes")
async def pars_nodes(request: Request):
    await _pars_v1_auth(request)
    return await list_nodes()

@app.post("/api/pars/v1/nodes/connect")
async def pars_connect_node(request: Request):
    await _pars_v1_auth(request)
    body=await request.json()
    # The current remote-node contract remains compatible with existing panels.
    return await add_node_from_pars(body)

async def add_node_from_pars(body: dict):
    payload = dict(body)
    payload["api_key"] = payload.get("api_key") or payload.get("pars_api_key")
    # Existing node storage currently uses spdr_ credentials. Accept psp_ at the
    # Pars Space boundary and keep a local compatibility credential internally.
    key = str(payload.get("api_key") or "")
    if key.startswith("psp_"):
        payload["api_key"] = "spdr_" + secrets.token_urlsafe(24)
    class _Req:
        async def json(self): return payload
    return await add_node(_Req(), None)

@app.post("/api/pars/v1/nodes/{node_id}/ping")
async def pars_node_ping(node_id: str, request: Request):
    await _pars_v1_auth(request)
    return await node_health(node_id)

@app.post("/api/pars/v1/nodes/{node_id}/sync")
async def pars_node_sync(node_id: str, request: Request):
    await _pars_v1_auth(request)
    # Reuse the existing full-node refresh/sync reconciliation.
    result = await refresh_node(node_id)
    return {"ok":True,"sent":0,"total":0,"node":result.get("node",{})}

@app.delete("/api/pars/v1/nodes/{node_id}")
async def pars_node_delete(node_id: str, request: Request):
    await _pars_v1_auth(request)
    return await delete_node(node_id)

@app.get("/api/pars/v1/credentials")
async def pars_credentials(request: Request):
    await _pars_v1_auth(request)
    return {"api_key":SETTINGS.get("pars_api_key") or PARS_API_KEY,"panel_id":SETTINGS.get("pars_panel_id")}

@app.post("/api/pars/v1/credentials/regenerate")
async def pars_regenerate_credentials(request: Request):
    await _pars_v1_auth(request)
    new_key="psp_"+secrets.token_urlsafe(24)
    SETTINGS["pars_api_key"]=new_key
    await save_state()
    return {"api_key":new_key,"panel_id":SETTINGS.get("pars_panel_id")}

# ── HTML Pages (SPA) ───────────────────────────────────────────────────────
import os as _os
_STATIC_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "static")
_os.makedirs(_STATIC_DIR, exist_ok=True)

# Serve static assets (mp3/png/jpg/index.html for the SPA). This was missing, so
# the panel music + background images 404'd.
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return FileResponse(_os.path.join(_STATIC_DIR, "login.html"))

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return FileResponse(_os.path.join(_STATIC_DIR, "index.html"))

@app.get("/spider", response_class=HTMLResponse)
async def spider_panel(request: Request):
    return RedirectResponse(url="/dashboard", status_code=307)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")


# ══════════════════════════════════════════════════════════════════════════════
# USER SUBSCRIPTION DATA API (Public, UUID only)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/sub/{uuid_key}")
async def api_user_sub(uuid_key: str):
    """Return public subscription data by config UUID only."""
    return await _build_subscription_data_by_uuid(uuid_key)


@app.get("/api/sub/{uuid_key}/qr")
async def sub_qr(uuid_key: str, cfg: str = ""):
    """Public QR code for a UUID-only subscription."""
    if not QR_AVAILABLE:
        raise HTTPException(status_code=501, detail="qr code generation not available")

    uid, user = await _find_user_by_config_uuid(uuid_key)
    if not user:
        raise HTTPException(status_code=404, detail="subscription not found")

    configs_data = await _build_subscription_data_by_uuid(uuid_key)
    qr_data = f"{SETTINGS.get('domain') or get_host()}/link/{uuid_key}"
    if cfg and cfg == uuid_key:
        qr_data = f"https://{SETTINGS.get('domain') or get_host()}/link/{uuid_key}"
    elif cfg and cfg.isdigit():
        idx = int(cfg)
        real_cfgs = [c for c in configs_data.get("configs", []) if c and "%F0%9F%93%8A" not in c]
        if 0 <= idx < len(real_cfgs):
            qr_data = real_cfgs[idx]

    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=3,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
    )
    qr.add_data(qr_data if qr_data.startswith("http") else str(qr_data))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS - Reality Settings
# ══════════════════════════════════════════════════════════════════════════════


@app.post("/api/tools/generate-reality-keys")
async def generate_reality_keys(_=Depends(require_auth)):
    """Generate a Reality key pair (x25519)."""
    try:
        priv_key, pub_key = _xray_x25519_keypair()
        return {"private_key": priv_key, "public_key": pub_key}
    except ImportError:
        # cryptography not installed - return error
        return {"error": True, "private_key": "", "public_key": "", "note": "cryptography not installed: pip install cryptography"}

@app.get("/api/tools/reality-settings")
async def get_reality_settings(_=Depends(require_auth)):
    """Get Reality settings from global SETTINGS."""
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
    host = get_host()
    return {
        "port": reality.get("port", 1234),
        "dest": reality.get("dest", "google.com:443"),
        "sni": reality.get("sni", host),
        "public_key": reality.get("public_key", ""),
        "short_id": reality.get("short_id", "6ba85179e30d4fc2"),
        "spiderx": reality.get("spiderx", "/"),
        "fingerprint": reality.get("fingerprint", "chrome"),
        "dest": reality.get("dest", "is1-ssl.mzstatic.com:443"),
        "external_domain": reality.get("external_domain", host),
        "external_port": reality.get("external_port", 443),
        "domain": reality.get("domain", host),
        "domain_history": reality.get("domain_history", []),
    }

@app.post("/api/tools/reality-settings")
async def set_reality_settings(request: Request, _=Depends(require_auth)):
    """Save Reality settings globally."""
    body = await request.json()
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
        if "port" in body:
            reality["port"] = int(body.get("port", 1234))
        if "dest" in body:
            reality["dest"] = str(body.get("dest", "google.com:443"))
        if "sni" in body:
            reality["sni"] = str(body.get("sni", get_host()))
        if "public_key" in body:
            reality["public_key"] = str(body.get("public_key", ""))
        if "short_id" in body:
            reality["short_id"] = str(body.get("short_id", "6ba85179e30d4fc2"))
        if "spiderx" in body:
            reality["spiderx"] = str(body.get("spiderx", "/"))
        if "external_domain" in body:
            reality["external_domain"] = str(body.get("external_domain", get_host()))
        if "external_port" in body:
            reality["external_port"] = int(body.get("external_port", 443))
        if "domain" in body:
            domain_val = str(body.get("domain", "")).strip()
            if domain_val:
                reality["domain"] = domain_val
                # manage domain history (keep last 20, unique)
                history = reality.get("domain_history", [])
                if domain_val in history:
                    history.remove(domain_val)
                history.insert(0, domain_val)
                reality["domain_history"] = history[:20]
        SETTINGS["reality"] = reality
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات Reality ذخیره شد", "ok")
    return {"ok": True, "reality": reality}

@app.get("/api/tools/settings")
async def get_global_settings(_=Depends(require_auth)):
    """Get global panel settings."""
    host = get_host()
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
    return {
        "domain": SETTINGS.get("domain", host),
        "default_path": SETTINGS.get("default_path", "/"),
        "default_transport": SETTINGS.get("default_transport", "ws"),
        "enabled_protocols": SETTINGS.get("enabled_protocols", ["vless", "vmess", "trojan", "reality"]),
        "reality": reality,
        "domain_history": reality.get("domain_history", []),
        "xhttp_mode": SETTINGS.get("xhttp_mode", True),
        "websocket_mode": SETTINGS.get("websocket_mode", True),
        "default_connection_mode": SETTINGS.get("default_connection_mode", "ws"),
        "bg_login": SETTINGS.get("bg_login", ""),
        "bg_dashboard": SETTINGS.get("bg_dashboard", ""),
        "bg_sub": SETTINGS.get("bg_sub", ""),
        "panel_audio": SETTINGS.get("panel_audio", ""),
        "panel_audio_enabled": SETTINGS.get("panel_audio_enabled", False),
    }

@app.post("/api/tools/settings")
async def set_global_settings(request: Request, _=Depends(require_auth)):
    """Save global panel settings."""
    body = await request.json()
    async with SETTINGS_LOCK:
        if "domain" in body:
            domain_val = str(body["domain"]).strip()
            if domain_val:
                # A public panel domain must be a real DNS name or globally
                # routable IP. Do not allow localhost/internal values into state.
                ep = _normalize_public_endpoint(domain_val)
                if not ep:
                    raise HTTPException(
                        status_code=400,
                        detail="domain must be a public hostname or globally routable IP",
                    )
                # Keep the normalized endpoint cache aligned with the manual value.
                _apply_public_endpoint(ep, "manual:settings")
                SETTINGS["domain"] = ep["host"]
                SETTINGS["domain_source"] = "manual"
                # update domain history in reality too
                reality = SETTINGS.get("reality", {})
                history = reality.get("domain_history", [])
                if domain_val in history:
                    history.remove(domain_val)
                history.insert(0, domain_val)
                reality["domain_history"] = history[:20]
                SETTINGS["reality"] = reality
        if "default_path" in body:
            SETTINGS["default_path"] = str(body["default_path"]).strip()
        if "default_transport" in body:
            val = str(body["default_transport"]).strip()
            if val in ("ws", "xhttp", "tcp"):
                SETTINGS["default_transport"] = val
        if "enabled_protocols" in body:
            SETTINGS["enabled_protocols"] = body["enabled_protocols"]
        if "xhttp_mode" in body:
            SETTINGS["xhttp_mode"] = bool(body["xhttp_mode"])
        if "websocket_mode" in body:
            SETTINGS["websocket_mode"] = bool(body["websocket_mode"])
        if "default_connection_mode" in body:
            val = str(body["default_connection_mode"]).strip()
            if val in ("ws", "xhttp", "tcp"):
                SETTINGS["default_connection_mode"] = val
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات کلی ذخیره شد", "ok")
    return {"ok": True}



# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED SETTINGS SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    """Return all settings, masking the security token."""
    SETTINGS.setdefault("panel_alias", "Pars Space")
    async with SETTINGS_LOCK:
        s = dict(SETTINGS)
        masked = _get_panel_api_key_sync()
        s["panel_api_key"] = masked[:8] + "********" if masked else ""
        s["security_token"] = s["panel_api_key"]
    s["public_endpoint"] = get_public_endpoint()
    return s


@app.post("/api/settings")
async def update_settings(request: Request, _=Depends(require_auth)):
    """Update settings from any subset of fields."""
    body = await request.json()
    allowed_keys = {
        "websocket_mode", "xhttp_mode", "default_connection_mode",
        "max_ip_per_user", "bandwidth_limit_mbps", "live_monitoring",
        "auto_ip_rotation", "server_ip", "country", "country_code", "country_flag", "panel_alias",
    }
    async with SETTINGS_LOCK:
        for k, v in body.items():
            if k in allowed_keys:
                if k == "max_ip_per_user" and isinstance(v, (int, float)):
                    SETTINGS[k] = int(v)
                elif k == "bandwidth_limit_mbps" and isinstance(v, (int, float)):
                    SETTINGS[k] = int(v)
                elif k == "default_connection_mode" and isinstance(v, str):
                    if v in ("ws", "xhttp", "tcp"):
                        SETTINGS[k] = v
                elif isinstance(v, bool):
                    SETTINGS[k] = v
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات پیشرفته به‌روزرسانی شد", "info")
    async with SETTINGS_LOCK:
        s = dict(SETTINGS)
        masked = _get_panel_api_key_sync()
        s["panel_api_key"] = masked[:8] + "********" if masked else ""
        s["security_token"] = s["panel_api_key"]
    return {"ok": True, "settings": s}




# ══════════════════════════════════════════════════════════════════════════════
# BACKUP / RESTORE - full SpiderPanel state
# ══════════════════════════════════════════════════════════════════════════════

BACKUP_VERSION = 2
BACKUP_MAX_BYTES = 25 * 1024 * 1024


def _build_backup_payload() -> dict:
    """Build a portable JSON backup from the live in-memory state.

    This intentionally mirrors save_state() so a downloaded backup can restore
    the same entities without depending on the on-disk DATA_FILE being present.
    Scanner saved results are included as well because they live outside the
    main JSON state file.
    """
    panel_key = _get_panel_api_key_sync()
    server_info = {
        "public_ip": str(SETTINGS.get("server_ip") or ""),
        "country": str(SETTINGS.get("country") or ""),
        "country_code": str(SETTINGS.get("country_code") or "").upper(),
        "country_flag": str(SETTINGS.get("country_flag") or "🌐"),
        "detected_at": SETTINGS.get("server_info_detected_at") or None,
    }
    return {
        "backup_format": "SpiderPanel",
        "backup_version": BACKUP_VERSION,
        "created_at": datetime.now().isoformat(),
        "state": {
            "links": dict(LINKS),
            "users": dict(USERS),
            "subs": dict(SUBS),
            "settings": dict(SETTINGS),
            "panel_api_key": panel_key,
            "server_info": server_info,
            "groups": dict(GROUPS),
            "inbounds": dict(INBOUNDS),
            "ip_pool": list(IP_POOL),
            "ip_blacklist": list(IP_BLACKLIST),
            "worker": dict(WORKER),
            "nodes": dict(NODES),
            "pending_node_deletions": dict(PENDING_NODE_DELETIONS),
            "bot_orders": dict(BOT_ORDERS),
            "username": AUTH.get("username", "admin"),
            "password_hash": AUTH.get("password_hash", ""),
            "saved_secret": CONFIG.get("secret", ""),
        },
        "scanner_saved": {
            ctype: _read_scanned_ips(ctype) for ctype in sorted(_SCANNED_TYPES)
        },
    }


def _validate_backup_payload(payload: dict) -> dict:
    """Validate and normalize both v2 backups and legacy state-file backups."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="فایل بکاپ معتبر نیست")

    state = payload.get("state") if isinstance(payload.get("state"), dict) else payload
    if not isinstance(state, dict):
        raise HTTPException(status_code=400, detail="ساختار فایل بکاپ نامعتبر است")

    # Require a meaningful SpiderPanel state marker so arbitrary JSON cannot be
    # accidentally imported over a live installation.
    required_any = ("users", "settings", "links", "inbounds", "groups", "worker")
    if not any(k in state for k in required_any):
        raise HTTPException(status_code=400, detail="این فایل بکاپ SpiderPanel نیست")

    # Keep only the expected container/value shapes. Individual records remain
    # intentionally schema-compatible with older panel versions.
    dict_fields = ("links", "users", "subs", "settings", "groups", "inbounds", "worker", "nodes", "pending_node_deletions", "bot_orders")
    for key in dict_fields:
        if key in state and not isinstance(state.get(key), dict):
            raise HTTPException(status_code=400, detail=f"فیلد {key} در بکاپ نامعتبر است")
    list_fields = ("ip_pool", "ip_blacklist")
    for key in list_fields:
        if key in state and not isinstance(state.get(key), list):
            raise HTTPException(status_code=400, detail=f"فیلد {key} در بکاپ نامعتبر است")

    return state


@app.get("/api/settings/backup")
async def download_backup(_=Depends(require_auth)):
    """Download the complete current SpiderPanel state as a JSON file."""
    payload = _build_backup_payload()
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    filename = "spider-panel-backup-" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".json"
    return Response(
        content=body,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/settings/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    """Restore a downloaded SpiderPanel JSON backup atomically."""
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "read"):
        raise HTTPException(status_code=400, detail="فایل بکاپ انتخاب نشده است")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="فایل بکاپ خالی است")
    if len(raw) > BACKUP_MAX_BYTES:
        raise HTTPException(status_code=413, detail="حجم فایل بکاپ بیشتر از حد مجاز است (حداکثر 25MB)")

    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"فایل بکاپ JSON معتبر نیست: {exc}")

    state = _validate_backup_payload(payload)

    # Do not mutate live state until the backup has been fully parsed and
    # validated. The disk write is also atomic so a failed restore cannot leave
    # a half-written spider_state.json.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    current_bytes = None
    if DATA_FILE.exists():
        try:
            current_bytes = DATA_FILE.read_bytes()
        except Exception:
            current_bytes = None

    normalized = dict(state)
    normalized.setdefault("saved_at", datetime.now().isoformat())
    tmp = DATA_FILE.with_name(DATA_FILE.name + ".restore.tmp")
    try:
        tmp.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(DATA_FILE)

        # Clear then reload so omitted optional fields from older backups do not
        # leave stale current-install data behind.
        LINKS.clear(); SUBS.clear(); USERS.clear(); GROUPS.clear(); INBOUNDS.clear()
        NODES.clear(); PENDING_NODE_DELETIONS.clear(); BOT_ORDERS.clear()
        IP_POOL.clear(); IP_BLACKLIST.clear(); WORKER.clear(); SETTINGS.clear()
        await load_state()

        # Restore scanner results that are stored as separate text files.
        scanner_saved = payload.get("scanner_saved", {}) if isinstance(payload, dict) else {}
        if not isinstance(scanner_saved, dict):
            scanner_saved = {}
        for ctype in _SCANNED_TYPES:
            entries = scanner_saved.get(ctype, [])
            if isinstance(entries, list):
                _save_scanned_ips(ctype, [str(x) for x in entries], replace=True)
    except HTTPException:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        # Best-effort rollback of the state file if writing/reloading failed.
        if current_bytes is not None:
            try:
                DATA_FILE.write_bytes(current_bytes)
            except Exception:
                pass
        logger.exception("Backup restore failed")
        raise HTTPException(status_code=500, detail=f"بازیابی بکاپ ناموفق بود: {exc}")

    await save_state()
    log_activity("settings", "بکاپ با موفقیت بازیابی شد", "ok")
    return {"ok": True, "detail": "بکاپ با موفقیت بازیابی شد"}

@app.post("/api/settings/security-token/rotate")
async def rotate_security_token(_=Depends(require_auth)):
    """Legacy alias for SpiderPanel API-key regeneration."""
    return await regenerate_panel_api_key()


# ══════════════════════════════════════════════════════════════════════════════
# REMOTE NODES — real SpiderPanel-to-SpiderPanel replication
# ══════════════════════════════════════════════════════════════════════════════

def _get_panel_api_key_sync() -> str:
    key = str(SETTINGS.get("panel_api_key") or SETTINGS.get("security_token") or "").strip()
    if not key:
        key = "spdr_" + secrets.token_urlsafe(24)
        SETTINGS["panel_api_key"] = key
        SETTINGS["security_token"] = key
    return key


def _normalize_node_key(value: str) -> str:
    key = str(value or "").strip()
    if key and not key.startswith("spdr_"):
        return "spdr_" + key
    return key


def _normalize_node_base_url(domain: str) -> str:
    """Normalize a remote SpiderPanel URL and enforce HTTPS except localhost."""
    from urllib.parse import urlsplit, urlunsplit
    raw = str(domain or "").strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    try:
        u = urlsplit(raw)
        host = (u.hostname or "").strip().lower()
        if not host:
            return ""
        local = host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
        scheme = (u.scheme or "https").lower()
        if scheme != "https" and not local:
            scheme = "https"
        netloc = u.netloc
        # urlsplit(netloc) preserves userinfo; reject it because node URLs must
        # never carry credentials in the URL.
        if "@" in netloc:
            return ""
        return urlunsplit((scheme, netloc, "", "", "")).rstrip("/")
    except Exception:
        return ""


def _node_base_url(domain: str) -> str:
    """Backward-compatible alias used by older node code."""
    return _normalize_node_base_url(domain)


def _selected_node_ids_for_user(user: dict) -> list[str]:
    """Return the union of all Node IDs selected by the user's inbounds."""
    inbound_ids = list(user.get("inbound_ids") or [])
    if not inbound_ids and user.get("inbound_id"):
        inbound_ids = [user.get("inbound_id")]
    seen = set()
    out = []
    for iid in inbound_ids:
        ib = INBOUNDS.get(str(iid)) or {}
        ids = ib.get("enabled_node_ids")
        if not isinstance(ids, list):
            ids = ib.get("node_ids") or []
        for nid in ids:
            nid = str(nid).strip()
            if nid and nid not in seen and nid in NODES:
                seen.add(nid)
                out.append(nid)
    return out


def _node_status(node: dict) -> str:
    return str(node.get("status") or node.get("last_status") or "offline").strip().lower()


def _node_country_flag(node: dict) -> str:
    return str(node.get("country_flag") or node.get("remote_flag") or "🌐").strip() or "🌐"


def _node_public_view(node_id: str, node: dict) -> dict:
    """Return browser-safe Node information; raw API keys never leave backend."""
    key = str(node.get("api_key") or "")
    status = _node_status(node)
    country_code = str(node.get("country_code") or "").upper()
    country = str(node.get("country") or node.get("country_name") or "").strip()
    public_ip = str(node.get("public_ip") or node.get("remote_ip") or "").strip()
    enabled_count = 0
    for ib in INBOUNDS.values():
        ids = ib.get("enabled_node_ids") if isinstance(ib.get("enabled_node_ids"), list) else ib.get("node_ids")
        if isinstance(ids, list) and node_id in [str(x) for x in ids]:
            enabled_count += 1
    synced_users = sum(
        1 for u in USERS.values()
        if isinstance(u.get("node_configs"), dict) and node_id in u.get("node_configs", {})
    )
    return {
        "node_id": node_id,
        "name": node.get("name") or node.get("domain") or node_id,
        "domain": node.get("domain", ""),
        "api_key_masked": (key[:6] + "…" + key[-4:]) if len(key) > 12 else ("•" * len(key)),
        "country": country,
        "country_code": country_code,
        "country_flag": _node_country_flag(node),
        "public_ip": public_ip,
        "status": status,
        "last_seen": node.get("last_seen") or node.get("last_checked"),
        "last_error": node.get("last_error") or node.get("error") or "",
        "latency": node.get("latency") if node.get("latency") is not None else node.get("latency_ms"),
        "created_at": node.get("created_at") or node.get("added_at"),
        "last_sync": node.get("last_sync"),
        "enabled_inbound_count": enabled_count,
        "synced_user_count": synced_users,
        "remote_users": int(node.get("remote_users") or 0),
        # Legacy aliases kept for the existing frontend and old saved state.
        "remote_host": node.get("remote_host", ""),
        "remote_ip": public_ip,
        "remote_flag": _node_country_flag(node),
        "last_status": status,
        "last_checked": node.get("last_checked"),
        "latency_ms": node.get("latency_ms"),
        "error": node.get("last_error") or node.get("error") or "",
    }


def _pending_delete_add(node_id: str, config_uuid: str, username: str = "") -> None:
    if not node_id or not config_uuid:
        return
    rows = PENDING_NODE_DELETIONS.setdefault(node_id, [])
    if any(str(x.get("config_uuid")) == str(config_uuid) for x in rows if isinstance(x, dict)):
        return
    rows.append({"config_uuid": str(config_uuid), "queued_at": datetime.now().isoformat(), "username": username})


def _pending_delete_remove(node_id: str, config_uuid: str) -> None:
    rows = PENDING_NODE_DELETIONS.get(node_id) or []
    rows = [x for x in rows if str(x.get("config_uuid")) != str(config_uuid)]
    if rows:
        PENDING_NODE_DELETIONS[node_id] = rows
    else:
        PENDING_NODE_DELETIONS.pop(node_id, None)


async def _probe_node(node: dict) -> dict:
    """Verify a remote SpiderPanel with GET /api/server-info and X-API-Key."""
    base = _normalize_node_base_url(node.get("domain", ""))
    key = _normalize_node_key(node.get("api_key", ""))
    started = time.perf_counter()
    out = {
        "last_checked": datetime.now().isoformat(),
        "last_seen": node.get("last_seen"),
        "status": "offline",
        "last_status": "offline",
        "latency": None,
        "latency_ms": None,
        "country": "",
        "country_code": "",
        "country_flag": "🌐",
        "public_ip": "",
        "remote_host": "",
        "remote_ip": "",
        "remote_flag": "🌐",
        "remote_users": 0,
        "remote_tls_ws": {},
        "last_error": "",
        "error": "",
    }
    if not base or not key:
        out["status"] = out["last_status"] = "error"
        out["last_error"] = out["error"] = "domain/api_key نامعتبر است"
        return out
    try:
        ac = http_client
        own_client = False
        if ac is None:
            ac = httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=True)
            own_client = True
        try:
            r = await ac.get(f"{base}/api/server-info", headers={"X-API-Key": key, "Accept": "application/json"})
        finally:
            if own_client:
                await ac.aclose()
        elapsed = round((time.perf_counter() - started) * 1000)
        out["latency"] = out["latency_ms"] = elapsed
        if r.status_code in (401, 403):
            out["status"] = out["last_status"] = "unauthorized"
            out["last_error"] = out["error"] = "API Key نامعتبر است"
            return out
        if r.status_code >= 500:
            out["status"] = out["last_status"] = "error"
            out["last_error"] = out["error"] = f"remote HTTP {r.status_code}"
            return out
        if r.status_code != 200:
            out["status"] = out["last_status"] = "offline"
            out["last_error"] = out["error"] = f"remote HTTP {r.status_code}"
            return out
        try:
            info = r.json() or {}
        except Exception:
            out["status"] = out["last_status"] = "error"
            out["last_error"] = out["error"] = "remote returned invalid JSON"
            return out
        if not isinstance(info, dict) or not info.get("public_ip"):
            out["status"] = out["last_status"] = "error"
            out["last_error"] = out["error"] = "invalid server-info payload"
            return out
        managed = info.get("default_tls_ws") or {}
        if not isinstance(managed, dict) or not managed.get("id"):
            out["status"] = out["last_status"] = "error"
            out["last_error"] = out["error"] = f"managed inbound {DEFAULT_TLS_WS_INBOUND_NAME} is missing"
            return out
        mnet = str(managed.get("network") or "").lower()
        msec = str(managed.get("security") or "").lower()
        if mnet != "ws" or msec != "tls":
            out["status"] = out["last_status"] = "error"
            out["last_error"] = out["error"] = "managed inbound is not TLS+WS"
            return out
        out.update({
            "status": "online", "last_status": "online",
            "last_seen": datetime.now().isoformat(),
            "country": str(info.get("country") or ""),
            "country_code": str(info.get("country_code") or "").upper(),
            "country_flag": str(info.get("country_flag") or "🌐"),
            "public_ip": str(info.get("public_ip") or ""),
            "remote_host": str(info.get("host") or info.get("domain") or ""),
            "remote_ip": str(info.get("public_ip") or ""),
            "remote_flag": str(info.get("country_flag") or "🌐"),
            "remote_users": int(info.get("users") or 0),
            "remote_tls_ws": dict(info.get("default_tls_ws") or {}),
            "last_error": "", "error": "",
        })
    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout, TimeoutError) as exc:
        out["status"] = out["last_status"] = "offline"
        out["last_error"] = out["error"] = "connection timeout"
    except httpx.ConnectError as exc:
        out["status"] = out["last_status"] = "offline"
        out["last_error"] = out["error"] = "connection failed"
    except Exception as exc:
        out["status"] = out["last_status"] = "error"
        out["last_error"] = out["error"] = str(exc)[:160]
    return out


async def _remote_request(node: dict, method: str, path: str, json_body=None, timeout: float = 15.0):
    """Call a remote SpiderPanel using its stored API key."""
    base = _normalize_node_base_url(node.get("domain", ""))
    key = _normalize_node_key(node.get("api_key", ""))
    if not base or not key:
        raise RuntimeError("invalid node endpoint or API key")
    ac = http_client
    own_client = False
    if ac is None:
        ac = httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(8.0, timeout)), follow_redirects=True)
        own_client = True
    try:
        return await ac.request(method, f"{base}{path}", json=json_body, headers={"X-API-Key": key, "Accept": "application/json"})
    finally:
        if own_client:
            await ac.aclose()


async def _remote_delete_user(node: dict, config_uuid: str) -> tuple[bool, str]:
    try:
        r = await _remote_request(node, "DELETE", f"/api/users/{quote(str(config_uuid), safe='')}")
        if r.status_code in (200, 204):
            return True, "deleted"
        if r.status_code == 404:
            return True, "already absent"
        if r.status_code in (401, 403):
            return False, "unauthorized"
        return False, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, str(exc)[:160]


async def _remote_upsert_user(node: dict, payload: dict) -> tuple[bool, dict, str]:
    try:
        r = await _remote_request(node, "POST", "/api/users", payload, timeout=15.0)
        if r.status_code in (200, 201):
            data = r.json() if r.content else {}
            return True, data if isinstance(data, dict) else {}, ""
        if r.status_code in (401, 403):
            return False, {}, "unauthorized"
        return False, {}, f"HTTP {r.status_code}: {r.text[:120]}"
    except Exception as exc:
        return False, {}, str(exc)[:160]


async def _sync_node_traffic(node_id: str, node: dict, user: dict) -> tuple[bool, int, str]:
    config_uuid = str(user.get("config_uuid") or "").strip()
    if not config_uuid:
        return False, 0, "missing config_uuid"
    try:
        r = await _remote_request(node, "GET", f"/api/users/{quote(config_uuid, safe='')}", timeout=10.0)
        if r.status_code == 404:
            return False, 0, "remote user not found"
        if r.status_code in (401, 403):
            return False, 0, "unauthorized"
        if r.status_code != 200:
            return False, 0, f"HTTP {r.status_code}"
        data = r.json() or {}
        used = int(data.get("traffic_used_bytes") or 0)
        return True, used, ""
    except Exception as exc:
        return False, 0, str(exc)[:120]


async def _retry_pending_node_deletions(node_id: str, node: dict) -> int:
    rows = list(PENDING_NODE_DELETIONS.get(node_id) or [])
    done = 0
    for row in rows:
        ok, _ = await _remote_delete_user(node, row.get("config_uuid") or "")
        if ok:
            _pending_delete_remove(node_id, str(row.get("config_uuid") or ""))
            done += 1
    return done


async def sync_inbounds_to_nodes(nodes: list) -> int:
    """Ensure the remote managed TLS+WS inbound exists on selected nodes."""
    sent = 0
    for nid, node in nodes:
        try:
            r = await _remote_request(node, "POST", "/api/inbounds", {
                "name": DEFAULT_TLS_WS_INBOUND_NAME,
                "protocol": "vless",
                "network": "ws",
                "security": "tls",
                "managed_default": True,
            }, timeout=15.0)
            if r.status_code in (200, 201):
                sent += 1
                async with NODES_LOCK:
                    if nid in NODES:
                        NODES[nid]["last_sync"] = datetime.now().isoformat()
        except Exception:
            continue
    return sent


@app.get("/api/nodes")
async def list_nodes(_=Depends(require_auth)):
    async with NODES_LOCK:
        snap = {nid: dict(n) for nid, n in NODES.items()}
    nodes = [_node_public_view(nid, n) for nid, n in snap.items()]
    nodes.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"nodes": nodes}


@app.post("/api/nodes")
async def add_node(request: Request, _=Depends(require_auth)):
    """Verify the remote panel first; only verified Nodes are persisted."""
    body = await request.json()
    domain = _normalize_node_base_url(body.get("domain") or body.get("url") or "")
    raw_api_key = str(body.get("api_key") or body.get("spi_key") or "").strip()
    if not raw_api_key or not raw_api_key.startswith("spdr_"):
        raise HTTPException(status_code=400, detail="SPI Key باید با spdr_ شروع شود")
    api_key = _normalize_node_key(raw_api_key)
    name = str(body.get("name") or "").strip()[:60]
    if not domain:
        raise HTTPException(status_code=400, detail="دامنه نود معتبر نیست")
    if not re.match(r"^https://", domain, re.I) and not re.match(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?$", domain, re.I):
        raise HTTPException(status_code=400, detail="اتصال Node راه دور فقط با HTTPS مجاز است")
    async with NODES_LOCK:
        if any(str(n.get("domain") or "").rstrip("/").lower() == domain.rstrip("/").lower() for n in NODES.values()):
            raise HTTPException(status_code=409, detail="این Node قبلاً ثبت شده است")
    node_id = "node_" + secrets.token_hex(6)
    node = {
        "name": name or "",
        "domain": domain,
        "url": domain,
        "api_key": api_key,
        "created_at": datetime.now().isoformat(),
        "last_sync": None,
        "status": "checking",
        "last_status": "checking",
        "last_error": "",
    }
    probe = await _probe_node(node)
    if probe.get("status") != "online":
        code = 401 if probe.get("status") == "unauthorized" else (504 if probe.get("status") == "offline" else 502)
        raise HTTPException(status_code=code, detail=probe.get("last_error") or "Node verification failed")
    node.update(probe)
    if not node.get("name"):
        node["name"] = f"{node.get('country_flag') or '🌐'} {node.get('country') or node.get('public_ip') or domain}"
    async with NODES_LOCK:
        NODES[node_id] = node
    await save_state()
    # Existing users are reconciled immediately if this Node was already selected
    # in any persisted inbound state; otherwise selection in the Node inbound will
    # trigger the same reconciler later.
    asyncio.create_task(refresh_all_selected_users())
    log_activity("node", f"نود «{node['name']}» اضافه شد", "ok")
    return {"ok": True, "node": _node_public_view(node_id, node)}


@app.patch("/api/nodes/{node_id}")
async def update_node(node_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        current = dict(NODES.get(node_id) or {})
    if not current:
        raise HTTPException(status_code=404, detail="نود پیدا نشد")
    name = str(body.get("name") or current.get("name") or "").strip()[:60]
    domain = _normalize_node_base_url(body.get("domain") if "domain" in body else current.get("domain"))
    raw_api_key = str(body.get("api_key") or "").strip()
    if raw_api_key and not raw_api_key.startswith("spdr_"):
        raise HTTPException(status_code=400, detail="SPI Key باید با spdr_ شروع شود")
    api_key = _normalize_node_key(raw_api_key if raw_api_key else current.get("api_key"))
    if not domain:
        raise HTTPException(status_code=400, detail="دامنه نود معتبر نیست")
    if not api_key.startswith("spdr_"):
        raise HTTPException(status_code=400, detail="SPI Key باید با spdr_ شروع شود")
    current.update({"name": name, "domain": domain, "url": domain, "api_key": api_key, "status": "checking"})
    probe = await _probe_node(current)
    if probe.get("status") != "online":
        code = 401 if probe.get("status") == "unauthorized" else (504 if probe.get("status") == "offline" else 502)
        # Keep the existing record but mark it with the actual state; invalid
        # edits never disappear silently.
        current.update(probe)
        async with NODES_LOCK:
            if node_id in NODES:
                NODES[node_id].update(current)
        await save_state()
        raise HTTPException(status_code=code, detail=probe.get("last_error") or "Node verification failed")
    current.update(probe)
    async with NODES_LOCK:
        NODES[node_id] = current
    await save_state()
    asyncio.create_task(refresh_all_selected_users())
    return {"ok": True, "node": _node_public_view(node_id, current)}


async def _cleanup_remote_users_for_node(node_id: str, node: dict) -> tuple[bool, list[str]]:
    """Best-effort cleanup of every local user that was ever synced to a Node."""
    async with USERS_LOCK:
        users = [(uid, dict(u)) for uid, u in USERS.items()]
    candidates = {}
    for uid, u in users:
        selected = set(_selected_node_ids_for_user(u))
        cfgs = u.get("node_configs") or {}
        if node_id in selected or node_id in cfgs:
            cuuid = str(u.get("config_uuid") or "")
            if cuuid:
                candidates[cuuid] = u.get("username") or uid
    for row in list(PENDING_NODE_DELETIONS.get(node_id) or []):
        if row.get("config_uuid"):
            candidates[str(row["config_uuid"])] = row.get("username") or ""
    failed = []
    for cuuid, uname in candidates.items():
        ok, detail = await _remote_delete_user(node, cuuid)
        if ok:
            _pending_delete_remove(node_id, cuuid)
        else:
            _pending_delete_add(node_id, cuuid, uname)
            failed.append(f"{uname or cuuid}: {detail}")
    return (not failed), failed


@app.get("/api/nodes/{node_id}/health")
async def node_health(node_id: str, _=Depends(require_auth)):
    async with NODES_LOCK:
        node = dict(NODES.get(node_id) or {})
    if not node:
        raise HTTPException(status_code=404, detail="نود پیدا نشد")
    probe = await _probe_node(node)
    async with NODES_LOCK:
        if node_id not in NODES:
            raise HTTPException(status_code=404, detail="نود پیدا نشد")
        NODES[node_id].update(probe)
        current = dict(NODES[node_id])
    await _retry_pending_node_deletions(node_id, current)
    await save_state()
    return {"ok": True, "node": _node_public_view(node_id, current)}


@app.post("/api/nodes/{node_id}/refresh")
async def refresh_node(node_id: str, _=Depends(require_auth)):
    return await node_health(node_id)


@app.post("/api/nodes/{node_id}/check")
async def check_node_legacy(node_id: str, _=Depends(require_auth)):
    return await node_health(node_id)


@app.delete("/api/nodes/{node_id}")
async def delete_node(node_id: str, _=Depends(require_auth)):
    async with NODES_LOCK:
        node = dict(NODES.get(node_id) or {})
    if not node:
        raise HTTPException(status_code=404, detail="نود پیدا نشد")
    ok, failed = await _cleanup_remote_users_for_node(node_id, node)
    if not ok:
        async with NODES_LOCK:
            current = NODES.get(node_id)
            if current:
                current["status"] = "orphan_cleanup_pending"
                current["last_status"] = "orphan_cleanup_pending"
                current["last_error"] = "; ".join(failed)[:500]
                current["orphan_cleanup_pending"] = True
        await save_state()
        return {"ok": False, "pending_cleanup": True, "node": _node_public_view(node_id, NODES[node_id]), "errors": failed}
    async with INBOUNDS_LOCK:
        for ib in INBOUNDS.values():
            for field in ("enabled_node_ids", "node_ids"):
                ids = ib.get(field)
                if isinstance(ids, list):
                    ib[field] = [str(x) for x in ids if str(x) != str(node_id)]
    async with USERS_LOCK:
        for user in USERS.values():
            cfgs = user.get("node_configs")
            if isinstance(cfgs, dict):
                cfgs.pop(node_id, None)
            states = user.get("node_sync_state")
            if isinstance(states, dict):
                states.pop(node_id, None)
    async with NODES_LOCK:
        NODES.pop(node_id, None)
    PENDING_NODE_DELETIONS.pop(node_id, None)
    await save_state()
    await refresh_all_selected_users()
    log_activity("node", f"نود «{node.get('name', node_id)}» حذف شد", "warn")
    return {"ok": True, "deleted": node_id}


@app.post("/api/nodes/sync-all")
async def sync_all_nodes(_=Depends(require_auth)):
    await refresh_all_selected_users()
    async with NODES_LOCK:
        count = len(NODES)
    return {"ok": True, "synced": count}


async def _node_heartbeat_loop():
    """Periodic real Node health checks + pending deletion retries + traffic pull."""
    await asyncio.sleep(10)
    while True:
        try:
            async with NODES_LOCK:
                items = [(nid, dict(n)) for nid, n in NODES.items()]
            for nid, node in items:
                try:
                    probe = await _probe_node(node)
                    async with NODES_LOCK:
                        if nid in NODES:
                            NODES[nid].update(probe)
                            current = dict(NODES[nid])
                    if probe.get("status") == "online":
                        await _retry_pending_node_deletions(nid, current)
                        await _poll_node_traffic(nid, current)
                except Exception as exc:
                    logger.warning("node heartbeat %s failed: %s", nid, exc)
            await save_state()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("node heartbeat loop failed: %s", exc)
        await asyncio.sleep(int(os.environ.get("NODE_HEARTBEAT_INTERVAL", "60")))


# `refresh_all_selected_users` and `_poll_node_traffic` are defined later; the
# function references are resolved only when the background task executes.



async def _node_identity(host: str) -> dict:
    """Resolve a host/IP to public IP + country metadata."""
    ip = ""
    flag = ""
    cc = ""
    country_name = ""
    try:
        target = str(host or "").strip()
        ac = http_client or httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0))
        own_client = http_client is None
        try:
            r = await ac.get(f"https://ipinfo.io/{target}/json", timeout=6)
            if r.status_code == 200:
                j = r.json() or {}
                ip = str(j.get("ip") or "")
                cc = str(j.get("country") or "").strip().upper()
                country_name = str(j.get("country_name") or j.get("countryName") or "").strip()
                if not country_name and cc:
                    try:
                        import pycountry
                        country_name = pycountry.countries.get(alpha_2=cc).name if pycountry.countries.get(alpha_2=cc) else ""
                    except Exception:
                        country_name = ""
                flag = _code_to_flag(cc) if cc else ""
        finally:
            if own_client:
                await ac.aclose()
    except Exception:
        pass
    return {"host": host, "ip": ip, "flag": flag, "country_code": cc, "country_name": country_name}


_main = None

def _get_main():
    """Return this already-loaded main module; never import a second main copy."""
    global _main
    if _main is None:
        _main = sys.modules.get(__name__) or sys.modules.get("main")
    if _main is None:
        raise RuntimeError("main module is not initialized")
    return _main



# ══════════════════════════════════════════════════════════════════════════════
# XHTTP Siz10 Module (merged from xhttp_siz10.py)
# ══════════════════════════════════════════════════════════════════════════════
# xhttp_siz10.py
# ══════════════════════════════════════════════════════════════════════════════
# Siz10a · XHTTP Ultra Transport — دو مد: packet-up / stream-up
#  (stream-one حذف شد. منطق relay_vless دست‌نخورده.
#   stream-up بازنویسی شده با موتور تطبیقی: _AdaptiveFlow (AIMD روی high-water)
#   + _QuotaGate تطبیقی (batch بر اساس نرخ واقعی هر سشن) + سوکت تیون‌شده)
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import socket
import time
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse


router = APIRouter()

# session_id -> exact proxy from the /proxyIP/{proxy}/... path (for XHTTP)
_SESSION_PROXY: dict = {}

XHTTP_BUF = 128 * 1024
DOWNLINK_QUEUE_MAX = 512
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0

# ── تنظیمات موتور تطبیقی ──────────────────────────────────────────────────────
SOCK_BUF_SIZE = 512 * 1024     # SO_SNDBUF / SO_RCVBUF

# _AdaptiveFlow: بازه‌ی مجاز برای high-water تطبیقی (AIMD)
FLOW_MIN_HW = 64 * 1024
FLOW_MAX_HW = 4 * 1024 * 1024
FLOW_START_HW = 512 * 1024
FLOW_FAST_DRAIN_MS = 2.0    # زیر این یعنی downstream خیلی سریعه → بافر مجاز رو زیاد کن
FLOW_SLOW_DRAIN_MS = 25.0   # بالای این یعنی backpressure واقعی → فوری نصفش کن

# _QuotaGate: بازه‌ی مجاز برای batch تطبیقی چک کوتا
QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 1 * 1024 * 1024
QUOTA_START_BATCH = 64 * 1024
QUOTA_CHECK_INTERVAL = 0.2  # سقف زمانی؛ حتی اگر batch پر نشده، بعد این مدت چک کن

PACKET_UP_HIGH_WATER = 2 * 1024 * 1024  # packet-up همون منطق ساده‌ی قبلی رو داره (تمرکز این راند فقط stream-up بود)

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()

FINGERPRINTS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"


def _resp_headers(fp: str) -> dict:
    return dict(FINGERPRINTS.get(fp, FINGERPRINTS[DEFAULT_FINGERPRINT]))


def _tune_socket(writer: asyncio.StreamWriter):
    """Apply low-latency TCP_NODELAY plus bounded OS socket buffers."""
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        if hasattr(socket, "SO_KEEPALIVE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


class _QuotaGate:
    """
    نسخه‌ی تطبیقی: به‌جای await check_and_use() به‌ازای هر چانک، و به‌جای یک آستانه‌ی
    ثابت، نرخ واقعی ترافیک هر سشن رو با EWMA اندازه می‌گیره و اندازه‌ی batch رو زنده
    عوض می‌کنه:
      - سشن پرسرعت (دانلود حجیم) → batch بزرگ می‌شه → await های سنگین کمتر.
      - سشن کم‌ترافیک/تعاملی → batch کوچیک می‌مونه → کوتا دقیق‌تر و قطع سریع‌تر
        اگه کاربر تموم کرده باشه.
    داده هیچ‌وقت نگه داشته نمی‌شه، فقط لحظه‌ی چک‌کردنِ کوتا adaptive هست.
    """
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            self.ok = await check_and_use(self.uuid, flush)
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            self.ok = self.ok and await check_and_use(self.uuid, flush)
        return self.ok


class _AdaptiveFlow:
    """
    high-water تطبیقی برای drain(), رفتار شبیه AIMD در TCP congestion control:
      - هر بار drain() صدا زده می‌شه، مدت زمانش اندازه‌گیری می‌شه.
      - اگه سریع تموم بشه (لینک پایین‌دستی داره جواب می‌ده) → سقف بافر مجاز رو
        additive increase می‌کنیم؛ یعنی دفعه‌ی بعد دیرتر drain صدا زده می‌شه،
        پس syscall/context-switch کمتر می‌شه و throughput واقعی بالا می‌ره.
      - اگه drain کند بشه (backpressure واقعیه، صف داره جمع می‌شه) → سقف رو فوری
        نصف می‌کنیم (multiplicative decrease) تا بافربلوت/لتنسی رشد نکنه.
    هر سشن یک نمونه‌ی جدا از این داره، پس مسیرهای کند و سریع تداخلی با هم ندارن.
    """
    __slots__ = ("high_water", "last_drain_ms")

    def __init__(self):
        self.high_water = FLOW_START_HW
        self.last_drain_ms = 0.0

    def should_drain(self, buf_size: int) -> bool:
        return buf_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        t0 = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - t0) * 1000
        self.last_drain_ms = elapsed_ms
        if elapsed_ms < FLOW_FAST_DRAIN_MS:
            self.high_water = min(FLOW_MAX_HW, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > FLOW_SLOW_DRAIN_MS:
            self.high_water = max(FLOW_MIN_HW, self.high_water // 2)


def _req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


async def _open_tcp_from_header(first_chunk: bytes, uuid: str = "", proxy_override: str = ""):
    command, address, port, payload = await parse_vless_header(first_chunk, uuid)
    # Route outbound through the user's proxy IP (same as WS relay).
    # proxy_connect is in main.py
    reader, writer = await asyncio.wait_for(
        _proxy_connect(uuid, address, port, proxy_override=proxy_override or None),
        timeout=TCP_CONNECT_TIMEOUT,
    )
    _tune_socket(writer)
    if payload:
        writer.write(payload)
        await writer.drain()
    return reader, writer, address, port


async def _check_link(uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")


async def _get_or_create_session(uuid: str, mode: str, session_id: str, ip: str = "نامشخص") -> dict:
    """Session بر اساس session_id که خودِ کلاینت در URL فرستاده، lazily ساخته می‌شه.

    همچنین IP واقعی کانفیگ را در USER_IP_MAP ثبت می‌کند و در صورت رسیدن
    کاربر به حداکثر IPهای مجاز، ارتباط را رد می‌کند.
    """
    # using inline functions from main
    if not await m.enforce_ip_limit_for_link(uuid, ip):
        raise HTTPException(status_code=403, detail="ip limit reached")
    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is not None:
            sess["last_seen"] = time.time()
            return sess
        conn_id = secrets.token_urlsafe(6)
        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
            "transport": f"xhttp-{mode}",
        }
        sess = {
            "uuid": uuid, "mode": mode, "writer": None,
            "downlink_task": None, "uplink_task": None,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "last_seen": time.time(),
            "conn_id": conn_id, "tcp_open": False, "closed": False,
            "seq_buf": {}, "next_seq": 0,
            "gate": None,  # لازی ساخته می‌شه: _QuotaGate تطبیقی مخصوص stream-up
            "flow": None,  # لازی ساخته می‌شه: _AdaptiveFlow مخصوص stream-up
            "ip": ip,
        }
        xhttp_sessions[session_id] = sess
        logger.info(f"new XHTTP[{mode}] session [{session_id[:8]}] uuid={uuid[:8]} ip={ip}")
        return sess


async def _teardown(session_id: str):
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    for t in ("uplink_task", "downlink_task"):
        task = sess.get(t)
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    connections.pop(sess.get("conn_id"), None)
    # Release the IP so USER_IP_MAP reflects live concurrent connections
    try:
        asyncio.create_task(m.release_ip_for_link(sess.get("uuid", ""), sess.get("ip", "")))
    except Exception:
        pass
    dq = sess.get("down_q")
    if dq:
        try:
            dq.put_nowait(None)
        except Exception:
            pass
    logger.info(f"closed XHTTP[{sess.get('mode')}] [{session_id[:8]}] total={len(xhttp_sessions)}")


async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = [sid for sid, s in xhttp_sessions.items()
                     if now - s["last_seen"] > SESSION_IDLE_TIMEOUT and not s.get("tcp_open")]
        for sid in stale:
            await _teardown(sid)


_reaper_started = False


def ensure_reaper():
    global _reaper_started
    if not _reaper_started:
        asyncio.create_task(_reaper())
        _reaper_started = True


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue):
    first = True
    gate = _QuotaGate(uuid)  # دانلینک هم از همون گیت batched استفاده می‌کنه
    try:
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                break
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                c = connections.get(sess["conn_id"])
                if c:
                    c["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await down_q.put(payload)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        await gate.flush()
        await _teardown(session_id)


async def _open_tcp_for_session(session_id: str, uuid: str, sess: dict, first_chunk: bytes):
    """تونل TCP رو از روی هدر VLESS باز می‌کنه و پمپ دانلینک رو راه می‌اندازه."""
    proxy_override = _SESSION_PROXY.get(session_id, "")
    reader, writer, address, port = await _open_tcp_from_header(first_chunk, uuid, proxy_override)
    logger.info(f"connect XHTTP[{sess['mode']}] [{session_id[:8]}] -> {address}:{port}")
    sess["writer"] = writer
    sess["tcp_open"] = True
    sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, uuid, reader, sess["down_q"])
    )
    asyncio.create_task(save_state())


def _downstream_gen(sess: dict):
    async def gen():
        try:
            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        finally:
            pass
    return gen()


# ══════════════════════════════ GET دانلینک (مشترک بین سه مد) ══════════════════════════════
@router.get("/xhttp-siz10/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    ensure_reaper()
    if mode not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await _get_or_create_session(uuid, mode, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])


# ══════════════════════════════ PACKET-UP (آپلینک با seq) ══════════════════════════════
@router.post("/xhttp-siz10/packet-up/{uuid}/{session_id}/{seq}")
async def packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "packet-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    body = await request.body()
    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await _teardown(session_id)
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")

    stats["total_requests"] += 1
    connections[sess["conn_id"]]["bytes"] += len(body)

    try:
        if sess["writer"] is None:
            # اولین پکتی که حاوی هدر VLESS است، می‌تونه seq=0 نباشه اگر پکت‌ها
            # خارج از ترتیب برسن؛ بافر کوچیک برای سورت کردن seqهای زودرس.
            if seq != 0:
                sess["seq_buf"][seq] = body
                return {"ok": True, "buffered": True}
            await _open_tcp_for_session(session_id, uuid, sess, body)
            # هر پکت بافرشده‌ای که حالا نوبتش رسیده رو هم بفرست
            nxt = 1
            while nxt in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(nxt)
                sess["writer"].write(pending)
                nxt += 1
            sess["next_seq"] = nxt
            return {"ok": True, "connected": True}

        if seq == sess["next_seq"]:
            sess["writer"].write(body)
            sess["next_seq"] += 1
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                sess["writer"].write(pending)
                sess["next_seq"] += 1
        else:
            sess["seq_buf"][seq] = body

        if sess["writer"].transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
            await sess["writer"].drain()
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}


# ══════════════════════════════ STREAM-UP (یک POST پیوسته) ══════════════════════════════
# موتور تطبیقی: _QuotaGate (batch کوتا بر اساس نرخ واقعی) + _AdaptiveFlow (AIMD روی
# high-water درین) + کش رفرنس‌ها داخل لوپ. هیچ داده‌ای بافر/coalesce نمی‌شه —
# هر بایت فوری write() می‌شه، فقط «کِی صبر کنیم برای drain» تطبیقیه.
@router.post("/xhttp-siz10/stream-up/{uuid}/{session_id}")
async def stream_up_upload(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "stream-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = _QuotaGate(uuid)
        sess["gate"] = gate

    flow = sess.get("flow")
    if flow is None:
        flow = _AdaptiveFlow()
        sess["flow"] = flow

    conn = connections[sess["conn_id"]]   # یک بار لوک‌آپ، نه هر چانک
    writer = sess["writer"]               # ممکنه هنوز None باشه

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")

            stats["total_requests"] += 1
            conn["bytes"] += len(chunk)

            if writer is None:
                await _open_tcp_for_session(session_id, uuid, sess, chunk)
                writer = sess["writer"]
                continue

            writer.write(chunk)
            if flow.should_drain(writer.transport.get_write_buffer_size()):
                await flow.drain(writer)
    except HTTPException:
        await gate.flush()
        await _teardown(session_id)
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await gate.flush()
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="stream error")

    await gate.flush()
    return {"ok": True}


# ══════════════════════════════ PROXY-IP ROUTES ══════════════════════════════
# Configs with a selected proxy IP carry path /proxyIP/{ip}/xhttp-siz10/...
# Accept the route and delegate to the real handler so the connection works,
# remembering the exact proxy from the path for the session.
@router.get("/proxyIP/{proxy}/xhttp-siz10/{mode}/{uuid}/{session_id}")
async def xhttp_downlink_proxy(proxy: str, mode: str, uuid: str, session_id: str, request: Request):
    _SESSION_PROXY[session_id] = proxy
    return await xhttp_downlink(mode, uuid, session_id, request)


@router.post("/proxyIP/{proxy}/xhttp-siz10/packet-up/{uuid}/{session_id}/{seq}")
async def packet_up_upload_proxy(proxy: str, uuid: str, session_id: str, seq: int, request: Request):
    _SESSION_PROXY[session_id] = proxy
    return await packet_up_upload(uuid, session_id, seq, request)


@router.post("/proxyIP/{proxy}/xhttp-siz10/stream-up/{uuid}/{session_id}")
async def stream_up_upload_proxy(proxy: str, uuid: str, session_id: str, request: Request):
    _SESSION_PROXY[session_id] = proxy
    return await stream_up_upload(uuid, session_id, request)


# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — low-latency + high-throughput transport
# ══════════════════════════════════════════════════════════════════════════════
#
# A single TCP/VLESS stream cannot be safely split across several TCP sockets
# without protocol-aware reassembly. Browsers already make multiple independent
# connections for page resources, so the relay optimizes those connection
# establishments instead:
#   * race a small number of viable proxy paths;
#   * keep an EWMA latency score for route ordering;
#   * apply TCP_NODELAY/keepalive where supported;
#   * use moderate buffers to avoid latency spikes from oversized queues;
#   * keep direct fallback after proxy paths only, preventing egress-IP leaks.
#
RELAY_BUF_LOCAL = 64 * 1024
RELAY_WRITE_HIGH_WATER = 128 * 1024
RELAY_PROXY_RACE = max(
    1, min(3, int(os.environ.get("RELAY_PROXY_RACE", "2") or "2"))
)
RELAY_PROXY_CONNECT_TIMEOUT = max(
    1.5,
    min(
        6.0,
        float(
            os.environ.get("RELAY_PROXY_CONNECT_TIMEOUT", "3.25") or "3.25"
        ),
    ),
)
RELAY_DIRECT_CONNECT_TIMEOUT = max(
    3.0,
    min(
        15.0,
        float(
            os.environ.get("RELAY_DIRECT_CONNECT_TIMEOUT", "8") or "8"
        ),
    ),
)
RELAY_PROXY_STAGGER_SECONDS = max(
    0.0,
    min(
        0.5,
        float(
            os.environ.get("RELAY_PROXY_STAGGER_SECONDS", "0.06") or "0.06"
        ),
    ),
)

_RELAY_PROXY_METRICS: dict[str, dict] = {}
_RELAY_PROXY_METRICS_LOCK = asyncio.Lock()


def _relay_proxy_key(proxy: dict) -> str:
    return "|".join(
        str(proxy.get(k) or "")
        for k in ("protocol", "hostname", "port", "username")
    )


async def _relay_record_proxy_result(
    proxy: dict, elapsed_ms: float, ok: bool
) -> None:
    key = _relay_proxy_key(proxy)
    async with _RELAY_PROXY_METRICS_LOCK:
        metric = _RELAY_PROXY_METRICS.setdefault(
            key,
            {
                "ewma_ms": 0.0,
                "failures": 0,
                "successes": 0,
                "last_ok": 0.0,
            },
        )
        if ok:
            old = float(metric.get("ewma_ms") or 0.0)
            metric["ewma_ms"] = round(
                elapsed_ms
                if old <= 0
                else (old * 0.75 + elapsed_ms * 0.25),
                2,
            )
            metric["failures"] = max(
                0, int(metric.get("failures") or 0) - 1
            )
            metric["successes"] = int(metric.get("successes") or 0) + 1
            metric["last_ok"] = time.time()
        else:
            metric["failures"] = int(metric.get("failures") or 0) + 1


async def _relay_rank_proxies(proxies: list[dict]) -> list[dict]:
    """Prefer fast/healthy routes while keeping unmeasured routes eligible."""
    async with _RELAY_PROXY_METRICS_LOCK:
        snapshot = {
            k: dict(v) for k, v in _RELAY_PROXY_METRICS.items()
        }

    def score(proxy: dict) -> tuple:
        metric = snapshot.get(_relay_proxy_key(proxy), {})
        ewma = float(metric.get("ewma_ms") or 0.0)
        failures = int(metric.get("failures") or 0)
        return (
            0 if ewma > 0 else 1,
            ewma if ewma > 0 else 9000.0,
            min(failures, 8) * 400.0,
        )

    return sorted(proxies, key=score)


def _tune_relay_socket(writer: asyncio.StreamWriter) -> None:
    """Apply conservative low-latency TCP options when supported."""
    try:
        transport = writer.transport
        sock = transport.get_extra_info("socket") if transport else None
    except Exception:
        sock = None
    if sock is None:
        return

    import socket as _socket

    options = [
        (_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1),
    ]
    if hasattr(_socket, "SO_KEEPALIVE"):
        options.append((_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1))

    for name, value in (
        ("TCP_KEEPIDLE", 45),
        ("TCP_KEEPINTVL", 15),
        ("TCP_KEEPCNT", 3),
    ):
        opt = getattr(_socket, name, None)
        if opt is not None:
            options.append((_socket.IPPROTO_TCP, opt, value))

    for level, opt, value in options:
        try:
            sock.setsockopt(level, opt, value)
        except OSError:
            pass


async def _race_proxy_candidates(
    candidates: list[dict],
    address: str,
    port: int,
    uuid_value: str,
):
    """Race small batches of proxy paths and return the first working stream.

    At most RELAY_PROXY_RACE sockets are attempted concurrently. If the batch
    fails, the next candidates are tried. This gives fast recovery without
    opening a large number of speculative connections per browser request.
    """
    if not candidates:
        return None

    async def attempt(proxy: dict, delay: float = 0.0):
        if delay:
            await asyncio.sleep(delay)

        started = time.perf_counter()

        try:
            got = await asyncio.wait_for(
                _try_proxy_order(proxy, address, port),
                timeout=RELAY_PROXY_CONNECT_TIMEOUT,
            )
            if got:
                elapsed = (time.perf_counter() - started) * 1000.0
                await _relay_record_proxy_result(proxy, elapsed, True)
                return got, proxy, elapsed
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

        # Raw ZEUS-style VLESS relay fallback.
        rwtr = None
        try:
            rrdr, rwtr = await asyncio.wait_for(
                asyncio.open_connection(
                    proxy["hostname"], proxy["port"]
                ),
                timeout=RELAY_PROXY_CONNECT_TIMEOUT,
            )
            _tune_relay_socket(rwtr)
            hdr = _build_vless_connect_header(
                uuid_value, address, port
            )
            rwtr.write(hdr)
            await rwtr.drain()

            elapsed = (time.perf_counter() - started) * 1000.0
            await _relay_record_proxy_result(proxy, elapsed, True)
            return (rrdr, rwtr), proxy, elapsed
        except asyncio.CancelledError:
            await _close_writer_safely(rwtr)
            raise
        except Exception:
            await _close_writer_safely(rwtr)
            elapsed = (time.perf_counter() - started) * 1000.0
            await _relay_record_proxy_result(proxy, elapsed, False)
            return None

    for offset in range(0, len(candidates), RELAY_PROXY_RACE):
        batch = candidates[offset:offset + RELAY_PROXY_RACE]
        tasks = [
            asyncio.create_task(
                attempt(proxy, idx * RELAY_PROXY_STAGGER_SECONDS)
            )
            for idx, proxy in enumerate(batch)
        ]

        try:
            for future in asyncio.as_completed(tasks):
                try:
                    result = await future
                except asyncio.CancelledError:
                    raise
                except Exception:
                    result = None

                if result:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    return result

            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    return None


def _build_proxy_candidates(
    entry: str, targets: list[list]
) -> list[dict]:
    """Preserve scheme/auth while expanding a proxy hostname to IP targets."""
    parsed = _parse_proxy_entry(entry)
    if not parsed:
        return []

    out = []
    seen = set()
    for target_host, target_port in targets:
        proxy = {
            **parsed,
            "hostname": str(target_host),
            "port": int(target_port),
        }
        key = _relay_proxy_key(proxy)
        if key in seen:
            continue
        seen.add(key)
        out.append(proxy)
    return out

def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"

async def parse_vless_header(chunk: bytes, expected_uuid: str | None = None):
    if len(chunk) < 24:
        raise ValueError("chunk too small")

    # The UUID is carried inside the VLESS request header. Validate it against
    # the UUID in /ws/{uuid} (or the XHTTP URL) so path/UUID can never diverge.
    header_uuid = chunk[1:17]
    if expected_uuid:
        try:
            expected_bytes = uuid.UUID(str(expected_uuid)).bytes
            if header_uuid != expected_bytes:
                raise ValueError("vless uuid mismatch")
        except (ValueError, AttributeError) as exc:
            if str(exc) == "vless uuid mismatch":
                raise
            raise ValueError("invalid expected uuid") from exc

    pos = 17
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    m = _get_main()
    async with m.LINKS_LOCK:
        link = m.LINKS.get(uid)
        if link is None:
            return False
        if not m.is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[m.now_ir().strftime("%H:00")] += n

    # Sync traffic back to user (so subscription page shows real usage)
    user_id = link.get("user_id")
    if user_id:
        async with m.USERS_LOCK:
            u = m.USERS.get(user_id)
            if u:
                u["traffic_used_bytes"] = u.get("traffic_used_bytes", 0) + n

    return True

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_WRITE_HIGH_WATER:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF_LOCAL)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            connections[conn_id]["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass

async def websocket_tunnel(ws: WebSocket, uuid: str, proxy_override: str = None):
    if proxy_override:
        try:
            from urllib.parse import unquote
            proxy_override = unquote(proxy_override)
        except Exception:
            pass
    await ws.accept()
    m = _get_main()

    async with m.LINKS_LOCK:
        link = m.LINKS.get(uuid)

    default_relay_id = find_default_tls_ws_inbound_id()
    relay_inbound_id = link.get("relay_inbound_id") if link else None
    relay_allowed = bool(
        link
        and link.get("relay_enabled")
        and default_relay_id
        and relay_inbound_id == default_relay_id
        and is_default_tls_ws_inbound(m.INBOUNDS.get(default_relay_id))
    )
    if not relay_allowed:
        logger.warning(f"WS rejected uuid={uuid[:8]}…: relay is only enabled for {DEFAULT_TLS_WS_INBOUND_NAME}")
        await ws.close(code=1008, reason="relay unavailable for this inbound")
        return

    if not m.is_link_allowed(link):
        logger.warning(f"WS rejected uuid={uuid[:8]}… (link={'not found' if link is None else 'disabled/expired'})")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)
    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    m.log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})", "info")

    # Enforce per-user IP limit using the real connection IP
    if not await m.enforce_ip_limit_for_link(uuid, ip):
        logger.warning(f"WS rejected uuid={uuid[:8]}… ip={ip}: IP limit reached")
        await ws.close(code=1008, reason="ip limit reached")
        return
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk, uuid)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"[{conn_id}] → {address}:{port}")

        # Route the outbound connection through the user's selected proxy IP(s),
        # so egress shows the proxy IP instead of the Railway host.
        reader, writer = await m.proxy_connect(uuid, address, port, proxy_override=proxy_override)
        _tune_relay_socket(writer)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(m.save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        # Release the IP so USER_IP_MAP reflects live concurrent connections
        try:
            asyncio.create_task(m.release_ip_for_link(uuid, ip))
        except Exception:
            pass
        logger.info(f"WS closed [{conn_id}] total={len(connections)}")


@app.get("/api/node/identity")
async def node_identity(request: Request):
    """Public handshake endpoint: a peer panel presents our security_token as
    X-Node-Key and gets back this panel's host/ip/flag + user count.

    This is the only endpoint a remote node is allowed to read, and it exposes
    nothing beyond identity — users, keys and configs stay local.
    """
    key = request.headers.get("X-API-Key") or request.headers.get("X-Node-Key") or request.query_params.get("key") or ""
    async with SETTINGS_LOCK:
        expected = _get_panel_api_key_sync()
    if not key or not expected or not secrets.compare_digest(str(key), expected):
        raise HTTPException(status_code=401, detail="invalid node key")
    host = SETTINGS.get("domain") or get_host()
    ident = await _node_identity(host)
    async with USERS_LOCK:
        users = len(USERS)
    default_iid = find_default_tls_ws_inbound_id()
    default_ib = dict(INBOUNDS.get(default_iid, {})) if default_iid else {}
    return {
        "ok": True, "host": host, "ip": ident.get("ip", ""), "flag": ident.get("flag", ""),
        "country_code": ident.get("country_code", ""), "country": ident.get("country_name", ""),
        "users": users, "version": "10.0",
        "default_tls_ws": {
            "id": default_iid or "", "name": default_ib.get("name", ""),
            "domain": default_ib.get("domain") or host,
            "port": default_ib.get("port") or 443,
            "external_port": default_ib.get("external_port") or 443,
            "network": default_ib.get("network", "ws"),
            "security": default_ib.get("security", "tls"),
            "path": str((default_ib.get("ws_settings") or {}).get("path") or "/ws/{uuid}"),
            "fingerprint": default_ib.get("fingerprint") or "chrome",
            "sni": default_ib.get("sni") or default_ib.get("domain") or host,
        },
    }


@app.post("/api/node/ping")
async def node_ping(request: Request):
    """Public latency probe used by a peer panel to measure RTT."""
    key = request.headers.get("X-API-Key") or request.headers.get("X-Node-Key") or request.query_params.get("key") or ""
    async with SETTINGS_LOCK:
        expected = _get_panel_api_key_sync()
    if not key or not expected or not secrets.compare_digest(str(key), expected):
        raise HTTPException(status_code=401, detail="invalid node key")
    return {"ok": True, "t": time.time()}


@app.get("/api/node/users/{username}")
async def node_get_user(username: str, request: Request):
    """Let a peer panel read back the sync state it previously pushed, so the
    origin can confirm the remote actually applied the user."""
    key = request.headers.get("X-API-Key") or request.headers.get("X-Node-Key") or request.query_params.get("key") or ""
    async with SETTINGS_LOCK:
        expected = _get_panel_api_key_sync()
    if not key or not expected or not secrets.compare_digest(str(key), expected):
        raise HTTPException(status_code=401, detail="invalid node key")
    async with USERS_LOCK:
        for uid, u in USERS.items():
            if u.get("username") == username:
                return {
                    "ok": True,
                    "user_id": uid,
                    "username": username,
                    "config_uuid": u.get("config_uuid", ""),
                    "status": u.get("status", "active"),
                    "from_node": u.get("from_node", ""),
                }
    raise HTTPException(status_code=404, detail="user not found")


@app.post("/api/node/sync-user")
async def node_sync_user(request: Request):
    """Receive a user pushed by a peer panel.

    The peer sends the *exact* config_uuid so the same UUID works across every
    node; node_ids on the origin are not sent here (they are a local concept).
    """
    key = request.headers.get("X-API-Key") or request.headers.get("X-Node-Key") or request.query_params.get("key") or ""
    async with SETTINGS_LOCK:
        expected = _get_panel_api_key_sync()
    if not key or not expected or not secrets.compare_digest(str(key), expected):
        raise HTTPException(status_code=401, detail="invalid node key")

    body = await request.json()
    username = str(body.get("username") or "").strip()[:40]
    config_uuid = str(body.get("config_uuid") or "").strip()
    if not username or not config_uuid:
        raise HTTPException(status_code=400, detail="username و config_uuid الزامی است")

    traffic_limit_bytes = int(body.get("traffic_limit_bytes") or 0)
    expire_at = body.get("expire_at")
    concurrent = int(body.get("concurrent_connections") or 0)
    from_node = str(body.get("from_node") or "").strip()
    path = str(body.get("path") or "").strip()
    relay_inbound_id = find_default_tls_ws_inbound_id()
    relay_inbound = INBOUNDS.get(relay_inbound_id, {}) if relay_inbound_id else {}
    if not relay_inbound_id or not is_default_tls_ws_inbound(relay_inbound):
        raise HTTPException(status_code=503, detail=f"{DEFAULT_TLS_WS_INBOUND_NAME} not found")
    path = f"/ws/{config_uuid}"

    async with USERS_LOCK:
        # Reuse the record if this UUID already arrived from the same origin —
        # the origin re-pushes on every edit, and we must not duplicate.
        target_uid = next(
            (uid for uid, u in USERS.items() if u.get("config_uuid") == config_uuid),
            None,
        )
        if target_uid is None:
            target_uid = generate_short_id()
        existing = USERS.get(target_uid, {})
        USERS[target_uid] = {
            **existing,
            "username": username,
            "protocol": "vless",
            "traffic_limit_bytes": traffic_limit_bytes,
            "traffic_used_bytes": existing.get("traffic_used_bytes", 0),
            "expire_at": expire_at,
            "concurrent_connections": concurrent,
            "created_at": existing.get("created_at") or datetime.now().isoformat(),
            "status": str(body.get("status") or "active"),
            "server": "node-sync",
            "config_uuid": config_uuid,
            "subscription_uuid": existing.get("subscription_uuid") or secrets.token_urlsafe(16),
            "sni": "", "path": path, "transport_type": "ws",
            "inbound_id": relay_inbound_id, "inbound_ids": [relay_inbound_id],
            "relay_inbound_id": relay_inbound_id, "from_node": from_node,
            "synced_at": datetime.now().isoformat(),
        }
        # Keep the traffic-counter link in step with the user record.
        LINKS.setdefault(config_uuid, {})
        LINKS[config_uuid].update({
            "label": username,
            "limit_bytes": traffic_limit_bytes,
            "created_at": USERS[target_uid]["created_at"],
            "active": USERS[target_uid]["status"] == "active",
            "expires_at": expire_at,
            "note": f"نود: {from_node or 'unknown'}",
            "is_default": False,
            "sub_id": None,
            "protocol": "vless-ws", "path": path, "user_id": target_uid,
            "inbound_id": relay_inbound_id, "relay_enabled": True,
            "relay_inbound_id": relay_inbound_id,
        })
    _rebuild_path_index()
    asyncio.create_task(save_state())
    node_user = dict(USERS[target_uid])
    node_cfg = generate_user_config(target_uid, node_user, relay_inbound_id)
    log_activity("node", f"کاربر «{username}» از نود {from_node or '?'} سینک شد", "ok")
    return {"ok": True, "user_id": target_uid, "config_uuid": config_uuid,
            "inbound_id": relay_inbound_id, "inbound_name": DEFAULT_TLS_WS_INBOUND_NAME,
            "config": node_cfg}


async def _ensure_user_sync_password(user_id: str, user: dict) -> str:
    pwd = str(user.get("node_sync_password") or "").strip()
    if len(pwd) >= 8:
        return pwd
    pwd = secrets.token_urlsafe(18)
    async with USERS_LOCK:
        current = USERS.get(user_id)
        if current is not None:
            current["node_sync_password"] = pwd
    return pwd


def _expire_days_from_user(user: dict) -> int:
    raw = user.get("expire_at")
    if not raw:
        return 0
    try:
        dt = datetime.fromisoformat(str(raw))
        days = int(max(0, (dt - datetime.now()).total_seconds() // 86400))
        return days
    except Exception:
        return 0


async def _sync_user_to_selected_nodes(user_id: str, user: dict, selected_override: list[str] | None = None, force_reset: bool = False) -> dict:
    """Authoritative Main Panel reconciliation for one user.

    Main Panel is the source of truth for user identity, UUID, limits, expiry,
    status and Node assignment. The remote panel is only the execution target.
    Selected Nodes are upserted; previously-synced but now-unselected Nodes are
    deleted. A failure on one Node never stops the others.
    """
    selected = [str(x) for x in (selected_override if selected_override is not None else _selected_node_ids_for_user(user)) if str(x).strip()]
    selected = list(dict.fromkeys(selected))
    previous = set(str(x) for x in (user.get("node_configs") or {}).keys())
    previous.update(str(x) for x in (user.get("node_sync_state") or {}).keys())
    targets = set(selected) | previous

    async with NODES_LOCK:
        nodes = {nid: dict(NODES[nid]) for nid in targets if nid in NODES}

    password = await _ensure_user_sync_password(user_id, user)
    cuuid = str(user.get("config_uuid") or "").strip()
    if not cuuid:
        return {"ok": False, "results": [], "error": "missing config_uuid"}

    results = []
    new_cfgs = dict(user.get("node_configs") or {})
    sync_states = dict(user.get("node_sync_state") or {})
    node_traffic = dict(user.get("node_traffic") or {})
    origin = SETTINGS.get("domain") or get_host()
    inbound_default = find_default_tls_ws_inbound_id() or ""

    for nid in targets:
        node = nodes.get(nid)
        if not node:
            continue
        if nid in selected:
            payload = {
                "username": user.get("username") or user_id,
                "password": password,
                "config_uuid": cuuid,
                "traffic_limit_gb": round(float(user.get("traffic_limit_bytes", 0)) / (1024 ** 3), 6) if user.get("traffic_limit_bytes", 0) else 0,
                "expire_days": _expire_days_from_user(user),
                "concurrent_connections": int(user.get("concurrent_connections") or 0),
                "status": user.get("status", "active"),
                "inbound_id": inbound_default,
                "inbound_ids": [inbound_default] if inbound_default else [],
                "subscription_uuid": user.get("subscription_uuid") or "",
                "path": f"/ws/{cuuid}",
                "from_node": origin,
                "reset_traffic": bool(force_reset),
            }
            ok, remote_json, detail = await _remote_upsert_user(node, payload)
            status = "online" if ok else ("unauthorized" if detail == "unauthorized" else "error")
            if ok:
                cfg = str(remote_json.get("config") or "")
                if cfg:
                    new_cfgs[nid] = cfg
                remote_used = int(remote_json.get("traffic_used_bytes") or 0)
                node_traffic[nid] = remote_used
                sync_states[nid] = {
                    "status": "online",
                    "last_sync": datetime.now().isoformat(),
                    "last_error": "",
                    "traffic_used_bytes": remote_used,
                }
                async with NODES_LOCK:
                    if nid in NODES:
                        NODES[nid]["last_sync"] = datetime.now().isoformat()
                _pending_delete_remove(nid, cuuid)
            else:
                sync_states[nid] = {
                    "status": status,
                    "last_sync": sync_states.get(nid, {}).get("last_sync"),
                    "last_error": detail,
                    "traffic_used_bytes": node_traffic.get(nid, 0),
                }
                if detail == "unauthorized":
                    async with NODES_LOCK:
                        if nid in NODES:
                            NODES[nid]["status"] = "unauthorized"
                            NODES[nid]["last_status"] = "unauthorized"
                            NODES[nid]["last_error"] = detail
            results.append({"node_id": nid, "name": node.get("name") or nid, "ok": ok, "status": status, "detail": detail})
        else:
            ok, detail = await _remote_delete_user(node, cuuid)
            if ok:
                new_cfgs.pop(nid, None)
                sync_states.pop(nid, None)
                node_traffic.pop(nid, None)
                _pending_delete_remove(nid, cuuid)
            else:
                _pending_delete_add(nid, cuuid, str(user.get("username") or user_id))
                sync_states[nid] = {
                    "status": "delete_pending",
                    "last_sync": sync_states.get(nid, {}).get("last_sync"),
                    "last_error": detail,
                    "traffic_used_bytes": node_traffic.get(nid, 0),
                }
            results.append({"node_id": nid, "name": node.get("name") or nid, "ok": ok, "status": "deleted" if ok else "delete_pending", "detail": detail})

    aggregate = sum(int(v or 0) for nid, v in node_traffic.items() if nid in selected)
    async with USERS_LOCK:
        current = USERS.get(user_id)
        if current is not None:
            current["node_configs"] = {nid: cfg for nid, cfg in new_cfgs.items() if nid in selected}
            current["node_sync_state"] = sync_states
            current["node_traffic"] = node_traffic
            current["node_traffic_used_bytes"] = aggregate
            snapshot = dict(current)
        else:
            snapshot = dict(user)
    await save_state()
    return {"ok": True, "results": results, "selected": selected, "node_traffic_used_bytes": aggregate}


async def sync_user_to_nodes(user_id: str, user: dict, primary_inbound_id: str, node_ids: list) -> dict:
    # Backward-compatible wrapper for older callers. New code uses the union of
    # all Node selections, but an explicit list still works for a targeted sync.
    return await _sync_user_to_selected_nodes(user_id, user, [str(x) for x in node_ids], False)


async def refresh_all_selected_users() -> dict:
    async with USERS_LOCK:
        users = [(uid, dict(u)) for uid, u in USERS.items()]
    results = []
    for uid, user in users:
        selected = _selected_node_ids_for_user(user)
        if selected or user.get("node_configs"):
            try:
                results.append(await _sync_user_to_selected_nodes(uid, user, selected))
            except Exception as exc:
                logger.warning("Node reconciliation failed for %s: %s", uid, exc)
                results.append({"ok": False, "user_id": uid, "error": str(exc)[:160]})
    await save_state()
    return {"ok": True, "users": len(results), "results": results}


async def _poll_node_traffic(node_id: str, node: dict):
    """Pull real traffic counters from the remote panel for selected users."""
    async with USERS_LOCK:
        candidates = [
            (uid, dict(u)) for uid, u in USERS.items()
            if node_id in _selected_node_ids_for_user(u)
        ]
    if not candidates:
        return
    for offset in range(0, len(candidates), 10):
        batch = candidates[offset:offset + 10]
        polled = await asyncio.gather(*[
            _sync_node_traffic(node_id, node, u) for _, u in batch
        ], return_exceptions=True)
        async with USERS_LOCK:
            for (uid, user), row in zip(batch, polled):
                if not isinstance(row, tuple) or len(row) != 3:
                    continue
                ok, used, detail = row
                current = USERS.get(uid)
                if current is None:
                    continue
                traffic = dict(current.get("node_traffic") or {})
                states = dict(current.get("node_sync_state") or {})
                if ok:
                    traffic[node_id] = int(used)
                    st = dict(states.get(node_id) or {})
                    st.update({"status": "online", "traffic_used_bytes": int(used), "last_error": ""})
                    states[node_id] = st
                elif detail == "unauthorized":
                    st = dict(states.get(node_id) or {})
                    st.update({"status": "unauthorized", "last_error": detail})
                    states[node_id] = st
                current["node_traffic"] = traffic
                selected_now = _selected_node_ids_for_user(current)
                current["node_traffic_used_bytes"] = sum(int(traffic.get(nid) or 0) for nid in selected_now)
                current["node_sync_state"] = states


async def refresh_node_inbound_configs(inbound_id: str = "Node"):
    """Reconcile every User attached to a Node selector inbound."""
    async with USERS_LOCK:
        users = [(uid, dict(u)) for uid, u in USERS.items()
                 if inbound_id in list(u.get("inbound_ids") or [])]
    for uid, user in users:
        try:
            await _sync_user_to_selected_nodes(uid, user)
        except Exception as exc:
            logger.warning("refresh_node_inbound_configs failed for user %s: %s", uid, exc)
    await save_state()


@app.post("/api/inbounds/{inbound_id}/sync-nodes")
async def sync_inbound_nodes(inbound_id: str, _=Depends(require_auth)):
    """Explicitly reconcile every User attached to this inbound with its selected Nodes."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        ids = list(ib.get("enabled_node_ids") or ib.get("node_ids") or [])
    if (ib.get("protocol") or "").lower() != "node":
        raise HTTPException(status_code=400, detail="این endpoint فقط برای Node inbound است")
    ids = [str(x) for x in ids if str(x).strip()]
    if not ids:
        return {"ok": True, "users": 0, "results": [], "node_ids": []}
    await refresh_node_inbound_configs(inbound_id)
    async with USERS_LOCK:
        count = sum(1 for u in USERS.values() if inbound_id in [str(x) for x in (u.get("inbound_ids") or [])])
    return {"ok": True, "users": count, "results": [], "node_ids": ids}


# ══════════════════════════════════════════════════════════════════════════════
# GROUP MANAGEMENT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/groups")
async def list_groups(_=Depends(require_auth)):
    """List all groups with user count."""
    async with GROUPS_LOCK:
        snap = dict(GROUPS)
    result = []
    for gid, g in snap.items():
        user_ids = g.get("user_ids", [])
        result.append({
            "group_id": gid,
            "name": g.get("name"),
            "description": g.get("description", ""),
            "user_count": len(user_ids),
            "user_ids": user_ids,
            "speed_limit": g.get("speed_limit", 0),
            "traffic_limit": g.get("traffic_limit", 0),
            "expire_days": g.get("expire_days", 0),
            "ip_pool": g.get("ip_pool", []),
            "rules": g.get("rules", {}),
            "created_at": g.get("created_at"),
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"groups": result}


@app.post("/api/groups")
async def create_group(request: Request, _=Depends(require_auth)):
    """Create a new group."""
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    description = (body.get("description") or "").strip()[:200]
    speed_limit = int(body.get("speed_limit") or 0)
    traffic_limit = int(body.get("traffic_limit") or 0)
    expire_days = int(body.get("expire_days") or 0)

    group_id = generate_short_id()
    async with GROUPS_LOCK:
        GROUPS[group_id] = {
            "name": name,
            "description": description,
            "user_ids": [],
            "ip_pool": body.get("ip_pool", []),
            "rules": body.get("rules", {}),
            "speed_limit": speed_limit,
            "traffic_limit": traffic_limit,
            "expire_days": expire_days,
            "created_at": datetime.now().isoformat(),
        }
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{name}» ساخته شد", "ok")
    return {"ok": True, "group_id": group_id, **GROUPS[group_id]}


@app.patch("/api/groups/{group_id}")
async def update_group(group_id: str, request: Request, _=Depends(require_auth)):
    """Update an existing group."""
    body = await request.json()
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        if "name" in body:
            g["name"] = str(body["name"])[:60]
        if "description" in body:
            g["description"] = str(body["description"])[:200]
        if "speed_limit" in body:
            g["speed_limit"] = int(body["speed_limit"])
        if "traffic_limit" in body:
            g["traffic_limit"] = int(body["traffic_limit"])
        if "expire_days" in body:
            g["expire_days"] = int(body["expire_days"])
        if "ip_pool" in body:
            g["ip_pool"] = list(body["ip_pool"])
        if "rules" in body:
            g["rules"] = dict(body["rules"])
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{g.get('name', group_id)}» ویرایش شد", "info")
    return {"ok": True}


@app.delete("/api/groups/{group_id}")
async def delete_group(group_id: str, _=Depends(require_auth)):
    """Delete a group and unlink all users from it."""
    async with GROUPS_LOCK:
        g = GROUPS.pop(group_id, None)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        name = g.get("name", group_id)
        user_ids = g.get("user_ids", [])
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": group_id, "unlinked_users": len(user_ids)}


@app.post("/api/groups/{group_id}/users")
async def add_user_to_group(group_id: str, request: Request, _=Depends(require_auth)):
    """Add a user to a group."""
    body = await request.json()
    user_id = str(body.get("user_id", ""))
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")

    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        ids = g.setdefault("user_ids", [])
        if user_id not in ids:
            ids.append(user_id)
    asyncio.create_task(save_state())
    log_activity("group", f"کاربر «{user_id}» به گروه «{g.get('name', group_id)}» اضافه شد", "info")
    return {"ok": True}


@app.delete("/api/groups/{group_id}/users/{user_id}")
async def remove_user_from_group(group_id: str, user_id: str, _=Depends(require_auth)):
    """Remove a user from a group."""
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        ids = g.get("user_ids", [])
        if user_id in ids:
            ids.remove(user_id)
        else:
            raise HTTPException(status_code=404, detail="user not in group")
    asyncio.create_task(save_state())
    log_activity("group", f"کاربر «{user_id}» از گروه «{g.get('name', group_id)}» حذف شد", "info")
    return {"ok": True}


@app.get("/api/groups/{group_id}/subscription")
async def group_subscription(group_id: str, _=Depends(require_auth)):
    """Generate subscription link for a group — base64-encoded configs of all active users."""
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        user_ids = list(g.get("user_ids", []))

    async with USERS_LOCK:
        snap = dict(USERS)

    configs = []
    for uid in user_ids:
        u = snap.get(uid)
        if u and is_user_allowed(u):
            cfg = generate_user_config(uid, u, u.get("inbound_id"))
            if cfg:
                configs.append(cfg)

    if not configs:
        raise HTTPException(status_code=404, detail="no active users in group")

    content = base64.b64encode("\n".join(configs).encode()).decode()
    host = SETTINGS.get("domain") or get_host()
    return {
        "group_id": group_id,
        "group_name": g.get("name"),
        "active_users": len(configs),
        "total_users": len(user_ids),
        "subscription_url": f"https://{host}/api/groups/{group_id}/subscription",
        "encoded_config": content,
    }


# ══════════════════════════════════════════════════════════════════════════════
# IP POOL MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ips")
async def list_ips(_=Depends(require_auth)):
    """List all IPs in the pool with status."""
    async with IP_POOL_LOCK:
        ips = list(IP_POOL)
    async with IP_BLACKLIST_LOCK:
        bl = set(IP_BLACKLIST)
    for entry in ips:
        entry["blacklisted"] = entry["ip"] in bl
    return {"ips": ips, "total": len(ips), "blacklisted_count": len(bl)}


@app.post("/api/ips")
async def add_ip(request: Request, _=Depends(require_auth)):
    """Add an IP to the pool."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_POOL_LOCK:
        if any(e["ip"] == ip_addr for e in IP_POOL):
            raise HTTPException(status_code=409, detail="ip already in pool")
        entry = {
            "ip": ip_addr,
            "status": body.get("status", "active"),
            "latency_ms": body.get("latency_ms", 0),
            "location": body.get("location", "Unknown"),
            "assigned_user": body.get("assigned_user"),
            "last_check": datetime.now().isoformat(),
        }
        IP_POOL.append(entry)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به مخزن اضافه شد", "info")
    return {"ok": True, "ip": entry}


@app.delete("/api/ips")
async def remove_ip(request: Request, _=Depends(require_auth)):
    """Remove an IP from the pool."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_POOL_LOCK:
        before = len(IP_POOL)
        IP_POOL[:] = [e for e in IP_POOL if e["ip"] != ip_addr]
        if len(IP_POOL) == before:
            raise HTTPException(status_code=404, detail="ip not found in pool")
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» از مخزن حذف شد", "warn")
    return {"ok": True, "deleted": ip_addr}


@app.post("/api/ips/blacklist")
async def blacklist_ip(request: Request, _=Depends(require_auth)):
    """Add an IP to the blacklist."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_BLACKLIST_LOCK:
        IP_BLACKLIST.add(ip_addr)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به لیست سیاه اضافه شد", "warn")
    return {"ok": True, "blacklisted": ip_addr}


@app.delete("/api/ips/blacklist")
async def unblacklist_ip(request: Request, _=Depends(require_auth)):
    """Remove an IP from the blacklist."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_BLACKLIST_LOCK:
        if ip_addr not in IP_BLACKLIST:
            raise HTTPException(status_code=404, detail="ip not in blacklist")
        IP_BLACKLIST.discard(ip_addr)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» از لیست سیاه خارج شد", "info")
    return {"ok": True, "removed": ip_addr}


@app.post("/api/ips/assign")
async def assign_ip_to_user(request: Request, _=Depends(require_auth)):
    """Assign an IP from the pool to a user."""
    body = await request.json()
    user_id = str(body.get("user_id", ""))
    ip_addr = str(body.get("ip", ""))
    if not user_id or not ip_addr:
        raise HTTPException(status_code=400, detail="user_id and ip are required")

    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")

    async with IP_POOL_LOCK:
        entry = next((e for e in IP_POOL if e["ip"] == ip_addr), None)
        if not entry:
            raise HTTPException(status_code=404, detail="ip not found in pool")
        entry["assigned_user"] = user_id
        entry["status"] = "assigned"

    async with USER_IP_MAP_LOCK:
        USER_IP_MAP[user_id].add(ip_addr)

    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به کاربر «{user_id}» اختصاص یافت", "info")
    return {"ok": True, "user_id": user_id, "ip": ip_addr}


@app.get("/api/ips/test")
async def test_ips(_=Depends(require_auth)):
    """Return simulated ping results for pool IPs."""
    import random
    async with IP_POOL_LOCK:
        ips = list(IP_POOL)
    results = []
    for entry in ips:
        latency = random.randint(20, 350)
        status = "ok" if latency < 300 else "timeout"
        results.append({
            "ip": entry["ip"],
            "latency_ms": latency,
            "status": status,
            "location": entry.get("location", "Unknown"),
            "assigned_user": entry.get("assigned_user"),
            "tested_at": datetime.now().isoformat(),
        })
    results.sort(key=lambda x: x["latency_ms"])
    return {"results": results, "tested_at": datetime.now().isoformat()}


@app.get("/api/ips/check")
async def check_ip(request: Request, _=Depends(require_auth)):
    """Check if an IP is in the blacklist."""
    ip_addr = request.query_params.get("ip", "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip query param is required")
    async with IP_BLACKLIST_LOCK:
        blacklisted = ip_addr in IP_BLACKLIST
    return {"ip": ip_addr, "blacklisted": blacklisted}


# ══════════════════════════════════════════════════════════════════════════════
# LIVE SERVER STATS — Helpers & WebSocket
# ══════════════════════════════════════════════════════════════════════════════

ws_client_count = 0
WS_LIVE_CLIENTS: set = set()

def get_live_stats() -> dict:
    """Get real server stats using psutil with fallback."""
    conn_count = len(connections)
    try:
        import psutil as _ps
        cpu_pct = round(_ps.cpu_percent(interval=0.3), 1)
        mem = _ps.virtual_memory()
        ram_pct = round(mem.percent, 1)
        ram_used_gb = round(mem.used / (1024**3), 2)
        ram_total_gb = round(mem.total / (1024**3), 2)
        disk = _ps.disk_usage('/')
        disk_pct = round(disk.percent, 1)
        disk_used_gb = round(disk.used / (1024**3), 2)
        disk_total_gb = round(disk.total / (1024**3), 2)
        net = _ps.net_io_counters()
        net_sent_mb = round(net.bytes_sent / (1024**2), 2)
        net_recv_mb = round(net.bytes_recv / (1024**2), 2)
        network_mbps = round(max((net.bytes_sent + net.bytes_recv) / (1024**2) / max(uptime_secs(), 1) * 8, 0.5), 2)
    except Exception:
        cpu_pct = round(min(conn_count * 0.3 + 5, 95), 1)
        ram_pct = round(min(45 + len(USERS) * 0.5 + conn_count * 0.1, 95), 1)
        ram_used_gb = round(ram_pct / 100 * 8, 2)
        ram_total_gb = 8
        disk_pct = round(min(25 + len(LINKS) * 0.02 + len(USERS) * 0.1, 90), 1)
        disk_used_gb = round(disk_pct / 100 * 50, 2)
        disk_total_gb = 50
        net_sent_mb = 0
        net_recv_mb = 0
        network_mbps = 2.5
    # Calculate total traffic from all users
    total_used = sum(u.get("traffic_used_bytes", 0) for u in USERS.values())
    total_limit = sum(u.get("traffic_limit_bytes", 0) for u in USERS.values())
    return {
        "cpu_percent": max(0, cpu_pct),
        "ram_percent": max(0, ram_pct),
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "disk_percent": max(0, disk_pct),
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "network_mbps": network_mbps,
        "net_sent_mb": net_sent_mb,
        "net_recv_mb": net_recv_mb,
        "net_total_mb": round(net_sent_mb + net_recv_mb, 2),
        "active_connections": conn_count,
        "ws_connections": ws_client_count,
        "total_users": len(USERS),
        "total_traffic_used_tb": round(total_used / (1024**4), 3),
        "total_traffic_used_gb": round(total_used / (1024**3), 2),
        "total_traffic_limit_tb": round(total_limit / (1024**4), 3) if total_limit > 0 else 0,
        "uptime": uptime(),
        "uptime_seconds": uptime_secs(),
        "timestamp": datetime.now().isoformat(),
    }


@app.websocket("/ws/live")
async def websocket_live_stats(websocket: WebSocket):
    global ws_client_count
    await websocket.accept()
    ws_client_count += 1
    WS_LIVE_CLIENTS.add(websocket)
    try:
        while True:
            try:
                stats_data = get_live_stats()
                await websocket.send_json(stats_data)
                await asyncio.sleep(2)
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        ws_client_count = max(0, ws_client_count - 1)
        WS_LIVE_CLIENTS.discard(websocket)


# ══════════════════════════════════════════════════════════════════════════════
# IP LIMIT ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/users/{user_id}/ip-check")
async def check_user_ip_limit(user_id: str, _=Depends(require_auth)):
    """Check if a user is within their IP limit."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        username = u.get("username")

    async with USER_IP_MAP_LOCK:
        ip_count = len(USER_IP_MAP.get(user_id, set()))

    async with SETTINGS_LOCK:
        max_ip = SETTINGS.get("max_ip_per_user", 3)

    within_limit = ip_count < max_ip
    return {
        "user_id": user_id,
        "username": username,
        "current_ip_count": ip_count,
        "max_ip_per_user": max_ip,
        "within_limit": within_limit,
        "ips": list(USER_IP_MAP.get(user_id, set())),
    }


async def _resolve_user_id_for_link(uuid: str) -> str | None:
    """Map a link/config UUID back to its owning user id.

    Priority: LINKS[link].user_id (explicit link) → USERS entry whose
    config_uuid matches (user-driven links) → a USERS key equal to the uuid.
    """
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
        if link and link.get("user_id"):
            return link["user_id"]
    for uid, u in USERS.items():
        if (u.get("config_uuid") or "") == uuid:
            return uid
    if uuid in USERS:
        return uuid
    return None


def _parse_proxy_entry(entry: str) -> dict | None:
    """Parse a proxy entry like the BPB worker does.

    Accepts: ip:port, user:pass@ip:port, socks5://user:pass@ip:port,
    http://ip:port, https://ip:port. Auth may be plain "user:pass" or a
    base64 blob. Returns {protocol, username, password, hostname, port}
    or None on invalid input.
    """
    import base64 as _b64
    import re as _re

    if not entry:
        return None
    e = str(entry).strip()
    # Strip leading protocol
    proto = "http"
    m = _re.match(r"^(socks5|socks4|http|https|turn|sstp)://", e, _re.I)
    if m:
        proto = m.group(1).lower()
        e = e[m.end():]
    # Drop fragment
    e = e.split("#")[0].strip()

    at = e.rfind("@")
    hostpart = e[at + 1:] if at != -1 else e
    authpart = e[:at] if at != -1 else ""
    username = password = None
    if authpart:
        # base64-encoded auth (worker supports it)
        b64re = _re.compile(r"^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$", _re.I)
        a = authpart.replace("%3D", "=")
        if ":" not in a and b64re.match(a):
            try:
                a = _b64.b64decode(a).decode("utf-8", "ignore")
            except Exception:
                a = authpart
        if ":" in a:
            username, password = a.split(":", 1)
        else:
            return None
    if hostpart.startswith("["):
        # IPv6 [::1]:port
        if "]:" in hostpart:
            h, _, rest = hostpart.partition("]:")
            hostname = h + "]"
            pport = rest.strip()
        else:
            hostname, pport = hostpart, ""
    elif ":" in hostpart:
        hostname, _, pport = hostpart.rpartition(":")
    else:
        hostname, pport = hostpart, ""
    try:
        port = int(pport) if pport else 80
    except ValueError:
        return None
    if not hostname:
        return None
    return {"protocol": proto, "username": username, "password": password,
            "hostname": hostname, "port": port}


async def _close_writer_safely(wtr):
    try:
        wtr.close()
        await wtr.wait_closed()
    except Exception:
        pass


async def _socks5_connect(proxy: dict, address: str, port: int):
    """SOCKS5 CONNECT through the proxy, mirroring the worker's socks5Connect."""
    import socket as _sock
    rdr, wtr = await asyncio.wait_for(
        asyncio.open_connection(proxy["hostname"], proxy["port"]), timeout=4.0
    )
    try:
        # Method negotiation
        methods = bytes([0x05, 0x02, 0x00, 0x02]) if proxy.get("username") else bytes([0x05, 0x01, 0x00])
        wtr.write(methods)
        await wtr.drain()
        resp = await asyncio.wait_for(rdr.readexactly(2), timeout=4.0)
        if resp[1] == 0x02:
            if not proxy.get("username"):
                raise ConnectionError("socks5 requires auth")
            ub = proxy["username"].encode()
            pb = proxy["password"].encode()
            wtr.write(bytes([0x01, len(ub)]) + ub + bytes([len(pb)]) + pb)
            await wtr.drain()
            auth = await asyncio.wait_for(rdr.readexactly(2), timeout=4.0)
            if auth[1] != 0x00:
                raise ConnectionError("socks5 auth failed")
        elif resp[1] != 0x00:
            raise ConnectionError(f"socks5 unsupported auth method {resp[1]}")
        return await _socks5_connect_send(proxy, address, port, rdr, wtr, _sock)
    except BaseException:
        await _close_writer_safely(wtr)
        raise


async def _socks5_connect_send(proxy: dict, address: str, port: int, rdr, wtr, _sock):
    """Send the SOCKS5 CONNECT packet and consume the full reply."""
    # CONNECT
    try:
        try:
            hb = _sock.inet_aton(address)
            atyp = 0x01
        except OSError:
            if ":" in address:  # IPv6
                atyp, hb = 0x04, _sock.inet_pton(_sock.AF_INET6, address)
            else:  # domain
                eb = address.encode()
                atyp, hb = 0x03, bytes([len(eb)]) + eb
        pkt = bytes([0x05, 0x01, 0x00, atyp]) + hb + bytes([port >> 8, port & 0xff])
        wtr.write(pkt)
        await wtr.drain()
        resp = await asyncio.wait_for(rdr.readexactly(4), timeout=4.0)
        if resp[1] != 0x00:
            raise ConnectionError(f"socks5 connect failed code={resp[1]}")
        # Consume the reply's BND.ADDR + BND.PORT so those bytes don't leak into
        # the relay's first read of the tunneled stream (RFC 1928 reply = VER REP
        # RSV ATYP BND.ADDR BND.PORT). ATYP of the reply drives the length.
        ratyp = resp[3]
        if ratyp == 0x01:
            await asyncio.wait_for(rdr.readexactly(4 + 2), timeout=4.0)
        elif ratyp == 0x04:
            await asyncio.wait_for(rdr.readexactly(16 + 2), timeout=4.0)
        elif ratyp == 0x03:
            ln = (await asyncio.wait_for(rdr.readexactly(1), timeout=4.0))[0]
            await asyncio.wait_for(rdr.readexactly(ln + 2), timeout=4.0)
        return rdr, wtr
    except BaseException:
        await _close_writer_safely(wtr)
        raise


async def _http_connect(proxy: dict, address: str, port: int, tls: bool = False):
    """HTTP CONNECT through the proxy, mirroring the worker's httpConnect."""
    rdr, wtr = await asyncio.wait_for(
        asyncio.open_connection(proxy["hostname"], proxy["port"]), timeout=4.0
    )
    try:
        host_header = f"[{address}]" if ":" in address else address
        auth = ""
        if proxy.get("username"):
            import base64 as _b64
            token = _b64.b64encode(f"{proxy['username']}:{proxy.get('password') or ''}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {token}\r\n"
        req = (f"CONNECT {host_header}:{port} HTTP/1.1\r\n"
               f"Host: {host_header}:{port}\r\n{auth}"
               f"User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n")
        wtr.write(req.encode())
        await wtr.drain()
        status = await asyncio.wait_for(rdr.readline(), timeout=4.0)
        # Skip headers
        while True:
            line = await asyncio.wait_for(rdr.readline(), timeout=8.0)
            if line in (b"\r\n", b"\n", b""):
                break
        if not re.search(rb"HTTP/\d\.\d 200", status):
            raise ConnectionError(f"http connect failed {status.decode().strip()}")
        return rdr, wtr
    except BaseException:
        await _close_writer_safely(wtr)
        raise


_PROXY_DOH_CACHE: dict = {}   # (host, type) -> list[str]


async def _resolve_proxy_targets(token: str):
    """Resolve a proxy token to concrete IPv4/IPv6 targets.

    Supports:
      - IP:PORT
      - user:pass@host:PORT
      - socks5://user:pass@host:PORT
      - domain.tp8443
      - plain domains (default port 443 for proxy lists)

    Authentication/scheme are kept by _build_proxy_candidates(); this helper
    only returns host/port pairs.
    """
    import ipaddress as _ipa

    token = str(token or "").strip()
    if not token:
        return []

    raw = re.sub(r"^(?:socks5|socks4|http|https|turn|sstp)://", "", token, flags=re.I)
    # Credentials do not belong in DNS hostnames.
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]

    host = raw
    port = 443

    # Bracketed IPv6.
    if host.startswith("[") and "]" in host:
        close = host.find("]")
        base = host[:close + 1]
        rest = host[close + 1:]
        host = base
        if rest.startswith(":"):
            try:
                port = int(rest[1:].strip())
            except ValueError:
                port = 443
    elif ":" in host:
        possible_host, possible_port = host.rsplit(":", 1)
        if possible_port.isdigit():
            host = possible_host
            port = int(possible_port)

    # Custom .tpN notation used by the worker/source lists.
    tp_m = re.search(r"\.tp(\d+)$", host, re.I)
    if tp_m:
        port = int(tp_m.group(1))
        host = re.sub(r"\.tp\d+$", "", host, flags=re.I)

    host = host.strip("[]").strip()
    if not host or not 1 <= port <= 65535:
        return []

    def _is_ip(h: str) -> bool:
        try:
            _ipa.ip_address(h)
            return True
        except ValueError:
            return False

    if _is_ip(host):
        return [[host, port]]

    cache_key = (host.lower(), "IP")
    cache_hit = _PROXY_DOH_CACHE.get(cache_key)
    if cache_hit and cache_hit["expires"] > time.time():
        return [[ip, port] for ip in cache_hit["ips"]]

    try:
        infos = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: [i[4][0] for i in socket.getaddrinfo(
                    host, None, type=socket.SOCK_STREAM
                )]
            ),
            timeout=2.5,
        )
        ips = list(dict.fromkeys(infos))
        if ips:
            _PROXY_DOH_CACHE[cache_key] = {
                "ips": ips,
                "expires": time.time() + 300,
            }
        return [[ip, port] for ip in ips]
    except Exception:
        return [[host, port]]


def _expand_proxy_tokens(tokens):
    """Mirror worker's 整理成数组: split on comma/tab/newline/quote -> clean list."""
    if isinstance(tokens, (list, tuple)):
        raw = ",".join(str(t) for t in tokens)
    else:
        raw = str(tokens or "")
    cleaned = re.sub(r'[\t"\'\r\n]+', ",", raw)
    cleaned = re.sub(r",+", ",", cleaned)
    return [p.strip() for p in cleaned.split(",") if p.strip()]


def _build_vless_connect_header(uuid: str, address: str, port: int) -> bytes:
    """Rebuild a VLESS CONNECT header for a raw relay (ZEUS-style).

    The proxy's relay reads this header, connects to `address:port`, and then
    tunnels the remaining payload (which the caller writes right after this
    header). Format: version(1) uuid(16) opt_len(1) cmd(1) port(2) atype(1) addr.
    """
    import socket as _sock
    try:
        hb = _sock.inet_aton(address)
        atype, ab = 0x01, hb
    except OSError:
        if ":" in address:
            atype, ab = 0x04, _sock.inet_pton(_sock.AF_INET6, address)
        else:
            eb = address.encode()
            atype, ab = 0x03, bytes([len(eb)]) + eb
    raw_uuid = uuid.replace("-", "")
    if len(raw_uuid) != 32:
        raw_uuid = (raw_uuid + "0" * 32)[:32]
    ubytes = bytes.fromhex(raw_uuid)
    return (b"\x00" + ubytes + b"\x00\x01"
            + bytes([port >> 8, port & 0xff]) + bytes([atype]) + ab)


async def proxy_connect(
    uuid: str, address: str, port: int, proxy_override: str = None
):
    """Open an outbound stream using the lowest-latency viable proxy path.

    The relay does not split one TCP stream across several sockets. Instead it
    races independent proxy paths for each browser-created connection. This is
    safe for HTTP/TLS/WebSocket streams and reduces connect-time variance.
    """
    user_id = await _resolve_user_id_for_link(uuid)
    entries: list[str] = []

    if proxy_override:
        entries = [proxy_override.strip()]
    elif user_id:
        async with USERS_LOCK:
            user = USERS.get(user_id)
            if user:
                entries = [
                    str(item).strip()
                    for item in (user.get("proxy_ips") or [])
                    if str(item).strip()
                ]

    if entries:
        candidates: list[dict] = []

        for entry in entries:
            try:
                targets = await _resolve_proxy_targets(entry)
                candidates.extend(
                    _build_proxy_candidates(entry, targets)
                )
            except Exception:
                continue

        unique: dict[str, dict] = {}
        for candidate in candidates:
            unique.setdefault(
                _relay_proxy_key(candidate), candidate
            )

        ordered = await _relay_rank_proxies(
            list(unique.values())
        )
        result = await _race_proxy_candidates(
            ordered, address, port, uuid
        )
        if result:
            conn, proxy, elapsed_ms = result
            _tune_relay_socket(conn[1])
            logger.info(
                "proxy_connect[race] %s:%s via %s:%s %.1fms",
                address,
                port,
                proxy.get("hostname"),
                proxy.get("port"),
                elapsed_ms,
            )
            return conn

        logger.warning(
            "proxy_connect pool failed for %s",
            ",".join(entries)[:300],
        )

    # Direct fallback stays last so an unhealthy proxy never causes an
    # accidental egress-IP leak during the racing phase.
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port),
        timeout=RELAY_DIRECT_CONNECT_TIMEOUT,
    )
    _tune_relay_socket(writer)
    return reader, writer


def _order_for(proto: str):
    if proto in ("socks5", "socks4"):
        return ["socks5", "http"]
    return ["http", "socks5"]


async def _try_proxy_order(proxy, address, port):
    for protocol in _order_for(
        proxy.get("protocol", "http")
    ):
        try:
            if protocol == "socks5":
                reader, writer = await _socks5_connect(
                    proxy, address, port
                )
            else:
                reader, writer = await _http_connect(
                    proxy,
                    address,
                    port,
                    tls=(proxy.get("protocol") == "https"),
                )
            _tune_relay_socket(writer)
            return reader, writer
        except Exception:
            continue
    return None


async def _link_max_ip(uuid: str) -> int:
    """Per-user concurrent_connections, falling back to global max_ip_per_user."""
    user_id = await _resolve_user_id_for_link(uuid)
    if user_id:
        async with USERS_LOCK:
            u = USERS.get(user_id)
        if u:
            _cc = u.get("concurrent_connections")
            return int(_cc) if _cc is not None else 0
    # No registered user → use global setting (covers raw links / group links)
    async with SETTINGS_LOCK:
        _mip = SETTINGS.get("max_ip_per_user")
        return int(_mip) if _mip is not None else 3

async def enforce_ip_limit_for_link(uuid: str, ip: str) -> bool:
    """Real per-user concurrent-IP limit enforcement.

    Called from the WS/XHTTP entrypoints with the actual client IP. Tracks the
    IP in USER_IP_MAP (the same store the dashboard's ip-check endpoint reads),
    so the panel shows real connected IPs instead of fake/manual assignments.
    Rejects the connection (returns False) when the user's IP count already
    reached the configured concurrent_connections / max_ip_per_user limit.

    NOTE: the relay modules import main lazily (avoiding circular imports), so
    they can call this function at connection time.
    """
    if not ip or ip in ("نامشخص", "unknown", "127.0.0.1"):
        return True

    max_ip = await _link_max_ip(uuid)
    if max_ip < 1:
        return True

    user_id = await _resolve_user_id_for_link(uuid)
    if not user_id:
        # No registered user → fall back to per-uuid tracking so the limit
        # still applies to raw links (default link, sub-group links, etc.)
        user_id = f"link:{uuid}"

    async with USER_IP_MAP_LOCK:
        ips = USER_IP_MAP[user_id]
        if ip in ips:
            # Same IP reconnecting → always allowed
            return True
        if len(ips) >= max_ip:
            return False
        ips.add(ip)
    asyncio.create_task(save_state())
    return True

async def release_ip_for_link(uuid: str, ip: str) -> None:
    """Remove a formerly-connected IP for a user/link.

    Called when a WS/XHTTP relay tears down so USER_IP_MAP reflects the *real*
    set of currently-connected IPs rather than stale historical assignments.
    """
    if not ip or ip in ("نامشخص", "unknown", "127.0.0.1"):
        return
    user_id = await _resolve_user_id_for_link(uuid)
    if not user_id:
        user_id = f"link:{uuid}"
    async with USER_IP_MAP_LOCK:
        s = USER_IP_MAP.get(user_id)
        if s:
            s.discard(ip)
    asyncio.create_task(save_state())


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/tools/config-generator")
async def config_generator(request: Request, _=Depends(require_auth)):
    """Generate a connection config string for given parameters."""
    body = await request.json()
    protocol = str(body.get("protocol", "vless")).lower()
    host = str(body.get("host", get_host())).strip()
    config_uuid = str(body.get("uuid") or generate_uuid())
    remark = str(body.get("remark", "Generated"))

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol. Must be one of: {', '.join(USER_PROTOCOLS)}")

    # Build a temporary user-like dict for generate_user_config
    temp_user = {
        "protocol": protocol,
        "config_uuid": config_uuid,
        "username": remark,
    }
    # Override host temporarily
    original_host = CONFIG.get("host")
    CONFIG["host"] = host
    config = generate_user_config("temp", temp_user)
    if original_host:
        CONFIG["host"] = original_host

    return {
        "protocol": protocol,
        "host": host,
        "uuid": config_uuid,
        "remark": remark,
        "config": config,
        "generated_at": datetime.now().isoformat(),
    }


@app.post("/api/tools/ip-test")
async def ip_test(request: Request, _=Depends(require_auth)):
    """Simulated ping test for a given IP."""
    import random
    body = await request.json()
    ip_addr = str(body.get("ip", "")).strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")

    # Simple IP format check
    parts = ip_addr.split(".")
    valid_format = len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if not valid_format:
        raise HTTPException(status_code=400, detail="invalid ip format")

    latency = random.randint(10, 400)
    status = "reachable" if latency < 350 else "unreachable"

    # Check blacklist
    async with IP_BLACKLIST_LOCK:
        blacklisted = ip_addr in IP_BLACKLIST

    return {
        "ip": ip_addr,
        "latency_ms": latency,
        "status": status,
        "blacklisted": blacklisted,
        "tested_at": datetime.now().isoformat(),
    }


@app.get("/api/tools/stress-test")
async def stress_test(_=Depends(require_auth)):
    """Simulated server load stats."""
    import random
    conn_count = len(connections)
    load_factor = min(conn_count / 500, 1.0) * 100
    return {
        "timestamp": datetime.now().isoformat(),
        "load_percent": round(load_factor, 1),
        "active_connections": conn_count,
        "max_theoretical_connections": 500,
        "cpu_percent": round(min(conn_count * 0.35 + random.uniform(2, 8), 95), 1),
        "ram_percent": round(min(50 + conn_count * 0.08 + random.uniform(1, 5), 95), 1),
        "disk_iops": random.randint(100, 2000),
        "network_mbps": round(random.uniform(2, 80), 2),
        "requests_per_second": stats.get("total_requests", 0) / max(time.time() - stats["start_time"], 1),
        "status": "healthy" if load_factor < 70 else ("degraded" if load_factor < 90 else "critical"),
    }


@app.post("/api/tools/bulk-create")
async def bulk_create_users(request: Request, _=Depends(require_auth)):
    """Create multiple users at once based on a template."""
    body = await request.json()
    count = int(body.get("count", 1))
    if count < 1:
        raise HTTPException(status_code=400, detail="count must be at least 1")
    if count > 100:
        raise HTTPException(status_code=400, detail="count cannot exceed 100")

    template = body.get("template", {})
    base_username = str(template.get("username_prefix", "bulk")).strip()[:20]
    protocol = str(template.get("protocol", "vless")).lower()
    traffic_limit_gb = float(template.get("traffic_limit_gb") or 0)
    expire_days = int(template.get("expire_days") or 0)
    concurrent = int(template.get("concurrent_connections") or 0)
    server = str(template.get("server", "IR-Tehran-01")).strip()[:40]

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

    created = []
    async with USERS_LOCK:
        for i in range(count):
            user_id = generate_short_id()
            username = f"{base_username}{i + 1}"
            # Avoid duplicates: append random suffix if needed
            if any(u.get("username") == username for u in USERS.values()):
                username = f"{base_username}{i + 1}_{secrets.token_hex(3)}"
            config_uuid = generate_uuid()
            traffic_limit_bytes = int(traffic_limit_gb * 1024 ** 3) if traffic_limit_gb > 0 else 0
            expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
            USERS[user_id] = {
                "username": username,
                "password_hash": hash_password(secrets.token_urlsafe(8)),
                "protocol": protocol,
                "traffic_limit_bytes": traffic_limit_bytes,
                "traffic_used_bytes": 0,
                "expire_at": expire_at,
                "concurrent_connections": concurrent,
                "created_at": datetime.now().isoformat(),
                "status": "active",
                "server": server,
                "config_uuid": config_uuid,
                "subscription_uuid": secrets.token_urlsafe(16),
            }
            if protocol == "telegram":
                USERS[user_id]["telegram_secret"] = derive_secret_from_uuid(config_uuid)
            created.append({"user_id": user_id, "username": username})

    asyncio.create_task(save_state())
    log_activity("user", f"{count} کاربر به‌صورت انبوه ساخته شد", "ok")
    return {"ok": True, "created_count": len(created), "users": created}


# ══════════════════════════════════════════════════════════════════════════════
# SERVER RESOURCES (neon bars)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/server/resources")
async def server_resources(_=Depends(require_auth)):
    """Return live CPU, RAM, Disk, uptime for neon status bars."""
    try:
        import psutil
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "cpu_count": psutil.cpu_count(),
            "ram_percent": psutil.virtual_memory().percent,
            "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 1),
            "ram_used_gb": round(psutil.virtual_memory().used / 1024**3, 1),
            "disk_percent": psutil.disk_usage("/").percent,
            "disk_total_gb": round(psutil.disk_usage("/").total / 1024**3, 1),
            "net_sent_mb": round(psutil.net_io_counters().bytes_sent / 1024**2, 1),
            "net_recv_mb": round(psutil.net_io_counters().bytes_recv / 1024**2, 1),
            "uptime_seconds": int(time.time() - stats.get("start_time", time.time())),
        }
    except ImportError:
        return {"error": "psutil not installed", "cpu_percent": 0, "ram_percent": 0, "disk_percent": 0}


# ══════════════════════════════════════════════════════════════════════════════
# XRAY CORE CONFIG GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_xray_server_config(inbound_id: str = None) -> dict:
    """
    Generate a complete Xray-core server config.json based on inbound settings.
    Returns a dict that can be saved as config.json for Xray core.
    """
    inbound = None
    if inbound_id:
        inbound = INBOUNDS.get(inbound_id)
    
    host = SETTINGS.get("domain") or get_host()
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": []
        }
    }
    
    if not inbound:
        # Generate for all inbounds
        for iid, ib in INBOUNDS.items():
            _add_inbound_to_xray(xray_config, ib, iid, host)
    else:
        _add_inbound_to_xray(xray_config, inbound, inbound_id, host)
    
    return xray_config


def _add_inbound_to_xray(cfg: dict, ib: dict, iid: str, host: str):
    """Add a single inbound to an Xray config dict.

    Reality inbounds are served natively by Xray. Native VMess/Trojan inbounds
    are also emitted when they use Reality security. Plain VMess can be emitted
    on a dedicated TCP port. Ordinary public TLS VMess/Trojan still requires a
    real certificate on the Xray host, so the panel never invents certificate paths.
    """
    protocol = ib.get("protocol", "vless")
    security = ib.get("security", "tls")
    is_reality = protocol == "reality" or security == "reality"
    if not is_reality and protocol not in ("vmess", "trojan"):
        return  # TLS WS/XHTTP + worker inbounds are handled by their relays
    # A reality inbound without a configured port is not ready yet — skip it
    # so Xray doesn't start on a wrong/default port.
    _raw_port = str(ib.get("port") or "").strip()
    if not _raw_port:
        return
    # Xray listens on the INTERNAL port; the external port is the Railway TCP
    # proxy port that forwards to it (client config uses external_port).
    port = int(_raw_port)
    network = ib.get("network", "ws")
    domain = ib.get("domain", host)
    sni_val = ib.get("sni", domain)
    fingerprint = ib.get("fingerprint", "chrome")
    rs = ib.get("reality_settings", {}) if (protocol == "reality" or security == "reality") else {}
    ws_settings = ib.get("ws_settings", {})
    xh_settings = ib.get("xhttp_settings", {})
    grpc_settings = ib.get("grpc_settings", {})
    
    xray_protocol = "vless" if protocol == "reality" else protocol
    inbound_settings = {"clients": []}
    if xray_protocol == "vless":
        inbound_settings["decryption"] = "none"
    inbound_obj = {
        "tag": f"inbound-{iid}",
        "listen": "0.0.0.0",
        "port": port,
        # Reality is a security layer. A Reality inbound declared as protocol
        # `reality` is invalid in Xray, so only that case maps to VLESS.
        "protocol": xray_protocol,
        "settings": inbound_settings,
        "streamSettings": {}
    }

    # Protocol-specific client settings — use REAL user UUIDs that picked this
    # inbound so they can actually connect through Xray. (Reality is a VLESS
    # client too, so it also carries uuid clients.)
    # Only users that are currently allowed (active + not expired + quota left)
    # are served — expired/disabled/quota-exceeded users are dropped so Xray
    # rejects their connections (real expiry/volume enforcement for Reality).
    if protocol in ("vless", "reality", "vmess", "trojan"):
        client_ids = set()
        for u in USERS.values():
            uids = u.get("inbound_ids") or ([u.get("inbound_id")] if u.get("inbound_id") else [])
            if iid in uids and u.get("config_uuid") and is_user_allowed(u):
                client_ids.add(u["config_uuid"])
        if not client_ids:
            # Keep a valid placeholder only when the inbound currently has no
            # active users. Never add a malformed/legacy user UUID.
            client_ids.add(str(uuid.uuid4()))
        clients = []
        for uid in client_ids:
            matched_user = next((uu for uu in USERS.values() if uu.get("config_uuid") == uid), {})
            if protocol in ("vless", "reality"):
                client = {"id": uid, "flow": ""}
            elif protocol == "vmess":
                client = {"id": uid, "alterId": 0, "security": "auto"}
            elif protocol == "trojan":
                # Trojan authenticates by password. A VLESS/VMess UUID field
                # is not part of a Trojan client and can make Xray reject it.
                client = {"password": str(matched_user.get("trojan_password") or matched_user.get("config_uuid") or uid)}
            clients.append(client)
        inbound_obj["settings"]["clients"] = clients

    # Transport / Stream settings
    if protocol == "reality" or security == "reality":
        # The Reality target is authoritative from this inbound's own
        # SNI/Destination/Server Names. Do not silently replace it with a
        # hard-coded target, otherwise the client SNI and Xray destination can
        # describe different TLS targets.
        rs_sni = str(rs.get("sni") or ib.get("sni") or "is1-ssl.mzstatic.com").strip()
        rs_dest = str(rs.get("dest") or (rs_sni + ":443")).strip()
        if "://" in rs_dest:
            rs_dest = rs_dest.split("://", 1)[1]
        rs_server_names = rs.get("server_names") or rs.get("serverNames") or [rs_sni]
        if isinstance(rs_server_names, str):
            rs_server_names = [x.strip() for x in rs_server_names.split(",") if x.strip()]
        if not rs_server_names:
            rs_server_names = [rs_sni]
        private_key = _xray_x25519_privkey_norm(str(rs.get("private_key") or ""))
        if not private_key:
            private_key = str(rs.get("private_key") or "").strip()
        short_id = str(rs.get("short_id") or rs.get("short_ids") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{1,16}", short_id or "") or len(short_id) % 2:
            short_id = secrets.token_hex(5)
        reality_settings = {
            "show": False,
            "target": rs_dest,
            "xver": 0,
            "serverNames": rs_server_names,
            "privateKey": private_key,
            "shortIds": [short_id],
        }
        # ML-DSA-65 is optional. Emit the fields only when a real seed was
        # generated by Xray and passed validation; never send stale placeholders.
        if _valid_mldsa65_seed(str(rs.get("mldsa65_seed") or "")):
            reality_settings["mldsa65Seed"] = rs["mldsa65_seed"]
        inbound_obj["streamSettings"] = {
            "network": network if network in ("tcp", "xhttp", "grpc") else "tcp",
            "security": "reality",
            "realitySettings": reality_settings,
        }
        _fm = ib.get("finalmask") or {}
        if isinstance(_fm, dict) and _fm:
            inbound_obj["streamSettings"]["finalmask"] = _fm
        if network == "xhttp":
            _xhttp_path = str(xh_settings.get("path") or "/").strip()
            if not _xhttp_path.startswith("/") or "#" in _xhttp_path or "?" in _xhttp_path:
                _xhttp_path = "/"
            _xhttp_mode = str(xh_settings.get("mode") or "stream-up").strip().lower()
            if _xhttp_mode == "auto" or _xhttp_mode not in ("packet-up", "stream-up", "stream-one"):
                _xhttp_mode = "stream-up"
            inbound_obj["streamSettings"]["xhttpSettings"] = {
                "path": _xhttp_path,
                "host": str(xh_settings.get("host") or "").strip(),
                "mode": _xhttp_mode,
                "xPaddingBytes": xh_settings.get("xPaddingBytes", "100-1000"),
                "scMaxEachPostBytes": xh_settings.get("scMaxEachPostBytes", "1000000"),
                "scMaxBufferedPosts": xh_settings.get("scMaxBufferedPosts", 30),
                "scStreamUpServerSecs": xh_settings.get("scStreamUpServerSecs", "20-80"),
            }
    elif protocol in ("vmess", "trojan") and security == "none":
        inbound_obj["streamSettings"] = {"network": network if network in ("tcp", "ws", "grpc") else "tcp", "security": "none"}
        if network == "ws":
            inbound_obj["streamSettings"]["wsSettings"] = {"path": ws_settings.get("path", "/"), "headers": {"Host": ws_settings.get("host", domain)}}
        elif network == "grpc":
            inbound_obj["streamSettings"]["grpcSettings"] = {"serviceName": grpc_settings.get("serviceName", "pars-space")}
    elif security == "tls":
        # Native TLS requires certificate files explicitly supplied to Xray.
        cert_file = os.environ.get("XRAY_CERT_FILE", "/etc/xray/cert.pem")
        key_file = os.environ.get("XRAY_KEY_FILE", "/etc/xray/key.pem")
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            logger.warning("Skipping native TLS %s inbound %s: certificate files are not present", protocol, iid)
            return
        inbound_obj["streamSettings"] = {
            "network": network,
            "security": "tls",
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "/etc/xray/cert.pem",
                    "keyFile": "/etc/xray/key.pem"
                }]
            }
        }
        if network == "ws":
            inbound_obj["streamSettings"]["wsSettings"] = {
                "path": ws_settings.get("path", "/"),
                "headers": {"Host": ws_settings.get("host", domain)}
            }
        elif network == "grpc":
            inbound_obj["streamSettings"]["grpcSettings"] = {
                "serviceName": grpc_settings.get("serviceName", "")
            }
        elif network == "xhttp":
            inbound_obj["streamSettings"]["xhttpSettings"] = {
                "path": xh_settings.get("path", "/"),
                "host": xh_settings.get("host", domain),
                "mode": xh_settings.get("mode", "auto"),
                "xPaddingBytes": xh_settings.get("xPaddingBytes", "100-1000"),
                "scMaxEachPostBytes": xh_settings.get("scMaxEachPostBytes", "1000000"),
            }
    else:
        # No TLS (raw)
        inbound_obj["streamSettings"] = {"network": network}
        if network == "ws":
            inbound_obj["streamSettings"]["wsSettings"] = {"path": ws_settings.get("path", "/")}
    
    _fm = ib.get("finalmask") or {}
    if isinstance(_fm, dict) and _fm:
        inbound_obj["streamSettings"]["finalmask"] = _fm

    # Add sniffing
    inbound_obj["sniffing"] = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic"]
    }
    
    cfg["inbounds"].append(inbound_obj)


def _validate_xray_server_config(config: dict) -> list[str]:
    """Fail closed on malformed Xray Reality/XHTTP configs before spawning Xray."""
    errors = []
    seen = set()
    for ib in config.get("inbounds") or []:
        try:
            port = int(ib.get("port"))
        except Exception:
            port = 0
        if not 1 <= port <= 65535:
            errors.append(f"{ib.get('tag')}: invalid port {ib.get('port')!r}")
        listen = str(ib.get("listen") or "")
        key = (listen, port)
        if key in seen:
            errors.append(f"{ib.get('tag')}: duplicate listener {listen}:{port}")
        seen.add(key)
        protocol = str(ib.get("protocol") or "")
        clients = ((ib.get("settings") or {}).get("clients") or [])
        if protocol == "vless":
            for client in clients:
                uid = str(client.get("id") or "")
                try:
                    uuid.UUID(uid)
                except Exception:
                    errors.append(f"{ib.get('tag')}: invalid VLESS client UUID {uid!r}")
        elif protocol == "vmess":
            for client in clients:
                uid = str(client.get("id") or "")
                try:
                    uuid.UUID(uid)
                except Exception:
                    errors.append(f"{ib.get('tag')}: invalid VMess client UUID {uid!r}")
                if "password" in client:
                    errors.append(f"{ib.get('tag')}: VMess client must not use Trojan password")
        elif protocol == "trojan":
            for client in clients:
                if not str(client.get("password") or "").strip():
                    errors.append(f"{ib.get('tag')}: Trojan client password is empty")
                if "id" in client:
                    errors.append(f"{ib.get('tag')}: Trojan client must not contain UUID id")
        else:
            errors.append(f"{ib.get('tag')}: unsupported native Xray protocol {protocol!r}")
        ss = ib.get("streamSettings") or {}
        if ss.get("security") != "reality":
            errors.append(f"{ib.get('tag')}: security must be reality")
        rs = ss.get("realitySettings") or {}
        private = str(rs.get("privateKey") or "")
        if not _xray_x25519_privkey_norm(private):
            errors.append(f"{ib.get('tag')}: invalid Reality privateKey")
        sids = rs.get("shortIds") or []
        if not sids or any(not re.fullmatch(r"[0-9a-fA-F]{2,16}", str(x)) or len(str(x)) % 2 for x in sids):
            errors.append(f"{ib.get('tag')}: invalid Reality shortIds")
        names = rs.get("serverNames") or []
        if not isinstance(names, list) or not names or any(not str(x).strip() for x in names):
            errors.append(f"{ib.get('tag')}: serverNames is empty")
        elif any("*" in str(x) for x in names):
            errors.append(f"{ib.get('tag')}: Reality serverNames must not contain wildcard '*' entries")
        if ss.get("network") == "xhttp":
            xh = ss.get("xhttpSettings") or {}
            path = str(xh.get("path") or "")
            if not path.startswith("/") or "#" in path or "?" in path:
                errors.append(f"{ib.get('tag')}: invalid XHTTP path")
            if xh.get("mode") not in ("packet-up", "stream-up", "stream-one"):
                errors.append(f"{ib.get('tag')}: invalid XHTTP mode {xh.get('mode')!r}")
    return errors

# ── Xray process manager ───────────────────────────────────────────────────────
_xray_proc: asyncio.subprocess.Process | None = None
_xray_restart_lock = asyncio.Lock()
# Set of user config_uuids the last _xray_apply() served on reality inbounds.
# The audit loop re-applies Xray when this set changes (user expires / disabled /
# quota exhausted over time), so Reality connections are actually cut.
_xray_last_served: set = set()


def _expected_xray_client_uuids() -> set:
    """Real users Xray should currently serve on reality inbounds."""
    out = set()
    for iid, ib in INBOUNDS.items():
        is_reality = ((ib.get("protocol") or "").lower() == "reality"
                      or (ib.get("security") or "").lower() == "reality")
        if not is_reality:
            continue
        for u in USERS.values():
            uids = u.get("inbound_ids") or ([u.get("inbound_id")] if u.get("inbound_id") else [])
            if iid in uids and u.get("config_uuid") and is_user_allowed(u):
                out.add(u["config_uuid"])
    return out


async def _xray_client_audit_loop():
    """Periodically drop Reality users who expired/ran out of quota/disabled.

    Xray enforces nothing itself; the panel cuts Reality access by regenerating
    the config without the disallowed UUIDs and restarting Xray.
    """
    global _xray_last_served
    await asyncio.sleep(45)
    while True:
        try:
            async with USERS_LOCK:
                for u in USERS.values():
                    auto_check_user_expiry(u)
            expected = _expected_xray_client_uuids()
            if expected != _xray_last_served:
                await _xray_apply()
        except Exception as e:
            logger.warning(f"xray client audit failed: {e}")
        await asyncio.sleep(60)


def _xray_bin_path() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__))) / "xray" / "xray"


async def _xray_start(config: dict) -> bool:
    """Write config.json and start the Xray subprocess (or restart if running)."""
    global _xray_proc
    bin_path = _xray_bin_path()
    if not bin_path.exists():
        logger.warning("xray binary missing; skipping xray start")
        return False
    # No reality inbounds configured yet → don't run Xray with an empty config
    # (it would fail to bind any listener). Stop any running instance.
    if not (config.get("inbounds") or []):
        if _xray_proc and _xray_proc.returncode is None:
            try:
                _xray_proc.terminate()
            except Exception:
                pass
        return False
    validation_errors = _validate_xray_server_config(config)
    if validation_errors:
        logger.error("Xray config validation failed: %s", " | ".join(validation_errors))
        return False
    async with _xray_restart_lock:
        # Stop existing
        if _xray_proc and _xray_proc.returncode is None:
            try:
                _xray_proc.terminate()
                await asyncio.wait_for(_xray_proc.wait(), timeout=3)
            except Exception:
                try:
                    _xray_proc.kill()
                except Exception:
                    pass
        cfg_path = bin_path.parent / "config.json"
        try:
            cfg_path.write_text(json.dumps(config, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.warning(f"xray config write failed: {e}")
            return False
        try:
            log_path = bin_path.parent / "xray-runtime.log"
            log_fp = open(log_path, "ab", buffering=0)
            _xray_proc = await asyncio.create_subprocess_exec(
                str(bin_path), "-c", str(cfg_path),
                stdout=log_fp,
                stderr=asyncio.subprocess.STDOUT,
            )
            await asyncio.sleep(0.8)
            if _xray_proc.returncode is not None:
                try:
                    tail = log_path.read_text(errors="ignore")[-5000:]
                except Exception:
                    tail = ""
                logger.error(f"Xray exited immediately (code={_xray_proc.returncode}). {tail}")
                return False
            logger.info(f"Xray started (pid={_xray_proc.pid}) on configured Reality ports")
            return True
        except Exception as e:
            logger.warning(f"xray start failed: {e}")
            return False


async def _xray_apply():
    """Regenerate config for all inbounds and (re)start Xray with it."""
    global _xray_last_served
    config = generate_xray_server_config()
    await _xray_start(config)
    _xray_last_served = _expected_xray_client_uuids()


@app.post("/api/tools/generate-xray-config")
async def gen_xray_server_config(request: Request, _=Depends(require_auth)):
    """Generate a complete Xray-core server config.json for all or specific inbounds."""
    body = await request.json()
    inbound_id = body.get("inbound_id") or None
    
    try:
        config = generate_xray_server_config(inbound_id)
        return {
            "ok": True,
            "config": config,
            "config_json": json.dumps(config, indent=2, ensure_ascii=False),
            "inbounds_count": len(config["inbounds"]),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/generate-xray-keys")
async def gen_xray_keys(_=Depends(require_auth)):
    """Generate all Xray-related keys: Reality x25519 keypair, UUID, shortId."""
    result = {
        "uuid": generate_uuid(),
        "short_id": secrets.token_hex(5)[:10],
    }
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import base64 as b64
        result["private_key"] = b64.b64encode(priv_bytes).decode()
        result["public_key"] = b64.b64encode(pub_bytes).decode()
    except ImportError:
        result["private_key"] = ""
        result["public_key"] = ""
        result["note"] = "cryptography not installed"
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SERVER STATS (HTTP polling)
# ══════════════════════════════════════════════════════════════════════════════

TRAFFIC_HISTORY = deque(maxlen=31 * 24 * 60)
_LAST_TRAFFIC_SAMPLE = {"ts": 0.0, "bytes": 0}


def _record_traffic_sample():
    now = time.time()
    total = int(stats.get("total_bytes", 0) or 0)
    if not TRAFFIC_HISTORY or now - float(TRAFFIC_HISTORY[-1]["ts"]) >= 10:
        TRAFFIC_HISTORY.append({"ts": now, "bytes": total, "connections": len(connections)})


def _traffic_window_seconds(name: str) -> int:
    return {"hour": 3600, "day": 86400, "week": 7 * 86400, "month": 30 * 86400}.get(name, 86400)


@app.get("/api/dashboard/traffic")
async def dashboard_traffic(range: str = "day", _=Depends(require_auth)):
    _record_traffic_sample()
    now = time.time()
    seconds = _traffic_window_seconds(str(range).lower())
    rows = [x for x in TRAFFIC_HISTORY if now - float(x["ts"]) <= seconds]
    if not rows:
        rows = [{"ts": now, "bytes": int(stats.get("total_bytes", 0) or 0), "connections": len(connections)}]
    base = rows[0]["bytes"]
    total = max(0, int(rows[-1]["bytes"]) - int(base))
    avg_conn = sum(float(x.get("connections", 0)) for x in rows) / max(len(rows), 1)
    peak_conn = max(int(x.get("connections", 0)) for x in rows)
    points = []
    for x in rows[-80:]:
        points.append({"ts": x["ts"], "bytes": max(0, int(x["bytes"]) - int(base)), "connections": int(x.get("connections", 0))})
    return {"range": range, "seconds": seconds, "total_bytes": total, "total_fmt": fmt_bytes(total), "average_connections": round(avg_conn, 1), "peak_connections": peak_conn, "current_connections": len(connections), "points": points}

@app.get("/api/server/stats")
async def server_stats_http(_=Depends(require_auth)):
    """One-shot HTTP response with live server stats (for polling clients)."""
    _record_traffic_sample()
    return get_live_stats()


# ── Static files mount (MUST be after all routes) ──
# ── Static files mount (MUST be after all routes) ──


# ══════════════════════════════════════════════════════════════════════════════
# FILE UPLOADS - Backgrounds, Audio, Custom Assets
# ══════════════════════════════════════════════════════════════════════════════

UPLOAD_DIR = _os.path.join(_STATIC_DIR, "uploads")
_os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/jpg", "image/webp", "image/gif"}
ALLOWED_AUDIO_TYPES = {"audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg", "audio/webm"}


@app.post("/api/upload/background")
async def upload_background(request: Request, _=Depends(require_auth)):
    """Upload a custom background image for login, dashboard, or sub page."""
    form = await request.form()
    file = form.get("file")
    bg_type = str(form.get("type") or "login").lower()  # login, dashboard, sub
    
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    content_type = file.content_type or ""
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {content_type}. Allowed: jpg, png, webp, gif")
    
    # Save file
    ext = file.filename.split(".")[-1] if "." in (file.filename or "") else "jpg"
    safe_name = f"bg_{bg_type}.{ext}"
    file_path = _os.path.join(UPLOAD_DIR, safe_name)
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB max
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    _os.makedirs(_os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Update settings
    bg_key = f"bg_{bg_type}"
    async with SETTINGS_LOCK:
        SETTINGS[bg_key] = f"/static/uploads/{safe_name}?t={int(time.time())}"
    
    await save_state()
    log_activity("settings", f"Background {bg_type} uploaded", "ok")
    return {"ok": True, "url": SETTINGS[bg_key], "type": bg_type}


@app.post("/api/upload/audio")
async def upload_audio(request: Request, _=Depends(require_auth)):
    """Upload a custom audio/music file for the panel."""
    form = await request.form()
    file = form.get("file")
    
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    content_type = file.content_type or ""
    if content_type not in ALLOWED_AUDIO_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {content_type}. Allowed: mp3, wav, ogg")
    
    ext = file.filename.split(".")[-1] if "." in (file.filename or "") else "mp3"
    safe_name = f"panel_audio.{ext}"
    file_path = _os.path.join(UPLOAD_DIR, safe_name)
    
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB max
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")
    
    _os.makedirs(_os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Update settings
    async with SETTINGS_LOCK:
        SETTINGS["panel_audio"] = f"/static/uploads/{safe_name}?t={int(time.time())}"
        SETTINGS["panel_audio_enabled"] = True
    
    await save_state()
    log_activity("settings", "Panel audio uploaded", "ok")
    return {"ok": True, "url": SETTINGS["panel_audio"]}


@app.post("/api/settings/background/remove")
async def remove_background(request: Request, _=Depends(require_auth)):
    """Remove a custom background."""
    body = await request.json()
    bg_type = str(body.get("type") or "login").lower()
    bg_key = f"bg_{bg_type}"
    async with SETTINGS_LOCK:
        SETTINGS.pop(bg_key, None)
    await save_state()
    return {"ok": True, "removed": bg_type}


@app.post("/api/settings/audio/remove")
async def remove_audio(_=Depends(require_auth)):
    """Remove panel audio."""
    async with SETTINGS_LOCK:
        SETTINGS["panel_audio"] = ""
        SETTINGS["panel_audio_enabled"] = False
    await save_state()
    return {"ok": True}


@app.get("/api/musix")
async def list_musix(_=Depends(require_auth)):
    """List mp3 files in static/musix for random panel music playback (any filename)."""
    musix_dir = _os.path.join(_STATIC_DIR, "musix")
    try:
        names = sorted(
            f for f in _os.listdir(musix_dir)
            if f.lower().endswith(".mp3") and _os.path.isfile(_os.path.join(musix_dir, f))
        )
    except OSError:
        names = []
    return {"tracks": [{"url": f"/static/musix/{quote(n)}", "name": n} for n in names]}


# ══════════════════════════════════════════════════════════════════════════════
# IP SCANNER - Railway IPs, Ping Tests, Current IP
# ══════════════════════════════════════════════════════════════════════════════

RAILWAY_REGIONS = [
    {"name": "us-west1 (Oregon)", "host": "us-west1.railway.app"},
    {"name": "us-east4 (Virginia)", "host": "us-east4.railway.app"},
    {"name": "us-central1 (Iowa)", "host": "us-central1.railway.app"},
    {"name": "europe-west4 (Netherlands)", "host": "europe-west4.railway.app"},
    {"name": "europe-west1 (Belgium)", "host": "europe-west1.railway.app"},
    {"name": "asia-southeast1 (Singapore)", "host": "asia-southeast1.railway.app"},
    {"name": "asia-east1 (Taiwan)", "host": "asia-east1.railway.app"},
    {"name": "asia-northeast1 (Tokyo)", "host": "asia-northeast1.railway.app"},
    {"name": "australia-southeast1 (Sydney)", "host": "australia-southeast1.railway.app"},
    {"name": "southamerica-east1 (Sao Paulo)", "host": "southamerica-east1.railway.app"},
]

FAMOUS_SITES = [
    {"name": "Google", "host": "google.com"},
    {"name": "Cloudflare", "host": "cloudflare.com"},
    {"name": "GitHub", "host": "github.com"},
    {"name": "YouTube", "host": "youtube.com"},
    {"name": "Amazon", "host": "amazon.com"},
    {"name": "Wikipedia", "host": "wikipedia.org"},
    {"name": "Microsoft", "host": "microsoft.com"},
    {"name": "Twitter/X", "host": "twitter.com"},
    {"name": "Instagram", "host": "instagram.com"},
    {"name": "Telegram", "host": "telegram.org"},
]


import subprocess
import platform


@app.get("/api/tools/my-ip")
async def get_my_ip(_=Depends(require_auth)):
    """Get the server's current public IP."""
    ips = {}
    # Try multiple services
    for service, url in [
        ("ipify", "https://api.ipify.org?format=json"),
        ("icanhazip", "https://icanhazip.com"),
        ("ipinfo", "https://ipinfo.io/json"),
    ]:
        try:
            async with http_client as client:
                resp = await client.get(url, timeout=5)
                if resp.status_code == 200:
                    body = resp.text.strip()
                    ips[service] = body
        except Exception:
            ips[service] = None
    
    # Try Railway metadata
    railway_ip = None
    try:
        if os.environ.get("RAILWAY_STATIC_URL"):
            railway_ip = os.environ.get("RAILWAY_STATIC_URL")
    except Exception:
        pass
    
    return {
        "ips": ips,
        "railway_url": railway_ip,
        "local_hostname": platform.node(),
    }


@app.get("/api/tools/ping-sites")
async def ping_famous_sites(_=Depends(require_auth)):
    """Ping famous websites and return latency results."""
    results = []
    for site in FAMOUS_SITES:
        latency = None
        status = "error"
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "3000", site["host"]]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", site["host"]]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            
            if proc.returncode == 0:
                output = stdout.decode(errors="ignore")
                # Extract time from ping output
                import re as _re
                if system == "windows":
                    match = _re.search(r"time[=<](\d+)ms", output)
                else:
                    match = _re.search(r"time=(\d+\.?\d*)\s*ms", output)
                if match:
                    latency = float(match.group(1))
                    status = "ok" if latency < 200 else ("slow" if latency < 500 else "very-slow")
                else:
                    status = "no-response"
            else:
                status = "unreachable"
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception:
            status = "error"
        
        results.append({
            "name": site["name"],
            "host": site["host"],
            "latency_ms": latency,
            "status": status,
        })
    return {"sites": results}


@app.get("/api/tools/scan-railway-ips")
async def scan_railway_ips(_=Depends(require_auth)):
    """Ping Railway region endpoints (NOT Cloudflare) to test connectivity."""
    results = []
    for region in RAILWAY_REGIONS:
        latency = None
        status = "error"
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "3000", region["host"]]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", region["host"]]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            
            if proc.returncode == 0:
                output = stdout.decode(errors="ignore")
                import re as _re
                if system == "windows":
                    match = _re.search(r"time[=<](\d+)ms", output)
                else:
                    match = _re.search(r"time=(\d+\.?\d*)\s*ms", output)
                if match:
                    latency = float(match.group(1))
                    status = "ok" if latency < 200 else ("slow" if latency < 500 else "very-slow")
                else:
                    status = "no-response"
            else:
                status = "unreachable"
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception:
            status = "error"
        
        results.append({
            "region": region["name"],
            "host": region["host"],
            "latency_ms": latency,
            "status": status,
        })
    return {"regions": results}


# ══════════════════════════════════════════════════════════════════════════════
# CLOUDFLARE PAGES WORKER MANAGER — multi-location proxy via Cloudflare Pages Advanced Mode
# Traffic: Client → Worker Domain → Cloudflare Worker → Selected Proxy IP → Internet
# Railway only hosts the panel/API; it is NOT in the VPN data path.
# ══════════════════════════════════════════════════════════════════════════════

CF_API = "https://api.cloudflare.com/client/v4"
CF_TOKEN_LINK = "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_routes%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%5D&accountId=*&zoneId=all&name=spider-Token"

# Worker script deployed to the user's Cloudflare account lives in the project
# at worker/worker.js (source of truth; deployment uploads it as _worker.js).
# The proxy map is stored in the worker KV control plane; adding/removing a country
# updates the KV config and may trigger a managed worker redeploy (see /api/worker/sync).
CF_WORKER_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "worker"
CF_WORKER_TEMPLATE = CF_WORKER_DIR / "worker.js"


def _worker_script() -> str:
    """Return the worker template source, or raise if the file is missing."""
    if not CF_WORKER_TEMPLATE.is_file():
        raise FileNotFoundError(
            f"worker template not found: {CF_WORKER_TEMPLATE} "
            "(create worker/worker.js in the project repo)"
        )
    return CF_WORKER_TEMPLATE.read_text(encoding="utf-8")


def _is_cf_gak(token: str) -> bool:
    """True if token is a Cloudflare Global API Key (panel cfk_/cf_ prefix).

    The full prefixed token is sent as-is to Cloudflare's X-Auth-Key header;
    the cfk_ prefix is part of the accepted key format.
    """
    t = str(token or "").strip()
    return t.startswith("cfk_") or t.startswith("cf_") or bool(re.fullmatch(r"[a-f0-9]{37}", t, re.IGNORECASE))

def _cf_auth_token(token: str) -> str:
    """Return the token value to send to Cloudflare as-is (no stripping)."""
    return str(token or "").strip()

async def _cf_api(method: str, path: str, token: str, payload: dict = None, email: str = ""):
    """Call the Cloudflare API v4. Returns (status_code, json).

    token is either a Bearer token (modern) or a Global API Key (cfk_...). When
    the token looks like a Global API Key, we authenticate with X-Auth-Email +
    X-Auth-Key instead of Authorization: Bearer.
    """
    token = str(token or "").strip()
    email = str(email or "").strip()
    headers = {"Content-Type": "application/json", "User-Agent": "Spider-Panel"}
    # Cloudflare Global API Key (cfk_/cf_ prefix or 37-char hex) → Global Key
    # auth (X-Auth-Email + X-Auth-Key). Modern Bearer tokens → Authorization.
    # Only a real GAK is sent via X-Auth-Key; a Bearer token always uses Bearer
    # auth even if an email happens to be on file (filling email must not turn a
    # valid API token into a rejected X-Auth-Key).
    _is_gak = _is_cf_gak(token)
    if _is_gak:
        headers["X-Auth-Key"] = token
        headers["X-Auth-Email"] = email or os.environ.get("CF_EMAIL", "")
    else:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=40) as client:
        try:
            r = await client.request(method, f"{CF_API}{path}", headers=headers, json=payload)
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, {}
        except Exception as e:
            return 0, {"errors": [{"message": str(e)}]}


def _worker_safe_domain(raw: str) -> str:
    raw = str(raw or "").strip().lower()
    raw = re.sub(r"^https?://", "", raw).rstrip("/")
    if not raw or raw in ("localhost", "0.0.0.0", "127.0.0.1"):
        return ""
    return raw


def _worker_public() -> dict:
    """Snapshot of worker state with the API token stripped."""
    return {
        "connected": WORKER.get("connected", False),
        "account_id": WORKER.get("account_id", ""),
        "worker_name": WORKER.get("worker_name", ""),
        "worker_domain": WORKER.get("worker_domain", ""),
        "worker_url": WORKER.get("worker_url", ""),
        "pages_project_name": WORKER.get("pages_project_name", ""),
        "pages_project_id": WORKER.get("pages_project_id", ""),
        "pages_url": WORKER.get("pages_url", ""),
        "panel_domain": WORKER.get("panel_domain", ""),
        "kv_namespace_id": WORKER.get("kv_namespace_id", ""),
        "kv_namespace_title": WORKER.get("kv_namespace_title", ""),
        "remote_status": WORKER.get("remote_status", ""),
        "last_heartbeat": WORKER.get("last_heartbeat", ""),
        "worker_users_online": int(WORKER.get("worker_users_online") or 0),
        "worker_traffic_bytes": int(WORKER.get("worker_traffic_bytes") or 0),
        "worker_user_count": int(WORKER.get("worker_user_count") or 0),
        "last_sync": WORKER.get("last_sync", ""),
        "last_error": WORKER.get("last_error", ""),
        "source_url": WORKER.get("source_url", ""),
        "auto_sync": bool(WORKER.get("auto_sync", True)),
        "sync_error": WORKER.get("sync_error", ""),
        "sync_count": int(WORKER.get("sync_count", 0)),
        "routing_status": dict(WORKER.get("routing_status") or {}),
        "token_link": CF_TOKEN_LINK,
        "tunnel_enabled": bool(WORKER.get("tunnel_enabled", False)),
        "tunnel_kv_namespace_id": WORKER.get("tunnel_kv_namespace_id", ""),
        "tunnel_kv_namespace_title": WORKER.get("tunnel_kv_namespace_title", ""),
        "reverse_kv_namespace_id": WORKER.get("reverse_kv_namespace_id", ""),
        "reverse_kv_namespace_title": WORKER.get("reverse_kv_namespace_title", ""),
        "proxies": [
            {"code": code, **dict(p)}
            for code, p in sorted((WORKER.get("proxies") or {}).items())
        ],
    }


async def _ensure_worker_kv() -> str | None:
    """Find or create the dedicated KV namespace for THIS worker ({worker}-db).

    Every deployed worker gets its own private KV namespace so multiple
    workers never share user/proxy state. The id is persisted in WORKER state;
    on reconnect the namespace is looked up by title and reused.
    """
    acct = str(WORKER.get("account_id") or "")
    cf_token = str(WORKER.get("token") or "")
    if not acct or not cf_token:
        return None
    existing = str(WORKER.get("kv_namespace_id") or "")
    if existing:
        return existing
    wname = str(WORKER.get("worker_name") or "").strip()
    kv_title = f"{wname}-db" if wname else "spider-worker-kv"
    # List existing namespaces, reuse ours if a previous deploy created it.
    code, data = await _cf_api("GET", f"/accounts/{acct}/storage/kv/namespaces", cf_token, email="")
    if code == 200:
        for ns in (data.get("result") or []):
            if ns.get("title") == kv_title:
                async with WORKER_LOCK:
                    WORKER["kv_namespace_id"] = ns.get("id")
                    WORKER["kv_namespace_title"] = kv_title
                asyncio.create_task(save_state())
                return ns.get("id")
    # Create a fresh dedicated namespace for this worker.
    code, data = await _cf_api(
        "POST", f"/accounts/{acct}/storage/kv/namespaces",
        cf_token, {"title": kv_title}, email="",
    )
    if code == 200 and data.get("result"):
        nid = data["result"].get("id")
        async with WORKER_LOCK:
            WORKER["kv_namespace_id"] = nid
            WORKER["kv_namespace_title"] = kv_title
        asyncio.create_task(save_state())
        return nid
    return None


async def _ensure_tunnel_kv() -> str | None:
    """Find or create the TUNNEL's own KV namespace ({worker}-tunnel-db).

    The tunnel keeps its state separate from the main worker KV. The name is
    derived from the worker's KV title so the pairing is always obvious.
    """
    acct = str(WORKER.get("account_id") or "")
    cf_token = str(WORKER.get("token") or "")
    if not acct or not cf_token:
        return None
    existing = str(WORKER.get("tunnel_kv_namespace_id") or "")
    if existing:
        return existing
    wname = str(WORKER.get("worker_name") or "").strip()
    base = f"{wname}-db" if wname else "spider-worker-kv"
    kv_title = f"{base}-tunnel"  # e.g. spider-a1b2c3-db-tunnel
    code, data = await _cf_api("GET", f"/accounts/{acct}/storage/kv/namespaces", cf_token, email="")
    if code == 200:
        for ns in (data.get("result") or []):
            if ns.get("title") == kv_title:
                async with WORKER_LOCK:
                    WORKER["tunnel_kv_namespace_id"] = ns.get("id")
                    WORKER["tunnel_kv_namespace_title"] = kv_title
                asyncio.create_task(save_state())
                return ns.get("id")
    code, data = await _cf_api(
        "POST", f"/accounts/{acct}/storage/kv/namespaces",
        cf_token, {"title": kv_title}, email="",
    )
    if code == 200 and data.get("result"):
        nid = data["result"].get("id")
        async with WORKER_LOCK:
            WORKER["tunnel_kv_namespace_id"] = nid
            WORKER["tunnel_kv_namespace_title"] = kv_title
        asyncio.create_task(save_state())
        return nid
    return None


async def _ensure_reverse_kv() -> str | None:
    """Find or create the REVERSE's own KV namespace ({worker}-db-reverse).

    Reverse mode: user → Worker → Railway → site. Its state (users, usage)
    lives in a third dedicated namespace so tunnel/reverse/worker never share
    keys and can never interfere with each other.
    """
    acct = str(WORKER.get("account_id") or "")
    cf_token = str(WORKER.get("token") or "")
    if not acct or not cf_token:
        return None
    existing = str(WORKER.get("reverse_kv_namespace_id") or "")
    if existing:
        return existing
    wname = str(WORKER.get("worker_name") or "").strip()
    base = f"{wname}-db" if wname else "spider-worker-kv"
    kv_title = f"{base}-reverse"  # e.g. spider-a1b2c3-db-reverse
    code, data = await _cf_api("GET", f"/accounts/{acct}/storage/kv/namespaces", cf_token, email="")
    if code == 200:
        for ns in (data.get("result") or []):
            if ns.get("title") == kv_title:
                async with WORKER_LOCK:
                    WORKER["reverse_kv_namespace_id"] = ns.get("id")
                    WORKER["reverse_kv_namespace_title"] = kv_title
                asyncio.create_task(save_state())
                return ns.get("id")
    code, data = await _cf_api(
        "POST", f"/accounts/{acct}/storage/kv/namespaces",
        cf_token, {"title": kv_title}, email="",
    )
    if code == 200 and data.get("result"):
        nid = data["result"].get("id")
        async with WORKER_LOCK:
            WORKER["reverse_kv_namespace_id"] = nid
            WORKER["reverse_kv_namespace_title"] = kv_title
        asyncio.create_task(save_state())
        return nid
    return None


async def _ensure_worker_pages_project(kv_id: str | None, tunnel_kv_id: str | None = None, reverse_kv_id: str | None = None) -> dict:
    """Create/refresh a Cloudflare Pages project used for the managed worker.

    The Pages project runs the advanced-mode `_worker.js` file generated from
    the local `worker/worker.js` source and binds the dedicated SPIDER_KV
    namespace (plus optional tunnel/reverse namespaces).
    """
    acct = str(WORKER.get("account_id") or "").strip()
    token = str(WORKER.get("token") or "").strip()
    name = str(WORKER.get("pages_project_name") or WORKER.get("worker_name") or "").strip().lower()
    if not acct or not token or not name:
        return {"ok": False, "detail": "Cloudflare account, token or Pages project name missing"}
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", name):
        name = "spider-" + secrets.token_hex(3)
        async with WORKER_LOCK:
            WORKER["pages_project_name"] = name
            WORKER["worker_name"] = name

    def deployment_config():
        kvs = {}
        if kv_id:
            kvs["SPIDER_KV"] = {"namespace_id": kv_id}
        if tunnel_kv_id:
            kvs["TUNNEL_KV"] = {"namespace_id": tunnel_kv_id}
        if reverse_kv_id:
            kvs["REVERSE_KV"] = {"namespace_id": reverse_kv_id}
        return {
            "compatibility_date": "2026-09-18",
            "kv_namespaces": kvs,
        }

    dep_cfg = {
        "production": deployment_config(),
        "preview": deployment_config(),
    }

    # Reuse project if it already exists.
    code, data = await _cf_api("GET", f"/accounts/{acct}/pages/projects/{name}", token, email="")
    project = data.get("result") if isinstance(data, dict) else None
    if code == 200 and project:
        project_id = project.get("id") or ""
        async with WORKER_LOCK:
            WORKER["pages_project_name"] = name
            WORKER["pages_project_id"] = project_id
            WORKER["worker_name"] = name
            WORKER["pages_url"] = f"https://{name}.pages.dev"
            WORKER["worker_domain"] = f"{name}.pages.dev"
            WORKER["worker_url"] = f"https://{name}.pages.dev"
        # Keep production/preview bindings in sync with our dedicated KV.
        ucode, udata = await _cf_api(
            "PATCH",
            f"/accounts/{acct}/pages/projects/{name}",
            token,
            {"production_branch": "main", "deployment_configs": dep_cfg},
            email="",
        )
        if ucode not in (200, 201):
            return {"ok": False, "detail": f"Pages binding update failed: {udata} "[:500]}
        return {"ok": True, "project": project, "status": ucode}

    # Create a new Direct Upload Pages project.
    payload = {
        "name": name,
        "production_branch": "main",
        "deployment_configs": dep_cfg,
    }
    ccode, cdata = await _cf_api(
        "POST",
        f"/accounts/{acct}/pages/projects",
        token,
        payload,
        email="",
    )
    if ccode not in (200, 201):
        errs = cdata.get("errors") or [] if isinstance(cdata, dict) else []
        msg = "; ".join(str(e.get("message") or e.get("code") or "unknown") for e in errs[:3]) or str(cdata)[:400]
        return {"ok": False, "detail": f"Pages project creation failed: {msg}"}
    project = cdata.get("result") or {}
    project_id = project.get("id") or ""
    async with WORKER_LOCK:
        WORKER["pages_project_name"] = name
        WORKER["pages_project_id"] = project_id
        WORKER["worker_name"] = name
        WORKER["pages_url"] = f"https://{name}.pages.dev"
        WORKER["worker_domain"] = f"{name}.pages.dev"
        WORKER["worker_url"] = f"https://{name}.pages.dev"
    asyncio.create_task(save_state())
    return {"ok": True, "project": project, "status": ccode}


async def _worker_deploy() -> tuple:
    """Deploy the managed VLESS Worker as a Cloudflare Pages Advanced Mode project.

    The panel creates/reuses a Pages project, configures the dedicated KV
    binding, and uploads `worker/worker.js` as `_worker.js` using the Pages
    Direct Upload API.
    """
    try:
        template = _worker_script()
    except Exception as e:
        return 0, {"errors": [{"message": str(e)}]}

    ctrl = str(WORKER.get("control_token") or "")
    if not ctrl:
        ctrl = secrets.token_urlsafe(24)
        async with WORKER_LOCK:
            WORKER["control_token"] = ctrl
        asyncio.create_task(save_state())

    panel_domain = _safe_host(SETTINGS.get("domain"), get_host())
    async with WORKER_LOCK:
        WORKER["panel_domain"] = panel_domain

    worker_domain = _worker_safe_domain(WORKER.get("worker_domain"))
    script = (
        template
        .replace("__PANEL_DOMAIN__", json.dumps(panel_domain))
        .replace("__WORKER_DOMAIN__", json.dumps(worker_domain))
        .replace("__PANEL_TOKEN__", json.dumps(ctrl))
    )

    cf_token = str(WORKER.get("token") or "")
    if not cf_token:
        return 0, {"errors": [{"message": "Cloudflare API token is missing"}]}

    kv_id = await _ensure_worker_kv()
    tunnel_kv_id = await _ensure_tunnel_kv() if WORKER.get("tunnel_enabled") else None
    reverse_kv_id = await _ensure_reverse_kv() if WORKER.get("tunnel_enabled") else None
    pages_res = await _ensure_worker_pages_project(kv_id, tunnel_kv_id, reverse_kv_id)
    if not pages_res.get("ok"):
        return 0, {"errors": [{"message": pages_res.get("detail", "Pages project setup failed")}]}

    # Refresh the resolved Pages domain after project creation/reuse.
    worker_domain = _worker_safe_domain(WORKER.get("worker_domain"))
    worker_bytes = script.encode("utf-8")
    # Pages direct-upload manifest uses content hashes.
    manifest = json.dumps({"_worker.js": hashlib.md5(worker_bytes).hexdigest()})

    _is_gak = _is_cf_gak(cf_token)
    if _is_gak:
        auth_headers = {"X-Auth-Email": "", "X-Auth-Key": cf_token}
    else:
        auth_headers = {"Authorization": f"Bearer {cf_token}"}

    project_name = str(WORKER.get("pages_project_name") or WORKER.get("worker_name") or "").strip()
    if not project_name:
        return 0, {"errors": [{"message": "Pages project name missing"}]}

    boundary = "----SpiderPages" + secrets.token_hex(12)
    def field(name: str, value: str) -> bytes:
        return (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        ).encode()

    body = bytearray()
    body += field("branch", "main")
    body += field("commit_dirty", "false")
    body += field("commit_message", "SpiderPanel managed worker deploy")
    body += field("manifest", manifest)
    body += (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="_worker.js"; filename="_worker.js"\r\n'
        "Content-Type: application/javascript\r\n\r\n"
    ).encode()
    body += worker_bytes + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            r = await client.post(
                f"{CF_API}/accounts/{WORKER.get('account_id','')}/pages/projects/{project_name}/deployments",
                headers={**auth_headers, "Content-Type": f"multipart/form-data; boundary={boundary}"},
                content=bytes(body),
            )
        try:
            deploy_json = r.json()
        except Exception:
            deploy_json = {}

        if r.status_code not in (200, 201):
            return r.status_code, deploy_json or {"errors": [{"message": r.text[:500]}]}

        result = deploy_json.get("result") or {}
        live_url = str(result.get("url") or "").strip()
        aliases = result.get("aliases") or []
        if not live_url and aliases:
            live_url = str(aliases[0] or "").strip()
        if live_url:
            live_domain = _worker_safe_domain(live_url)
            # Only use stable project.pages.dev for the VLESS address.
            stable_domain = f"{project_name}.pages.dev"
            async with WORKER_LOCK:
                WORKER["pages_url"] = f"https://{stable_domain}"
                WORKER["worker_domain"] = stable_domain
                WORKER["worker_url"] = f"https://{stable_domain}"
                WORKER["last_error"] = ""
                WORKER["remote_status"] = "deployed"
            asyncio.create_task(save_state())
        return r.status_code, deploy_json
    except Exception as e:
        return 0, {"errors": [{"message": str(e)}]}


async def _worker_enable_workers_dev() -> dict:
    """Compatibility shim: managed deployments now use Cloudflare Pages."""
    return {"ok": True, "detail": "Pages deployment does not require workers.dev activation"}


async def _worker_sync_users() -> dict:
    """Push all panel users (with volume + expiry) to the worker's KV store.

    Each active panel user who picked the worker inbound is written to the
    worker via its admin API (POST /api/users) so the VLESS worker can
    authenticate them and enforce traffic/expiry. Returns {"ok": bool, count": N}.
    """
    domain = str(WORKER.get("worker_domain") or "").strip().lower()
    ctrl = str(WORKER.get("control_token") or "")
    if not domain or not ctrl or domain in ("localhost", "0.0.0.0", "127.0.0.1"):
        return {"ok": False, "detail": "worker not connected / no control token"}
    # Only users that reference the worker inbound are synced.
    wid = None
    for iid, ib in INBOUNDS.items():
        if (ib.get("protocol") or "").lower() == "worker":
            wid = iid
            break
    if not wid:
        return {"ok": False, "detail": "no worker inbound"}
    synced = 0
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        for uid, u in USERS.items():
            iids = u.get("inbound_ids") or ([u.get("inbound_id")] if u.get("inbound_id") else [])
            if wid not in iids:
                continue
            cuuid = u.get("config_uuid") or uid
            deadline = 0
            if u.get("expire_at"):
                try:
                    deadline = int(datetime.fromisoformat(u["expire_at"]).timestamp())
                except Exception:
                    deadline = 0
            limit = int(u.get("traffic_limit_bytes") or 0)
            disabled = (u.get("status") or "active") != "active"
            try:
                if disabled:
                    # Disabled user → drop from the worker so it stops authenticating.
                    r = await client.delete(
                        f"https://{domain}/api/user/{cuuid}",
                        headers={"Authorization": f"Bearer {ctrl}"},
                    )
                else:
                    r = await client.post(
                        f"https://{domain}/api/users",
                        headers={"Authorization": f"Bearer {ctrl}"},
                        json={
                            "uuid": cuuid,
                            "remark": u.get("username", uid),
                            "limit_bytes": limit,
                            "expire": deadline,
                            "used_bytes": int(u.get("traffic_used_bytes") or 0),
                            "proxy_ip": str(u.get("proxy_ip") or ""),
                            "proxy_ips": [str(x).strip() for x in (u.get("proxy_ips") or []) if str(x).strip()][:6],
                            "concurrent_connections": int(u.get("concurrent_connections") or 0),
                            "countries": [],
                        },
                    )
                if r.status_code in (200, 204):
                    if r.status_code == 200:
                        try:
                            payload = r.json().get("user") or {}
                            if payload.get("configs") is not None:
                                u["worker_configs"] = payload.get("configs") or []
                            if payload.get("used_bytes") is not None:
                                u["traffic_used_bytes"] = int(payload.get("used_bytes") or 0)
                        except Exception:
                            pass
                    synced += 1
            except Exception as e:
                logger.warning(f"worker user sync failed for {uid}: {e}")
    return {"ok": True, "count": synced}


async def _worker_pull_user(uid: str, u: dict) -> dict:
    """Pull usage/expiry/country and worker-generated config metadata back from Worker."""
    domain = str(WORKER.get("worker_domain") or "").strip().lower()
    ctrl = str(WORKER.get("control_token") or "")
    cuuid = u.get("config_uuid") or uid
    if not domain or not ctrl or not cuuid:
        return u
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            r = await client.get(f"https://{domain}/api/user/{cuuid}", headers={"Authorization": f"Bearer {ctrl}"})
        if r.status_code != 200:
            return u
        data = r.json().get("user") or {}
        if "used_bytes" in data:
            u["traffic_used_bytes"] = int(data.get("used_bytes") or 0)
        if data.get("expire"):
            u["worker_expire"] = int(data.get("expire"))
        # countries field removed - no longer used
        if isinstance(data.get("configs"), list):
            u["worker_configs"] = list(data.get("configs"))
        return u
    except Exception as e:
        logger.warning(f"worker pull failed for {uid}: {e}")
        return u

async def _worker_pull_all_users() -> int:
    count = 0
    async with USERS_LOCK:
        targets = [(uid, u) for uid, u in USERS.items() if _user_uses_worker_inbound(u)]
    for uid, u in targets:
        before = u.get("traffic_used_bytes")
        out = await _worker_pull_user(uid, u)
        if out is not u:
            async with USERS_LOCK:
                USERS[uid].update(out)
        if out.get("traffic_used_bytes") != before or out.get("worker_configs") is not None:
            count += 1
    if count:
        asyncio.create_task(save_state())
    return count


def _user_uses_worker_inbound(u: dict) -> bool:
    """True if the user references the worker inbound (needs quota/expiry sync)."""
    iids = u.get("inbound_ids") or ([u.get("inbound_id")] if u.get("inbound_id") else [])
    return any((INBOUNDS.get(iid) or {}).get("protocol") == "worker" for iid in iids)


async def _ensure_worker_inbound() -> bool:
    """Create or refresh the default Worker inbound to match the connected
    worker domain. Called after a worker connects/deploys so the worker inbound
    always points address/host/sni at the current worker domain."""
    wdom = _worker_safe_domain(WORKER.get("worker_domain"))
    if not wdom:
        return False
    changed = False
    async with INBOUNDS_LOCK:
        wid = next((i for i, ib in INBOUNDS.items() if (ib.get("protocol") or "").lower() == "worker"), None)
        if wid:
            ib = INBOUNDS[wid]
            if (ib.get("domain") or "") != wdom or (ib.get("external_domain") or "") != wdom:
                ib["domain"] = wdom
                ib["external_domain"] = wdom
                changed = True
        else:
            INBOUNDS["default-worker"] = {
                "name": "Worker (Multi-Location)",
                "protocol": "worker",
                "port": 443,
                "network": "ws",
                "security": "tls",
                "domain": wdom,
                "external_domain": wdom,
                "sni": "www.hcaptcha.com",
                "spoof_ip": "8.6.112.4",
                "external_port": 443,
                "fingerprint": "chrome",
                "reality_settings": {},
                "xhttp_settings": {},
                "ws_settings": {"path": "/ws/{uuid}"},
                "grpc_settings": {},
                "created_at": datetime.now().isoformat(),
            }
            changed = True
    if changed:
        asyncio.create_task(save_state())
    return True


def _worker_transient_network_error(detail: str) -> bool:
    """Return True for deployment-time DNS/connection errors that may clear after Pages propagates."""
    msg = str(detail or '').lower()
    transient_tokens = (
        'name or service not known',
        'temporary failure in name resolution',
        'temporary failure',
        'nodename nor servname provided',
        'getaddrinfo failed',
        'network is unreachable',
        'connection refused',
        'connect timeout',
        'timed out',
        '502', '503', '504',
    )
    return any(tok in msg for tok in transient_tokens)


async def _worker_retry_after_deploy() -> None:
    """Retry remote control after a fresh Pages deploy while DNS/route propagation settles."""
    delays = (5, 10, 20, 30, 45)
    for delay in delays:
        await asyncio.sleep(delay)
        try:
            if not WORKER.get('connected'):
                return
            res = await _worker_push_config()
            if res.get('ok'):
                await _worker_pull_all_users()
                await _worker_pull_status()
                return
        except Exception:
            pass


async def _worker_push_config() -> dict:
    """Remote control: push the full panel config to the worker in one call.

    POST /panel/config (Bearer control token) carries users (uuid, limit,
    expire, used, countries), the proxy routes and settings. The worker stores
    everything in its dedicated KV and answers with a summary. This is the
    single "panel → worker" channel; individual /api/users calls stay for
    incremental updates.
    """
    domain = str(WORKER.get("worker_domain") or "").strip().lower()
    ctrl = str(WORKER.get("control_token") or "")
    if not domain or not ctrl or domain in ("localhost", "0.0.0.0", "127.0.0.1"):
        return {"ok": False, "detail": "worker not connected / no control token"}
    wid = next((iid for iid, ib in INBOUNDS.items()
                if ((ib or {}).get("protocol") or "").lower() == "worker"), None)
    if not wid:
        return {"ok": False, "detail": "no worker inbound"}
    users = []
    async with USERS_LOCK:
        for uid, u in USERS.items():
            iids = u.get("inbound_ids") or ([u.get("inbound_id")] if u.get("inbound_id") else [])
            if wid and wid not in iids:
                continue
            cuuid = u.get("config_uuid") or uid
            deadline = 0
            if u.get("expire_at"):
                try:
                    deadline = int(datetime.fromisoformat(u["expire_at"]).timestamp())
                except Exception:
                    deadline = 0
            users.append({
                "uuid": cuuid,
                "remark": u.get("username", uid),
                "limit_bytes": int(u.get("traffic_limit_bytes") or 0),
                "expire": deadline,
                "used_bytes": int(u.get("traffic_used_bytes") or 0),
                "concurrent_connections": int(u.get("concurrent_connections") or 0),
                "proxy_ip": str(u.get("proxy_ip") or ""),
                "proxy_ips": [str(x).strip() for x in (u.get("proxy_ips") or []) if str(x).strip()][:6],
                "countries": [],
                "disabled": (u.get("status") or "active") != "active",
            })
    try:
        last_detail = ''
        # A new Pages project can be deployed before its *.pages.dev hostname
        # becomes resolvable. Retry briefly instead of failing worker creation.
        for attempt, delay in enumerate((0, 2, 4, 8), 1):
            if delay:
                await asyncio.sleep(delay)
            try:
                async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                    r = await client.post(
                        f"https://{domain}/panel/config",
                        headers={"Authorization": f"Bearer {ctrl}"},
                        json={
                            "users": users,
                            "routes": {},
                            "proxies": dict(WORKER.get("proxies") or {}),
                            "settings": {
                                "adaptive_routing": True,
                                "proxy_race": 2,
                                "health_check_interval_ms": 30000,
                            },
                        },
                    )
                if r.status_code == 200:
                    break
                last_detail = f"worker returned HTTP {r.status_code}: {r.text[:120]}"
                if r.status_code not in (502, 503, 504):
                    return {"ok": False, "detail": last_detail}
            except Exception as exc:
                last_detail = str(exc)
                if not _worker_transient_network_error(last_detail) or attempt == 4:
                    return {"ok": False, "detail": last_detail}
        if r.status_code == 200:
            data = {}
            try:
                data = r.json()
            except Exception:
                pass
            async with WORKER_LOCK:
                WORKER["remote_status"] = "online"
                WORKER["last_heartbeat"] = now_ir().isoformat(timespec="seconds")
                WORKER["worker_user_count"] = int(data.get("users") or len(users))
                WORKER["worker_traffic_bytes"] = int(data.get("traffic") or 0)
                WORKER["worker_users_online"] = int(data.get("online") or 0)
            asyncio.create_task(save_state())
            return {"ok": True, "detail": "config pushed", "users": data.get("users", len(users))}
        return {"ok": False, "detail": last_detail or f"worker returned HTTP {r.status_code}: {r.text[:120]}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}

async def _worker_pull_status() -> dict:
    """Pull live status from the worker's GET /panel/status API.

    Returns {ok, online, traffic, users} and records a heartbeat timestamp so
    the UI can show how fresh the remote state is.
    """
    domain = str(WORKER.get("worker_domain") or "").strip().lower()
    ctrl = str(WORKER.get("control_token") or "")
    if not domain or not ctrl or domain in ("localhost", "0.0.0.0", "127.0.0.1"):
        return {"ok": False, "detail": "worker not connected"}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(f"https://{domain}/panel/status",
                                 headers={"Authorization": f"Bearer {ctrl}"})
        if r.status_code != 200:
            async with WORKER_LOCK:
                WORKER["remote_status"] = "unreachable"
            return {"ok": False, "detail": f"HTTP {r.status_code}"}
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        hb = now_ir().isoformat(timespec="seconds")
        async with WORKER_LOCK:
            WORKER["remote_status"] = "online"
            WORKER["last_heartbeat"] = hb
            WORKER["worker_user_count"] = int(data.get("users") or 0)
            WORKER["worker_traffic_bytes"] = int(data.get("traffic") or 0)
            WORKER["worker_users_online"] = int(data.get("online") or 0)
            if isinstance(data.get("routing"), dict):
                WORKER["routing_status"] = dict(data.get("routing") or {})
        asyncio.create_task(save_state())
        return {"ok": True, **data}
    except Exception as e:
        async with WORKER_LOCK:
            WORKER["remote_status"] = "unreachable"
        return {"ok": False, "detail": str(e)}

async def _worker_control_update() -> dict:
    """Keep worker KV synchronized (no multi-location anymore)."""
    domain = str(WORKER.get("worker_domain") or "").strip().lower()
    ctrl = str(WORKER.get("control_token") or "")
    if not domain or not ctrl or domain in ("localhost", "0.0.0.0", "127.0.0.1"):
        return {"ok": False, "detail": "worker not connected / no control token"}
    # Single-location worker - no routes to sync
    try:
        # Single-location worker - nothing to sync
        return {"ok": True, "detail": "no multi-location to sync"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


# ── Daily proxy source sync ──────────────────────────────────────────────────
# Source file format (ProxyIP-Daily.md by NiREvil):
#   ## 🇩🇪 Germany (517 proxies)      ← flag emoji encodes the ISO code
#   <details><summary>...</summary>
#   | IP | ISP | Location | Risk Score |
#   | <pre><code>94.141.123.243</code></pre> | ISP | Hesse, Frankfurt | badge |
# ISP-grouped sections (Google/Amazon/…) have no flag → skipped.
_FLAG_RE = re.compile(r"^##\s*([\U0001F1E6-\U0001F1FF]{2})\s*([^\s(][^()]*?)\s*\(\d+\s*proxies\)")
_IPCELL_RE = re.compile(r"<pre><code>\s*((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})\s*</code></pre>", re.I)
# A few sections show only a bare code (e.g. "AD") instead of a full name.
_CODE_NAME = {
    "AD": "Andorra", "BA": "Bosnia & Herzegovina", "BD": "Bangladesh",
    "DO": "Dominican Republic", "IS": "Iceland", "KG": "Kyrgyzstan", "SY": "Syria",
}


def _flag_to_code(flag: str) -> str:
    """Decode a flag emoji (regional indicators) into an ISO 3166-1 alpha-2 code."""
    cps = [ord(c) for c in flag]
    if len(cps) < 2 or not all(0x1F1E6 <= c <= 0x1F1FF for c in cps):
        return ""
    return "".join(chr(0x41 + (c - 0x1F1E6)) for c in cps)


def _code_to_flag(code: str) -> str:
    """Encode an ISO 3166-1 alpha-2 code into a flag emoji."""
    code = str(code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return chr(0x1F1E6 + (ord(code[0]) - ord('A'))) + chr(0x1F1E6 + (ord(code[1]) - ord('A')))


def _parse_proxy_daily(text: str, limit_per_country: int = 3) -> dict:
    """Parse the daily markdown into {code: {country, proxy, port}}.

    For each country section the first `limit_per_country` IP cells are kept
    (rows are sorted best-first by risk score). Only sections with a flag emoji
    are used; ISP-grouped sections are skipped.
    """
    out: dict = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = _FLAG_RE.match(lines[i].strip())
        if not m:
            i += 1
            continue
        code = _flag_to_code(m.group(1)).lower()
        name = (m.group(2) or "").strip()
        if not code:
            i += 1
            continue
        if len(name) == 2 and name.isupper():
            name = _CODE_NAME.get(name.upper(), name)
        # Collect IP cells until the next '## ' section header.
        picked: list[str] = []
        j = i + 1
        while j < n:
            line = lines[j].strip()
            if line.startswith("## ") or line.startswith("---"):
                break
            if line.startswith("|") and "<pre><code>" in line:
                cell = _IPCELL_RE.search(line)
                if cell and cell.group(1) not in picked:
                    picked.append(cell.group(1))
                    if len(picked) >= limit_per_country:
                        break
            j += 1
        if picked:
            out[code] = {
                "country": name or code.upper(),
                "country_code": code.upper(),
                "proxy": picked[0],
                "port": 443,
                "proxies": picked,
            }
        i = j
    return out


async def _fetch_proxy_daily(url: str) -> str:
    """Fetch the daily proxy markdown, preferring the raw GitHub URL."""
    url = str(url or "").strip()
    if not url:
        raise ValueError("منبع پروکسی تنظیم نشده است")
    # GitHub blob page → raw URL so we get the file, not HTML.
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url)
    if m:
        url = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"
    async with httpx.AsyncClient(timeout=40, follow_redirects=True) as client:
        r = await client.get(url)
    if r.status_code != 200:
        raise ValueError(f"دریافت منبع ناموفق بود (HTTP {r.status_code})")
    return r.text


async def _sync_worker_proxies_from_source() -> dict:
    """Fetch + parse the daily proxy source and push it to the deployed worker.

    Returns a summary dict. Under WORKER_SYNC_LOCK so the hourly loop and the
    manual button never run concurrently.
    """
    async with WORKER_SYNC_LOCK:
        source_url = WORKER.get("source_url", "")
        try:
            text = await _fetch_proxy_daily(source_url)
            parsed = _parse_proxy_daily(text)
            if not parsed:
                raise ValueError("در منبع، کشوری پیدا نشد (قالب تغییر کرده؟)")
            async with WORKER_LOCK:
                # Merge: entries manually added/edited in the panel (manual=True)
                # survive the source refresh, so admin edits are never wiped out.
                manual = {
                    code: p for code, p in (WORKER.get("proxies") or {}).items()
                    if p.get("manual")
                }
                parsed.update(manual)
                WORKER["proxies"] = parsed
                WORKER["sync_count"] = int(WORKER.get("sync_count", 0)) + 1
            deploy_ok = True
            if WORKER.get("connected"):
                sc, sd = await _worker_deploy()
                deploy_ok = sc in (200, 201, 409)
                if not deploy_ok:
                    raise ValueError((sd.get("errors") or [{}])[0].get("message", "deploy failed"))
                # After deploy, immediately push the fresh proxy map + users
                # into the Worker KV. The deployed script itself is provider
                # neutral; runtime routing state lives in the dedicated KV.
                push = await _worker_push_config()
                if not push.get("ok"):
                    logger.warning("worker runtime config push after source sync failed: %s", push.get("detail"))
            # Keep the default Worker inbound pointed at the worker domain.
            await _ensure_worker_inbound()
            async with WORKER_LOCK:
                WORKER["last_sync"] = now_ir().isoformat(timespec="seconds")
                WORKER["sync_error"] = ""
                WORKER["last_error"] = ""
            asyncio.create_task(save_state())
            log_activity("worker", f"پروکسی‌های Worker از منبع بروزرسانی شد ({len(parsed)} کشور)", "ok")
            return {
                "ok": True,
                "countries": len(parsed),
                "count": sum(len(v.get("proxies") or [v.get("proxy")]) for v in parsed.values()),
                "deployed": deploy_ok,
            }
        except Exception as e:
            msg = str(e)
            async with WORKER_LOCK:
                WORKER["sync_error"] = msg
                WORKER["last_error"] = msg
            asyncio.create_task(save_state())
            logger.warning(f"worker proxy sync failed: {msg}")
            return {"ok": False, "error": msg}


@app.get("/api/worker")
async def worker_get(_=Depends(require_auth)):
    """Worker status + proxy map (token is never exposed)."""
    async with WORKER_LOCK:
        return {"ok": True, **_worker_public()}


@app.post("/api/worker/setup")
async def worker_setup(request: Request, _=Depends(require_auth)):
    """Create/reuse a Cloudflare Pages project and deploy the managed worker source as `_worker.js`.

    The supplied Cloudflare API token is validated first. A dedicated KV
    namespace is created/attached, then the project is deployed in Pages
    Advanced Mode with `_worker.js` and the SPIDER_KV binding.
    """
    body = await request.json()
    token = str(body.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token is required")

    account_id = ""
    email = ""

    # Verify token.
    _is_gak = _is_cf_gak(token)
    verify_path = "/user/tokens/verify" if not _is_gak else "/user"
    code, data = await _cf_api("GET", verify_path, token, email=email)
    if code != 200 or not data.get("success"):
        msg = (data.get("errors") or [{}])[0].get("message", "invalid token")
        raise HTTPException(status_code=400, detail=f"Cloudflare token rejected: {msg}")

    # Auto-detect account.
    code_acc, data_acc = await _cf_api(
        "GET",
        "/accounts?page=1&per_page=50",
        token,
        email=email,
    )
    if code_acc == 200 and data_acc.get("result"):
        accounts = data_acc["result"]
        if isinstance(accounts, list) and accounts:
            account_id = str(accounts[0].get("id") or "")

    if not account_id:
        errs = data_acc.get("errors") or []
        detail = "Could not auto-detect Cloudflare Account ID. The token needs account access plus Pages Write and Workers KV Storage Edit."
        if errs:
            detail = "Cloudflare account lookup failed: " + "; ".join(
                str(e.get("message") or e.get("code") or "unknown error")
                for e in errs[:3]
            )
        raise HTTPException(status_code=400, detail=detail)

    worker_name = str(body.get("worker_name") or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", worker_name or ""):
        worker_name = "spider-" + secrets.token_hex(3)

    stable_domain = f"{worker_name}.pages.dev"

    async with WORKER_LOCK:
        WORKER.update({
            "connected": True,
            "account_id": account_id,
            "worker_name": worker_name,
            "worker_domain": stable_domain,
            "worker_url": f"https://{stable_domain}",
            "pages_project_name": worker_name,
            "pages_project_id": "",
            "pages_url": f"https://{stable_domain}",
            "token": token,
            "kv_namespace_id": "",
            "kv_namespace_title": "",
            "remote_status": "",
            "last_heartbeat": "",
            "worker_users_online": 0,
            "worker_traffic_bytes": 0,
            "worker_user_count": 0,
            "last_error": "",
        })

    kv_id = await _ensure_worker_kv()
    if not kv_id:
        async with WORKER_LOCK:
            WORKER["last_error"] = "Could not create/find dedicated Worker KV namespace"
        asyncio.create_task(save_state())
        raise HTTPException(status_code=500, detail="Could not create/find dedicated Worker KV namespace")

    sc, sd = await _worker_deploy()
    if sc not in (200, 201, 409):
        msg = (sd.get("errors") or [{}])[0].get("message", "Pages deploy failed")
        async with WORKER_LOCK:
            WORKER["last_error"] = msg
        asyncio.create_task(save_state())
        raise HTTPException(status_code=500, detail=f"Worker Pages deploy failed: {msg}")

    await _ensure_worker_inbound()
    ctrl_res = await _worker_push_config()
    deferred_sync = False
    deferred_reason = ""
    if not ctrl_res.get("ok"):
        detail = ctrl_res.get("detail", "worker config push failed")
        if _worker_transient_network_error(detail):
            # Pages deployments can need a short DNS propagation window. The
            # worker is already deployed, so do not report creation as failed.
            deferred_sync = True
            deferred_reason = detail
            async with WORKER_LOCK:
                WORKER["last_error"] = ""
                WORKER["remote_status"] = "pending"
            asyncio.create_task(_worker_retry_after_deploy())
        else:
            async with WORKER_LOCK:
                WORKER["last_error"] = detail
            asyncio.create_task(save_state())
            raise HTTPException(status_code=502, detail=f"Worker control sync failed: {detail}")

    if not deferred_sync:
        await _worker_pull_all_users()

    async with WORKER_LOCK:
        WORKER["last_sync"] = now_ir().isoformat(timespec="seconds")
        WORKER["last_error"] = ""
        WORKER["remote_status"] = "pending" if deferred_sync else "deployed"

    asyncio.create_task(save_state())
    log_activity(
        "worker",
        f"Cloudflare Pages Worker ساخته و Deploy شد ({worker_name} / KV: {WORKER.get('kv_namespace_title') or kv_id})",
        "ok",
    )
    async with WORKER_LOCK:
        out = {"ok": True, **_worker_public()}
    if deferred_sync:
        out["deferred_sync"] = True
        out["deferred_reason"] = deferred_reason
    return out


@app.post("/api/worker/sync")
async def worker_sync(_=Depends(require_auth)):
    """Re-deploy the managed Pages Worker after proxy changes and re-push users/quotas."""
    if not WORKER.get("connected"):
        raise HTTPException(status_code=400, detail="worker is not connected")
    sc, sd = await _worker_deploy()
    if sc in (200, 201, 409):
        await _ensure_worker_inbound()
        push = await _worker_push_config()
        if not push.get("ok"):
            await _worker_sync_users()
        await _worker_pull_all_users()
    async with WORKER_LOCK:
        if sc in (200, 201, 409):
            WORKER["last_sync"] = now_ir().isoformat(timespec="seconds")
            WORKER["last_error"] = ""
            out = {"ok": True, **_worker_public()}
        else:
            msg = (sd.get("errors") or [{}])[0].get("message", "deploy failed")
            WORKER["last_error"] = msg
            out = {"ok": False, "error": msg, **_worker_public()}
    asyncio.create_task(save_state())
    return out


@app.post("/api/worker/sync-source")
async def worker_sync_source(_=Depends(require_auth)):
    """Fetch the daily proxy source now, update the pool and re-deploy."""
    res = await _sync_worker_proxies_from_source()
    if not res.get("ok"):
        return JSONResponse(status_code=400, content={"ok": False, "error": res.get("error")})
    async with WORKER_LOCK:
        return {"ok": True, **_worker_public(), "sync": res}


@app.post("/api/worker/settings")
async def worker_settings(request: Request, _=Depends(require_auth)):
    """Update worker source URL / auto-sync preference."""
    body = await request.json()
    async with WORKER_LOCK:
        if "source_url" in body:
            src = str(body["source_url"] or "").strip()
            if src:
                WORKER["source_url"] = src
        if "auto_sync" in body:
            WORKER["auto_sync"] = bool(body["auto_sync"])
        out = {"ok": True, **_worker_public()}
    asyncio.create_task(save_state())
    return out


@app.post("/api/worker/health-check")
async def worker_health_check(_=Depends(require_auth)):
    """Force an active Cloudflare Worker downstream route health check."""
    if not WORKER.get("connected"):
        raise HTTPException(status_code=400, detail="worker is not connected")
    domain = _worker_safe_domain(WORKER.get("worker_domain"))
    ctrl = str(WORKER.get("control_token") or "")
    if not domain or not ctrl:
        raise HTTPException(status_code=400, detail="worker control plane is unavailable")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.post(f"https://{domain}/panel/health-check", headers={"Authorization": f"Bearer {ctrl}"})
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code != 200:
            return JSONResponse(status_code=502, content={"ok": False, "detail": data.get("error") or f"HTTP {r.status_code}"})
        async with WORKER_LOCK:
            WORKER["routing_status"] = dict(data.get("routing") or {})
            WORKER["last_heartbeat"] = now_ir().isoformat(timespec="seconds")
            WORKER["remote_status"] = "online"
        asyncio.create_task(save_state())
        return {"ok": True, "routing": data.get("routing") or {}, **_worker_public()}
    except Exception as e:
        async with WORKER_LOCK:
            WORKER["remote_status"] = "unreachable"
            WORKER["last_error"] = str(e)
        asyncio.create_task(save_state())
        return JSONResponse(status_code=502, content={"ok": False, "detail": str(e), **_worker_public()})


@app.post("/api/worker/heartbeat")
async def worker_heartbeat(_=Depends(require_auth)):
    """Ping the worker's /panel/status and refresh remote counters (traffic,
    online users, user count). Called by the UI on a timer."""
    if not WORKER.get("connected"):
        raise HTTPException(status_code=400, detail="worker is not connected")
    res = await _worker_pull_status()
    async with WORKER_LOCK:
        out = {"ok": bool(res.get("ok")), "detail": res.get("detail", ""), **_worker_public()}
    return out

@app.delete("/api/worker")
async def worker_disconnect(_=Depends(require_auth)):
    """Remove the worker connection (keeps nothing sensitive)."""
    async with WORKER_LOCK:
        WORKER.clear()
        WORKER.update({
            "connected": False,
            "account_id": "",
            "worker_name": "",
            "worker_domain": "",
            "worker_url": "",
            "pages_project_name": "",
            "pages_project_id": "",
            "pages_url": "",
            "token": "",
            "kv_namespace_id": "",
            "kv_namespace_title": "",
            "remote_status": "",
            "last_heartbeat": "",
            "worker_users_online": 0,
            "worker_traffic_bytes": 0,
            "worker_user_count": 0,
            "proxies": {},
            "last_sync": "",
            "last_error": "",
            "source_url": "https://raw.githubusercontent.com/NiREvil/vless/main/sub/ProxyIP-Daily.md",
            "auto_sync": True,
            "sync_error": "",
            "sync_count": 0,
            "routing_status": {},
        })
    asyncio.create_task(save_state())
    log_activity("worker", "Worker قطع شد", "warn")
    return {"ok": True}


@app.post("/api/worker/proxies")
async def worker_add_proxy(request: Request, _=Depends(require_auth)):
    """Add or update a proxy country entry, then re-deploy the worker."""
    body = await request.json()
    code = str(body.get("code") or "").strip().lower()
    country = str(body.get("country") or "").strip()
    proxy = str(body.get("proxy") or "").strip()
    port = int(body.get("port") or 443)
    continent = str(body.get("continent") or "").strip().upper()[:2]
    colo = str(body.get("colo") or "").strip().upper()[:8]
    region = str(body.get("region") or "").strip()[:80]
    try:
        latitude = float(body.get("latitude")) if body.get("latitude") not in (None, "") else 0.0
        longitude = float(body.get("longitude")) if body.get("longitude") not in (None, "") else 0.0
    except Exception:
        latitude, longitude = 0.0, 0.0
    if not code or not country or not proxy:
        raise HTTPException(status_code=400, detail="code, country and proxy are required")
    if not re.fullmatch(r"[a-z0-9_-]{1,16}", code):
        raise HTTPException(status_code=400, detail="invalid country code (a-z0-9_-)")
    async with WORKER_LOCK:
        (WORKER.setdefault("proxies", {}))[code] = {
            "country": country,
            "country_code": code.upper(),
            "proxy": proxy,
            "port": max(1, min(65535, port)),
            "continent": continent,
            "colo": colo,
            "region": region,
            "latitude": latitude if -90 <= latitude <= 90 else 0.0,
            "longitude": longitude if -180 <= longitude <= 180 else 0.0,
            "manual": True,
        }
    if WORKER.get("connected"):
        await worker_sync(None)
    else:
        asyncio.create_task(save_state())
    async with WORKER_LOCK:
        return {"ok": True, **_worker_public()}


@app.delete("/api/worker/proxies/{code}")
async def worker_del_proxy(code: str, _=Depends(require_auth)):
    """Remove a proxy country entry and re-deploy."""
    async with WORKER_LOCK:
        (WORKER.get("proxies") or {}).pop(code.lower(), None)
    if WORKER.get("connected"):
        await worker_sync(None)
    else:
        asyncio.create_task(save_state())
    async with WORKER_LOCK:
        return {"ok": True, **_worker_public()}


@app.get("/api/worker/locations")
async def worker_locations(_=Depends(require_auth)):
    """Location status list for the Map tab. Prefers live data from the worker."""
    async with WORKER_LOCK:
        if WORKER.get("connected") and WORKER.get("worker_url"):
            try:
                async with httpx.AsyncClient(timeout=12) as client:
                    r = await client.get(f"{WORKER['worker_url']}/api/locations")
                if r.status_code == 200:
                    return {"ok": True, "locations": r.json()}
            except Exception:
                pass
            return {"ok": True, "locations": [
                {"country": p.get("country"), "code": c, "proxy": p.get("proxy"),
                 "port": p.get("port", 443), "status": "online", "ping": 0}
                for c, p in (WORKER.get("proxies") or {}).items()
            ]}
    return {"ok": True, "locations": []}


@app.get("/api/worker/inbounds")
async def worker_inbounds(_=Depends(require_auth)):
    """Return worker inbounds with their country options for user creation modal."""
    async with INBOUNDS_LOCK:
        worker_inbounds = []
        for iid, ib in INBOUNDS.items():
            if (ib.get("protocol") or "").lower() == "worker":
                worker_inbounds.append({
                    "inbound_id": iid,
                    "name": ib.get("name", "Worker"),
                    "domain": ib.get("domain", ""),
                    "countries": [
                        {"code": c, "country": p.get("country", c.upper())}
                        for c, p in (WORKER.get("proxies") or {}).items()
                    ]
                })
    return {"ok": True, "inbounds": worker_inbounds}


# ══════════════════════════════════════════════════════════════════════════════
# TUNNEL — user → Railway → Cloudflare Worker → site
# The tunnel inbound is a TLS+WS inbound on the RAILWAY domain with path
# /tunnel/{uuid}. Railway forwards to the Worker; the Worker connects out to
# the destination. The tunnel has its own dedicated KV namespace (TUNNEL_KV).
# ══════════════════════════════════════════════════════════════════════════════

def _tunnel_log(msg: str):
    WORKER.setdefault("tunnel_logs", []).append(
        {"msg": str(msg)[:250], "time": now_ir().isoformat(timespec="seconds")})
    if len(WORKER["tunnel_logs"]) > 100:
        del WORKER["tunnel_logs"][:-100]


@app.post("/api/tunnel/create")
async def tunnel_create(_=Depends(require_auth)):
    """Create the Tunnel inbound + its dedicated KV namespace.

    Steps:
      1. ensure the TUNNEL_KV namespace exists ({worker}-db-tunnel),
      2. mark tunnel_enabled → next deploy binds TUNNEL_KV and re-deploys,
      3. create/refresh the 'default-tunnel' inbound: TLS + WS on the Railway
         panel domain with ws path /tunnel/{uuid}.
    """
    if not WORKER.get("connected"):
        raise HTTPException(status_code=400, detail="worker is not connected")
    kv_id = await _ensure_tunnel_kv()
    if not kv_id:
        raise HTTPException(status_code=500, detail="could not create tunnel KV namespace")
    async with WORKER_LOCK:
        WORKER["tunnel_enabled"] = True
        if not WORKER.get("tunnel_created_at"):
            WORKER["tunnel_created_at"] = now_ir().isoformat(timespec="seconds")
        _tunnel_log(f"Tunnel KV ساخته شد: {WORKER.get('tunnel_kv_namespace_title')}")
    # Re-deploy so the TUNNEL_KV binding goes live.
    sc, sd = await _worker_deploy()
    ok_deploy = sc in (200, 201, 409)
    async with WORKER_LOCK:
        _tunnel_log("Worker با binding جدید deploy شد" if ok_deploy else f"deploy ناموفق: {sc}")
    panel_domain = _safe_host(SETTINGS.get("domain"), get_host())
    async with INBOUNDS_LOCK:
        INBOUNDS["default-tunnel"] = {
            "name": "Tunnel (Railway → CF Worker)",
            "protocol": "tunnel",
            "port": 443,
            "network": "ws",
            "security": "tls",
            "domain": panel_domain,
            "external_domain": panel_domain,
            "sni": "",
            "spoof_ip": "",
            "external_port": 443,
            "fingerprint": "chrome",
            "reality_settings": {},
            "xhttp_settings": {},
            "ws_settings": {"path": "/tunnel/{uuid}"},
            "grpc_settings": {},
            "worker_domain": str(WORKER.get("worker_domain") or ""),
            "created_at": datetime.now().isoformat(),
        }
        changed = True
    asyncio.create_task(save_state())
    async with WORKER_LOCK:
        _tunnel_log(f"اینباند Tunnel روی {panel_domain} با مسیر /tunnel/{{uuid}} ساخته شد")
    log_activity("tunnel", "اینباند Tunnel ایجاد شد", "ok")
    asyncio.create_task(save_state())
    return {"ok": True, **_worker_public(), "deployed": ok_deploy}


@app.get("/api/tunnel/status")
async def tunnel_status(_=Depends(require_auth)):
    """Tunnel tab data: ping server→worker, details, logs."""
    wdom = str(WORKER.get("worker_domain") or "").strip().lower()
    ping_ms = None
    if wdom:
        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(f"https://{wdom}/")
            if r.status_code < 500:
                ping_ms = round((time.time() - t0) * 1000)
        except Exception:
            ping_ms = None
    tid = next((iid for iid, ib in INBOUNDS.items()
                if ((ib or {}).get("protocol") or "").lower() == "tunnel"), None)
    # Reverse info (shown under the tunnel info in the Tunnel tab).
    rev_ping_ms = None
    if wdom:
        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r2 = await client.get(f"https://{wdom}/health")
            if r2.status_code < 500:
                rev_ping_ms = round((time.time() - t0) * 1000)
        except Exception:
            rev_ping_ms = None
    return {
        "ok": True,
        "worker_connected": bool(WORKER.get("connected")),
        "tunnel_enabled": bool(WORKER.get("tunnel_enabled")),
        "inbound_exists": tid is not None,
        "ping_ms": ping_ms,
        "worker_url": WORKER.get("worker_url", ""),
        "worker_domain": wdom,
        "panel_domain": _safe_host(SETTINGS.get("domain"), get_host()),
        "tunnel_kv_title": WORKER.get("tunnel_kv_namespace_title", ""),
        "tunnel_kv_id": WORKER.get("tunnel_kv_namespace_id", ""),
        "reverse_enabled": bool(tid and (INBOUNDS[tid] or {}).get("reverse_enabled")),
        "reverse_ping_ms": rev_ping_ms,
        "reverse_path": f"/reverse/{{uuid}}" if (tid and (INBOUNDS[tid] or {}).get("reverse_enabled")) else "",
        "reverse_kv_title": WORKER.get("reverse_kv_namespace_title", ""),
        "reverse_kv_id": WORKER.get("reverse_kv_namespace_id", ""),
        "last_heartbeat": WORKER.get("last_heartbeat", ""),
        "remote_status": WORKER.get("remote_status", ""),
        "logs": list(WORKER.get("tunnel_logs") or [])[-30:],
    }


@app.post("/api/tunnel/reverse")
async def tunnel_reverse_toggle(request: Request, _=Depends(require_auth)):
    """Toggle reverse mode on the tunnel inbound.

    ON:  user → Worker → Railway → site; config domain = worker domain,
         ws path /reverse/{uuid}; user records live in REVERSE_KV.
    OFF: back to the plain tunnel chain (user → Railway → Worker → site).
    """
    body = await request.json()
    enabled = bool(body.get("enabled"))
    if not WORKER.get("connected"):
        raise HTTPException(status_code=400, detail="worker is not connected")
    async with INBOUNDS_LOCK:
        tid = next((iid for iid, ib in INBOUNDS.items()
                    if ((ib or {}).get("protocol") or "").lower() == "tunnel"), None)
        if not tid:
            raise HTTPException(status_code=400, detail="ابتدا اینباند Tunnel را بسازید")
        INBOUNDS[tid]["reverse_enabled"] = enabled
    if enabled:
        kv_ok = await _ensure_reverse_kv()
        if not kv_ok:
            raise HTTPException(status_code=500, detail="could not create reverse KV namespace")
        async with WORKER_LOCK:
            _tunnel_log(f"Reverse KV آماده شد: {WORKER.get('reverse_kv_namespace_title')}")
    # Re-deploy so the REVERSE_KV binding goes live when first needed.
    sc, sd = await _worker_deploy()
    ok_deploy = sc in (200, 201, 409)
    wdom = str(WORKER.get("worker_domain") or "")
    async with WORKER_LOCK:
        if enabled:
            _tunnel_log(f"Reverse فعال شد — دامنه {wdom} با مسیر /reverse/{{uuid}}")
            _tunnel_log("Worker با REVERSE_KV deploy شد" if ok_deploy else f"deploy ناموفق: {sc}")
        else:
            _tunnel_log("Reverse غیرفعال شد")
    log_activity("tunnel", f"Reverse {'فعال' if enabled else 'غیرفعال'} شد", "ok")
    asyncio.create_task(save_state())
    return {"ok": True, "enabled": enabled, **_worker_public(), "deployed": ok_deploy}


# ══════════════════════════════════════════════════════════════════════════════
# IP SCANNER endpoints — live-saved scanned IPs + DNS resolve for the TCP tab
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/scanner/ips/{ctype}")
async def scanner_get_ips(ctype: str, _=Depends(require_auth)):
    """Return the live-saved ip:port list for a scanned source (cf | railway)."""
    ctype = ctype.strip().lower()
    if ctype not in _SCANNED_TYPES:
        raise HTTPException(status_code=400, detail="invalid scanner source")
    return {"ok": True, "type": ctype, "ips": _read_scanned_ips(ctype), "seq": SCANNED_SEQ.get(ctype, 0)}


@app.get("/api/scanner/cf-subnets")
async def scanner_cf_subnets(_=Depends(require_auth)):
    """Return Cloudflare subnets from cf_subnets.txt for IP range generation."""
    subnets_file = Path(os.path.dirname(os.path.abspath(__file__))) / "data" / "cf_subnets.txt"
    if not subnets_file.is_file():
        subnets_file = DATA_DIR / "cf_subnets.txt"
    if not subnets_file.is_file():
        return {"subnets": []}
    lines = subnets_file.read_text(errors="ignore").splitlines()
    subnets = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    return {"subnets": subnets}


@app.get("/api/scanner/sni-list")
async def scanner_sni_list(_=Depends(require_auth)):
    """Return SNI list from sni-list.txt for spoof scanning."""
    sni_file = Path(os.path.dirname(os.path.abspath(__file__))) / "data" / "sni-list.txt"
    if not sni_file.is_file():
        sni_file = DATA_DIR / "sni-list.txt"
    if not sni_file.is_file():
        return {"sni_list": []}
    lines = sni_file.read_text(errors="ignore").splitlines()
    snis = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    return {"sni_list": snis}


@app.post("/api/scanner/save")
async def scanner_save_ips(request: Request, _=Depends(require_auth)):
    """Live-save found ip:port entries to the source file (first 10 kept).

    Every write is guarded by a per-type sequence number: the client sends the
    seq of the last write it saw, and any write carrying an older seq is dropped.
    This guarantees a clear() can never be undone by a scan save that was already
    in flight when the user clicked "پاک کردن".
    """
    body = await request.json()
    ctype = str(body.get("type") or "").strip().lower()
    if ctype not in _SCANNED_TYPES:
        raise HTTPException(status_code=400, detail="invalid scanner source")
    raw = body.get("ips") or []
    replace = bool(body.get("replace"))
    cur_seq = SCANNED_SEQ.get(ctype, 0)
    sent_seq = int(body.get("seq") or 0)
    # Stale write (clear landed first, or an older save raced a newer clear).
    if sent_seq != cur_seq:
        return {"ok": False, "stale": True, "type": ctype, "seq": cur_seq, "ips": _read_scanned_ips(ctype)}
    entries = []
    for x in raw[:_SCANNED_MAX]:
        x = str(x).strip()
        if not x:
            continue
        if ":" in x:
            ip, _, port = x.rpartition(":")
        elif " " in x:
            ip, _, port = x.partition(" ")
        else:
            ip, port = x, "443"
        ip, port = ip.strip(), port.strip()
        if ip and port:
            entries.append(f"{ip}:{port}")
    merged = _save_scanned_ips(ctype, entries, replace=replace)
    SCANNED_SEQ[ctype] = cur_seq + 1
    return {"ok": True, "type": ctype, "ips": merged, "seq": SCANNED_SEQ[ctype]}


@app.get("/api/scanner/resolve")
async def scanner_resolve(host: str, _=Depends(require_auth)):
    """Resolve a hostname to its A/AAAA IPs (used by the TCP scanner tab)."""
    host = str(host or "").strip().lower()
    if not host:
        raise HTTPException(status_code=400, detail="empty host")
    ips = []
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, proto=6)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return {"ok": True, "host": host, "ips": ips[:8]}


@app.post("/api/scanner/ping-batch")
async def scanner_ping_batch(request: Request, _=Depends(require_auth)):
    """TCP-connect latency check for arbitrary ip[:port] targets.

    The IP scanner generates candidate CF / Railway IPs in the browser and sends
    them here in batches; the panel measures real connect latency so the result
    is reliable (browsers cannot open raw TCP sockets).
    """
    body = await request.json()
    targets = body.get("targets") or []
    timeout = max(0.4, min(float(body.get("timeout") or 2.0), 6.0))
    if isinstance(targets, str):
        targets = [x for x in targets.replace(",", " ").split() if x]
    targets = [str(t).strip() for t in targets][:150]

    sem = asyncio.Semaphore(20)

    async def probe(t):
        if ":" in t:
            ip, _, port = t.rpartition(":")
        else:
            ip, port = t, "443"
        ip = ip.strip()
        try:
            port = int(port.strip())
        except Exception:
            port = 443
        async with sem:
            t0 = time.time()
            try:
                rdr, wtr = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
                lat = int((time.time() - t0) * 1000)
                try:
                    wtr.close()
                    await wtr.wait_closed()
                except Exception:
                    pass
                return {"target": t, "ip": ip, "port": port, "latency_ms": lat, "ok": True}
            except Exception:
                return {"target": t, "ip": ip, "port": port, "latency_ms": None, "ok": False}

    results = await asyncio.gather(*(probe(t) for t in targets))
    results.sort(key=lambda r: (not r["ok"], r["latency_ms"] if r["latency_ms"] is not None else 10 ** 9))
    return {"ok": True, "count": len(results), "results": results}


# ══════════════════════════════════════════════════════════════════════════════
# SNI SCANNER endpoints — scan SNI list and find fastest for Reality
# ══════════════════════════════════════════════════════════════════════════════

def _sni_scan_file() -> Path:
    """Path to the SNI scan source file."""
    p = Path(os.path.dirname(os.path.abspath(__file__))) / "data" / "sni_reality_for_scan.txt"
    if p.is_file():
        return p
    return DATA_DIR / "sni_reality_for_scan.txt"


def _sni_result_file() -> Path:
    """Path to the SNI scan results file."""
    p = Path(os.path.dirname(os.path.abspath(__file__))) / "data" / "sni_reality.txt"
    if p.is_file():
        return p
    return DATA_DIR / "sni_reality.txt"


def _read_sni_list() -> list:
    """Read SNI list from the scan source file."""
    f = _sni_scan_file()
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Clean markdown links: [text](url) → text
        if line.startswith("[") and "](" in line:
            line = line.split("](")[0].lstrip("[")
        out.append(line)
    return out


def _read_sni_results() -> list:
    """Read the fastest SNIs from the results file."""
    f = _sni_result_file()
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        sni = parts[0].strip()
        latency = int(parts[1].strip()) if len(parts) > 1 else 0
        if sni:
            out.append({"sni": sni, "latency_ms": latency})
    return out


@app.get("/api/scanner/sni-check")
async def scanner_sni_check(host: str, port: int = 443, _=Depends(require_auth)):
    """Perform a real TLS handshake using the supplied hostname as SNI."""
    import ssl
    host = str(host or "").strip().lower()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host) or "/" in host:
        raise HTTPException(status_code=400, detail="invalid SNI host")
    port = int(port or 443)
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="invalid port")
    started = time.perf_counter()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=3.0
        )
        ms = round((time.perf_counter() - started) * 1000, 2)
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
        return {"ok": True, "sni": host, "latency_ms": ms, "port": port}
    except Exception as e:
        return {"ok": False, "sni": host, "latency_ms": round((time.perf_counter()-started)*1000,2), "port": port, "error": str(e)[:180]}


@app.get("/api/scanner/sni-scan-list")
async def scanner_sni_scan_list(_=Depends(require_auth)):
    """Return the SNI list for scanning."""
    snis = _read_sni_list()
    return {"ok": True, "snis": snis, "count": len(snis)}


@app.get("/api/scanner/sni-results")
async def scanner_sni_results(_=Depends(require_auth)):
    """Return the fastest SNIs from previous scans."""
    results = _read_sni_results()
    return {"ok": True, "results": results}


@app.post("/api/scanner/sni-clear-results")
async def scanner_sni_clear_results(_=Depends(require_auth)):
    """Clear live SNI results before a new manual/auto scan."""
    f = _sni_result_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# Fastest SNIs for Reality\n# Format: sni|latency_ms\n", encoding="utf-8")
    return {"ok": True, "results": []}


@app.post("/api/scanner/sni-save-results")
async def scanner_sni_save_results(request: Request, _=Depends(require_auth)):
    body = await request.json()
    incoming = body.get("results") or []
    top_n = max(1, min(int(body.get("top") or 3), 10))
    merged = {}
    for old in _read_sni_results():
        name = str(old.get("sni") or "").strip().lower()
        try: lat = float(old.get("latency_ms"))
        except Exception: continue
        if name and lat >= 0: merged[name] = lat
    for r in incoming:
        name = str(r.get("sni") or "").strip().lower()
        try: lat = float(r.get("latency_ms"))
        except Exception: continue
        if name and lat >= 0 and (name not in merged or lat < merged[name]): merged[name] = lat
    results = [{"sni":k,"latency_ms":round(v,2)} for k,v in merged.items()]
    results.sort(key=lambda x:x["latency_ms"])
    results = results[:top_n]
    f=_sni_result_file(); f.parent.mkdir(parents=True,exist_ok=True)
    f.write_text("# Fastest SNIs for Reality\n# Format: sni|latency_ms\n"+"\n".join(f"{r['sni']}|{r['latency_ms']}" for r in results)+"\n",encoding="utf-8")
    return {"ok":True,"saved":len(results),"results":results}


@app.get("/api/scanner/sni-fastest")
async def scanner_sni_fastest(_=Depends(require_auth)):
    """Return the single fastest SNI from results (for the lightning button)."""
    results = _read_sni_results()
    if results:
        return {"ok": True, "sni": results[0]["sni"], "latency_ms": results[0].get("latency_ms", 0)}
    return {"ok": False, "sni": "", "latency_ms": 0}



# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM BOT AUTOMATION
# ══════════════════════════════════════════════════════════════════════════════


def _bot_cfg() -> dict:
    cfg = SETTINGS.setdefault("telegram_bot", {})
    cfg.setdefault("token", "")
    cfg.setdefault("channel", {})
    cfg.setdefault("sell", {})

    ch = cfg["channel"]
    ch.setdefault("enabled", False)
    ch.setdefault("channel", "")
    ch.setdefault("interval_minutes", 60)
    ch.setdefault("username_prefix", "spider")
    ch.setdefault("traffic_limit_gb", 0)
    ch.setdefault("expire_days", 30)
    ch.setdefault("inbound_id", "")
    ch.setdefault("replace_previous", True)
    ch.setdefault("pending_delete_user_ids", [])
    ch.setdefault("last_run_at", "")
    ch.setdefault("last_user_id", "")
    ch.setdefault("last_message_id", 0)
    ch.setdefault("success_count", 0)
    ch.setdefault("error_count", 0)
    ch.setdefault("last_error", "")
    ch.setdefault("last_delete_error", "")
    ch.setdefault("next_run_at", "")

    sell = cfg["sell"]
    sell.setdefault("enabled", False)
    sell.setdefault("admin_chat_id", "")
    sell.setdefault("support_username", "")
    sell.setdefault("support_text", "💬 برای پشتیبانی با مدیر فروش تماس بگیرید.")
    sell.setdefault("payment_url", "")
    sell.setdefault("payment_details", "")
    sell.setdefault("required_channels", [])
    if not isinstance(sell.get("required_channels"), list):
        sell["required_channels"] = []
    sell["required_channels"] = [x for x in sell["required_channels"][:200] if isinstance(x, (str, dict))]
    sell.setdefault("welcome_text", "سلام 👋\nبرای مشاهده پلن‌ها از دکمه‌های زیر استفاده کنید.")
    sell.setdefault("last_update_at", "")
    sell.setdefault("last_error", "")
    sell.setdefault("offset", 0)
    sell.setdefault("plans", [])
    sell.setdefault("customer_users", {})

    # One-time migration from the old single-plan schema.
    plans_raw = sell.get("plans", None)
    plans_missing = not isinstance(plans_raw, list)
    if plans_missing:
        plans = []
        sell["plans"] = plans
    else:
        plans = plans_raw
    # Legacy single-plan migration is allowed only when the old key did not exist.
    # An intentionally empty plan list must remain empty so the final plan can be deleted.
    if plans_missing and any(str(sell.get(k) or "").strip() for k in ("plan_name", "price")):
        plans.append({
            "id": "pln_" + secrets.token_hex(4),
            "name": str(sell.get("plan_name") or "1 ماهه").strip()[:80],
            "price": str(sell.get("price") or "توافقی").strip()[:80],
            "traffic_gb": max(0.0, float(sell.get("traffic_gb") or 0)),
            "expire_days": max(0, int(sell.get("expire_days") or 0)),
            "inbound_id": str(sell.get("inbound_id") or _bot_default_inbound_id()).strip(),
            "username_prefix": "shop",
            "enabled": True,
            "created_at": datetime.now().isoformat(),
        })
    # Backward-compatible display fields.
    if plans:
        first = plans[0]
        sell["plan_name"] = first.get("name") or "1 ماهه"
        sell["price"] = first.get("price") or ""
        sell["traffic_gb"] = first.get("traffic_gb") or 0
        sell["expire_days"] = first.get("expire_days") or 0
    return cfg


def _mask_bot_token(token: str) -> str:
    token = str(token or "")
    if len(token) <= 10:
        return "••••••••" if token else ""
    return token[:6] + "••••••••" + token[-4:]


def _normalize_tg_channel(value: str):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Channel link / @username is required")
    if re.fullmatch(r"-?\d{5,}", raw):
        return raw, "", raw
    if raw.startswith("@") and re.fullmatch(r"@[A-Za-z0-9_]{4,}", raw):
        username = raw[1:]
        return raw, f"https://t.me/{username}", f"@{username}"
    m = re.match(r"^https?://(?:www\.)?t\.me/([^/?#]+)", raw, re.I)
    if m:
        slug = m.group(1)
        if slug.startswith("+"):
            return raw, raw, raw
        if slug.lower().startswith("c/"):
            return raw, raw, raw
        username = slug.lstrip("@").strip()
        if re.fullmatch(r"[A-Za-z0-9_]{4,}", username):
            return f"@{username}", f"https://t.me/{username}", f"@{username}"
    raise ValueError("Use @channelusername, https://t.me/channelusername, or the numeric chat id")


async def _telegram_api(token: str, method: str, data: dict | None = None, files=None, timeout: float = 20.0):
    token = str(token or "").strip()
    if not token:
        raise ValueError("Telegram Bot API key is not configured")
    url = f"https://api.telegram.org/bot{token}/{method}"
    client = http_client
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=8.0), follow_redirects=True)
    try:
        if files is not None:
            resp = await client.post(url, data=data or {}, files=files, timeout=timeout)
        else:
            resp = await client.post(url, json=data or {}, timeout=timeout)
        try:
            payload = resp.json()
        except Exception:
            payload = {"ok": False, "description": resp.text[:500]}
        if resp.status_code >= 400 or not payload.get("ok"):
            raise RuntimeError(str(payload.get("description") or f"Telegram HTTP {resp.status_code}"))
        return payload.get("result")
    finally:
        if own:
            await client.aclose()


async def _telegram_send_message(token: str, chat_id, text_value: str, parse_mode: str | None = "HTML", reply_markup=None):
    data = {"chat_id": chat_id, "text": text_value, "disable_web_page_preview": False}
    if parse_mode:
        data["parse_mode"] = parse_mode
    if reply_markup is not None:
        data["reply_markup"] = reply_markup
    return await _telegram_api(token, "sendMessage", data=data, timeout=20)


async def _telegram_send_photo(token: str, chat_id, png_bytes: bytes, caption: str, reply_markup=None):
    files = {"photo": ("subscription-qr.png", png_bytes, "image/png")}
    data = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
    if reply_markup is not None:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    return await _telegram_api(token, "sendPhoto", data=data, files=files, timeout=30)


async def _telegram_send_photo_id(token: str, chat_id, file_id: str, caption: str, reply_markup=None):
    data = {"chat_id": chat_id, "photo": file_id, "caption": caption, "parse_mode": "HTML"}
    if reply_markup is not None:
        data["reply_markup"] = reply_markup
    return await _telegram_api(token, "sendPhoto", data=data, timeout=30)


async def _telegram_send_document_id(token: str, chat_id, file_id: str, caption: str, reply_markup=None):
    data = {"chat_id": chat_id, "document": file_id, "caption": caption, "parse_mode": "HTML"}
    if reply_markup is not None:
        data["reply_markup"] = reply_markup
    return await _telegram_api(token, "sendDocument", data=data, timeout=30)


async def _telegram_answer_callback(token: str, callback_id: str, text_value: str = "", show_alert: bool = False):
    data = {"callback_query_id": callback_id}
    if text_value:
        data["text"] = text_value[:180]
    data["show_alert"] = bool(show_alert)
    return await _telegram_api(token, "answerCallbackQuery", data=data, timeout=10)


async def _telegram_edit_message_reply_markup(token: str, chat_id, message_id: int, reply_markup=None):
    data = {"chat_id": chat_id, "message_id": message_id, "reply_markup": reply_markup or {"inline_keyboard": []}}
    return await _telegram_api(token, "editMessageReplyMarkup", data=data, timeout=10)


async def _telegram_edit_message_caption(token: str, chat_id, message_id: int, caption: str):
    return await _telegram_api(token, "editMessageCaption", data={
        "chat_id": chat_id, "message_id": message_id, "caption": caption, "parse_mode": "HTML"
    }, timeout=10)


def _bot_public_subscription_url(config_uuid: str) -> str:
    host = str(SETTINGS.get("domain") or get_host() or "").strip()
    host = re.sub(r"^https?://", "", host, flags=re.I).rstrip("/")
    if not host or host in {"localhost", "127.0.0.1", "0.0.0.0"} or re.match(r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?$", host, re.I):
        raise ValueError("Panel public domain is not ready yet")
    return f"https://{host}/link/{config_uuid}"


def _subscription_qr_bytes(sub_url: str) -> bytes:
    if not QR_AVAILABLE:
        raise RuntimeError("QR generator is unavailable")
    qr = qrcode.QRCode(version=1, box_size=8, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(sub_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _bot_default_inbound_id() -> str:
    preferred = find_default_tls_ws_inbound_id()
    if preferred and preferred in INBOUNDS:
        return str(preferred)
    for iid, ib in INBOUNDS.items():
        if iid == "Node" or bool(ib.get("system")):
            continue
        if str(ib.get("protocol") or "").lower() != "telegram":
            return str(iid)
    return ""


async def _create_bot_user(body: dict) -> dict:
    """Use the normal authenticated create-user route so existing sync logic stays centralized."""
    token = await create_session()
    try:
        client = http_client
        own = client is None
        if own:
            client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=8.0), follow_redirects=True)
        try:
            r = await client.post(
                "http://127.0.0.1:8080/api/users",
                json=body,
                cookies={SESSION_COOKIE: token},
                headers={"X-Spider-Bot": "1"},
                timeout=30.0,
            )
        finally:
            if own:
                await client.aclose()
        try:
            payload = r.json()
        except Exception:
            payload = {"detail": r.text[:500]}
        if r.status_code >= 400:
            raise RuntimeError(str(payload.get("detail") or payload.get("error") or f"create user failed ({r.status_code})"))
        return payload
    finally:
        await destroy_session(token)


async def _delete_bot_user(user_id: str) -> None:
    token = await create_session()
    try:
        client = http_client
        own = client is None
        if own:
            client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=8.0), follow_redirects=True)
        try:
            r = await client.delete(
                f"http://127.0.0.1:8080/api/users/{quote(str(user_id), safe='')}",
                cookies={SESSION_COOKIE: token},
                headers={"X-Spider-Bot": "1"},
                timeout=30.0,
            )
        finally:
            if own:
                await client.aclose()
        if r.status_code not in (200, 404):
            try:
                payload = r.json()
            except Exception:
                payload = {}
            raise RuntimeError(str(payload.get("detail") or f"delete user failed ({r.status_code})"))
    finally:
        await destroy_session(token)


def _make_bot_username(prefix: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", str(prefix or "spider")).strip("-_")[:18] or "spider"
    return f"{safe}-{datetime.now().strftime('%m%d%H%M%S')}-{secrets.token_hex(2)}"[:40]


def _html_tag_link(label: str, url: str) -> str:
    import html as _html
    return f'<a href="{_html.escape(url, quote=True)}">{_html.escape(label or url)}</a>'


def _sell_plans() -> list[dict]:
    sell = _bot_cfg().get("sell") or {}
    plans = sell.get("plans") or []
    return [p for p in plans if isinstance(p, dict) and bool(p.get("enabled", True))]


def _find_sell_plan(plan_id: str) -> dict | None:
    pid = str(plan_id or "").strip()
    for plan in _sell_plans():
        if str(plan.get("id") or "") == pid:
            return dict(plan)
    return None


def _validate_admin_id(value: str) -> str:
    raw = str(value or "").strip()
    if not re.fullmatch(r"\d{1,20}", raw):
        raise ValueError("Admin ID must be the numeric Telegram user ID")
    n = int(raw)
    if n <= 0 or n > 2**63 - 1:
        raise ValueError("Admin ID is out of range")
    return raw


def _normalize_plan_input(data: dict, existing: dict | None = None) -> dict:
    old = existing or {}
    name = str(data.get("name", old.get("name") or "")).strip()[:80]
    if not name:
        raise ValueError("Plan name is required")
    price = str(data.get("price", old.get("price") or "")).strip()[:80]
    if not price:
        raise ValueError("Plan price is required")
    traffic_gb = float(data.get("traffic_gb", old.get("traffic_gb") or 0) or 0)
    expire_days = int(data.get("expire_days", old.get("expire_days") or 0) or 0)
    inbound_id = str(data.get("inbound_id", old.get("inbound_id") or "")).strip()
    if not inbound_id:
        inbound_id = _bot_default_inbound_id()
    if not inbound_id or inbound_id not in INBOUNDS:
        raise ValueError("Select a valid inbound for this plan")
    if traffic_gb < 0 or traffic_gb > 10**6:
        raise ValueError("Traffic is invalid")
    if expire_days < 0 or expire_days > 36500:
        raise ValueError("Time is invalid")
    prefix = re.sub(r"[^A-Za-z0-9_-]+", "-", str(data.get("username_prefix", old.get("username_prefix") or "shop"))).strip("-_")[:24] or "shop"
    return {
        "id": str(old.get("id") or "pln_" + secrets.token_hex(4)),
        "name": name,
        "price": price,
        "traffic_gb": round(traffic_gb, 3),
        "expire_days": expire_days,
        "inbound_id": inbound_id,
        "username_prefix": prefix,
        "enabled": bool(data.get("enabled", old.get("enabled", True))),
        "created_at": str(old.get("created_at") or datetime.now().isoformat()),
        "updated_at": datetime.now().isoformat(),
    }


async def _channel_bot_delete_pending(ch: dict) -> None:
    pending = [str(x) for x in (ch.get("pending_delete_user_ids") or []) if str(x).strip()]
    if not pending:
        ch["last_delete_error"] = ""
        return
    remaining = []
    errors = []
    for uid in pending:
        try:
            await _delete_bot_user(uid)
        except Exception as e:
            remaining.append(uid)
            errors.append(str(e)[:150])
    ch["pending_delete_user_ids"] = remaining[-20:]
    ch["last_delete_error"] = "; ".join(errors)[:400]


async def _channel_bot_run_once() -> dict:
    cfg = _bot_cfg()
    token = str(cfg.get("token") or "").strip()
    ch = cfg.get("channel") or {}
    channel_input = str(ch.get("channel") or "").strip()
    if not token:
        raise RuntimeError("Telegram Bot API key is not configured")
    chat_id, channel_url, channel_label = _normalize_tg_channel(channel_input)
    chat = None
    if str(chat_id).startswith("@") or re.fullmatch(r"-?\d{5,}", str(chat_id)):
        chat = await _telegram_api(token, "getChat", data={"chat_id": chat_id}, timeout=15)
    if chat and str(chat.get("type") or "") != "channel":
        raise RuntimeError("The configured chat is not a Telegram channel")
    if chat:
        username = str(chat.get("username") or "").strip()
        title = str(chat.get("title") or chat.get("username") or channel_label or "Channel").strip()
        if username:
            channel_url = f"https://t.me/{username}"
            channel_label = f"@{username}"
        else:
            channel_label = title
    if not channel_url:
        channel_url = channel_input
    inbound_id = str(ch.get("inbound_id") or _bot_default_inbound_id()).strip()
    body = {
        "username": _make_bot_username(ch.get("username_prefix") or "spider"),
        "traffic_limit_gb": max(0.0, float(ch.get("traffic_limit_gb") or 0)),
        "expire_days": max(0, int(ch.get("expire_days") or 0)),
        "inbound_id": inbound_id or None,
        "inbound_ids": [inbound_id] if inbound_id else [],
        "protocol": "vless",
        "transport_type": "ws",
        "server": "Telegram Channel Bot",
    }
    user = await _create_bot_user(body)
    config_uuid = str(user.get("config_uuid") or "").strip()
    username = str(user.get("username") or body["username"]).strip()
    sub_url = str(user.get("subscription_url") or "").strip() or _bot_public_subscription_url(config_uuid)
    qr_png = _subscription_qr_bytes(sub_url)
    channel_link = _html_tag_link(channel_label or "Channel", channel_url)
    caption = (
        f"<b>🕷 SpiderPanel</b>\n"
        f"👤 <code>{username}</code>\n"
        f"🔗 {_html_tag_link('لینک ساب', sub_url)}\n"
        f"📣 {channel_link}"
    )
    try:
        sent = await _telegram_send_photo(token, chat_id, qr_png, caption)
    except Exception:
        # Do not leak an unpublished channel user.
        try:
            await _delete_bot_user(str(user.get("user_id") or ""))
        except Exception:
            pass
        raise

    previous_user_id = str(ch.get("last_user_id") or "").strip()
    if bool(ch.get("replace_previous", True)) and previous_user_id and previous_user_id != str(user.get("user_id") or ""):
        pending = [str(x) for x in (ch.get("pending_delete_user_ids") or []) if str(x).strip()]
        if previous_user_id not in pending:
            pending.append(previous_user_id)
        ch["pending_delete_user_ids"] = pending[-20:]
        await _channel_bot_delete_pending(ch)

    ch["last_run_at"] = datetime.now().isoformat()
    ch["last_user_id"] = str(user.get("user_id") or "")
    ch["last_message_id"] = int((sent or {}).get("message_id") or 0)
    ch["success_count"] = int(ch.get("success_count") or 0) + 1
    ch["last_error"] = ""
    interval = max(1, min(int(ch.get("interval_minutes") or 60), 10080))
    ch["next_run_at"] = (datetime.now() + timedelta(minutes=interval)).isoformat()
    asyncio.create_task(save_state())
    log_activity("bot", f"Channel Bot: کاربر «{username}» ساخته و به کانال ارسال شد", "ok")
    return {"ok": True, "user": user, "subscription_url": sub_url, "message_id": ch["last_message_id"]}


async def _channel_bot_loop():
    while True:
        try:
            cfg = _bot_cfg()
            ch = cfg.get("channel") or {}
            if not bool(ch.get("enabled")) or not str(cfg.get("token") or "").strip() or not str(ch.get("channel") or "").strip():
                ch["next_run_at"] = ""
                try:
                    await asyncio.wait_for(BOT_WAKE.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    continue
                BOT_WAKE.clear()
                continue
            # Retry any previous user deletions before/alongside scheduled work.
            try:
                await _channel_bot_delete_pending(ch)
            except Exception as e:
                ch["last_delete_error"] = str(e)[:400]
            interval = max(1, min(int(ch.get("interval_minutes") or 60), 10080))
            next_run = 0.0
            if ch.get("next_run_at"):
                try:
                    next_run = datetime.fromisoformat(str(ch["next_run_at"])).timestamp()
                except Exception:
                    next_run = 0.0
            if next_run <= 0:
                ch["next_run_at"] = (datetime.now() + timedelta(minutes=interval)).isoformat()
                asyncio.create_task(save_state())
                next_run = time.time() + interval * 60
            delay = max(0.5, next_run - time.time())
            try:
                await asyncio.wait_for(BOT_WAKE.wait(), timeout=delay)
                BOT_WAKE.clear()
                continue
            except asyncio.TimeoutError:
                pass
            try:
                await _channel_bot_run_once()
            except Exception as e:
                ch["error_count"] = int(ch.get("error_count") or 0) + 1
                ch["last_error"] = str(e)[:400]
                ch["next_run_at"] = (datetime.now() + timedelta(minutes=min(interval, 30))).isoformat()
                asyncio.create_task(save_state())
                logger.warning("Channel Bot run failed: %s", e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Channel Bot scheduler error: %s", e)
            await asyncio.sleep(5)



async def _sell_bot_reset_customer_ui(token: str, chat_id) -> None:
    """Clear the last customer inline keyboard so every new command starts clean."""
    cid = str(chat_id)
    async with BOT_CUSTOMER_UI_LOCK:
        state = dict(BOT_CUSTOMER_UI.get(cid) or {})
        BOT_CUSTOMER_UI.pop(cid, None)
    mid = int(state.get("menu_message_id") or 0)
    if mid:
        try:
            await _telegram_edit_message_reply_markup(token, chat_id, mid, {"inline_keyboard": []})
        except Exception:
            pass


async def _sell_bot_track_customer_message(chat_id, result, section: str = "menu") -> dict:
    """Track only the latest navigational message for this customer."""
    mid = int((result or {}).get("message_id") or 0)
    if mid:
        async with BOT_CUSTOMER_UI_LOCK:
            BOT_CUSTOMER_UI[str(chat_id)] = {
                "menu_message_id": mid,
                "section": str(section or "menu"),
                "updated_at": datetime.now().isoformat(),
            }
    return result or {}


def _sell_main_menu_markup():
    # Keep the customer home screen intentionally small: the three requested sections.
    return {"inline_keyboard": [
        [{"text": "🟢 اعتبار من", "callback_data": "sell:account"},
         {"text": "🛍 محصولات", "callback_data": "sell:products"}],
        [{"text": "💬 پشتیبانی", "callback_data": "sell:support"}],
    ]}


async def _sell_bot_send_main_menu(token: str, chat_id, welcome: str | None = None):
    text = str(welcome or "🕷 <b>SpiderPanel Shop</b>\n\nیکی از بخش‌های زیر را انتخاب کنید:")
    sent = await _telegram_send_message(token, chat_id, text, reply_markup=_sell_main_menu_markup())
    return await _sell_bot_track_customer_message(chat_id, sent, "menu")


def _normalize_required_channel(item) -> dict:
    import html as _html
    if isinstance(item, dict):
        chat_id = str(item.get("chat_id") or item.get("id") or item.get("channel") or "").strip()
        join_url = str(item.get("join_url") or item.get("url") or "").strip()
        title = str(item.get("title") or "").strip()[:80]
    else:
        chat_id = str(item or "").strip()
        join_url = ""
        title = ""
    if not chat_id:
        raise ValueError("شناسه یا @username کانال الزامی است")
    if re.fullmatch(r"@[A-Za-z0-9_]{4,}", chat_id):
        username = chat_id[1:]
        join_url = join_url or f"https://t.me/{username}"
        title = title or f"@{username}"
    elif re.fullmatch(r"-?\d{5,}", chat_id):
        title = title or chat_id
        if not join_url:
            raise ValueError("برای کانال عددی، Join Link الزامی است")
    else:
        m = re.match(r"^https?://(?:www\.)?t\.me/([^/?#]+)$", chat_id, re.I)
        if m and not m.group(1).startswith(("+", "c/")):
            username = m.group(1).lstrip("@")
            if re.fullmatch(r"[A-Za-z0-9_]{4,}", username):
                chat_id = "@" + username
                join_url = join_url or f"https://t.me/{username}"
                title = title or chat_id
        if not chat_id.startswith("@") and not re.fullmatch(r"-?\d{5,}", chat_id):
            raise ValueError("Channel باید @username یا Numeric Chat ID باشد")
    if join_url and not re.match(r"^https?://t\.me/", join_url, re.I):
        raise ValueError("Join Link باید از t.me باشد")
    return {"chat_id": chat_id, "join_url": join_url, "title": title or chat_id}


def _required_channels():
    sell = _bot_cfg().get("sell") or {}
    out = []
    for item in sell.get("required_channels") or []:
        try:
            out.append(_normalize_required_channel(item))
        except Exception:
            continue
    return out


async def _sell_bot_missing_joins(token: str, user_id) -> list[dict]:
    """Return all configured channels where the Telegram user is not a member.

    Checks run concurrently with a small limit so a large required-channel list
    does not make the customer wait serially for every Telegram API request.
    """
    channels = _required_channels()
    if not channels:
        return []
    uid = int(user_id)
    sem = asyncio.Semaphore(8)

    async def check(channel: dict):
        async with sem:
            try:
                member = await _telegram_api(
                    token, "getChatMember",
                    data={"chat_id": channel["chat_id"], "user_id": uid},
                    timeout=12,
                )
                status = str(member.get("status") or "").lower()
                joined = status in {"creator", "administrator", "member"} or (
                    status == "restricted" and bool(member.get("is_member"))
                )
                return None if joined else channel
            except Exception as e:
                return {**channel, "error": str(e)[:180]}

    results = await asyncio.gather(*(check(ch) for ch in channels), return_exceptions=False)
    return [item for item in results if item]


async def _sell_bot_require_joins(token: str, chat_id, user_id) -> bool:
    missing = await _sell_bot_missing_joins(token, user_id)
    if not missing:
        return True
    rows = []
    for ch in missing[:200]:
        url = ch.get("join_url") or (f"https://t.me/{ch['chat_id'][1:]}" if str(ch.get("chat_id") or "").startswith("@") else "")
        if url:
            rows.append([{"text": f"📢 عضویت: {str(ch.get('title') or ch.get('chat_id'))[:28]}", "url": url}])
        else:
            rows.append([{ "text": f"📢 {str(ch.get('title') or ch.get('chat_id'))[:28]}", "callback_data": "sell:join:noop" }])
    rows.append([{"text": "✅ بررسی عضویت", "callback_data": "sell:join:check"}])
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}])
    msg = "🔒 <b>عضویت اجباری</b>\n\nبرای استفاده از فروشگاه، ابتدا در کانال‌های زیر عضو شوید. سپس «بررسی عضویت» را بزنید."
    await _telegram_send_message(token, chat_id, msg, reply_markup={"inline_keyboard": rows})
    return False


async def _sell_bot_get_customer_user(chat_id):
    sell = _bot_cfg().get("sell") or {}
    key = str(chat_id)
    uid = str((sell.get("customer_users") or {}).get(key) or "").strip()
    async with USERS_LOCK:
        user = dict(USERS.get(uid) or {}) if uid else None
    if user is None:
        return None
    exp = str(user.get("expire_at") or "").strip()
    expired = False
    if exp:
        try:
            expired = datetime.now() >= datetime.fromisoformat(exp)
        except Exception:
            expired = False
    if expired or user.get("status") == "expired":
        try:
            await _delete_bot_user(uid)
        except Exception as e:
            logger.warning("Sell customer expired account delete failed uid=%s: %s", uid, e)
            return "expired_pending"
        sell.setdefault("customer_users", {}).pop(key, None)
        asyncio.create_task(save_state())
        return "expired"
    return user


async def _sell_bot_send_account(token: str, chat_id):
    result = await _sell_bot_get_customer_user(chat_id)
    if result == "expired":
        await _telegram_send_message(token, chat_id, "⛔ <b>اعتبار شما تمام شده است.</b>\nاکانت شما از پنل حذف شد. برای خرید مجدد به بخش «محصولات» بروید.", reply_markup=_sell_main_menu_markup())
        return
    if result == "expired_pending":
        await _telegram_send_message(token, chat_id, "⛔ <b>اعتبار شما تمام شده است.</b>\nحساب منقضی شده و حذف آن در حال انجام است؛ لطفاً چند لحظه بعد دوباره بررسی کنید.", reply_markup=_sell_main_menu_markup())
        return
    if not result:
        await _sell_bot_send_main_menu(token, chat_id, "ℹ️ <b>اعتبار من</b>\n\nهنوز اشتراک فعالی برای این حساب ثبت نشده است.")
        return
    user = dict(result)
    traffic_limit = int(user.get("traffic_limit_bytes") or 0)
    traffic_used = int(user.get("traffic_used_bytes") or 0)
    if traffic_limit <= 0:
        traffic_text = "نامحدود"
        remain_text = "نامحدود"
    else:
        remain = max(0, traffic_limit - traffic_used)
        traffic_text = fmt_bytes(traffic_limit)
        remain_text = fmt_bytes(remain)
    exp = str(user.get("expire_at") or "").strip()
    if exp:
        try:
            dt = datetime.fromisoformat(exp)
            remain_days = max(0, (dt - datetime.now()).total_seconds()/86400)
            expiry_text = f"{dt.strftime('%Y-%m-%d %H:%M')} · {remain_days:.1f} روز باقی‌مانده"
        except Exception:
            expiry_text = exp
    else:
        expiry_text = "نامحدود"
    text_value = (
        "🟢 <b>اعتبار من</b>\n\n"
        f"🆔 Telegram ID: <code>{chat_id}</code>\n"
        f"👤 نام کاربر پنل: <code>{user.get('username') or '—'}</code>\n"
        f"🟢 وضعیت: <b>{'فعال' if is_user_allowed(user) else 'غیرفعال'}</b>\n"
        f"💾 مصرف: <b>{fmt_bytes(traffic_used)}</b> / <b>{traffic_text}</b>\n"
        f"📉 مانده: <b>{remain_text}</b>\n"
        f"⏳ اعتبار: <b>{expiry_text}</b>"
    )
    sub_url = str(user.get("subscription_url") or "").strip()
    if not sub_url and user.get("config_uuid"):
        try:
            sub_url = _bot_public_subscription_url(str(user.get("config_uuid")))
        except Exception:
            sub_url = ""
    markup_rows = []
    if sub_url:
        markup_rows.append([{ "text": "🔗 لینک اشتراک", "url": sub_url }])
    markup_rows.append([{ "text": "🛍 محصولات", "callback_data": "sell:products" }, {"text": "💬 پشتیبانی", "callback_data": "sell:support"}])
    markup_rows.append([{ "text": "🏠 منوی اصلی", "callback_data": "sell:menu" }])
    if QR_AVAILABLE and sub_url:
        try:
            qr = _subscription_qr_bytes(sub_url)
            sent = await _telegram_send_photo(token, chat_id, qr, text_value, reply_markup={"inline_keyboard": markup_rows})
            await _sell_bot_track_customer_message(chat_id, sent, "account")
            return
        except Exception:
            pass
    sent = await _telegram_send_message(token, chat_id, text_value, reply_markup={"inline_keyboard": markup_rows})
    await _sell_bot_track_customer_message(chat_id, sent, "account")


async def _sell_bot_send_support(token: str, chat_id):
    sell = _bot_cfg().get("sell") or {}
    support = str(sell.get("support_username") or "").strip()
    text_value = str(sell.get("support_text") or "💬 برای پشتیبانی با مدیر فروش تماس بگیرید.").strip()
    rows = []
    if support:
        if support.startswith("https://t.me/"):
            url = support
            label = support.rsplit("/",1)[-1]
        else:
            label = support.lstrip("@")
            url = f"https://t.me/{label}"
        rows.append([{ "text": "💬 تماس با پشتیبانی", "url": url }])
    rows.append([{ "text": "🏠 منوی اصلی", "callback_data": "sell:menu" }])
    sent = await _telegram_send_message(token, chat_id, text_value, reply_markup={"inline_keyboard": rows})
    await _sell_bot_track_customer_message(chat_id, sent, "support")


async def _sell_bot_send_plans(token: str, chat_id):
    sell = _bot_cfg().get("sell") or {}
    plans = _sell_plans()
    if not plans:
        sent = await _telegram_send_message(token, chat_id, "🛍 <b>محصولات</b>\n\nفعلاً هیچ Plan فعالی برای فروش وجود ندارد.", reply_markup={"inline_keyboard": [[{"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}]]})
        return await _sell_bot_track_customer_message(chat_id, sent, "products")
    rows = []
    keyboard = []
    for plan in plans[:30]:
        traffic = float(plan.get("traffic_gb") or 0)
        days = int(plan.get("expire_days") or 0)
        traffic_text = "نامحدود" if traffic <= 0 else f"{traffic:g} GB"
        days_text = "نامحدود" if days <= 0 else f"{days} روز"
        inbound_name = str((INBOUNDS.get(str(plan.get("inbound_id") or "")) or {}).get("name") or plan.get("inbound_id") or "Default")
        rows.append(
            f"📦 <b>{plan.get('name')}</b>\n"
            f"💾 {traffic_text} · ⏳ {days_text}\n"
            f"🌐 {inbound_name}\n"
            f"💰 <b>{plan.get('price')}</b>"
        )
        keyboard.append([{"text": f"💳 خرید {str(plan.get('name') or '')[:28]}", "callback_data": f"sell:plan:{plan.get('id')}"}])
    keyboard.append([{ "text": "🟢 اعتبار من", "callback_data": "sell:account" }, {"text": "💬 پشتیبانی", "callback_data": "sell:support"}])
    keyboard.append([{ "text": "🏠 منوی اصلی", "callback_data": "sell:menu" }])
    text_value = "🛍 <b>محصولات</b>\n\n" + "\n\n".join(rows)
    payment = str(sell.get("payment_details") or "").strip()
    payment_url = str(sell.get("payment_url") or "").strip()
    if payment:
        text_value += f"\n\n💳 <b>روش پرداخت</b>\n{payment}"
    if payment_url:
        text_value += f"\n🔗 <a href=\"{payment_url}\">لینک پرداخت</a>"
    sent = await _telegram_send_message(token, chat_id, text_value, reply_markup={"inline_keyboard": keyboard})
    return await _sell_bot_track_customer_message(chat_id, sent, "products")


def _sell_admin_menu_markup():
    return {"inline_keyboard": [
        [{"text": "➕ افزودن Plan", "callback_data": "sell:admin:add"}],
        [{"text": "📦 مدیریت Planها", "callback_data": "sell:admin:plans"}],
        [{"text": "🧾 سفارش‌های در انتظار", "callback_data": "sell:admin:pending"}],
        [{"text": "❌ بستن", "callback_data": "sell:admin:close"}],
    ]}


def _sell_admin_format_plan(plan: dict) -> str:
    traffic = float(plan.get("traffic_gb") or 0)
    days = int(plan.get("expire_days") or 0)
    return (
        f"📦 <b>{plan.get('name') or 'بدون نام'}</b>\n"
        f"💰 {plan.get('price') or '—'}\n"
        f"💾 {'نامحدود' if traffic <= 0 else f'{traffic:g} GB'} · "
        f"⏳ {'نامحدود' if days <= 0 else f'{days} روز'}\n"
        f"🌐 <code>{plan.get('inbound_id') or '—'}</code> · 👤 <code>{plan.get('username_prefix') or 'shop'}</code>"
    )


async def _sell_bot_admin_plans(token: str, chat_id):
    sell = _bot_cfg().get("sell") or {}
    plans = [p for p in (sell.get("plans") or []) if isinstance(p, dict)]
    if not plans:
        return await _telegram_send_message(
            token, chat_id, "📦 هنوز هیچ Planای ساخته نشده است.",
            reply_markup={"inline_keyboard": [[{"text": "➕ افزودن Plan", "callback_data": "sell:admin:add"}], [{"text": "↩️ منوی مدیریت", "callback_data": "sell:admin:menu"}]]}
        )
    await _telegram_send_message(token, chat_id, "📦 <b>مدیریت Planها</b>")
    for plan in plans[:30]:
        pid = str(plan.get("id") or "")
        enabled = bool(plan.get("enabled", True))
        toggle_text = "⏸ غیرفعال" if enabled else "▶️ فعال"
        toggle_value = "0" if enabled else "1"
        markup = {"inline_keyboard": [[
            {"text": "✏️ ویرایش", "callback_data": f"sell:admin:edit:{pid}"},
            {"text": toggle_text, "callback_data": f"sell:admin:toggle:{pid}:{toggle_value}"},
            {"text": "🗑 حذف", "callback_data": f"sell:admin:delete:{pid}"},
        ] ]}
        await _telegram_send_message(token, chat_id, _sell_admin_format_plan(plan), reply_markup=markup)
    await _telegram_send_message(token, chat_id, "⚙️ مدیریت", reply_markup={"inline_keyboard": [[{"text": "➕ افزودن Plan", "callback_data": "sell:admin:add"}, {"text": "↩️ بازگشت", "callback_data": "sell:admin:menu"}]]})


async def _sell_bot_admin_start_wizard(token: str, admin_id: str, mode: str = "add", existing: dict | None = None):
    plan = dict(existing or {})
    if not plan:
        plan = {"enabled": True, "username_prefix": "shop"}
    async with BOT_ADMIN_WIZARD_LOCK:
        BOT_ADMIN_WIZARD[str(admin_id)] = {
            "mode": mode,
            "step": "name",
            "plan": plan,
            "started_at": datetime.now().isoformat(),
        }
    title = "افزودن Plan" if mode == "add" else "ویرایش Plan"
    prompt = f"⚙️ <b>{title}</b>\n\n✏️ <b>مرحله ۱/۶</b>\nاسم Plan را ارسال کنید."
    if existing:
        prompt += f"\nمقدار فعلی: <code>{existing.get('name') or '—'}</code>"
    prompt += "\n\nبرای لغو /cancel را بفرستید."
    await _telegram_send_message(token, admin_id, prompt, reply_markup={"inline_keyboard": [[{"text": "❌ لغو", "callback_data": "sell:wiz:cancel"}]]})


def _sell_admin_inbound_markup():
    rows = []
    for iid, ib in list(INBOUNDS.items()):
        if iid == "Node" or bool(ib.get("system")):
            continue
        label = str(ib.get("name") or iid)[:36]
        rows.append([{"text": f"🌐 {label}", "callback_data": f"sell:wiz:inbound:{str(iid)[:35]}"}])
    if not rows:
        rows = [[{"text": "❌ هیچ Inboundای موجود نیست", "callback_data": "sell:wiz:cancel"}]]
    rows.append([{"text": "❌ لغو", "callback_data": "sell:wiz:cancel"}])
    return {"inline_keyboard": rows[:50]}


def _sell_admin_traffic_markup():
    vals = [("10 GB", 10), ("30 GB", 30), ("50 GB", 50), ("100 GB", 100), ("200 GB", 200), ("500 GB", 500), ("♾ نامحدود", 0), ("✏️ مقدار دلخواه", "custom")]
    rows = []
    for i in range(0, len(vals), 2):
        rows.append([{"text": label, "callback_data": f"sell:wiz:traffic:{value}"} for label, value in vals[i:i+2]])
    rows.append([{"text": "❌ لغو", "callback_data": "sell:wiz:cancel"}])
    return {"inline_keyboard": rows}


def _sell_admin_days_markup():
    vals = [("7 روز", 7), ("30 روز", 30), ("60 روز", 60), ("90 روز", 90), ("180 روز", 180), ("365 روز", 365), ("♾ نامحدود", 0), ("✏️ مقدار دلخواه", "custom")]
    rows = []
    for i in range(0, len(vals), 2):
        rows.append([{"text": label, "callback_data": f"sell:wiz:days:{value}"} for label, value in vals[i:i+2]])
    rows.append([{"text": "❌ لغو", "callback_data": "sell:wiz:cancel"}])
    return {"inline_keyboard": rows}


async def _sell_bot_admin_handle_text(token: str, msg: dict) -> bool:
    from_user = msg.get("from") or {}
    admin_id = str(from_user.get("id") or "")
    sell = _bot_cfg().get("sell") or {}
    if not admin_id or admin_id != str(sell.get("admin_chat_id") or "").strip():
        return False
    if str((msg.get("chat") or {}).get("type") or "") != "private":
        return False
    text_value = str(msg.get("text") or "").strip()
    if not text_value:
        return False
    async with BOT_ADMIN_WIZARD_LOCK:
        state = dict(BOT_ADMIN_WIZARD.get(admin_id) or {})
    if not state:
        return False
    if text_value.lower() in {"/cancel", "cancel", "لغو"}:
        async with BOT_ADMIN_WIZARD_LOCK:
            BOT_ADMIN_WIZARD.pop(admin_id, None)
        await _telegram_send_message(token, msg.get("chat", {}).get("id") or admin_id, "✅ عملیات Plan لغو شد.", reply_markup=_sell_admin_menu_markup())
        return True

    step = str(state.get("step") or "")
    plan = dict(state.get("plan") or {})
    chat_id = msg.get("chat", {}).get("id") or admin_id
    try:
        if step == "name":
            if not 1 <= len(text_value) <= 80:
                raise ValueError("اسم Plan باید بین ۱ تا ۸۰ کاراکتر باشد")
            plan["name"] = text_value
            state["step"] = "price"
            state["plan"] = plan
            await _telegram_send_message(token, chat_id, "✏️ <b>مرحله ۲/۶</b>\nقیمت Plan را ارسال کنید.\nمثلاً: <code>250000 تومان</code>")
        elif step == "price":
            if not 1 <= len(text_value) <= 80:
                raise ValueError("قیمت نامعتبر است")
            plan["price"] = text_value
            state["step"] = "inbound"
            state["plan"] = plan
            await _telegram_send_message(token, chat_id, "🌐 <b>مرحله ۳/۶</b>\nInbound این Plan را انتخاب کنید:", reply_markup=_sell_admin_inbound_markup())
        elif step == "traffic_custom":
            value = float(text_value.replace(",", "."))
            if value < 0 or value > 1_000_000:
                raise ValueError("حجم خارج از محدوده است")
            plan["traffic_gb"] = value
            state["step"] = "days"
            state["plan"] = plan
            await _telegram_send_message(token, chat_id, "⏳ <b>مرحله ۵/۶</b>\nمدت اعتبار را انتخاب کنید:", reply_markup=_sell_admin_days_markup())
        elif step == "days_custom":
            value = int(text_value)
            if value < 0 or value > 36500:
                raise ValueError("زمان خارج از محدوده است")
            plan["expire_days"] = value
            state["step"] = "prefix"
            state["plan"] = plan
            await _telegram_send_message(token, chat_id, "👤 <b>مرحله ۶/۶</b>\nپیشوند نام کاربر را ارسال کنید.\nمثلاً: <code>shop</code>")
        elif step == "prefix":
            prefix = re.sub(r"[^A-Za-z0-9_-]+", "-", text_value).strip("-_")[:24]
            if not prefix:
                raise ValueError("پیشوند نام کاربر نامعتبر است")
            plan["username_prefix"] = prefix
            state["step"] = "confirm"
            state["plan"] = plan
            traffic = float(plan.get("traffic_gb") or 0)
            days = int(plan.get("expire_days") or 0)
            preview = (
                "✅ <b>پلن آمادهٔ ذخیره است</b>\n\n" + _sell_admin_format_plan(plan) +
                "\n\nبا دکمهٔ پایین ذخیره کنید."
            )
            await _telegram_send_message(token, chat_id, preview, reply_markup={"inline_keyboard": [[{"text": "✅ ذخیره Plan", "callback_data": "sell:wiz:confirm"}, {"text": "❌ لغو", "callback_data": "sell:wiz:cancel"}]]})
        else:
            return False
        async with BOT_ADMIN_WIZARD_LOCK:
            BOT_ADMIN_WIZARD[admin_id] = state
        return True
    except (ValueError, TypeError) as e:
        await _telegram_send_message(token, chat_id, f"❌ {e}")
        return True



async def _find_active_sell_order(chat_id: int | str):
    cid = str(chat_id)
    async with BOT_ORDERS_LOCK:
        for oid, order in BOT_ORDERS.items():
            if str(order.get("chat_id")) == cid and str(order.get("status")) in {"awaiting_payment", "payment_submitted", "processing"}:
                return oid, dict(order)
    return None, None


async def _activate_sell_order(order_id: str, admin_chat_id) -> dict:
    order_id = str(order_id or "").strip().upper()
    async with BOT_ORDERS_LOCK:
        order = BOT_ORDERS.get(order_id)
        if not order:
            raise RuntimeError("order not found")
        if order.get("status") == "approved":
            raise RuntimeError("order already approved")
        if order.get("status") == "rejected":
            raise RuntimeError("order already rejected")
        if order.get("status") == "processing":
            raise RuntimeError("order is already being processed")
        if order.get("status") != "payment_submitted" and not bool(order.get("activation_applied")):
            raise RuntimeError("payment screenshot has not been submitted yet")
        order["status"] = "processing"
        plan = dict(order.get("plan_snapshot") or {})
        chat_id = order.get("chat_id")
        customer_name = str(order.get("customer_username") or "").strip()
        activation_user_id = str(order.get("activation_user_id") or "").strip()
        activation_applied = bool(order.get("activation_applied"))
        delivery_sent = bool(order.get("delivery_sent"))

    # Require a usable public panel URL before fulfilling the order.
    _bot_public_subscription_url("health-check")
    inbound_id = str(plan.get("inbound_id") or _bot_default_inbound_id()).strip()
    traffic_gb = max(0.0, float(plan.get("traffic_gb") or 0))
    expire_days = max(0, int(plan.get("expire_days") or 0))
    username_prefix = str(plan.get("username_prefix") or "shop")
    customer_key = str(chat_id)

    try:
        user = None
        user_id = activation_user_id
        # Retry path: the account was already activated but final delivery failed.
        if user_id:
            async with USERS_LOCK:
                user = USERS.get(user_id)
            if user is None:
                # A manually deleted account makes the old activation impossible to resume safely.
                user_id = ""
                activation_applied = False

        if not activation_applied:
            sell = _bot_cfg().get("sell") or {}
            customer_users = sell.setdefault("customer_users", {})
            async with USERS_LOCK:
                existing_id = str(customer_users.get(customer_key) or "").strip()
                if existing_id and existing_id in USERS:
                    user_id = existing_id
                    user = USERS[existing_id]
                elif not existing_id:
                    # Recover the mapping if state was imported without the customer index.
                    for candidate_id, candidate in USERS.items():
                        if str(candidate.get("telegram_chat_id") or "") == customer_key:
                            user_id = str(candidate_id)
                            user = candidate
                            break

                if user is not None:
                    now = datetime.now()
                    _mapped_exp = str(user.get("expire_at") or "").strip()
                    try:
                        _mapped_expired = bool(_mapped_exp and now >= datetime.fromisoformat(_mapped_exp)) or user.get("status") == "expired"
                    except Exception:
                        _mapped_expired = user.get("status") == "expired"
                    if _mapped_expired:
                        user = None
                        if existing_id:
                            customer_users.pop(customer_key, None)
                if user is not None:
                    current_limit = int(user.get("traffic_limit_bytes") or 0)
                    add_limit = int(traffic_gb * 1024**3) if traffic_gb > 0 else 0
                    if add_limit <= 0:
                        # An unlimited plan upgrades the account to unlimited.
                        user["traffic_limit_bytes"] = 0
                    elif current_limit > 0:
                        user["traffic_limit_bytes"] = current_limit + add_limit
                    else:
                        # Existing unlimited users remain unlimited.
                        user["traffic_limit_bytes"] = 0
                    current_exp = None
                    try:
                        if user.get("expire_at"):
                            current_exp = datetime.fromisoformat(str(user.get("expire_at")))
                    except Exception:
                        current_exp = None
                    if expire_days <= 0 or (user.get("expire_at") in (None, "") and str(user.get("status") or "active") == "active"):
                        # Keep an already-unlimited active account unlimited.
                        user["expire_at"] = None
                    else:
                        base = current_exp if current_exp and current_exp > now else now
                        user["expire_at"] = (base + timedelta(days=expire_days)).isoformat()
                    if inbound_id and inbound_id in INBOUNDS:
                        ids = [str(x) for x in (user.get("inbound_ids") or []) if str(x).strip()]
                        if inbound_id not in ids:
                            ids.append(inbound_id)
                        user["inbound_ids"] = ids
                        user["inbound_id"] = inbound_id
                    user["status"] = "active"
                    user["telegram_chat_id"] = customer_key
                    user["telegram_username"] = customer_name or str(user.get("telegram_username") or "")
                    user.setdefault("sell_plan_history", []).append({"order_id": order_id, "plan_id": plan.get("id"), "at": datetime.now().isoformat()})
                else:
                    user = None

            if user is None:
                body = {
                    "username": _make_bot_username(username_prefix),
                    "traffic_limit_gb": traffic_gb,
                    "expire_days": expire_days,
                    "inbound_id": inbound_id or None,
                    "inbound_ids": [inbound_id] if inbound_id else [],
                    "protocol": "vless",
                    "transport_type": "ws",
                    "server": "Sell Bot",
                }
                user = await _create_bot_user(body)
                user_id = str(user.get("user_id") or "")
                if not user_id:
                    raise RuntimeError("created user did not return user_id")
                async with USERS_LOCK:
                    local = USERS.get(user_id)
                    if local is not None:
                        local["telegram_chat_id"] = customer_key
                        local["telegram_username"] = customer_name
                        local.setdefault("sell_plan_history", []).append({"order_id": order_id, "plan_id": plan.get("id"), "at": datetime.now().isoformat()})
                        user = local
            activation_applied = True
            # Persist the activation marker BEFORE external delivery. This makes retry idempotent.
            sell = _bot_cfg().get("sell") or {}
            sell.setdefault("customer_users", {})[customer_key] = user_id
            async with BOT_ORDERS_LOCK:
                order = BOT_ORDERS.get(order_id)
                if order is not None:
                    order["activation_applied"] = True
                    order["activation_user_id"] = user_id
                    order["activation_at"] = datetime.now().isoformat()
            asyncio.create_task(save_state())

            # Refresh dependent services after account mutation.
            local_user = dict(USERS.get(user_id) or user)
            if WORKER.get("connected") and _user_uses_worker_inbound(local_user):
                asyncio.create_task(_worker_sync_users())
            if _selected_node_ids_for_user(local_user):
                asyncio.create_task(_sync_user_to_selected_nodes(user_id, local_user))
            asyncio.create_task(_xray_apply())
        else:
            user = dict(USERS.get(user_id) or user or {})

        cfg_uuid = str(user.get("config_uuid") or "").strip()
        sub_url = str(user.get("subscription_url") or "").strip() or _bot_public_subscription_url(cfg_uuid)
        token = str((_bot_cfg().get("token") or "")).strip()

        if not delivery_sent:
            qr = _subscription_qr_bytes(sub_url)
            customer_caption = (
                f"✅ <b>پرداخت تأیید شد</b>\n"
                f"📦 {plan.get('name')}\n"
                f"👤 <code>{user.get('username','')}</code>\n"
                f"🔗 {_html_tag_link('لینک ساب', sub_url)}"
            )
            sent_delivery = await _telegram_send_photo(token, chat_id, qr, customer_caption, reply_markup=_sell_main_menu_markup())
            await _sell_bot_track_customer_message(chat_id, sent_delivery, "delivery")
            delivery_sent = True
            async with BOT_ORDERS_LOCK:
                order = BOT_ORDERS.get(order_id)
                if order is not None:
                    order["delivery_sent"] = True
                    order["delivery_at"] = datetime.now().isoformat()

        async with BOT_ORDERS_LOCK:
            order = BOT_ORDERS.get(order_id) or {}
            order.update({
                "status": "approved",
                "user_id": user_id,
                "username": str(user.get("username") or ""),
                "approved_at": datetime.now().isoformat(),
                "delivery_sent": bool(delivery_sent),
            })
        try:
            await _telegram_send_message(token, admin_chat_id, f"✅ سفارش <code>{order_id}</code> تأیید و اکانت فعال شد: <code>{user.get('username','')}</code>")
        except Exception as admin_notify_error:
            logger.warning("Sell Bot admin completion notification failed: %s", admin_notify_error)
        asyncio.create_task(save_state())
        return {"ok": True, "user": dict(user), "subscription_url": sub_url}
    except Exception:
        async with BOT_ORDERS_LOCK:
            if order_id in BOT_ORDERS and BOT_ORDERS[order_id].get("status") == "processing":
                BOT_ORDERS[order_id]["status"] = "payment_submitted"
        raise


async def _sell_bot_reject_order(token: str, order_id: str, admin_chat_id):
    order_id = str(order_id or "").strip().upper()
    async with BOT_ORDERS_LOCK:
        order = BOT_ORDERS.get(order_id)
        if not order:
            raise RuntimeError("order not found")
        if order.get("status") == "approved":
            raise RuntimeError("order already approved")
        if order.get("status") == "rejected":
            raise RuntimeError("order already rejected")
        order["status"] = "rejected"
        order["rejected_at"] = datetime.now().isoformat()
        customer_id = order.get("chat_id")
    await _telegram_send_message(token, admin_chat_id, f"✅ سفارش <code>{order_id}</code> رد شد")
    if customer_id:
        await _sell_bot_send_main_menu(token, customer_id, f"❌ سفارش <code>{order_id}</code> رد شد. می‌توانید دوباره از «محصولات» خرید کنید.")
    asyncio.create_task(save_state())


async def _sell_bot_send_payment_prompt(token: str, chat_id, order_id: str, plan: dict):
    sell = _bot_cfg().get("sell") or {}
    traffic = float(plan.get("traffic_gb") or 0)
    days = int(plan.get("expire_days") or 0)
    traffic_text = "نامحدود" if traffic <= 0 else f"{traffic:g} GB"
    days_text = "نامحدود" if days <= 0 else f"{days} روز"
    text_value = (
        f"🧾 <b>سفارش {order_id}</b>\n\n"
        f"📦 پلن: <b>{plan.get('name')}</b>\n"
        f"💾 حجم: {traffic_text}\n"
        f"⏳ اعتبار: {days_text}\n"
        f"💰 مبلغ: <b>{plan.get('price')}</b>\n\n"
    )
    payment_details = str(sell.get("payment_details") or "").strip()
    payment_url = str(sell.get("payment_url") or "").strip()
    if payment_details:
        text_value += f"💳 <b>روش پرداخت</b>\n{payment_details}\n\n"
    if payment_url:
        text_value += f"🔗 <a href=\"{payment_url}\">لینک پرداخت</a>\n\n"
    text_value += "📸 بعد از پرداخت، <b>اسکرین‌شات رسید</b> را همین‌جا به صورت عکس یا فایل ارسال کنید."
    sent = await _telegram_send_message(token, chat_id, text_value, reply_markup={"inline_keyboard": [[{"text": "❌ لغو سفارش", "callback_data": f"sell:cancel:{order_id}"}]]})
    return await _sell_bot_track_customer_message(chat_id, sent, "payment")


async def _sell_bot_handle_message(token: str, msg: dict):
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if chat_id is None:
        return
    sell = _bot_cfg().get("sell") or {}
    if not bool(sell.get("enabled")):
        return
    from_user = msg.get("from") or {}
    is_admin = str(from_user.get("id") or "") == str(sell.get("admin_chat_id") or "").strip()
    text_value = str(msg.get("text") or "").strip()
    command, _, arg = text_value.partition(" ")
    command = command.split("@", 1)[0].lower() if command else ""

    # Admin wizard consumes plain text only in the private admin chat.
    if is_admin and str(chat.get("type") or "") == "private" and text_value and not command.startswith("/"):
        if await _sell_bot_admin_handle_text(token, msg):
            return
    if is_admin and str(chat.get("type") or "") == "private" and command in {"/cancel"}:
        if await _sell_bot_admin_handle_text(token, msg):
            return

    # Payment receipt: photo or document is forwarded to the configured admin.
    if msg.get("photo") or msg.get("document"):
        if str(chat.get("type") or "") != "private":
            return
        order_id, order = await _find_active_sell_order(chat_id)
        if not order:
            await _telegram_send_message(token, chat_id, "ℹ️ اول یک Plan را از /plans انتخاب کنید و سپس رسید را ارسال کنید.")
            return
        if order.get("status") == "payment_submitted":
            await _telegram_send_message(token, chat_id, f"ℹ️ رسید سفارش <code>{order_id}</code> قبلاً برای ادمین ارسال شده است. لطفاً منتظر تأیید بمانید.")
            return
        if order.get("status") != "awaiting_payment":
            await _telegram_send_message(token, chat_id, "ℹ️ این سفارش در حال پردازش است؛ رسید جدید ارسال نکنید.")
            return
        payment_file_id = ""
        media_kind = "photo"
        if msg.get("photo"):
            sizes = msg.get("photo") or []
            payment_file_id = str((sizes[-1] if sizes else {}).get("file_id") or "")
            media_kind = "photo"
        elif msg.get("document"):
            payment_file_id = str((msg.get("document") or {}).get("file_id") or "")
            media_kind = "document"
        if not payment_file_id:
            await _telegram_send_message(token, chat_id, "❌ فایل رسید قابل تشخیص نبود. دوباره ارسال کنید.")
            return
        caption = str(msg.get("caption") or "").strip()[:1000]
        admin_id = str(sell.get("admin_chat_id") or "").strip()
        if not admin_id:
            await _telegram_send_message(token, chat_id, "❌ ادمین فروش هنوز تنظیم نشده است.")
            return
        plan = dict(order.get("plan_snapshot") or {})
        admin_caption = (
            f"🧾 <b>رسید پرداخت جدید</b>\n"
            f"🆔 سفارش: <code>{order_id}</code>\n"
            f"👤 کاربر: <code>{order.get('customer_username') or 'بدون یوزرنیم'}</code>\n"
            f"💬 Telegram ID: <code>{order.get('telegram_user_id') or chat_id}</code>\n"
            f"📦 Plan: <b>{plan.get('name')}</b>\n"
            f"💰 مبلغ: <b>{plan.get('price')}</b>"
        )
        if caption:
            admin_caption += f"\n📝 توضیح خریدار: {caption}"
        markup = {"inline_keyboard": [[
            {"text": "✅ تأیید و فعال‌سازی", "callback_data": f"sell:approve:{order_id}"},
            {"text": "❌ رد رسید", "callback_data": f"sell:reject:{order_id}"},
        ]]}
        if media_kind == "photo":
            sent = await _telegram_send_photo_id(token, admin_id, payment_file_id, admin_caption, reply_markup=markup)
        else:
            sent = await _telegram_send_document_id(token, admin_id, payment_file_id, admin_caption, reply_markup=markup)
        async with BOT_ORDERS_LOCK:
            order = BOT_ORDERS.get(order_id)
            if order:
                order.update({
                    "status": "payment_submitted",
                    "payment_file_id": payment_file_id,
                    "payment_media_kind": media_kind,
                    "payment_message_id": int(msg.get("message_id") or 0),
                    "admin_message_id": int((sent or {}).get("message_id") or 0),
                    "payment_caption": caption,
                    "payment_submitted_at": datetime.now().isoformat(),
                    "customer_username": str(from_user.get("username") or order.get("customer_username") or ""),
                })
        await _sell_bot_reset_customer_ui(token, chat_id)
        await _telegram_send_message(token, chat_id, f"✅ رسید شما برای ادمین ارسال شد.\n🧾 سفارش: <code>{order_id}</code>\n⏳ منتظر تأیید بمانید.")
        asyncio.create_task(save_state())
        return

    if not text_value:
        return

    # Every command resets the customer's previous inline UI before showing a fresh section.
    await _sell_bot_reset_customer_ui(token, chat_id)
    if not is_admin and str(chat.get("type") or "") == "private":
        if command not in {"/start", "/help"} and not await _sell_bot_require_joins(token, chat_id, from_user.get("id")):
            return
        if command in {"/start", "/help"}:
            if not await _sell_bot_require_joins(token, chat_id, from_user.get("id")):
                return
    if command in ("/start", "/help"):
        welcome = str(sell.get("welcome_text") or "سلام 👋\nبرای استفاده از فروشگاه یکی از بخش‌های زیر را انتخاب کنید.")
        if is_admin:
            await _sell_bot_admin_menu(token, chat_id)
            await _sell_bot_send_main_menu(token, chat_id, welcome)
        else:
            await _sell_bot_send_main_menu(token, chat_id, welcome)
    elif command in ("/plans", "/buy"):
        await _sell_bot_send_plans(token, chat_id)
    elif command in ("/account", "/status", "/myaccount"):
        await _sell_bot_send_account(token, chat_id)
    elif command in ("/support", "/contact"):
        await _sell_bot_send_support(token, chat_id)
    elif command in ("/cancel",):
        oid, order = await _find_active_sell_order(chat_id)
        if oid and order and order.get("status") == "awaiting_payment":
            async with BOT_ORDERS_LOCK:
                if oid in BOT_ORDERS:
                    BOT_ORDERS[oid]["status"] = "cancelled"
                    BOT_ORDERS[oid]["cancelled_at"] = datetime.now().isoformat()
            await _telegram_send_message(token, chat_id, f"✅ سفارش <code>{oid}</code> لغو شد.")
            asyncio.create_task(save_state())
        elif not is_admin:
            await _telegram_send_message(token, chat_id, "ℹ️ سفارش قابل لغو وجود ندارد.")
        await _sell_bot_send_main_menu(token, chat_id)
    elif command in ("/orders", "/myorders"):
        async with BOT_ORDERS_LOCK:
            mine = [dict(o, order_id=oid) for oid, o in BOT_ORDERS.items() if str(o.get("chat_id")) == str(chat_id)]
        mine = mine[-8:]
        if not mine:
            sent = await _telegram_send_message(token, chat_id, "🧾 <b>سفارش‌های من</b>\n\nهنوز سفارشی ثبت نکرده‌اید.", reply_markup={"inline_keyboard": [[{"text": "🛍 محصولات", "callback_data": "sell:products"}, {"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}]]})
        else:
            labels = {"awaiting_payment":"در انتظار رسید", "payment_submitted":"در انتظار تأیید", "approved":"تأیید شد", "rejected":"رد شد", "cancelled":"لغو شد", "processing":"در حال پردازش"}
            lines = [f"🧾 <code>{o['order_id']}</code> · {o.get('plan_snapshot',{}).get('name','')} · {labels.get(o.get('status'), o.get('status'))}" for o in mine]
            sent = await _telegram_send_message(token, chat_id, "🧾 <b>سفارش‌های من</b>\n\n" + "\n".join(lines), reply_markup={"inline_keyboard": [[{"text": "🛍 محصولات", "callback_data": "sell:products"}], [{"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}]]})
        await _sell_bot_track_customer_message(chat_id, sent, "orders")
    elif command == "/admin" and is_admin:
        await _sell_bot_admin_menu(token, chat_id)
    elif command == "/pending" and is_admin:
        async with BOT_ORDERS_LOCK:
            pending = [(oid, dict(o)) for oid, o in BOT_ORDERS.items() if o.get("status") == "payment_submitted"]
        if not pending:
            await _telegram_send_message(token, chat_id, "✅ رسید معلقی وجود ندارد.")
        else:
            for oid, o in pending[-20:]:
                plan = o.get("plan_snapshot") or {}
                await _telegram_send_message(token, chat_id, f"🧾 <b>سفارش {oid}</b>\n👤 <code>{o.get('telegram_user_id') or o.get('chat_id')}</code>\n📦 {plan.get('name')}", reply_markup={"inline_keyboard": [[{"text": "✅ تأیید", "callback_data": f"sell:approve:{oid}"}, {"text": "❌ رد", "callback_data": f"sell:reject:{oid}"}], [{"text": "⚙️ مدیریت", "callback_data": "sell:admin:menu"}]]})


async def _sell_bot_handle_callback(token: str, callback: dict):
    data = str(callback.get("data") or "").strip()
    callback_id = str(callback.get("id") or "")
    from_user = callback.get("from") or {}
    user_id = str(from_user.get("id") or "")
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    parts = data.split(":")
    if len(parts) < 2 or parts[0] != "sell":
        return
    action = parts[1]
    args = parts[2:]
    sell = _bot_cfg().get("sell") or {}
    admin_id = str(sell.get("admin_chat_id") or "").strip()
    is_admin = user_id == admin_id
    try:
        # Admin callbacks always bypass the customer join gate. Customer callbacks
        # clear the previous UI first, so an old button can never remain actionable
        # behind a new join-gate or section screen.
        if not is_admin and str(chat.get("type") or "") == "private":
            if action != "join":
                await _sell_bot_reset_customer_ui(token, chat_id)
                if not await _sell_bot_require_joins(token, chat_id, user_id):
                    await _telegram_answer_callback(token, callback_id, "ابتدا در کانال‌ها عضو شوید", True)
                    return
        if action == "menu":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_main_menu(token, chat_id)
            return
        if action == "account":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_account(token, chat_id)
            return
        if action == "products":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_plans(token, chat_id)
            return
        if action == "support":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_support(token, chat_id)
            return
        if action == "join":
            sub = args[0] if args else "check"
            if sub == "check":
                await _telegram_answer_callback(token, callback_id, "در حال بررسی…")
                if await _sell_bot_require_joins(token, chat_id, user_id):
                    await _sell_bot_reset_customer_ui(token, chat_id)
                    await _sell_bot_send_main_menu(token, chat_id)
                return
            await _telegram_answer_callback(token, callback_id)
            return
        # Customer plan pagination / selection.
        if action == "plans":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_plans(token, chat_id)
            return
        if action == "help":
            await _telegram_answer_callback(token, callback_id)
            await _sell_bot_send_main_menu(token, chat_id, "ℹ️ یک Plan را از «محصولات» انتخاب کنید، پرداخت را انجام دهید و رسید را همین‌جا ارسال کنید.")
            return
        if action == "orders":
            await _telegram_answer_callback(token, callback_id)
            async with BOT_ORDERS_LOCK:
                mine = [dict(o, order_id=oid) for oid, o in BOT_ORDERS.items() if str(o.get("chat_id")) == str(chat_id)]
            mine = mine[-8:]
            if not mine:
                sent = await _telegram_send_message(
                    token, chat_id,
                    "🧾 <b>سفارش‌های من</b>\n\nهنوز سفارشی ثبت نکرده‌اید.",
                    reply_markup={"inline_keyboard": [[{"text": "🛍 محصولات", "callback_data": "sell:products"}, {"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}]]}
                )
            else:
                labels = {"awaiting_payment":"در انتظار رسید", "payment_submitted":"در انتظار تأیید", "approved":"تأیید شد", "rejected":"رد شد", "cancelled":"لغو شد", "processing":"در حال پردازش"}
                lines = [f"🧾 <code>{o['order_id']}</code> · {o.get('plan_snapshot',{}).get('name','')} · {labels.get(o.get('status'), o.get('status'))}" for o in mine]
                sent = await _telegram_send_message(
                    token, chat_id,
                    "🧾 <b>سفارش‌های من</b>\n\n" + "\n".join(lines),
                    reply_markup={"inline_keyboard": [[{"text": "🛍 محصولات", "callback_data": "sell:products"}], [{"text": "🏠 منوی اصلی", "callback_data": "sell:menu"}]]}
                )
            await _sell_bot_track_customer_message(chat_id, sent, "orders")
            return
        if action == "cancel":
            oid = str(args[0] if args else "").strip().upper()
            async with BOT_ORDERS_LOCK:
                order = BOT_ORDERS.get(oid)
                if not order or str(order.get("chat_id")) != str(user_id) or order.get("status") != "awaiting_payment":
                    raise RuntimeError("این سفارش قابل لغو نیست")
                order["status"] = "cancelled"
                order["cancelled_at"] = datetime.now().isoformat()
            await _telegram_answer_callback(token, callback_id, "سفارش لغو شد")
            await _sell_bot_send_main_menu(token, chat_id, f"✅ سفارش <code>{oid}</code> لغو شد.")
            asyncio.create_task(save_state())
            return
        if action == "plan":
            if str(chat.get("type") or "") != "private":
                raise RuntimeError("خرید فقط در Private Chat انجام می‌شود")
            plan_id = str(args[0] if args else "").strip()
            plan = _find_sell_plan(plan_id)
            if not plan:
                raise RuntimeError("Plan پیدا نشد یا غیرفعال است")
            existing_oid, _existing = await _find_active_sell_order(user_id)
            if existing_oid:
                raise RuntimeError(f"یک سفارش فعال دارید: {existing_oid} — ابتدا آن را تکمیل یا لغو کنید")
            order_id = "ORD-" + secrets.token_hex(3).upper()
            async with BOT_ORDERS_LOCK:
                BOT_ORDERS[order_id] = {
                    "chat_id": chat_id,
                    "telegram_user_id": user_id,
                    "customer_username": str(from_user.get("username") or ""),
                    "plan_snapshot": plan,
                    "status": "awaiting_payment",
                    "created_at": datetime.now().isoformat(),
                }
            await _telegram_answer_callback(token, callback_id, "Plan انتخاب شد")
            await _sell_bot_send_payment_prompt(token, chat_id, order_id, plan)
            asyncio.create_task(save_state())
            return

        # Admin controls.
        if action == "admin":
            if not is_admin:
                await _telegram_answer_callback(token, callback_id, "دسترسی ندارید", True)
                return
            sub = args[0] if args else "menu"
            await _telegram_answer_callback(token, callback_id)
            if sub == "menu":
                await _sell_bot_admin_menu(token, chat_id)
            elif sub == "add":
                await _sell_bot_admin_start_wizard(token, admin_id, "add")
            elif sub == "plans":
                await _sell_bot_admin_plans(token, chat_id)
            elif sub == "pending":
                await _sell_bot_handle_message(token, {"chat": {"id": chat_id, "type": "private"}, "from": {"id": user_id}, "text": "/pending"})
            elif sub == "close":
                await _telegram_send_message(token, chat_id, "✅ منوی مدیریت بسته شد.")
            elif sub == "edit":
                pid = ":".join(args[1:]).strip()
                plans = [p for p in (sell.get("plans") or []) if isinstance(p, dict)]
                plan = next((dict(p) for p in plans if str(p.get("id") or "") == pid), None)
                if not plan:
                    raise RuntimeError("Plan پیدا نشد")
                await _sell_bot_admin_start_wizard(token, admin_id, "edit", plan)
            elif sub == "toggle":
                if len(args) < 3:
                    raise RuntimeError("شناسه Plan نامعتبر است")
                pid = str(args[1])
                enabled = str(args[2]) == "1"
                plans = sell.setdefault("plans", [])
                for plan in plans:
                    if str(plan.get("id") or "") == pid:
                        plan["enabled"] = enabled
                        plan["updated_at"] = datetime.now().isoformat()
                        break
                else:
                    raise RuntimeError("Plan پیدا نشد")
                asyncio.create_task(save_state())
                await _telegram_send_message(token, chat_id, "✅ وضعیت Plan تغییر کرد.", reply_markup={"inline_keyboard": [[{"text": "📦 Planها", "callback_data": "sell:admin:plans"}, {"text": "⚙️ مدیریت", "callback_data": "sell:admin:menu"}]]})
            elif sub == "delete":
                pid = ":".join(args[1:]).strip()
                plans = sell.setdefault("plans", [])
                before = len(plans)
                sell["plans"] = [p for p in plans if str(p.get("id") or "") != pid]
                if len(sell["plans"]) == before:
                    raise RuntimeError("Plan پیدا نشد")
                if not sell["plans"]:
                    for legacy_key in ("plan_name", "price", "traffic_gb", "expire_days", "inbound_id"):
                        sell.pop(legacy_key, None)
                asyncio.create_task(save_state())
                await _telegram_send_message(token, chat_id, "🗑 Plan حذف شد.", reply_markup={"inline_keyboard": [[{"text": "📦 Planها", "callback_data": "sell:admin:plans"}, {"text": "➕ Plan جدید", "callback_data": "sell:admin:add"}]]})
            return

        if action == "wiz":
            if not is_admin:
                await _telegram_answer_callback(token, callback_id, "دسترسی ندارید", True)
                return
            step_action = args[0] if args else ""
            async with BOT_ADMIN_WIZARD_LOCK:
                state = dict(BOT_ADMIN_WIZARD.get(admin_id) or {})
            if not state and step_action not in {"cancel"}:
                raise RuntimeError("فرآیند ساخت Plan منقضی شده است؛ دوباره شروع کنید")
            if step_action == "cancel":
                async with BOT_ADMIN_WIZARD_LOCK:
                    BOT_ADMIN_WIZARD.pop(admin_id, None)
                await _telegram_answer_callback(token, callback_id, "لغو شد")
                await _sell_bot_admin_menu(token, chat_id)
                return
            plan = dict(state.get("plan") or {})
            if step_action == "inbound":
                inbound_id = ":".join(args[1:]).strip()
                if not inbound_id or inbound_id not in INBOUNDS or inbound_id == "Node" or bool((INBOUNDS.get(inbound_id) or {}).get("system")):
                    raise RuntimeError("Inbound نامعتبر است")
                plan["inbound_id"] = inbound_id
                state["step"] = "traffic"
                state["plan"] = plan
                await _telegram_answer_callback(token, callback_id, "Inbound انتخاب شد")
                await _telegram_send_message(token, chat_id, "💾 <b>مرحله ۴/۶</b>\nحجم Plan را انتخاب کنید:", reply_markup=_sell_admin_traffic_markup())
            elif step_action == "traffic":
                value = ":".join(args[1:])
                if value == "custom":
                    state["step"] = "traffic_custom"
                    await _telegram_answer_callback(token, callback_id)
                    await _telegram_send_message(token, chat_id, "💾 مقدار حجم را به GB ارسال کنید. برای نامحدود <code>0</code> بفرستید.")
                else:
                    try:
                        traffic = float(value)
                    except Exception:
                        raise RuntimeError("حجم نامعتبر است")
                    if traffic < 0 or traffic > 1_000_000:
                        raise RuntimeError("حجم خارج از محدوده است")
                    plan["traffic_gb"] = traffic
                    state["step"] = "days"
                    state["plan"] = plan
                    await _telegram_answer_callback(token, callback_id, "حجم انتخاب شد")
                    await _telegram_send_message(token, chat_id, "⏳ <b>مرحله ۵/۶</b>\nمدت اعتبار را انتخاب کنید:", reply_markup=_sell_admin_days_markup())
                async with BOT_ADMIN_WIZARD_LOCK:
                    BOT_ADMIN_WIZARD[admin_id] = state
            elif step_action == "days":
                value = ":".join(args[1:])
                if value == "custom":
                    state["step"] = "days_custom"
                    await _telegram_answer_callback(token, callback_id)
                    await _telegram_send_message(token, chat_id, "⏳ تعداد روز را ارسال کنید. برای نامحدود <code>0</code> بفرستید.")
                else:
                    try:
                        days = int(value)
                    except Exception:
                        raise RuntimeError("زمان نامعتبر است")
                    if days < 0 or days > 36500:
                        raise RuntimeError("زمان خارج از محدوده است")
                    plan["expire_days"] = days
                    state["step"] = "prefix"
                    state["plan"] = plan
                    await _telegram_answer_callback(token, callback_id, "زمان انتخاب شد")
                    await _telegram_send_message(token, chat_id, "👤 <b>مرحله ۶/۶</b>\nپیشوند نام کاربر را ارسال کنید.\nمثلاً: <code>shop</code>")
                async with BOT_ADMIN_WIZARD_LOCK:
                    BOT_ADMIN_WIZARD[admin_id] = state
            elif step_action == "confirm":
                normalized = _normalize_plan_input(plan, plan if state.get("mode") == "edit" else None)
                plans = sell.setdefault("plans", [])
                if state.get("mode") == "edit":
                    pid = str(plan.get("id") or "")
                    for idx, old in enumerate(plans):
                        if str(old.get("id") or "") == pid:
                            plans[idx] = normalized
                            break
                    else:
                        raise RuntimeError("Plan برای ویرایش پیدا نشد")
                    text_value = "✅ Plan ویرایش شد."
                else:
                    plans.append(normalized)
                    text_value = "✅ Plan اضافه شد."
                async with BOT_ADMIN_WIZARD_LOCK:
                    BOT_ADMIN_WIZARD.pop(admin_id, None)
                await _telegram_answer_callback(token, callback_id, "ذخیره شد")
                await _telegram_send_message(token, chat_id, text_value, reply_markup={"inline_keyboard": [[{"text": "📦 Planها", "callback_data": "sell:admin:plans"}, {"text": "➕ Plan بعدی", "callback_data": "sell:admin:add"}], [{"text": "⚙️ مدیریت", "callback_data": "sell:admin:menu"}]]})
                asyncio.create_task(save_state())
            async with BOT_ADMIN_WIZARD_LOCK:
                if admin_id in BOT_ADMIN_WIZARD and state.get("step") not in {"confirm"}:
                    BOT_ADMIN_WIZARD[admin_id] = state
            return

        if action == "approve" or action == "reject":
            if not is_admin:
                await _telegram_answer_callback(token, callback_id, "دسترسی ندارید", True)
                return
            oid = str(args[0] if args else "").strip().upper()
            await _telegram_answer_callback(token, callback_id, "در حال پردازش…")
            if action == "approve":
                try:
                    await _activate_sell_order(oid, admin_id)
                except RuntimeError as exc:
                    if "already approved" not in str(exc):
                        raise
            else:
                await _sell_bot_reject_order(token, oid, admin_id)
            mid = int(message.get("message_id") or 0)
            if mid:
                try:
                    await _telegram_edit_message_reply_markup(token, chat_id, mid, {"inline_keyboard": []})
                    label = "✅ رسید تأیید شد و حساب فعال شد." if action == "approve" else "❌ رسید رد شد."
                    await _telegram_edit_message_caption(token, chat_id, mid, f"<b>{label}</b>\n🧾 سفارش <code>{oid}</code>")
                except Exception:
                    pass
            return

        if action == "help":
            await _telegram_answer_callback(token, callback_id)
            return

    except Exception as e:
        await _telegram_answer_callback(token, callback_id, str(e)[:180], True)
        logger.warning("Sell Bot callback failed: %s", e)



async def _sell_bot_expiry_loop():
    """Remove expired panel users and notify Telegram-linked customers."""
    await asyncio.sleep(20)
    while True:
        try:
            now = datetime.now()
            expired = []
            async with USERS_LOCK:
                for uid, user in list(USERS.items()):
                    exp = str(user.get("expire_at") or "").strip()
                    if not exp or user.get("status") == "disabled":
                        continue
                    try:
                        if now >= datetime.fromisoformat(exp):
                            expired.append((str(uid), dict(user)))
                    except Exception:
                        continue
            for uid, user in expired[:100]:
                chat_id = str(user.get("telegram_chat_id") or "").strip()
                try:
                    await _delete_bot_user(uid)
                except Exception as e:
                    logger.warning("Expired user delete failed uid=%s: %s", uid, e)
                    continue
                sell = _bot_cfg().get("sell") or {}
                if chat_id and str((sell.get("customer_users") or {}).get(chat_id) or "") == uid:
                    sell.setdefault("customer_users", {}).pop(chat_id, None)
                token = str(_bot_cfg().get("token") or "").strip()
                if token and chat_id:
                    try:
                        await _telegram_send_message(
                            token, chat_id,
                            "⛔ <b>اعتبار اشتراک شما تمام شد.</b>\nاکانت شما از پنل حذف شد. برای خرید مجدد به بخش «محصولات» بروید.",
                            reply_markup=_sell_main_menu_markup(),
                        )
                    except Exception as e:
                        logger.warning("Expired user Telegram notify failed chat=%s: %s", chat_id, e)
            if expired:
                asyncio.create_task(save_state())
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Expiry sweep failed: %s", e)
        await asyncio.sleep(60)


async def _sell_bot_loop():
    cleared_token = ""
    last_save_monotonic = 0.0
    while True:
        try:
            cfg = _bot_cfg()
            sell = cfg.get("sell") or {}
            token = str(cfg.get("token") or "").strip()
            if not token or not bool(sell.get("enabled")):
                cleared_token = ""
                try:
                    await asyncio.wait_for(BOT_WAKE.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    continue
                BOT_WAKE.clear()
                continue
            if cleared_token != token:
                try:
                    await _telegram_api(token, "deleteWebhook", data={"drop_pending_updates": False}, timeout=10)
                    cleared_token = token
                except Exception as e:
                    sell["last_error"] = str(e)[:400]
                    await asyncio.sleep(10)
                    continue
            offset = int(sell.get("offset") or 0)
            params = {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]}
            try:
                updates = await _telegram_api(token, "getUpdates", data=params, timeout=32)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                sell["last_error"] = str(e)[:400]
                await asyncio.sleep(5)
                continue
            changed = False
            for update in updates or []:
                changed = True
                try:
                    upd_id = int(update.get("update_id") or 0)
                    if upd_id >= offset:
                        sell["offset"] = upd_id + 1
                    if update.get("callback_query"):
                        await _sell_bot_handle_callback(token, update.get("callback_query") or {})
                    elif update.get("message"):
                        await _sell_bot_handle_message(token, update.get("message") or {})
                except Exception as e:
                    logger.warning("Sell Bot update failed: %s", e)
            sell["last_update_at"] = datetime.now().isoformat()
            sell["last_error"] = ""
            now_m = time.monotonic()
            if changed or (now_m - last_save_monotonic) >= 60:
                last_save_monotonic = now_m
                asyncio.create_task(save_state())
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Sell Bot poller error: %s", e)
            await asyncio.sleep(5)


@app.get("/api/bot/status")
async def bot_status(_=Depends(require_auth)):
    cfg = _bot_cfg()
    token = str(cfg.get("token") or "")
    channel = dict(cfg.get("channel") or {})
    sell = dict(cfg.get("sell") or {})
    channel["channel"] = str(channel.get("channel") or "")
    plans = []
    for p in (sell.get("plans") or []):
        if isinstance(p, dict):
            q = dict(p)
            q.pop("created_at", None)
            plans.append(q)
    sell_public = dict(sell)
    sell_public["required_channels"] = [_normalize_required_channel(x) for x in (sell.get("required_channels") or []) if isinstance(x, (str, dict))]
    sell_public.pop("customer_users", None)
    sell_public.pop("offset", None)
    return {
        "ok": True,
        "token_configured": bool(token),
        "token_masked": _mask_bot_token(token),
        "channel": channel,
        "sell": sell_public,
        "plans": plans,
        "orders": {
            "pending": sum(1 for x in BOT_ORDERS.values() if x.get("status") in {"awaiting_payment", "payment_submitted", "processing"}),
            "payment_submitted": sum(1 for x in BOT_ORDERS.values() if x.get("status") == "payment_submitted"),
            "approved": sum(1 for x in BOT_ORDERS.values() if x.get("status") == "approved"),
            "rejected": sum(1 for x in BOT_ORDERS.values() if x.get("status") == "rejected"),
            "cancelled": sum(1 for x in BOT_ORDERS.values() if x.get("status") == "cancelled"),
        },
        "scheduler_running": bool(BOT_SCHEDULER_TASK and not BOT_SCHEDULER_TASK.done()),
        "poller_running": bool(BOT_POLL_TASK and not BOT_POLL_TASK.done()),
    }


@app.get("/api/bot/sell/plans")
async def bot_sell_plans(_=Depends(require_auth)):
    return {"ok": True, "plans": list(_bot_cfg()["sell"].get("plans") or [])}


@app.post("/api/bot/sell/plans")
async def bot_sell_plan_create(request: Request, _=Depends(require_auth)):
    body = await request.json()
    sell = _bot_cfg()["sell"]
    plan = _normalize_plan_input(body or {})
    sell.setdefault("plans", []).append(plan)
    asyncio.create_task(save_state())
    BOT_WAKE.set()
    return {"ok": True, "plan": plan}


@app.patch("/api/bot/sell/plans/{plan_id}")
async def bot_sell_plan_edit(plan_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    sell = _bot_cfg()["sell"]
    plans = sell.setdefault("plans", [])
    for i, old in enumerate(plans):
        if str(old.get("id")) == str(plan_id):
            plan = _normalize_plan_input(body or {}, old)
            plans[i] = plan
            asyncio.create_task(save_state())
            BOT_WAKE.set()
            return {"ok": True, "plan": plan}
    raise HTTPException(status_code=404, detail="plan not found")


@app.delete("/api/bot/sell/plans/{plan_id}")
async def bot_sell_plan_delete(plan_id: str, _=Depends(require_auth)):
    sell = _bot_cfg()["sell"]
    plans = sell.setdefault("plans", [])
    before = len(plans)
    sell["plans"] = [p for p in plans if str(p.get("id")) != str(plan_id)]
    if len(sell["plans"]) == before:
        raise HTTPException(status_code=404, detail="plan not found")
    if not sell["plans"]:
        # Clear legacy display fields so an empty store never resurrects a default plan.
        for legacy_key in ("plan_name", "price", "traffic_gb", "expire_days", "inbound_id"):
            sell.pop(legacy_key, None)
    asyncio.create_task(save_state())
    return {"ok": True}


@app.post("/api/bot/config")
async def bot_config_save(request: Request, _=Depends(require_auth)):
    body = await request.json()
    cfg = _bot_cfg()
    incoming_token = str(body.get("token") or "").strip()
    if incoming_token:
        if not re.fullmatch(r"\d{6,12}:[A-Za-z0-9_-]{20,}", incoming_token):
            raise HTTPException(status_code=400, detail="فرمت API Key تلگرام معتبر نیست")
        cfg["token"] = incoming_token
    ch_in = body.get("channel") or {}
    sell_in = body.get("sell") or {}
    ch = cfg["channel"]
    ch["enabled"] = bool(ch_in.get("enabled", ch.get("enabled")))
    ch["channel"] = str(ch_in.get("channel", ch.get("channel")) or "").strip()[:300]
    ch["interval_minutes"] = max(1, min(int(ch_in.get("interval_minutes", ch.get("interval_minutes") or 60)), 10080))
    ch["username_prefix"] = str(ch_in.get("username_prefix", ch.get("username_prefix") or "spider")).strip()[:24] or "spider"
    ch["traffic_limit_gb"] = max(0.0, float(ch_in.get("traffic_limit_gb", ch.get("traffic_limit_gb") or 0) or 0))
    ch["expire_days"] = max(0, int(ch_in.get("expire_days", ch.get("expire_days") or 0) or 0))
    ch["inbound_id"] = str(ch_in.get("inbound_id", ch.get("inbound_id") or "")).strip()
    ch["replace_previous"] = bool(ch_in.get("replace_previous", ch.get("replace_previous", True)))
    if not ch["enabled"]:
        ch["next_run_at"] = ""
    elif not ch.get("next_run_at"):
        ch["next_run_at"] = (datetime.now() + timedelta(minutes=ch["interval_minutes"])).isoformat()
    sell = cfg["sell"]
    sell["enabled"] = bool(sell_in.get("enabled", sell.get("enabled")))
    try:
        incoming_admin = str(sell_in.get("admin_chat_id", sell.get("admin_chat_id") or "")).strip()
        if sell["enabled"] and not incoming_admin:
            raise ValueError("Admin Numeric Telegram ID is required when Sell Bot is enabled")
        if incoming_admin:
            sell["admin_chat_id"] = _validate_admin_id(incoming_admin)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    sell["support_username"] = str(sell_in.get("support_username", sell.get("support_username") or "")).strip()[:64]
    sell["support_text"] = str(sell_in.get("support_text", sell.get("support_text") or "")).strip()[:1000]
    sell["payment_url"] = str(sell_in.get("payment_url", sell.get("payment_url") or "")).strip()[:500]
    sell["payment_details"] = str(sell_in.get("payment_details", sell.get("payment_details") or "")).strip()[:3000]
    required_in = sell_in.get("required_channels", None)
    if required_in is not None:
        if not isinstance(required_in, list):
            raise HTTPException(status_code=400, detail="required_channels must be a list")
        normalized_channels = []
        try:
            for item in required_in[:200]:
                normalized_channels.append(_normalize_required_channel(item))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        sell["required_channels"] = normalized_channels
    sell["welcome_text"] = str(sell_in.get("welcome_text", sell.get("welcome_text") or "")).strip()[:1200]
    # Do not destroy managed plans when saving general bot settings.
    if isinstance(sell_in.get("plans"), list):
        normalized = []
        for item in sell_in.get("plans")[:100]:
            try:
                normalized.append(_normalize_plan_input(item, item if item.get("id") else None))
            except Exception:
                continue
        if normalized:
            sell["plans"] = normalized
    asyncio.create_task(save_state())
    BOT_WAKE.set()
    return {"ok": True, "token_masked": _mask_bot_token(cfg.get("token")), "channel": ch, "sell": sell, "plans": sell.get("plans") or []}


@app.post("/api/bot/test")
async def bot_test(request: Request, _=Depends(require_auth)):
    body = await request.json()
    cfg = _bot_cfg()
    token = str(body.get("token") or cfg.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="اول Telegram Bot API Key را وارد کنید")
    try:
        me = await _telegram_api(token, "getMe", data={}, timeout=12)
        channel_input = str(body.get("channel") or (cfg.get("channel") or {}).get("channel") or "").strip()
        channel_info = None
        if channel_input:
            chat_id, channel_url, channel_label = _normalize_tg_channel(channel_input)
            if str(chat_id).startswith("@") or re.fullmatch(r"-?\d{5,}", str(chat_id)):
                chat = await _telegram_api(token, "getChat", data={"chat_id": chat_id}, timeout=12)
                if str(chat.get("type") or "") != "channel":
                    raise RuntimeError("آی‌دی وارد شده مربوط به Channel نیست")
                admins = []
                try:
                    admins = await _telegram_api(token, "getChatAdministrators", data={"chat_id": chat_id}, timeout=12)
                except Exception:
                    admins = []
                bot_id = int(me.get("id") or 0)
                bot_member = next((a for a in admins if int((a.get("user") or {}).get("id") or 0) == bot_id), None)
                channel_info = {
                    "id": chat.get("id"),
                    "title": chat.get("title"),
                    "username": chat.get("username"),
                    "is_admin": bool(bot_member),
                    "can_post_messages": bool((bot_member or {}).get("can_post_messages", False)) if bot_member else False,
                    "url": (f"https://t.me/{chat.get('username')}" if chat.get("username") else channel_url),
                }
        return {"ok": True, "bot": {"id": me.get("id"), "username": me.get("username"), "first_name": me.get("first_name")}, "channel": channel_info}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/bot/channel/run")
async def bot_channel_run(_=Depends(require_auth)):
    cfg = _bot_cfg()
    if not cfg.get("channel", {}).get("channel"):
        raise HTTPException(status_code=400, detail="Channel را تنظیم کنید")
    try:
        return await _channel_bot_run_once()
    except Exception as e:
        ch = cfg.get("channel") or {}
        ch["error_count"] = int(ch.get("error_count") or 0) + 1
        ch["last_error"] = str(e)[:400]
        asyncio.create_task(save_state())
        raise HTTPException(status_code=400, detail=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# PROXY IP endpoints
# ══════════════════════════════════════════════════════════════════════════════

# (removed dead proxy-ips endpoints — proxy source is now the daily GitHub list)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
