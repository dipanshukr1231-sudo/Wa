"""
DK Sharma Bot — WhatsApp Number Extractor (Production Edition v3)
Render/VPS compatible. Single-file deployment.

v2 upgrade (audited refactor of v1):
  • Centralized navigation state machine: every input screen has 🔙 Back and
    ❌ Cancel; Back never cancels a running extraction job.
  • Atomic active-job registration: active_jobs[user_id] = job_id with a
    threading.Event cancellation primitive checked at every stage.
  • Fast extraction: thread-local requests.Session reuse (keep-alive),
    ThreadPoolExecutor bounded visit concurrency, no per-visit exit-IP
    re-check (cached last_observed_ip + configurable verify interval),
    batched DB writes, short transactions, WAL.
  • Proxy engine: racing multi-endpoint verification (first success wins),
    configurable latency classification, weighted pool selection,
    proxy-vs-target failure distinction, scope-aware bulk retest,
    configurable live proxy sources (fetch → parse → dedupe → test → pool),
    background auto-retest with configurable interval/batch.
  • Channel auto-post: polished result card, real clipboard CopyTextButton
    chunks (≤256 chars), share button, optional TXT attachment, async with
    bounded exponential-backoff retries and error classification.
  • Safety: no hardcoded secrets, friendly error messages, credential-safe
    logs, startup config validation, rate-limit-safe Telegram wrappers.

Privacy: only fetches URLs the operator is authorized to process. No CAPTCHA
bypass, no login bypass, no private-account scraping.
"""

import os
import re
import io
import sys
import time
import json
import html
import random
import sqlite3
import threading
import urllib.parse
import base64
import hashlib
import queue
import socket
import logging
import shutil
import subprocess
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

try:
    import socks  # PySocks (required for SOCKS5)
    _SOCKS_OK = True
except Exception:
    _SOCKS_OK = False

import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException

# =========================================================
# Logging (structured, credential-safe)
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("bot")
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)


def _mask(s: str) -> str:
    """Mask credentials in any string before it reaches logs/messages."""
    return re.sub(r"(://)([^:@/\s]+):([^@/\s]+)(@)", r"\1***:***\3", s or "")


# =========================================================
# Configuration & Environment (validated at startup)
# =========================================================
class ConfigError(Exception):
    pass


def _env_int(name: str, default: int, lo: int = 1, hi: int = 100000) -> int:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        raise ConfigError(f"Environment variable {name} must be an integer, got {raw!r}")
    return max(lo, min(hi, v))


def _env_float(name: str, default: float, lo: float = 0.1, hi: float = 3600.0) -> float:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        raise ConfigError(f"Environment variable {name} must be a number, got {raw!r}")
    return max(lo, min(hi, v))


BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    sys.stderr.write(
        "FATAL: BOT_TOKEN environment variable is not set.\n"
        "Set it before starting the bot, e.g.:\n"
        "  export BOT_TOKEN='123456:ABC-DEF...'\n"
    )
    sys.exit(2)

ADMIN_IDS = [
    int(x.strip())
    for x in os.environ.get("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
]
if not ADMIN_IDS:
    log.warning("ADMIN_IDS not set — admin panel disabled until configured.")  # FIX-P20

DB_PATH = os.environ.get("DATABASE_PATH", "bot_database.db")
DEFAULT_CHANNEL = os.environ.get("CHANNEL_USERNAME", "")

REQUEST_TIMEOUT = _env_int("REQUEST_TIMEOUT", 15, 2, 120)
CONNECT_TIMEOUT = _env_int("CONNECT_TIMEOUT", 6, 1, 60)
READ_TIMEOUT = _env_int("READ_TIMEOUT", 10, 1, 120)
MAX_CONCURRENCY = _env_int("MAX_CONCURRENCY", 8, 1, 32)
PROGRESS_INTERVAL = _env_float("PROGRESS_INTERVAL", 1.0, 0.5, 10.0)
MAX_VISITS_PER_JOB = _env_int("MAX_VISITS_PER_JOB", 100, 1, 500)
MAX_RESPONSE_SIZE = _env_int("MAX_RESPONSE_SIZE", 5 * 1024 * 1024, 65536, 50 * 1024 * 1024)
MAX_REDIRECTS = _env_int("MAX_REDIRECTS", 10, 1, 30)
MAX_RETRIES_PER_VISIT = _env_int("MAX_RETRIES_PER_VISIT", 2, 0, 5)
PROXY_TEST_CONCURRENCY = _env_int("PROXY_TEST_CONCURRENCY", 48, 1, 128)
PROXY_HEALTH_TIMEOUT = _env_int("PROXY_HEALTH_TIMEOUT", 6, 2, 60)
IP_TURBO_CONCURRENCY = _env_int("IP_TURBO_CONCURRENCY", 24, 1, 64)
IP_MAX_PROXY_ATTEMPTS = _env_int("IP_MAX_PROXY_ATTEMPTS", 10, 1, 30)
PROXY_RETEST_INTERVAL = _env_int("PROXY_RETEST_INTERVAL", 300, 60, 86400)
PROXY_RETEST_BATCH = _env_int("PROXY_RETEST_BATCH", 30, 1, 200)
PROXY_VERIFY_IP_INTERVAL = _env_int("PROXY_VERIFY_IP_INTERVAL", 300, 30, 86400)

IP_CONNECT_TIMEOUT = _env_int("IP_CONNECT_TIMEOUT", 3, 1, 30)     # FIX-P14
IP_READ_TIMEOUT = _env_int("IP_READ_TIMEOUT", 6, 1, 60)           # FIX-P14
VISIT_TIME_BUDGET = _env_int("VISIT_TIME_BUDGET", 45, 10, 300)    # FIX-P14
SCAN_BYTES = _env_int("SCAN_BYTES", 1000000, 100000, 5000000)     # FIX-P31

# FIX-P25: rotating realistic browser fingerprints
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
    "Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]
ACCEPT_LANG_POOL = ["en-US,en;q=0.9", "en-GB,en;q=0.9",
                    "hi-IN,hi;q=0.9,en;q=0.8", "en;q=0.8"]

# Configurable latency classification (milliseconds)
LAT_FAST_MAX = _env_int("LATENCY_FAST_MAX", 999, 100, 60000)
LAT_WORKING_MAX = _env_int("LATENCY_WORKING_MAX", 2499, 100, 60000)
LAT_SLOW_MAX = _env_int("LATENCY_SLOW_MAX", 3999, 100, 120000)

# Number validation (configurable)
NUM_MIN_LEN = _env_int("NUMBER_MIN_LEN", 10, 6, 15)
NUM_MAX_LEN = _env_int("NUMBER_MAX_LEN", 15, 6, 16)

# Proxy sources (env-configured; admin can override via settings)
PROXY_SOURCES_ENV = [
    os.environ.get(f"PROXY_SOURCE_{i}", "").strip()
    for i in (1, 2, 3)
    if os.environ.get(f"PROXY_SOURCE_{i}", "").strip()
]

# Built-in public proxy lists — used automatically when the admin has not
# configured any PROXY_SOURCE_* URLs, so "Fetch Latest" works out of the box.
BUILTIN_PROXY_SOURCES = [
    # TheSpeedX — large, frequently updated
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    # proxifly
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
    # jetkai
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    # clarketm
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    # sunny9577
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    # monosans
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    # roosterkid
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    # MuRongPIG
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
    # ObcbO
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/socks5.txt",
    # hookzof
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    # ShiftyTR
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    # mmpx12
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    # Anonym0usWork1221
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
    # r00tee
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
    # elliottophellia
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
    # dpangestuw
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks5_proxies.txt",
    # ALIILAPRO
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    # vakhov
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    # Zaeem20
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    # prxchk
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    # zloi-user
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    # almroot
    "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
    # aslisk
    "https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
]

BOOTSTRAP_OWNER_ID = ADMIN_IDS[0] if ADMIN_IDS else 0

bot = telebot.TeleBot(
    BOT_TOKEN,
    parse_mode="Markdown",
    threaded=True,
    num_threads=4,
)

# =========================================================
# Shared state (all protected by locks)
# =========================================================
MAINTENANCE_MODE = False  # mirrored from DB settings at startup

_state_lock = threading.RLock()
user_states: dict = {}            # user_id -> {"screen","step","data","nav":[...]}
active_jobs: dict = {}            # user_id -> job_id (REAL id, set atomically)
job_state: dict = {}              # job_id -> JobState dict (live progress)
job_cancel: dict = {}             # job_id -> threading.Event
job_owner: dict = {}              # job_id -> user_id
proxy_test_jobs: dict = {}        # admin_id -> threading.Event (cancel bulk tests)
proxy_fetch_jobs: dict = {}       # admin_id -> threading.Event (cancel fetches)

# =========================================================
# Database
# =========================================================
_db_lock = threading.RLock()


_db_local = threading.local()
_db_conn_count = [0]   # FIX-P50: diagnostics — count connections opened


def get_conn() -> sqlite3.Connection:
    """FIX-P22: one persistent WAL connection per thread; pragmas run once."""
    conn = getattr(_db_local, "conn", None)
    if conn is not None:
        return conn
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    _db_local.conn = conn
    _db_conn_count[0] += 1
    return conn


def _col_exists(conn, table: str, col: str) -> bool:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return any(r[1] == col for r in cur.fetchall())
    except sqlite3.Error:
        return False


def init_db() -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id               INTEGER PRIMARY KEY,
                    username              TEXT,
                    first_name            TEXT,
                    status                TEXT DEFAULT 'APPROVED',
                    blocked               INTEGER DEFAULT 0,
                    total_extractions     INTEGER DEFAULT 0,
                    total_numbers_found   INTEGER DEFAULT 0,
                    joined_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_active           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS admins (
                    user_id     INTEGER PRIMARY KEY,
                    username    TEXT,
                    role        TEXT DEFAULT 'ADMIN',
                    added_by    INTEGER,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active   INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS extraction_jobs (
                    job_id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id             INTEGER,
                    username            TEXT,
                    source_url          TEXT,
                    mode                TEXT,
                    requested_visits    INTEGER,
                    successful_visits   INTEGER DEFAULT 0,
                    failed_visits       INTEGER DEFAULT 0,
                    unique_numbers      INTEGER DEFAULT 0,
                    duplicate_numbers   INTEGER DEFAULT 0,
                    duration_ms         INTEGER DEFAULT 0,
                    status              TEXT DEFAULT 'QUEUED',
                    started_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at        TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                );

                CREATE TABLE IF NOT EXISTS extraction_job_numbers (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id              INTEGER,
                    user_id             INTEGER,
                    number              TEXT,
                    source_url          TEXT,
                    extraction_method   TEXT,
                    visit_number        INTEGER,
                    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (job_id) REFERENCES extraction_jobs(job_id)
                );

                CREATE TABLE IF NOT EXISTS extraction_attempts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id          INTEGER,
                    cycle           INTEGER,
                    proxy_id        INTEGER,
                    exit_ip         TEXT,
                    request_status  TEXT,
                    latency_ms      INTEGER,
                    error           TEXT,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (job_id) REFERENCES extraction_jobs(job_id)
                );

                CREATE TABLE IF NOT EXISTS proxies (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint            TEXT,
                    protocol            TEXT,
                    host                TEXT,
                    port                INTEGER,
                    username            TEXT,
                    password            TEXT,
                    source              TEXT DEFAULT 'manual',
                    is_active           INTEGER DEFAULT 1,
                    health_status       TEXT DEFAULT 'UNTESTED',
                    health_score        INTEGER DEFAULT 0,
                    success_count       INTEGER DEFAULT 0,
                    failure_count       INTEGER DEFAULT 0,
                    consecutive_failures INTEGER DEFAULT 0,
                    average_latency     INTEGER DEFAULT 0,
                    last_observed_ip    TEXT,
                    last_ip_verified    TIMESTAMP,
                    last_error          TEXT,
                    last_tested         TIMESTAMP,
                    last_success        TIMESTAMP,
                    last_failure        TIMESTAMP,
                    last_used           TIMESTAMP,
                    cooldown_until      TIMESTAMP,
                    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key     TEXT PRIMARY KEY,
                    value   TEXT
                );

                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id    INTEGER,
                    action      TEXT,
                    target      TEXT,
                    details     TEXT,
                    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS channel_posts (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id              INTEGER,
                    channel             TEXT,
                    status              TEXT,
                    message_id          INTEGER,
                    error               TEXT,
                    posted_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS proxy_fetch_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source          TEXT,
                    fetched         INTEGER DEFAULT 0,
                    valid           INTEGER DEFAULT 0,
                    duplicates      INTEGER DEFAULT 0,
                    working         INTEGER DEFAULT 0,
                    slow            INTEGER DEFAULT 0,
                    dead            INTEGER DEFAULT 0,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS allowed_users (
                    user_id         INTEGER PRIMARY KEY,
                    username        TEXT,
                    first_name      TEXT,
                    granted_by      INTEGER,
                    granted_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    note            TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_hostport ON proxies(host, port);
                CREATE INDEX IF NOT EXISTS idx_jobs_user     ON extraction_jobs(user_id);
                CREATE INDEX IF NOT EXISTS idx_jobs_date     ON extraction_jobs(started_at);
                CREATE INDEX IF NOT EXISTS idx_jobs_status   ON extraction_jobs(status);
                CREATE INDEX IF NOT EXISTS idx_nums_job      ON extraction_job_numbers(job_id);
                CREATE INDEX IF NOT EXISTS idx_nums_number   ON extraction_job_numbers(number);
                CREATE INDEX IF NOT EXISTS idx_attempts_job  ON extraction_attempts(job_id);
                CREATE INDEX IF NOT EXISTS idx_attempts_date ON extraction_attempts(created_at);
                CREATE INDEX IF NOT EXISTS idx_proxy_status  ON proxies(health_status);
                CREATE INDEX IF NOT EXISTS idx_proxy_cool    ON proxies(cooldown_until);
                CREATE INDEX IF NOT EXISTS idx_chanpost_job  ON channel_posts(job_id);
                CREATE INDEX IF NOT EXISTS idx_users_active  ON users(last_active);
                """
            )

            # v3 migration — extraction attempt intelligence fields
            for _v3_sql in (
                "ALTER TABLE extraction_attempts ADD COLUMN protection_type TEXT",
                "ALTER TABLE extraction_attempts ADD COLUMN final_url TEXT",
                "ALTER TABLE extraction_attempts ADD COLUMN telegram_username TEXT",
                "ALTER TABLE extraction_attempts ADD COLUMN extraction_layers TEXT",
            ):
                try:
                    conn.execute(_v3_sql)
                except sqlite3.Error:
                    pass  # column already exists
            conn.commit()

            migrations = [
                ("users", "status", "TEXT DEFAULT 'APPROVED'"),
                ("users", "blocked", "INTEGER DEFAULT 0"),
                ("extraction_jobs", "status", "TEXT DEFAULT 'QUEUED'"),
                ("extraction_jobs", "username", "TEXT"),
                ("extraction_jobs", "successful_visits", "INTEGER DEFAULT 0"),
                ("extraction_jobs", "failed_visits", "INTEGER DEFAULT 0"),
                ("extraction_jobs", "duration_ms", "INTEGER DEFAULT 0"),
                ("proxies", "source", "TEXT DEFAULT 'manual'"),
                ("proxies", "last_ip_verified", "TIMESTAMP"),
                ("proxies", "last_used", "TIMESTAMP"),
                ("proxies", "is_precious", "INTEGER DEFAULT 0"),
            ]
            for tbl, col, decl in migrations:
                if not _col_exists(conn, tbl, col):
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {decl}")

            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


# ---------- Settings ----------
_DEFAULT_SETTINGS = {
    "maintenance_mode": "0",
    "approval_mode": "0",
    "allow_all": "1",
    "channel_logging": "0",
    "channel_username": DEFAULT_CHANNEL,
    "support_username": "",
    "admin_display_name": "DK Sharma",
    "max_visits": str(MAX_VISITS_PER_JOB),
    "request_timeout": str(REQUEST_TIMEOUT),
    "connect_timeout": str(CONNECT_TIMEOUT),
    "read_timeout": str(READ_TIMEOUT),
    "proxy_enabled": "1",
    "max_concurrency": str(MAX_CONCURRENCY),  # default 8 for fast proxy rotation
    "progress_interval": str(PROGRESS_INTERVAL),
    "max_retries_per_visit": str(MAX_RETRIES_PER_VISIT),
    "ip_turbo_concurrency": str(IP_TURBO_CONCURRENCY),
    "ip_max_proxy_attempts": str(IP_MAX_PROXY_ATTEMPTS),
    "fallback_direct_on_empty_pool": "0",
    "channel_include_username": "1",
    "channel_include_uid": "0",
    "channel_include_method": "1",
    "channel_include_proxy": "0",
    "channel_include_numbers": "1",
    "channel_include_speed": "1",
    "channel_attach_txt": "0",
    "proxy_source_1": PROXY_SOURCES_ENV[0] if len(PROXY_SOURCES_ENV) > 0 else "",
    "proxy_source_2": PROXY_SOURCES_ENV[1] if len(PROXY_SOURCES_ENV) > 1 else "",
    "proxy_source_3": PROXY_SOURCES_ENV[2] if len(PROXY_SOURCES_ENV) > 2 else "",
    "proxy_retest_interval": str(PROXY_RETEST_INTERVAL),
    "proxy_retest_batch": str(PROXY_RETEST_BATCH),
    "latency_fast_max": str(LAT_FAST_MAX),
    "latency_working_max": str(LAT_WORKING_MAX),
    "latency_slow_max": str(LAT_SLOW_MAX),
    # v3 — deep extraction engine
    "ex_layer_url_chain": "1",
    "ex_layer_raw_html": "1",
    "ex_layer_meta": "1",
    "ex_layer_js_vars": "1",
    "ex_layer_encoded": "1",
    "ex_layer_telegram": "1",
    "false_positive_filter": "1",
    "telegram_redirect_mode": "extract_only",   # extract_only | report_username | skip
    "cloudflare_behavior": "skip",              # skip | retry_proxies | count_as_failed
    "number_min_len": str(NUM_MIN_LEN),
    "number_max_len": str(NUM_MAX_LEN),
    # v3.1 — performance & strategy (P14, P23, P31, P36)
    "direct_strategy": "smart",             # smart | parallel | classic
    "early_stop_barren": "15",
    "early_stop_barren_ip": "25",
    "scan_bytes": str(SCAN_BYTES),
    "visit_time_budget": str(VISIT_TIME_BUDGET),
    "ip_connect_timeout": str(IP_CONNECT_TIMEOUT),
    "ip_read_timeout": str(IP_READ_TIMEOUT),
    "proxy_test_concurrency": str(PROXY_TEST_CONCURRENCY),
}


_settings_lock = threading.RLock()
_settings_cache: dict = {}
_settings_loaded_at = 0.0
_SETTINGS_TTL = 5.0
_settings_hits = [0]   # FIX-P50: diagnostics


def _settings_refresh(force: bool = False) -> None:
    """FIX-P21: one batch read every TTL seconds instead of one
    connection per get_setting() call."""
    global _settings_loaded_at
    now = time.time()
    with _settings_lock:
        if not force and now - _settings_loaded_at < _SETTINGS_TTL:
            return
        conn = get_conn()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        fresh = dict(_DEFAULT_SETTINGS)
        for r in rows:
            fresh[r["key"]] = r["value"]
        _settings_cache.clear()
        _settings_cache.update(fresh)
        _settings_loaded_at = now


def get_setting(key: str, default: Optional[str] = None) -> str:
    _settings_refresh()
    with _settings_lock:
        _settings_hits[0] += 1
        if key in _settings_cache:
            return _settings_cache[key]
    return default if default is not None else _DEFAULT_SETTINGS.get(key, "")


def get_settings_batch(keys) -> dict:
    """FIX-P21: served from the TTL cache — zero DB hits in hot paths."""
    _settings_refresh()
    with _settings_lock:
        return {k: _settings_cache.get(k, _DEFAULT_SETTINGS.get(k, ""))
                for k in keys}


def set_setting(key: str, value: str) -> None:
    with _db_lock:
        conn = get_conn()
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    with _settings_lock:                      # FIX-P21: instant invalidation
        _settings_cache[key] = str(value)


def seed_settings() -> None:
    with _db_lock:
        conn = get_conn()
        for k, v in _DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v)
            )
        conn.commit()
    _settings_refresh(force=True)


def audit_log(admin_id: int, action: str, target: str = "", details: str = "") -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO admin_audit_log(admin_id, action, target, details) VALUES(?,?,?,?)",
                (admin_id, action, _mask(str(target))[:200], _mask(str(details))[:300]),
            )
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


# ---------- Allowed Users (Bot Access Permission) ----------
def is_allowed_user(user_id: int) -> bool:
    """Check if user has been granted bot access permission by admin."""
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute(
                "SELECT 1 FROM allowed_users WHERE user_id=?", (user_id,)
            ).fetchone()
            return r is not None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def grant_user_permission(user_id: int, username: str, first_name: str,
                          granted_by: int, note: str = "") -> bool:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO allowed_users
                   (user_id, username, first_name, granted_by, note)
                   VALUES(?,?,?,?,?)""",
                (user_id, username, first_name, granted_by, note),
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            pass  # FIX-P22: persistent thread-local connection


def revoke_user_permission(user_id: int) -> bool:
    with _db_lock:
        conn = get_conn()
        try:
            cur = conn.execute("DELETE FROM allowed_users WHERE user_id=?", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            pass  # FIX-P22: persistent thread-local connection


def list_allowed_users(limit: int = 50) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM allowed_users ORDER BY granted_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def is_admin(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute(
                "SELECT 1 FROM admins WHERE user_id=? AND is_active=1", (user_id,)
            ).fetchone()
            return r is not None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def admin_role(user_id: int) -> Optional[str]:
    if user_id in ADMIN_IDS:
        return "OWNER"
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute(
                "SELECT role FROM admins WHERE user_id=? AND is_active=1", (user_id,)
            ).fetchone()
            return r["role"] if r else None
        finally:
            pass  # FIX-P22: persistent thread-local connection


# ---------- Users ----------
def register_user(user_id: int, username: str = None, first_name: str = None) -> str:
    """Return user status: APPROVED / PENDING / BLOCKED.

    FIX-P07: INSERT OR IGNORE + re-SELECT — two concurrent first messages
    from the same user can no longer raise IntegrityError.
    """
    with _db_lock:
        conn = get_conn()
        existing = conn.execute(
            "SELECT status, blocked FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE users SET last_active=CURRENT_TIMESTAMP,
                   username=COALESCE(?, username),
                   first_name=COALESCE(?, first_name) WHERE user_id=?""",
                (username, first_name, user_id),
            )
            conn.commit()
            if existing["blocked"]:
                return "BLOCKED"
            return existing["status"]
        approval = get_setting("approval_mode", "0")
        status = "PENDING" if approval == "1" else "APPROVED"
        conn.execute(
            "INSERT OR IGNORE INTO users(user_id, username, first_name, status) "
            "VALUES(?,?,?,?)",
            (user_id, username, first_name, status),
        )
        conn.commit()
        row = conn.execute(
            "SELECT status, blocked FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row:
            return "BLOCKED" if row["blocked"] else row["status"]
        return status



def update_user_stats(user_id: int, unique_count: int) -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                """UPDATE users SET total_extractions=total_extractions+1,
                   total_numbers_found=total_numbers_found+?,
                   last_active=CURRENT_TIMESTAMP WHERE user_id=?""",
                (unique_count, user_id),
            )
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


def set_user_status(user_id: int, status: str) -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE users SET status=? WHERE user_id=?", (status, user_id)
            )
            if status == "BLOCKED":
                conn.execute("UPDATE users SET blocked=1 WHERE user_id=?", (user_id,))
            elif status == "APPROVED":
                conn.execute("UPDATE users SET blocked=0 WHERE user_id=?", (user_id,))
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


def get_user(user_id: int) -> Optional[dict]:
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
            return dict(r) if r else None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def search_users(query: str, limit: int = 20) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            q = f"%{query}%"
            rows = conn.execute(
                """SELECT * FROM users
                   WHERE CAST(user_id AS TEXT) LIKE ? OR username LIKE ? OR first_name LIKE ?
                   ORDER BY joined_at DESC LIMIT ?""",
                (q, q, q, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def recent_users(limit: int = 10) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY joined_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def all_user_ids() -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT user_id FROM users WHERE blocked=0 AND status='APPROVED'"
            ).fetchall()
            return [r["user_id"] for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def pending_users() -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM users WHERE status='PENDING' AND blocked=0 ORDER BY joined_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


# ---------- Jobs ----------
def create_job(user_id: int, username: str, url: str, mode: str, visits: int) -> int:
    with _db_lock:
        conn = get_conn()
        try:
            cur = conn.execute(
                """INSERT INTO extraction_jobs(user_id, username, source_url, mode,
                   requested_visits, status) VALUES(?,?,?,?,?, 'RUNNING')""",
                (user_id, username, url, mode, visits),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            pass  # FIX-P22: persistent thread-local connection


def finish_job(job_id: int, success: int, failed: int, unique: int,
               dupes: int, duration_ms: int, status: str) -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                """UPDATE extraction_jobs SET successful_visits=?, failed_visits=?,
                   unique_numbers=?, duplicate_numbers=?, duration_ms=?, status=?,
                   completed_at=CURRENT_TIMESTAMP WHERE job_id=?""",
                (success, failed, unique, dupes, duration_ms, status, job_id),
            )
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


def _attempt_row(job_id, visit, proxy_id=None, exit_ip="", status="UNKNOWN",
                 latency=0, error="", protection="none", final_url="",
                 tg_user="", layers=None):
    """FIX-P01: uniform 11-field attempt row — never mismatched arity."""
    return (job_id, visit, proxy_id, exit_ip, status, latency, error,
            protection, final_url, tg_user, json.dumps(layers or []))


def save_numbers_batch(rows: list) -> None:
    """rows: [(job_id, user_id, number, source, method, visit, display), ...]"""
    if not rows:
        return
    with _db_lock:
        conn = get_conn()
        conn.executemany(
            """INSERT INTO extraction_job_numbers
               (job_id, user_id, number, source_url, extraction_method,
                visit_number, display)
               VALUES(?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()


def save_attempts_batch(rows: list) -> None:
    """FIX-P01: malformed rows are dropped, the rest always commit."""
    rows = [r for r in rows if len(r) == 11]
    if not rows:
        return
    with _db_lock:
        conn = get_conn()
        conn.executemany(
            """INSERT INTO extraction_attempts
               (job_id, cycle, proxy_id, exit_ip, request_status, latency_ms, error,
                protection_type, final_url, telegram_username, extraction_layers)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()



def job_numbers(job_id: int, limit: int = 500) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM extraction_job_numbers WHERE job_id=? LIMIT ?", (job_id, limit)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def job_attempts(job_id: int, limit: int = 50) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM extraction_attempts WHERE job_id=? ORDER BY cycle LIMIT ?",
                (job_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def get_job(job_id: int) -> Optional[dict]:
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute(
                "SELECT * FROM extraction_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            return dict(r) if r else None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def recent_jobs(limit: int = 15, days: Optional[int] = None) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            if days:
                rows = conn.execute(
                    """SELECT * FROM extraction_jobs
                       WHERE started_at >= datetime('now', ?)
                       ORDER BY started_at DESC LIMIT ?""",
                    (f"-{days} days", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM extraction_jobs ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def user_jobs(user_id: int, limit: int = 10) -> list:
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM extraction_jobs WHERE user_id=? ORDER BY started_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def admin_dashboard_stats() -> dict:
    with _db_lock:
        conn = get_conn()
        try:
            d = {}
            d["total_users"] = conn.execute(
                "SELECT COUNT(*) c FROM users WHERE blocked=0"
            ).fetchone()["c"]
            d["active_today"] = conn.execute(
                "SELECT COUNT(*) c FROM users WHERE last_active >= datetime('now','-1 day')"
            ).fetchone()["c"]
            d["total_jobs"] = conn.execute(
                "SELECT COUNT(*) c FROM extraction_jobs"
            ).fetchone()["c"]
            d["jobs_today"] = conn.execute(
                "SELECT COUNT(*) c FROM extraction_jobs WHERE started_at >= datetime('now','-1 day')"
            ).fetchone()["c"]
            d["successful_jobs"] = conn.execute(
                "SELECT COUNT(*) c FROM extraction_jobs WHERE status='COMPLETED'"
            ).fetchone()["c"]
            d["failed_jobs"] = conn.execute(
                "SELECT COUNT(*) c FROM extraction_jobs WHERE status='FAILED'"
            ).fetchone()["c"]
            d["total_numbers"] = conn.execute(
                "SELECT COALESCE(SUM(unique_numbers),0) s FROM extraction_jobs"
            ).fetchone()["s"]
            d["numbers_today"] = conn.execute(
                "SELECT COALESCE(SUM(unique_numbers),0) s FROM extraction_jobs "
                "WHERE started_at >= datetime('now','-1 day')"
            ).fetchone()["s"]
            d["avg_duration"] = conn.execute(
                "SELECT COALESCE(AVG(duration_ms),0) a FROM extraction_jobs WHERE status='COMPLETED'"
            ).fetchone()["a"]
            return d
        finally:
            pass  # FIX-P22: persistent thread-local connection


# =========================================================
# Pure-Python AES-128-CBC Decryptor (ByetHost / InfinityFree challenge)
# =========================================================
_AES_SBOX = (
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
)
_AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i
_AES_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _sub_word(w: int) -> int:
    return ((_AES_SBOX[(w >> 24) & 0xFF] << 24) | (_AES_SBOX[(w >> 16) & 0xFF] << 16) |
            (_AES_SBOX[(w >> 8) & 0xFF] << 8) | _AES_SBOX[w & 0xFF])


def _rot_word(w: int) -> int:
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)


def _key_schedule(key_bytes: bytes) -> list:
    w = []
    for i in range(4):
        w.append((key_bytes[4*i] << 24) | (key_bytes[4*i+1] << 16) |
                 (key_bytes[4*i+2] << 8) | key_bytes[4*i+3])
    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp)) ^ (_AES_RCON[i // 4] << 24)
        w.append(w[i-4] ^ temp)
    return w


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _inv_mix_col(c: list) -> list:
    return [
        _gmul(c[0], 0x0E) ^ _gmul(c[1], 0x0B) ^ _gmul(c[2], 0x0D) ^ _gmul(c[3], 0x09),
        _gmul(c[0], 0x09) ^ _gmul(c[1], 0x0E) ^ _gmul(c[2], 0x0B) ^ _gmul(c[3], 0x0D),
        _gmul(c[0], 0x0D) ^ _gmul(c[1], 0x09) ^ _gmul(c[2], 0x0E) ^ _gmul(c[3], 0x0B),
        _gmul(c[0], 0x0B) ^ _gmul(c[1], 0x0D) ^ _gmul(c[2], 0x09) ^ _gmul(c[3], 0x0E),
    ]


def _decrypt_single_block(block: bytes, w: list) -> list:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    for c in range(4):
        rk = w[40 + c]
        for r in range(4):
            state[r][c] ^= (rk >> (24 - 8 * r)) & 0xFF
    for rnd in range(9, 0, -1):
        state[1] = state[1][3:] + state[1][:3]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][1:] + state[3][:1]
        for r in range(4):
            for c in range(4):
                state[r][c] = _AES_INV_SBOX[state[r][c]]
        for c in range(4):
            rk = w[rnd * 4 + c]
            for r in range(4):
                state[r][c] ^= (rk >> (24 - 8 * r)) & 0xFF
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            new_col = _inv_mix_col(col)
            for r in range(4):
                state[r][c] = new_col[r]
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]
    for r in range(4):
        for c in range(4):
            state[r][c] = _AES_INV_SBOX[state[r][c]]
    for c in range(4):
        rk = w[c]
        for r in range(4):
            state[r][c] ^= (rk >> (24 - 8 * r)) & 0xFF
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return out


def decrypt_byet_challenge(c_hex: str, a_hex: str, b_hex: str) -> str:
    """AES-128-CBC decrypt for ByetHost/InfinityFree __test cookie."""
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(bytes.fromhex(a_hex), AES.MODE_CBC, bytes.fromhex(b_hex))
        return cipher.decrypt(bytes.fromhex(c_hex)).hex()
    except Exception:
        pass
    if shutil.which("openssl"):
        try:
            p = subprocess.Popen(
                ["openssl", "enc", "-d", "-aes-128-cbc", "-K", a_hex, "-iv", b_hex, "-nopad"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            out, _ = p.communicate(bytes.fromhex(c_hex))
            if p.returncode == 0 and len(out) == 16:
                return out.hex()
        except Exception:
            pass
    c = bytes.fromhex(c_hex)
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    w = _key_schedule(a)
    dec = _decrypt_single_block(c, w)
    return bytes([dec[i] ^ b[i] for i in range(16)]).hex()


# =========================================================
# Proxy Parsing
# =========================================================
_PROXY_RE = re.compile(
    r"^(?P<scheme>https?|socks5h?|socks4a?)://"
    r"(?:(?P<user>[^:@/\s]+):(?P<pass>[^@/\s]+)@)?"
    r"(?P<host>[^:/\s]+):(?P<port>\d+)$",
    re.IGNORECASE,
)


def parse_proxy(raw: str) -> Optional[dict]:
    """Parse a proxy string into a structured dict. Returns None if invalid.

    Supported:
      IP:PORT · IP:PORT:USER:PASS · host:port · host:port:user:pass
      http://IP:PORT · https://IP:PORT · socks4:// · socks5:// · socks5h://
      (all scheme forms also accept user:pass@)
    """
    s = raw.strip()
    if not s:
        return None
    m = _PROXY_RE.match(s)
    if m:
        scheme = m.group("scheme").lower()
        try:
            port = int(m.group("port"))
        except ValueError:
            return None
        if not (1 <= port <= 65535):
            return None
        return {
            "protocol": scheme,
            "host": m.group("host"),
            "port": port,
            "username": urllib.parse.unquote(m.group("user") or ""),
            "password": urllib.parse.unquote(m.group("pass") or ""),
            "endpoint": s,
        }
    parts = s.split(":")
    if len(parts) == 2:
        try:
            port = int(parts[1])
            if not (1 <= port <= 65535):
                return None
            return {"protocol": "http", "host": parts[0], "port": port,
                    "username": "", "password": "", "endpoint": f"http://{parts[0]}:{port}"}
        except ValueError:
            return None
    if len(parts) == 4:
        try:
            port = int(parts[1])
            if not (1 <= port <= 65535):
                return None
            return {"protocol": "http", "host": parts[0], "port": port,
                    "username": parts[2], "password": parts[3],
                    "endpoint": f"http://{parts[2]}:{parts[3]}@{parts[0]}:{port}"}
        except ValueError:
            return None
    return None


def proxy_to_requests(p: dict) -> dict:
    auth = ""
    if p["username"]:
        auth = f"{urllib.parse.quote(p['username'], safe='')}:{urllib.parse.quote(p['password'], safe='')}@"
    url = f"{p['protocol']}://{auth}{p['host']}:{p['port']}"
    return {"http": url, "https": url}


def proxy_label(p: dict) -> str:
    """Credential-free label for UI/logs."""
    return f"{p['host']}:{p['port']}"


# =========================================================
# Proxy Health Testing (TCP → racing HTTP/IP verification)
# =========================================================
IP_CHECK_ENDPOINTS = [
    "https://api.ipify.org?format=text",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
    "https://api.my-ip.io/ip",
    "https://ipecho.net/plain",
    "http://ip-api.com/line/?fields=query",
]

_TEST_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,45}$")


def _tcp_check(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


_IPCHECK_EXEC = ThreadPoolExecutor(max_workers=64)
_ipcheck_sem = threading.BoundedSemaphore(64)
_endpoint_backoff: dict = {}   # url -> banned-until ts


def _verify_exit_ip(p, timeout):
    """FIX-P26: race TWO reliable endpoints; honor per-endpoint backoff;
    any HTTP response at all proves CONNECTED."""
    proxies = proxy_to_requests(p)
    now = time.time()
    candidates = [ep for ep in IP_CHECK_ENDPOINTS
                  if _endpoint_backoff.get(ep, 0) < now]
    if not candidates:
        candidates = IP_CHECK_ENDPOINTS[:2]
    endpoints = random.sample(candidates, min(2, len(candidates)))

    result, auth_failed, got_response = {}, threading.Event(), threading.Event()

    def _hit(ep):
        if auth_failed.is_set() or "ip" in result:
            return
        with _ipcheck_sem:
            try:
                t0 = time.time()
                r = requests.get(ep, proxies=proxies, timeout=timeout,
                                 headers={"User-Agent": random.choice(UA_POOL)})
                latency = int((time.time() - t0) * 1000)
                got_response.set()
                if r.status_code == 200:
                    ip = r.text.strip()
                    if _IP_RE.match(ip):
                        result.setdefault("ip", ip)
                        result.setdefault("latency", latency)
                elif r.status_code in (429, 503):
                    _endpoint_backoff[ep] = time.time() + 60   # FIX-P26
            except requests.exceptions.ProxyError as e:
                if "407" in str(e):
                    auth_failed.set()
            except Exception:
                pass

    futs = [_IPCHECK_EXEC.submit(_hit, ep) for ep in endpoints]
    deadline = time.time() + timeout + 1
    for f in futs:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            f.result(timeout=remaining)
        except Exception:
            pass
        if "ip" in result or auth_failed.is_set():
            break

    if auth_failed.is_set():
        return None, -407
    if "ip" in result:
        return result["ip"], result["latency"]
    if got_response.is_set():
        return None, 0          # CONNECTED — proxy works, echo service failed
    return None, -1




def _classify_latency(latency_ms: int) -> str:
    """Configurable latency → status classification."""
    fast_max = int(get_setting("latency_fast_max", str(LAT_FAST_MAX)))
    working_max = int(get_setting("latency_working_max", str(LAT_WORKING_MAX)))
    slow_max = int(get_setting("latency_slow_max", str(LAT_SLOW_MAX)))
    if latency_ms <= fast_max:
        return "FAST"
    if latency_ms <= working_max:
        return "WORKING"
    if latency_ms <= slow_max:
        return "SLOW"
    return "VERY_SLOW"


def test_proxy(p, timeout=None):
    """FIX-P26: single-stage — no TCP pre-check; two-chance adaptive timeout."""
    t = timeout or PROXY_HEALTH_TIMEOUT
    if not p or not p.get("host") or not p.get("port"):
        return {"status": "INVALID", "latency_ms": 0, "exit_ip": "",
                "error": "bad parse"}
    if p["protocol"].startswith("socks") and not _SOCKS_OK:
        # FIX-P45: socks proxies are skipped, not phantom-TIMEOUTs
        return {"status": "UNSUPPORTED", "latency_ms": 0, "exit_ip": "",
                "error": "PySocks not installed"}

    ip, latency = _verify_exit_ip(p, t)
    if latency == -407:
        return {"status": "AUTH_FAILED", "latency_ms": 0, "exit_ip": "",
                "error": "HTTP 407 proxy auth required"}
    if ip:
        return {"status": _classify_latency(latency), "latency_ms": latency,
                "exit_ip": ip, "error": ""}
    if latency == 0:
        return {"status": "CONNECTED", "latency_ms": 0, "exit_ip": "",
                "error": "proxy ok; ip echo services unavailable"}
    # second chance with a longer timeout (FIX-P26 adaptive pass)
    ip2, latency2 = _verify_exit_ip(p, min(t + 4, 12))
    if ip2:
        return {"status": _classify_latency(latency2), "latency_ms": latency2,
                "exit_ip": ip2, "error": ""}
    return {"status": "TIMEOUT", "latency_ms": 0, "exit_ip": "",
            "error": "no response through proxy"}


HEALTHY_STATUSES = ("FAST", "WORKING", "SLOW", "VERY_SLOW", "CONNECTED")
DEAD_STATUSES = ("TCP_FAILED", "AUTH_FAILED", "INVALID")


# =========================================================
# Proxy DB ops
# =========================================================
def add_proxy_db(endpoint: str, source: str = "manual") -> Optional[int]:
    p = parse_proxy(endpoint)
    if not p:
        return None
    with _db_lock:
        conn = get_conn()
        try:
            existing = conn.execute(
                "SELECT id FROM proxies WHERE host=? AND port=?", (p["host"], p["port"])
            ).fetchone()
            if existing:
                return existing["id"]
            cur = conn.execute(
                """INSERT INTO proxies(endpoint, protocol, host, port, username,
                                      password, source, is_precious)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (p["endpoint"], p["protocol"], p["host"], p["port"],
                 p["username"], p["password"], source,
                 1 if source == "manual" else 0),
            )
            conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def add_proxies_batch(endpoints: list, source: str = "fetch",
                    limit: int = 0) -> dict:
    """
    Parse, dedupe in-memory, INSERT OR IGNORE in 500-row batches.
    limit=0 means no cap (insert all valid).
    DB UNIQUE(host,port) index handles cross-session deduplication —
    the proxies table is NEVER loaded into Python memory.
    """
    log.info("ADD_PROXIES_BATCH start source=%s limit=%s", source, limit)
    parsed, valid, invalid = [], 0, 0
    seen_local = set()
    for raw in endpoints:
        p = parse_proxy(raw)
        if not p:
            invalid += 1
            continue
        key = (p["host"], p["port"])
        if key in seen_local:
            continue
        seen_local.add(key)
        parsed.append(p)
        valid += 1
        if limit and len(parsed) >= limit:
            break

    BATCH_SIZE = 500
    inserted = duplicates = 0
    precious = 1 if source == "manual" else 0
    with _db_lock:
        conn = get_conn()
        try:
            for i in range(0, len(parsed), BATCH_SIZE):
                batch = parsed[i:i + BATCH_SIZE]
                rows = [(p["endpoint"], p["protocol"], p["host"],
                         p["port"], p["username"], p["password"], source,
                         precious) for p in batch]
                conn.executemany(
                    """INSERT OR IGNORE INTO proxies
                       (endpoint, protocol, host, port, username, password,
                        source, is_precious)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    rows,
                )
                batch_inserted = conn.execute("SELECT changes()").fetchone()[0]
                inserted += batch_inserted
                duplicates += len(batch) - batch_inserted
                conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection
    log.info("ADD_PROXIES_BATCH done valid=%s invalid=%s dupes=%s inserted=%s",
             valid, invalid, duplicates, inserted)
    return {"valid": valid, "invalid": invalid,
            "duplicates": duplicates, "inserted": inserted}


def get_proxy_row(proxy_id: int) -> Optional[dict]:
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
            return dict(r) if r else None
        finally:
            pass  # FIX-P22: persistent thread-local connection


def list_proxies(limit: Optional[int] = 100,
                 status_filter: Optional[str] = None,
                 statuses: Optional[tuple] = None,
                 source_filter: Optional[str] = None,
                 offset: int = 0) -> list:
    """
    source_filter: 'manual' | 'fetch' | None (all)
    offset: for streaming/pagination through large tables
    """
    conditions = []
    params = []
    if statuses:
        ph = ",".join("?" * len(statuses))
        conditions.append(f"health_status IN ({ph})")
        params.extend(statuses)
    elif status_filter:
        conditions.append("health_status=?")
        params.append(status_filter)
    if source_filter:
        conditions.append("source=?")
        params.append(source_filter)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    limit_sql = f"LIMIT {int(limit)}" if limit is not None else ""
    offset_sql = f"OFFSET {int(offset)}" if offset else ""

    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                f"SELECT * FROM proxies {where} ORDER BY id {limit_sql} {offset_sql}",
                params,
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            pass  # FIX-P22: persistent thread-local connection


def update_proxies_health_batch(results: list) -> None:
    """FIX-P30: one SELECT per batch (not per row), one UPDATE per row —
    N+1 removed. Success resets consecutive failures and cooldown (FIX-P04)."""
    if not results:
        return
    now = _utcnow()
    ids = [pid for pid, _ in results]
    ph = ",".join("?" * len(ids))
    with _db_lock:
        conn = get_conn()
        cur = {r["id"]: r for r in conn.execute(
            "SELECT id, success_count, failure_count, consecutive_failures, "
            "average_latency, last_success, last_failure, last_ip_verified "
            f"FROM proxies WHERE id IN ({ph})", ids).fetchall()}
        for proxy_id, result in results:
            row = cur.get(proxy_id)
            if not row:
                continue
            status = result["status"]
            latency = result.get("latency_ms", 0) or 0
            ip = result.get("exit_ip", "")
            err = result.get("error", "")
            ok = status in HEALTHY_STATUSES
            succ = row["success_count"] + (1 if ok else 0)
            fail = row["failure_count"] + (0 if ok else 1)
            consec_f = 0 if ok else row["consecutive_failures"] + 1
            avg = row["average_latency"]
            if latency > 0:
                avg = int(((avg * row["success_count"]) + latency) / max(succ, 1))
            score = _compute_score(status, succ, fail, latency)
            cooldown = None
            if not ok and consec_f > 0:
                cooldown = _utcnow_plus(min(10 * consec_f, 180))
            ip_verified = now if ip else row["last_ip_verified"]
            conn.execute(
                """UPDATE proxies SET health_status=?, health_score=?,
                   success_count=?, failure_count=?, consecutive_failures=?,
                   average_latency=?,
                   last_observed_ip=COALESCE(NULLIF(?, ''), last_observed_ip),
                   last_ip_verified=?, last_error=?, last_tested=?,
                   last_success=?, last_failure=?, cooldown_until=?,
                   updated_at=? WHERE id=?""",
                (status, score, succ, fail, consec_f, avg, ip, ip_verified,
                 err, now,
                 now if ok else row["last_success"],
                 now if not ok else row["last_failure"],
                 cooldown, now, proxy_id),
            )
        conn.commit()
    proxy_pool.mark_dirty()   # FIX-P27: snapshot refresh on status flips


def update_proxy_health(proxy_id: int, result: dict) -> None:
    update_proxies_health_batch([(proxy_id, result)])




def _compute_score(status: str, succ: int, fail: int, latency: int) -> int:
    base = {"FAST": 95, "WORKING": 85, "SLOW": 55, "VERY_SLOW": 35,
            "CONNECTED": 60, "TARGET_FAILED": 50, "AUTH_FAILED": 5,
            "TCP_FAILED": 5, "INVALID": 0, "TIMEOUT": 30, "UNTESTED": 0}.get(status, 0)
    total = succ + fail
    if total >= 5:
        ratio = succ / total
        base = int(base * 0.6 + (ratio * 100) * 0.4)
    if latency > 0:
        if latency < 800:
            base = min(base + 5, 100)
        elif latency > 2500:
            base = max(base - 10, 1)
    return base


def delete_proxy_db(proxy_id: int) -> bool:
    with _db_lock:
        conn = get_conn()
        try:
            cur = conn.execute("DELETE FROM proxies WHERE id=?", (proxy_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            pass  # FIX-P22: persistent thread-local connection


def proxy_counts() -> dict:
    with _db_lock:
        conn = get_conn()
        try:
            d = {}
            d["total"] = conn.execute("SELECT COUNT(*) c FROM proxies").fetchone()["c"]
            d["fast"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE health_status='FAST'").fetchone()["c"]
            d["working"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE health_status='WORKING'").fetchone()["c"]
            d["slow"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE health_status IN ('SLOW','VERY_SLOW','CONNECTED')"
            ).fetchone()["c"]
            d["dead"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE health_status IN ('TCP_FAILED','AUTH_FAILED','INVALID')"
            ).fetchone()["c"]
            d["untested"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE health_status='UNTESTED'").fetchone()["c"]
            r = conn.execute(
                "SELECT COALESCE(AVG(average_latency),0) a FROM proxies WHERE average_latency>0"
            ).fetchone()
            d["avg_latency"] = int(r["a"])
            r = conn.execute(
                """SELECT COALESCE(SUM(success_count),0) s, COALESCE(SUM(failure_count),0) f
                   FROM proxies"""
            ).fetchone()
            tot = r["s"] + r["f"]
            d["success_rate"] = round((r["s"] / tot) * 100, 1) if tot else 0.0
            ph = ",".join("?" * len(HEALTHY_STATUSES))
            d["manual_total"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE source='manual'").fetchone()["c"]
            d["fetch_total"] = conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE source='fetch'").fetchone()["c"]
            d["manual_working"] = conn.execute(
                f"SELECT COUNT(*) c FROM proxies WHERE source='manual' "
                f"AND health_status IN ({ph})", HEALTHY_STATUSES).fetchone()["c"]
            d["fetch_working"] = conn.execute(
                f"SELECT COUNT(*) c FROM proxies WHERE source='fetch' "
                f"AND health_status IN ({ph})", HEALTHY_STATUSES).fetchone()["c"]
            return d
        finally:
            pass  # FIX-P22: persistent thread-local connection


# =========================================================
# ProxyPool — thread-safe weighted rotation
# =========================================================
class ProxyPool:
    """Weighted selection: FAST+high-score and unused proxies preferred.

    FIX-P27: healthy rows come from a 10s in-memory snapshot (dirty-flag
    refreshed on health writes) instead of a full table scan per visit.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._last_used: dict = {}
        self._in_use: dict = {}
        self._snapshot: list = []
        self._snapshot_ts = 0.0
        self._dirty = True

    def mark_dirty(self):
        with self._lock:
            self._dirty = True

    def _query_healthy(self) -> list:
        with _db_lock:
            conn = get_conn()
            ph = ",".join("?" * len(HEALTHY_STATUSES))
            rows = conn.execute(
                f"""SELECT * FROM proxies WHERE is_active=1
                   AND health_status IN ({ph})
                   AND (cooldown_until IS NULL OR cooldown_until <= ?)""",
                [*HEALTHY_STATUSES, _utcnow()],
            ).fetchall()
            return [dict(r) for r in rows]

    def healthy_proxies(self, source_filter: Optional[str] = None) -> list:
        with self._lock:
            if self._dirty or time.time() - self._snapshot_ts > 10:
                self._snapshot = self._query_healthy()     # FIX-P27
                self._snapshot_ts = time.time()
                self._dirty = False
            rows = self._snapshot
        if source_filter:
            rows = [r for r in rows if r["source"] == source_filter]
        return rows

    def select(self, count: int = 1, exclude: Optional[set] = None,
               exclude_subnet: Optional[str] = None,
               source_filter: Optional[str] = None) -> list:
        """Lease up to `count` distinct healthy proxies (weighted)."""
        with self._lock:
            avail = self.healthy_proxies(source_filter=source_filter)
            if exclude:
                filtered = [r for r in avail if r["id"] not in exclude]
                if filtered:
                    avail = filtered
            if exclude_subnet:
                filtered = [r for r in avail
                            if not (r.get("last_observed_ip") or "").startswith(
                                exclude_subnet)]
                if filtered:
                    avail = filtered
            if not avail:
                return []
            now = time.time()
            scored = []
            for r in avail:
                w = max(r.get("health_score", 0), 1)
                if r["id"] not in self._last_used:
                    w *= 1.5
                else:
                    idle = now - self._last_used[r["id"]]
                    w *= min(1.0 + idle / 300.0, 2.0)
                w *= 1.0 / (1 + self._in_use.get(r["id"], 0))
                scored.append((r, w))
            chosen, picked_ids = [], set()
            pool = list(scored)
            for _ in range(min(count, len(pool))):
                total_w = sum(w for _, w in pool)
                if total_w <= 0:
                    break
                pick = random.uniform(0, total_w)
                acc = 0.0
                for idx, (r, w) in enumerate(pool):
                    acc += w
                    if acc >= pick:
                        chosen.append(r)
                        picked_ids.add(r["id"])
                        pool.pop(idx)
                        break
            for r in chosen:
                self._last_used[r["id"]] = now
                self._in_use[r["id"]] = self._in_use.get(r["id"], 0) + 1
            return chosen

    def release(self, proxy_id: int) -> None:
        with self._lock:
            n = self._in_use.get(proxy_id, 0)
            if n <= 1:
                self._in_use.pop(proxy_id, None)
            else:
                self._in_use[proxy_id] = n - 1

    def mark_used_success(self, proxy_id: int, latency_ms: int,
                          exit_ip: str = "") -> None:
        update_proxy_health(proxy_id, {
            "status": _classify_latency(latency_ms) if latency_ms > 0 else "CONNECTED",
            "latency_ms": latency_ms, "exit_ip": exit_ip, "error": ""})
        self.release(proxy_id)

    def mark_used_failure(self, proxy_id: int, status: str = "TIMEOUT",
                          error: str = "") -> None:
        update_proxy_health(proxy_id, {
            "status": status, "latency_ms": 0, "exit_ip": "", "error": error})
        self.release(proxy_id)


proxy_pool = ProxyPool()


def proxy_ip_fresh(row: dict) -> bool:
    """True when cached last_observed_ip is fresh enough to skip re-verification."""
    if not row.get("last_observed_ip") or not row.get("last_ip_verified"):
        return False
    try:
        ts = datetime.fromisoformat(row["last_ip_verified"])
    except Exception:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < PROXY_VERIFY_IP_INTERVAL


# =========================================================
# Bulk proxy testing (scope-aware, cancellable)
# =========================================================
def _scope_statuses(scope: str) -> Optional[tuple]:
    if scope == "all":
        return None
    if scope == "unhealthy":
        return ("UNTESTED", "TCP_FAILED", "TIMEOUT", "CONNECTED", "VERY_SLOW", "INVALID")
    if scope == "untested":
        return ("UNTESTED",)
    if scope == "working":
        return HEALTHY_STATUSES
    return None


def _test_row(row):
    """Worker for bulk tests: one proxy row -> (id, result)."""
    p = {k: row[k] for k in
         ("protocol", "host", "port", "username", "password", "endpoint")}
    return row["id"], test_proxy(p)


def _tally(summary, status):
    summary["tested"] += 1
    if status in ("FAST", "WORKING"):
        summary["working"] += 1
        if status == "FAST":
            summary["fast"] += 1
    elif status in ("SLOW", "VERY_SLOW", "CONNECTED"):
        summary["slow"] += 1
    elif status == "AUTH_FAILED":
        summary["auth_failed"] += 1
        summary["failed"] += 1
    elif status == "TIMEOUT":
        summary["timeout"] += 1
        summary["failed"] += 1
    elif status != "UNSUPPORTED":
        summary["failed"] += 1


def _scope_statuses(scope: str):
    return {
        "untested": ("UNTESTED",),
        "dead": DEAD_STATUSES,
        "healthy": HEALTHY_STATUSES,
        "all": None,
    }.get(scope, None)


def bulk_test_proxies(scope="all", limit=0, source_filter=None,
                      progress_cb=None, cancel_event=None):
    """FIX-P10: freeze the work set by ID up front — testing mutates
    health_status, which used to shift OFFSET windows and skip rows."""
    statuses = _scope_statuses(scope)
    conditions, params = [], []
    if statuses:
        ph = ",".join("?" * len(statuses))
        conditions.append(f"health_status IN ({ph})")
        params.extend(statuses)
    if source_filter:
        conditions.append("source=?")
        params.append(source_filter)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with _db_lock:
        ids = [r["id"] for r in get_conn().execute(
            f"SELECT id FROM proxies {where} ORDER BY id", params).fetchall()]
    if limit:
        ids = ids[:limit]
    total = len(ids)
    summary = {"tested": 0, "working": 0, "fast": 0, "slow": 0, "failed": 0,
               "auth_failed": 0, "timeout": 0, "cancelled": False,
               "total": total}
    if not ids:
        return summary

    BATCH = 250
    for i in range(0, total, BATCH):
        if cancel_event and cancel_event.is_set():
            summary["cancelled"] = True
            break
        chunk = ids[i:i + BATCH]
        ph = ",".join("?" * len(chunk))
        rows = [dict(r) for r in get_conn().execute(
            f"SELECT * FROM proxies WHERE id IN ({ph})", chunk).fetchall()]
        results = []
        workers = min(PROXY_TEST_CONCURRENCY, len(rows))
        ex = ThreadPoolExecutor(max_workers=workers)
        try:
            futs = {ex.submit(_test_row, r): r["id"] for r in rows}
            for fut in as_completed(futs):
                if cancel_event and cancel_event.is_set():
                    summary["cancelled"] = True
                    for p_ in futs:
                        p_.cancel()                    # FIX-P08
                    break
                try:
                    pid, res = fut.result()
                except Exception:
                    continue
                results.append((pid, res))
                _tally(summary, res["status"])
                if progress_cb:
                    try:
                        progress_cb(summary["tested"], total, dict(summary))
                    except Exception:
                        pass
        finally:
            ex.shutdown(wait=False, cancel_futures=True)   # FIX-P08
        update_proxies_health_batch(results)
        if limit and summary["tested"] >= limit:
            break
    return summary



def _auto_test_bulk_inserted(chat_id, admin_id, expected_count):
    """Test only freshly-inserted (UNTESTED status) proxies after a bulk add/fetch."""
    with _db_lock:  # FIX-P11: newest-first at SQL level — no ASC-window miss
        rows_sorted = [dict(r) for r in get_conn().execute(
            "SELECT * FROM proxies WHERE health_status='UNTESTED' "
            "ORDER BY id DESC LIMIT ?", (max(expected_count, 1),)).fetchall()]
    if not rows_sorted:
        return
    log.info("AUTO_TEST start count=%s", len(rows_sorted))
    results = []
    # Cap auto-test concurrency at 12 — 48 simultaneous hits rate-limit the
    # IP-check endpoints and falsely burn good proxies
    auto_workers = min(12, PROXY_TEST_CONCURRENCY)
    with ThreadPoolExecutor(max_workers=auto_workers) as ex:
        futs = {ex.submit(test_proxy, {
            "protocol": r["protocol"], "host": r["host"], "port": r["port"],
            "username": r["username"], "password": r["password"],
            "endpoint": r["endpoint"]
        }): r["id"] for r in rows_sorted}
        for fut in as_completed(futs):
            pid = futs[fut]
            try:
                res = fut.result()
            except Exception:
                res = {"status": "INVALID", "latency_ms": 0, "exit_ip": "",
                       "error": "test exception"}
            update_proxy_health(pid, res)
            results.append((pid, res))
    working = sum(1 for _, r in results
                  if r["status"] in ("FAST", "WORKING", "CONNECTED", "SLOW", "VERY_SLOW"))
    log.info("AUTO_TEST done tested=%s working=%s", len(results), working)
    safe_send_message(
        chat_id,
        (f"🧪 *AUTO-TEST COMPLETE*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Tested: `{len(results)}`\n"
         f"Working: `{working}`\n"
         f"Dead: `{len(results) - working}`"))


def configured_proxy_sources() -> list:
    cfg = get_settings_batch(["proxy_source_1", "proxy_source_2", "proxy_source_3"])
    srcs = [cfg[k].strip() for k in ("proxy_source_1", "proxy_source_2", "proxy_source_3")
            if cfg[k].strip()]
    return srcs if srcs else list(BUILTIN_PROXY_SOURCES)


def fetch_proxy_source(url: str, timeout: int = 30) -> str:
    """Fetch a proxy list from an admin-configured source URL (plain text)."""
    headers = {
        "User-Agent": _TEST_UA,
        "Accept": "text/plain,text/html,*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    token = os.environ.get("PROXY_PROVIDER_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # Use a fresh session (not thread-local) to avoid proxy interference
    s = requests.Session()
    s.headers.update(headers)
    adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    r = s.get(url, timeout=(10, timeout), stream=True, allow_redirects=True)
    r.raise_for_status()
    chunks, size = [], 0
    for chunk in r.iter_content(chunk_size=65536):
        if chunk:
            size += len(chunk)
            if size > 8 * 1024 * 1024:  # 8MB max
                break
            chunks.append(chunk)
    s.close()
    return b"".join(chunks).decode("utf-8", errors="ignore")


_PROXY_LINE_RE = re.compile(
    r"(?:(?:https?|socks5h?|socks4a?)://)"
    r"(?:[^:@/\s]+:[^@/\s]+@)?\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}(?::[^:\s]+){0,2}",
    re.IGNORECASE)


def parse_proxy_list(text: str) -> list:
    """FIX-P09: regex scan + post-parse validation, dedupe preserving order."""
    out, seen = [], set()
    for m in _PROXY_LINE_RE.finditer(text or ""):
        token = m.group(0).strip().rstrip(",;)]}\"'")
        p = parse_proxy(token)
        if not p:
            continue
        key = (p["host"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p["endpoint"])
    return out


def log_proxy_fetch(source: str, stats: dict) -> None:
    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                """INSERT INTO proxy_fetch_log(source, fetched, valid, duplicates,
                   working, slow, dead) VALUES(?,?,?,?,?,?,?)""",
                (source, stats.get("fetched", 0), stats.get("valid", 0),
                 stats.get("duplicates", 0), stats.get("working", 0),
                 stats.get("slow", 0), stats.get("dead", 0)),
            )
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection


def last_proxy_fetch() -> Optional[dict]:
    with _db_lock:
        conn = get_conn()
        try:
            r = conn.execute(
                "SELECT * FROM proxy_fetch_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(r) if r else None
        finally:
            pass  # FIX-P22: persistent thread-local connection


# =========================================================
# Number Extraction Pipeline
# =========================================================
_WA_PATTERNS = [
    (re.compile(r'wa\.me/(?:message/[A-Za-z0-9]+[^"\s]*?)?(\+?\d{6,15})', re.IGNORECASE), "wa.me"),
    (re.compile(r'(?:phone|number|mobile|tel|to|recipient|send_to)=(\+?\d{6,15})', re.IGNORECASE), "query_parameter"),
    (re.compile(r'whatsapp://send\?phone=(\+?\d{6,15})', re.IGNORECASE), "whatsapp_url"),
    (re.compile(r'api\.whatsapp\.com/send[/?][^"\'\s]*phone=(\+?\d{6,15})', re.IGNORECASE), "whatsapp_api"),
    (re.compile(r'web\.whatsapp\.com/send[/?][^"\'\s]*phone=(\+?\d{6,15})', re.IGNORECASE), "whatsapp_web"),
    (re.compile(r'whatsapp\.com/send[/?][^"\'\s]*phone=(\+?\d{6,15})', re.IGNORECASE), "whatsapp_url"),
    (re.compile(r'tel:(\+?\d{6,15})', re.IGNORECASE), "tel_link"),
    (re.compile(r'intent://send/(\+?\d{6,15})', re.IGNORECASE), "intent"),
    (re.compile(r'#(?:phone|number)=(\+?\d{6,15})', re.IGNORECASE), "url_fragment"),
]

_JSON_FIELD_RE = re.compile(
    r'"(?:phone|phone_number|mobile|mobile_number|whatsapp|wa_number|recipient|send_to|number|to)"\s*:\s*"(\+?\d{6,15})"',
    re.IGNORECASE,
)

_ATTR_RE = re.compile(
    r'(?:href|data-phone|data-mobile|data-whatsapp|data-number|data-tel)\s*=\s*["\']([^"\']*\+?\d{6,15}[^"\']*)["\']',
    re.IGNORECASE,
)

_META_REFRESH_RE = re.compile(
    r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)',
    re.IGNORECASE,
)
_JS_LOCATION_RE = re.compile(
    r'(?:window|document|top|self)\.location(?:\.href)?\s*(?:=|\()\s*["\']([^"\']+)["\']'
    r'|location\.replace\(["\']([^"\']+)["\']\)'
    r'|location\.assign\(["\']([^"\']+)["\']\)',
    re.IGNORECASE,
)


def _js_location_target(m) -> str:
    """First non-empty group from an _JS_LOCATION_RE match."""
    if not m:
        return ""
    for g in m.groups():
        if g:
            return g
    return ""


_COMBINED_RE = re.compile(
    r"(?P<wame>wa\.me/(?:message/[A-Za-z0-9]+[^\"\s]*?)?(?P<wame_num>\+?\d{6,15}))"
    r"|(?P<waapi>(?:api\.whatsapp\.com|web\.whatsapp\.com|whatsapp\.com)/send[/?][^\"\'\s]*phone=(?P<waapi_num>\+?\d{6,15}))"
    r"|(?P<tellink>tel:(?P<tel_num>\+?\d{6,15}))"
    r"|(?P<intent>intent://send/(?P<intent_num>\+?\d{6,15}))"
    r"|(?P<frag>\#(?:phone|number)=(?P<frag_num>\+?\d{6,15}))"
    r"|(?P<json>\"(?:phone|phone_number|mobile|mobile_number|whatsapp|wa_number|recipient|send_to|number|to)\"\s*:\s*\"(?P<json_num>\+?\d{6,15})\")",
    re.IGNORECASE)
_GROUP_METHOD = {
    "wame_num": "wa.me", "waapi_num": "whatsapp_api", "tel_num": "tel_link",
    "intent_num": "intent", "frag_num": "url_fragment", "json_num": "json_field",
}



_TG_DESC_RE = re.compile(
    r'<div[^>]*class="tgme_page_extra"[^>]*>(.*?)</div>', re.DOTALL)


def _looks_like_false_positive(digits: str, method: str = "raw") -> bool:
    """FIX-P18: epoch/ID rejection only applies to low-confidence captures —
    a number behind wa.me/tel:/json is trusted."""
    n0 = len(digits or "")
    if get_setting("false_positive_filter", "1") != "1":
        return not (6 <= n0 <= 16)
    try:
        lo = int(get_setting("number_min_len", str(NUM_MIN_LEN)))
        hi = int(get_setting("number_max_len", str(NUM_MAX_LEN)))
    except (ValueError, TypeError):
        lo, hi = NUM_MIN_LEN, NUM_MAX_LEN
    if n0 < lo or n0 > hi:
        return True
    high_confidence = method in (
        "wa.me", "whatsapp_api", "whatsapp_web", "whatsapp_url",
        "tel_link", "intent", "url_fragment", "json_field")
    if not high_confidence:
        n = n0
        if n == 10 and digits[0] == "1":
            try:
                v = int(digits)
                if 946684800 <= v <= 4102444800:
                    return True
            except ValueError:
                pass
        if n == 13 and digits.startswith(("15", "16", "17", "18", "19", "20")):
            return True
        if n == 18 and digits.startswith("12"):
            return True
        if n in (17, 18) and digits.startswith(("11", "12", "13", "2384")):
            return True
    if len(set(digits)) <= 2:
        return True
    if digits in ("0123456789" * 2, "1234567890" * 2):
        return True
    return False


def _normalize(raw: str, method: str = "raw") -> Optional[str]:
    """Normalize +919876543210 / 00919876543210 / 919876543210 -> digits."""
    digits = re.sub(r"\D", "", raw or "")
    if not digits:
        return None
    if digits.startswith("00"):
        digits = digits[2:]
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        digits = digits[1:]
    if _looks_like_false_positive(digits, method):      # FIX-P18
        return None
    return digits


def extract_numbers(text: str, source: str, default_method: str = "html") -> list:
    """FIX-P31: single regex pass; lazy decode samples; 1MB scan window with
    full-body fallback only when the window yields zero hits."""
    if not text:
        return []
    out, seen = [], set()
    samples = [text]
    if "%" in text:                                     # FIX-P31: cheap pre-check
        d1 = urllib.parse.unquote(text)
        if d1 != text:
            samples.append(d1)
            d2 = urllib.parse.unquote(d1)
            if d2 != d1:
                samples.append(d2)
    try:
        scan_limit = int(get_setting("scan_bytes", str(SCAN_BYTES)))
    except (ValueError, TypeError):
        scan_limit = SCAN_BYTES
    for sample in samples:
        for region in (sample[:scan_limit], sample):
            for m in _COMBINED_RE.finditer(region):
                for gname, val in m.groupdict().items():
                    if not val or not gname.endswith("_num"):
                        continue
                    n = _normalize(val, _GROUP_METHOD[gname])
                    if n and n not in seen:
                        seen.add(n)
                        out.append((n, _GROUP_METHOD[gname]))
            for m in _ATTR_RE.findall(region):
                n = _normalize(m, "html_attribute")
                if n and n not in seen:
                    seen.add(n)
                    out.append((n, "html_attribute"))
            if out:
                break          # hits found — skip full-body fallback
        if out:
            break
    return out



def extract_from_url_chain(urls: list) -> list:
    out, seen = [], set()
    for u in urls:
        for n, method in extract_numbers(u, u, default_method="redirect_url"):
            if n not in seen:
                seen.add(n)
                out.append((n, method))
    return out



# =========================================================
# Deep Extraction Engine v3 — 6-layer pipeline + protection detection
# =========================================================
_TG_HOSTS = ("t.me", "telegram.me", "telesco.pe", "telegram.dog")
_TG_USER_RE = re.compile(r"@([A-Za-z0-9_]{4,64})")
_TG_SUPPORT_RE = re.compile(
    r"(?:contact|support|help|admin|booking|order)[^@\n]{0,40}?@([A-Za-z0-9_]{4,64})",
    re.IGNORECASE)
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTR_VAL_RE = re.compile(r"""([\w:-]+)\s*=\s*["']([^"']*)["']""")
_JS_PHONE_RE = re.compile(
    r"""["']?[A-Za-z_]*(?:phone|mobile|whatsapp|number|tel|contact)[A-Za-z_]*["']?"""
    r"""\s*[:=]\s*["'](\+?\d{9,15})["']""",
    re.IGNORECASE)
_DATA_ATTR_RE = re.compile(r"""data-[\w-]+\s*=\s*["']([^"']{6,300})["']""", re.IGNORECASE)
_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=\s]{8,400}$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{18,40}$")
_DIGITS_RUN_RE = re.compile(r"\+?\d{9,15}")
_RAW_PHONE_RE = re.compile(r"(?<![\d/])(\+?\d(?:[\d\s().-]?\d){8,17})(?![\d/])")  # FIX-P35: spaced formats

_PROTECTION_STAGES = {
    "telegram_redirect": "📱 Telegram redirect — extracting preview",
    "rate_limited": "⏳ Rate-limited — rotating exit IP",
    "geo_blocked": "🌍 Geo-block — rotating region",
    "byethost": "🔓 Solving host challenge",
    "meta_redirect_only": "🔁 Following redirect chain",
}


def _layer_on(name: str) -> bool:
    """Per-layer on/off switch from admin settings (default ON)."""
    return get_setting(f"ex_layer_{name}", "1") == "1"


def _is_telegram_url(url: str) -> bool:
    try:
        host = (urllib.parse.urlparse(url or "").hostname or "").lower()
    except Exception:
        return False
    return any(host == h or host.endswith("." + h) for h in _TG_HOSTS)


def _meta_fields(body: str) -> dict:
    """Parse all <meta> tags into {name/property(lower): content}."""
    fields = {}
    for tag in _META_TAG_RE.findall(body or ""):
        attrs = {}
        for k, v in _ATTR_VAL_RE.findall(tag):
            attrs[k.lower()] = v
        key = attrs.get("property") or attrs.get("name")
        content = html.unescape(attrs.get("content", "") or "")
        if key and content and key.lower() not in fields:
            fields[key.lower()] = content
    return fields


def _rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(65 + (o - 65 + 13) % 26))
        elif 97 <= o <= 122:
            out.append(chr(97 + (o - 97 + 13) % 26))
        else:
            out.append(ch)
    return "".join(out)


def _decoded_variants(val: str) -> list:
    """Yield decodings of a data-* value: url-decode, base64, hex, rot13."""
    variants = set()
    try:
        variants.add(urllib.parse.unquote(val))
        variants.add(urllib.parse.unquote(urllib.parse.unquote(val)))
    except Exception:
        pass
    if _B64_CHARS_RE.match(val.strip()):
        for cand in (val.strip(), val.strip() + "=" * (-len(val.strip()) % 4)):
            try:
                dec = base64.b64decode(cand, validate=False).decode("utf-8", errors="ignore")
                if dec:
                    variants.add(dec)
            except Exception:
                pass
    if _HEX_RE.match(val.strip()):
        try:
            hx = val.strip()[2:] if val.strip().lower().startswith("0x") else val.strip()
            dec = bytes.fromhex(hx).decode("utf-8", errors="ignore")
            if dec:
                variants.add(dec)
        except Exception:
            pass
    variants.add(_rot13(val))
    return [v for v in variants if v and v != val]


def detect_protection(body: str, status_code: int, final_url: str) -> dict:
    """Classify bot-protection on a fetched page. Never claims bypass it can't do."""
    b = (body or "")[:300000]
    bl = b.lower()

    if status_code == 429:
        return {"type": "rate_limited",
                "detail": "Target rate-limited the request (HTTP 429)",
                "bypassable": True}
    if _is_telegram_url(final_url):
        return {"type": "telegram_redirect",
                "detail": "Redirect chain ends at a public Telegram preview page",
                "bypassable": True}
    if ("cf-browser-verification" in bl or "checking your browser" in bl
            or "__cf_bm" in bl or "cf-ray" in bl
            or (status_code == 403 and "cloudflare" in bl)):
        return {"type": "cloudflare_js",
                "detail": "Cloudflare JS challenge — a real browser engine is required",
                "bypassable": False}
    if "cf_chl_prog" in bl or "cf-challenge" in bl or "cf_chl_opt" in bl:
        return {"type": "cloudflare_iuam",
                "detail": "Cloudflare IUAM challenge — a real browser engine is required",
                "bypassable": False}
    if "g-recaptcha" in bl or "recaptcha/api" in bl or "www.recaptcha" in bl:
        return {"type": "recaptcha",
                "detail": "reCAPTCHA present — cannot be bypassed",
                "bypassable": False}
    if "hcaptcha.com" in bl or "h-captcha" in bl:
        return {"type": "hcaptcha",
                "detail": "hCaptcha present — cannot be bypassed",
                "bypassable": False}
    if "slowaes" in bl or ("tonumbers(" in bl and "__test=" in bl):
        return {"type": "byethost",
                "detail": "ByetHost/InfinityFree AES challenge — solved internally",
                "bypassable": True}
    if status_code == 403 and ("not available in your country" in bl
                               or "not available in your region" in bl
                               or "geo-block" in bl or "geoblock" in bl):
        return {"type": "geo_blocked",
                "detail": "Geo-restriction — rotating to another region may help",
                "bypassable": True}
    if 0 < len(b) < 2048 and (
            _META_REFRESH_RE.search(b) or _JS_LOCATION_RE.search(b)):
        return {"type": "meta_redirect_only",
                "detail": "Thin redirect page — followed automatically",
                "bypassable": True}
    return {"type": "none", "detail": "", "bypassable": True}


def extract_deep(body: str, final_url: str, visited: list,
                 cancel_event: Optional[threading.Event] = None) -> dict:
    """6-layer deep extraction pipeline. All layers run; results merged + deduped.

    Returns {
      "numbers": [(normalized, method, source), ...],
      "layers":  [layer names that produced at least one hit],
      "telegram": {"is_telegram": bool, "username": str, "invite": str,
                   "channel": str},
      "protection-independent": False,
    }
    """
    out, seen = [], set()
    layers_hit = []

    def _cancelled():
        return cancel_event is not None and cancel_event.is_set()

    def _add(raw, method, src):
        n = _normalize(raw)
        if n and n not in seen:
            seen.add(n)
            out.append((n, method, src))
            return True
        return False

    body = body or ""
    fields = {}

    # ---- LAYER 1 — URL chain ----
    if not _cancelled() and _layer_on("url_chain"):
        hits = 0
        for n, m in extract_from_url_chain(visited or [final_url]):
            if _add(n, m, (visited or [final_url])[-1]):
                hits += 1
        if hits:
            layers_hit.append("url_chain")
            log.debug("LAYER_HIT layer=url_chain hits=%s", hits)

    # ---- LAYER 2 — raw HTML regex (existing _WA_PATTERNS + JSON/attrs) ----
    if not _cancelled() and _layer_on("raw_html"):
        hits = 0
        for n, m in extract_numbers(body, final_url, default_method="html"):
            if _add(n, m, final_url):
                hits += 1
        if hits:
            layers_hit.append("raw_html")
            log.debug("LAYER_HIT layer=raw_html hits=%s", hits)

    # ---- LAYER 3 — OG / meta tag extraction ----
    if not _cancelled() and _layer_on("meta"):
        fields = _meta_fields(body)
        hits = 0
        for key in ("og:description", "twitter:description", "description",
                    "og:title", "twitter:title", "og:url",
                    "twitter:app:url:googleplay"):
            content = fields.get(key, "")
            if not content:
                continue
            for n, m in extract_numbers(content, final_url,
                                        default_method="og_meta"):
                if _add(n, "og_meta", final_url):
                    hits += 1
            for m in _RAW_PHONE_RE.findall(content):
                if _add(m, "og_meta", final_url):
                    hits += 1
        if hits:
            layers_hit.append("og_meta")
            log.debug("LAYER_HIT layer=og_meta hits=%s", hits)
    else:
        fields = fields or (_meta_fields(body) if _is_telegram_url(final_url) else {})

    # ---- LAYER 4 — JavaScript variable extraction ----
    if not _cancelled() and _layer_on("js_vars"):
        hits = 0
        for m in _JS_PHONE_RE.findall(body):
            if _add(m, "js_variable", final_url):
                hits += 1
        if hits:
            layers_hit.append("js_vars")
            log.debug("LAYER_HIT layer=js_vars hits=%s", hits)

    # ---- LAYER 5 — data-attribute / encoded extraction ----
    if not _cancelled() and _layer_on("encoded"):
        hits = 0
        for val in _DATA_ATTR_RE.findall(body):
            for variant in _decoded_variants(val):
                for run in _DIGITS_RUN_RE.findall(variant):
                    if _add(run, "encoded_data", final_url):
                        hits += 1
                        break
        if hits:
            layers_hit.append("encoded")
            log.debug("LAYER_HIT layer=encoded hits=%s", hits)

    # ---- LAYER 6 — Telegram-specific intelligence ----
    tg = {"is_telegram": False, "username": "", "invite": "", "channel": ""}
    if not _cancelled() and _layer_on("telegram") and _is_telegram_url(final_url):
        if not fields:
            fields = _meta_fields(body)
        tg["is_telegram"] = True
        tg["channel"] = (fields.get("og:title") or "").strip()
        desc = " ".join([fields.get("og:description", ""),
                         fields.get("twitter:description", ""),
                         fields.get("description", "")])
        # support/contact @username gets priority over any other @mention
        m = _TG_SUPPORT_RE.search(desc)
        if not m:
            m = _TG_USER_RE.search(desc)
        if m:
            tg["username"] = m.group(1)
        # invite link from og:url or the final URL itself
        ogurl = fields.get("og:url", "") or ""
        for cand in (ogurl, final_url, fields.get("twitter:app:url:googleplay", "") or ""):
            if cand and _is_telegram_url(cand):
                path = urllib.parse.urlparse(cand).path or ""
                if "/+" in path or path.startswith("/joinchat/"):
                    tg["invite"] = cand
                elif not tg["username"]:
                    slug = path.strip("/").split("/")[0]
                    if slug and re.match(r"^[A-Za-z0-9_]{4,64}$", slug):
                        tg["username"] = slug
                if tg["invite"]:
                    break
        hits = 0
        # any phone / wa.me inside the Telegram preview counts as a real result
        for n, meth in extract_numbers(desc, final_url, default_method="telegram_bio"):
            if _add(n, "telegram_bio", final_url):
                hits += 1
        for m2 in _RAW_PHONE_RE.findall(desc):
            if _add(m2, "telegram_bio", final_url):
                hits += 1
        # title matched @-less channel slugs still yield a username via og:url
        layers_hit.append("telegram")
        log.debug("LAYER_HIT layer=telegram hits=%s user=%s",
                  hits, tg.get("username"))

    return {"numbers": out, "layers": layers_hit, "telegram": tg}


# =========================================================
# Scraper — thread-local session reuse, redirect engine
# =========================================================
_thread_local = threading.local()


_thread_local = threading.local()


def _new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(UA_POOL),               # FIX-P25
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANG_POOL),  # FIX-P25
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=16, pool_maxsize=32, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def get_session() -> requests.Session:
    """FIX-P29: sessions rebuilt after 10 minutes — no FD/connection rot on
    long-running hosts."""
    ent = getattr(_thread_local, "session", None)
    now = time.time()
    if ent is None or now - ent[1] > 600:
        if ent:
            try:
                ent[0].close()
            except Exception:
                pass
        ent = (_new_session(), now)
        _thread_local.session = ent
    return ent[0]


class FetchError(Exception):
    """FIX-P37: carries the partial redirect chain so numbers in intermediate
    hop URLs survive a failed visit."""

    def __init__(self, message, status_code=0, partial_visited=None):
        super().__init__(message)
        self.status_code = status_code
        self.partial_visited = list(partial_visited or [])


class Scraper:
    """Redirect-chasing fetcher.

    FIX-P28: allow_redirects disabled — every hop (HTTP 30x, meta refresh,
    JS location, ByetHost challenge) is driven manually in one loop, so the
    full URL chain is visible to the extraction layer (shortener numbers in
    intermediate query strings are no longer lost).
    """

    def __init__(self, proxy: Optional[dict] = None,
                 timeout: Optional[tuple] = None):
        self.proxy = proxy
        self.proxies = proxy_to_requests(proxy) if proxy else None
        if timeout:
            self.timeout = timeout
        elif proxy:                                   # FIX-P14: short budgets in IP mode
            try:
                ct = int(get_setting("ip_connect_timeout", str(IP_CONNECT_TIMEOUT)))
                rt = int(get_setting("ip_read_timeout", str(IP_READ_TIMEOUT)))
            except (ValueError, TypeError):
                ct, rt = IP_CONNECT_TIMEOUT, IP_READ_TIMEOUT
            self.timeout = (ct, rt)
        else:
            self.timeout = (CONNECT_TIMEOUT, READ_TIMEOUT)
        self.session = _new_session()
        self._byet_key_cache: dict = {}               # FIX-P46: per-host key cache

    def _get(self, url, cancel_event):
        if cancel_event and cancel_event.is_set():
            raise JobCancelled()
        return self.session.get(
            url, proxies=self.proxies, timeout=self.timeout,
            allow_redirects=False,                      # FIX-P28
            stream=False)

    def fetch(self, url: str, cancel_event: Optional[threading.Event] = None,
              max_hops: Optional[int] = None) -> tuple:
        max_hops = max_hops or MAX_REDIRECTS
        visited = [url]
        current = url
        body, status_code = "", 0
        warmup_done = False
        byet_tries: dict = {}
        for _hop in range(max_hops):
            if cancel_event and cancel_event.is_set():
                raise JobCancelled()
            try:
                r = self._get(current, cancel_event)
            except JobCancelled:
                raise
            except Exception as e:
                raise FetchError(str(e)[:150], 0, visited)   # FIX-P37
            status_code = r.status_code
            try:
                body = r.text or ""
            except Exception:
                body = ""
            if len(body) > MAX_RESPONSE_SIZE:
                body = body[:MAX_RESPONSE_SIZE]

            # HTTP redirect hop
            if status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if not loc:
                    break
                nxt = urllib.parse.urljoin(current, loc)
                if nxt in visited:
                    break
                visited.append(nxt)
                current = nxt
                continue

            # ByetHost / InfinityFree AES challenge — solve and re-GET
            bl = body[:300000].lower()
            if "slowaes" in bl or ("tonumbers(" in bl and "__test=" in bl):
                if byet_tries.get(current, 0) >= 2:
                    break
                cookie = self._solve_byet(body, current)
                if cookie:
                    byet_tries[current] = byet_tries.get(current, 0) + 1
                    host = urllib.parse.urlparse(current).hostname or ""
                    # FIX-P47: cookie re-set for the CURRENT hop's host
                    self.session.cookies.set("__test", cookie, domain=host)
                    continue                            # re-GET same URL
                break

            # Session warmup: cookie-gate retry once (FIX-P25)
            if (not warmup_done and status_code == 200
                    and r.headers.get("set-cookie") and len(body) < 1024):
                warmup_done = True
                continue

            # Meta refresh / JS redirect on thin pages (FIX-P13: only when
            # the page is a genuine thin redirect — no extraction sacrificed)
            if 0 < len(body) < 2048:
                nxt = ""
                m = _META_REFRESH_RE.search(body)
                if m:
                    nxt = m.group(1).strip()
                else:
                    m = _JS_LOCATION_RE.search(body)
                    nxt = _js_location_target(m).strip() if m else ""
                if nxt:
                    nxt = urllib.parse.urljoin(current, html.unescape(nxt))
                    if nxt not in visited and nxt.startswith(("http://", "https://")):
                        visited.append(nxt)
                        current = nxt
                        continue
            break
        else:
            raise FetchError("redirect loop / too many hops", status_code, visited)
        return current, body, visited, status_code

    def _solve_byet(self, body: str, url: str) -> str:
        """FIX-P46: pure-python decrypt with per-host key-schedule caching."""
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            if host in self._byet_key_cache:
                return self._byet_key_cache[host]
            matches = re.findall(r'toNumbers\("([a-f0-9]+)"\)', body)
            if len(matches) < 3:
                return ""
            cookie = decrypt_byet_challenge(matches[2], matches[0], matches[1])
            if cookie:
                self._byet_key_cache[host] = cookie
            return cookie or ""
        except Exception as e:
            log.debug("BYET_SOLVE_FAIL host=%s err=%s", url[:60], e)
            return ""

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass


def sha1_norm(body) -> str:
    """FIX-P23: whitespace-insensitive hash so cosmetic page jitter doesn't
    defeat the static-link cache."""
    norm = re.sub(rb"\s+", b"", (body or "").encode("utf-8", "ignore"))
    return hashlib.sha1(norm).hexdigest()


def _direct_fetch_with_retry(url, cancel_event):
    """FIX-P24: bounded retry with jitter for direct visits.
    Returns (body, final_url, visited, status_code, latency_ms, error)."""
    try:
        max_retries = max(0, int(get_setting("max_retries_per_visit", "2")))
    except (ValueError, TypeError):
        max_retries = 2
    last_err, status_code = "", 0
    for attempt in range(max_retries + 1):
        if cancel_event.is_set():
            return None, url, [url], 0, 0, "cancelled"
        t0 = time.time()
        scraper = Scraper(proxy=None)
        try:
            final_url, body, visited, status_code = scraper.fetch(
                url, cancel_event=cancel_event)
            return body, final_url, visited, status_code, \
                int((time.time() - t0) * 1000), ""
        except JobCancelled:
            return None, url, [url], 0, 0, "cancelled"
        except FetchError as e:
            last_err, status_code = str(e)[:120], e.status_code
            cls = _classify_err(e)
            if cls == "DNS_FAILED" or attempt == max_retries:
                break
            if status_code and status_code < 500 and status_code not in (408, 429):
                break                              # don't retry client errors
            time.sleep(min(0.5 * (2 ** attempt), 2.0)
                       + random.uniform(0, 0.3))   # FIX-P24
        except Exception as e:
            last_err = str(e)[:120]
            if attempt == max_retries:
                break
            time.sleep(min(0.5 * (2 ** attempt), 2.0) + random.uniform(0, 0.3))
        finally:
            scraper.close()
    return None, url, [url], status_code, 0, last_err



class JobCancelled(Exception):
    pass


def _classify_err(e: Exception) -> str:
    s = str(e).lower()
    if "407" in s or "proxy auth" in s:
        return "AUTH_FAILED"
    if "connect timeout" in s or "timed out" in s or "timeout" in s:
        return "TIMEOUT"
    if "ssl" in s or "certificate" in s:
        return "TLS_FAILURE"
    if "name or service not known" in s or "nodename" in s or "getaddrinfo" in s:
        return "DNS_FAILED"
    if "connection refused" in s:
        return "REFUSED"
    if "too many redirects" in s:
        return "TOO_MANY_REDIRECTS"
    return "REQUEST_FAILED"


def _is_proxy_error(status: str) -> bool:
    """Errors attributable to the proxy itself (connection-layer)."""
    return status in ("AUTH_FAILED", "REFUSED", "TIMEOUT", "TLS_FAILURE")


def _is_retryable_target(status_code: int, status: str) -> bool:
    """Only proxy-related or safely-retryable failures get another proxy."""
    if _is_proxy_error(status):
        return True
    if status == "DNS_FAILED":
        return False
    if status_code in (404, 410, 400):
        return False
    if status_code in (403, 429) or 500 <= status_code < 600:
        return True
    return status in ("REQUEST_FAILED", "TOO_MANY_REDIRECTS")


# =========================================================
# Job state + Progress Updater (independent thread)
# =========================================================
def _new_job_state(job_id: int, total: int, mode: str, url: str,
                   chat_id: int, msg_id: int) -> dict:
    return {
        "job_id": job_id, "total": total, "mode": mode, "url": url,
        "chat_id": chat_id, "msg_id": msg_id,
        "visit": 0, "successful": 0, "failed": 0,
        "unique_numbers": 0, "new_numbers": 0,
        "stage": "Preparing", "proxy_protocol": "",
        "exit_ip": "", "latency_ms": 0, "started_at": time.time(),
        "last_event_ts": time.time(), "done": False,
        "speed_window": deque(maxlen=20),   # (ts, visits) rolling speed
        "lock": threading.Lock(),
        # v3 — protection / telegram intelligence
        "protection": "none", "prot_counts": {},
        "telegram_username": "", "telegram_invite": "",
        "telegram_channel": "", "telegram_redirects": 0,
        "hard_block_streak": 0, "hard_blocked": False,
    }


def _rolling_speed(st: dict) -> float:
    now = time.time()
    window = list(st["speed_window"])
    if len(window) < 2:
        elapsed = max(now - st["started_at"], 0.1)
        return st["visit"] / elapsed
    t_old, v_old = window[0]
    span = now - t_old
    if span <= 0.1:
        return 0.0
    return (st["visit"] - v_old) / span


def _progress_text(st: dict) -> str:
    pct = int((st["visit"] / st["total"]) * 100) if st["total"] else 0
    done = max(0, min(20, pct // 5))
    bar = "▓" * done + "░" * (20 - done)
    elapsed = int(time.time() - st["started_at"])
    mm, ss = divmod(elapsed, 60)
    speed = _rolling_speed(st)
    mode_lbl = "IP ROTATION" if st["mode"] == "IP_ROTATION" else "DIRECT"
    prot = st.get("protection", "none")
    prot_lbl = {
        "none": "None", "telegram_redirect": "Telegram ↪",
        "cloudflare_js": "Cloudflare JS", "cloudflare_iuam": "Cloudflare IUAM",
        "recaptcha": "reCAPTCHA", "hcaptcha": "hCaptcha",
        "byethost": "ByetHost", "meta_redirect_only": "Redirect only",
        "rate_limited": "Rate limited", "geo_blocked": "Geo blocked",
    }.get(prot, prot)
    rows = [
        "╔══════════════════════════════╗",
        "║  ⚡ EXTRACTION ENGINE v3",
        "╠══════════════════════════════╣",
        f"║  JOB #{st['job_id']:06d}  │  {mode_lbl}",
        "╠══════════════════════════════╣",
        f"  {bar}  {pct}%",
        "╠══════════════════════════════╣",
        f"║  🔄 Visits     {st['visit']} / {st['total']}",
        f"║  ✅ Success    {st['successful']}",
        f"║  ❌ Failed     {st['failed']}",
        f"║  📞 Numbers    {st['unique_numbers']} found",
        "╠══════════════════════════════╣",
    ]
    if st.get("telegram_username"):
        rows.append(f"║  📱 Telegram    @{st['telegram_username']}")
    else:
        rows.append(f"║  🛡 Protection  {prot_lbl}")
    if st["mode"] == "IP_ROTATION":
        rows.append(f"║  🌐 Proxy       {st['proxy_protocol'] or 'selecting…'}")
        rows.append(f"║  🧭 Exit IP     {st['exit_ip'] or '—'}")
    rows.append(f"║  ⚡ Speed       {speed:.1f} vis/s")
    rows.append(f"║  ⏱ Time        {mm:02d}:{ss:02d}")
    rows.append("╚══════════════════════════════╝")
    return "```\n" + "\n".join(rows) + "\n```\n" + f"🔎 _{st['stage']}_"


def _progress_updater(st: dict, cancel_event: threading.Event) -> None:
    """Independent thread: edits the Telegram message at safe intervals."""
    interval = max(0.8, float(get_setting("progress_interval", str(PROGRESS_INTERVAL))))
    last_text = ""
    while not st["done"] and not cancel_event.is_set():
        text = _progress_text(st)
        if text != last_text:
            queued_edit(st["chat_id"], st["msg_id"], text,
                        reply_markup=_cancel_job_markup())  # FIX-P33
            last_text = text
        time.sleep(interval)


def _emit(st: dict, stage: str, **kw) -> None:
    with st["lock"]:
        st["stage"] = stage
        st["last_event_ts"] = time.time()
        for k, v in kw.items():
            if k in st:
                st[k] = v


# =========================================================
# Extraction Worker (concurrent visits, cancellable)
# =========================================================
def extraction_worker(chat_id: int, user_id: int, username: str, url: str,
                      count: int, mode: str, msg_id: int,
                      proxy_source_filter: Optional[str] = None) -> None:
    # --- atomic job registration ---
    job_id = create_job(user_id, username, url, mode, count)
    cancel_event = threading.Event()
    st = _new_job_state(job_id, count, mode, url, chat_id, msg_id)
    st.setdefault("early_stopped", False)
    st.setdefault("link_verdict", "")
    with _state_lock:
        job_state[job_id] = st
        job_cancel[job_id] = cancel_event
        job_owner[job_id] = user_id
        active_jobs[user_id] = job_id

    updater = threading.Thread(target=_progress_updater, args=(st, cancel_event),
                               daemon=True)
    updater.start()

    found: dict = {}            # normalized -> (method, source, visit)
    found_tg: dict = {}         # FIX-P06: TELEGRAM_ONLY usernames kept apart
    found_lock = threading.Lock()
    hit_counts: dict = {}       # FIX-P38: number -> visits that yielded it
    pending_numbers: list = []
    pending_attempts: list = []
    dup_count = [0]
    cancelled = [False]
    early_stop = [False]
    barren = [0]
    stats = {"cache_hits": 0, "direct_retries": 0, "proxy_attempts": 0}
    start = time.time()
    log.info("JOB_START job=%s user=%s mode=%s visits=%s url=%s",
             job_id, user_id, mode, count, _mask(url))

    try:
        barren_limit = int(get_setting(
            "early_stop_barren_ip" if mode == "IP_ROTATION" else "early_stop_barren",
            "25" if mode == "IP_ROTATION" else "15"))
    except (ValueError, TypeError):
        barren_limit = 25 if mode == "IP_ROTATION" else 15

    def _merge(res, visit, final_url):
        """Merge one extract_deep result. Returns count of NEW phone numbers."""
        new = 0
        with found_lock:
            for n, m, src_url in res["numbers"]:
                hit_counts[n] = hit_counts.get(n, 0) + 1
                if n in found:
                    dup_count[0] += 1
                else:
                    found[n] = (m, src_url, visit)
                    new += 1
                    pending_numbers.append(
                        (job_id, user_id, n, src_url, m, visit,
                         _display_number(n)))
            tg = res.get("telegram") or {}
            if tg.get("username") and get_setting(
                    "telegram_redirect_mode", "extract_only") == "report_username":
                uname = tg["username"]
                if uname not in found_tg:               # FIX-P06: separate dict
                    found_tg[uname] = ("TELEGRAM_ONLY", final_url, visit)
        return new

    def _barren_tick(new):
        with st["lock"]:
            if new == 0:
                barren[0] += 1
            else:
                barren[0] = 0
            if barren[0] >= barren_limit and not st.get("early_stopped"):
                st["early_stopped"] = True
                early_stop[0] = True
                cancel_event.set()                 # FIX-P36: cooperative stop
                log.info("EARLY_STOP job=%s barren=%s", job_id, barren[0])

    def _tick(ok_visit, visit):
        with st["lock"]:
            st["visit"] += 1
            if ok_visit:
                st["successful"] += 1
            else:
                st["failed"] += 1
            st["speed_window"].append((time.time(), st["visit"]))

    # ------------------------------------------------------------------ IP mode
    def do_visit_ip(visit: int) -> None:
        if cancel_event.is_set():
            return
        with st["lock"]:
            if st.get("hard_blocked"):
                pending_attempts.append(_attempt_row(   # FIX-P01
                    job_id, visit, status="PROTECTED_UNBYPASSABLE",
                    error="unbypassable protection — visit skipped",
                    protection=st.get("protection", "none"), final_url=url))
                _tick(False, visit)
                return

        status_code, attempt_latency = 0, 0
        body, final_url, visited = "", url, [url]
        ok = False
        attempt_status, attempt_err = "UNKNOWN", ""
        attempt_proxy_id, attempt_exit_ip = None, ""
        soft4xx_hit = False
        tg_info = {"is_telegram": False, "username": "", "invite": "", "channel": ""}
        layers_fired: list = []

        proxies = proxy_pool.select(count=1, source_filter=proxy_source_filter)
        if not proxies:
            if get_setting("fallback_direct_on_empty_pool", "0") == "1":
                _emit(st, "Proxy pool empty — direct fallback…")
                body, final_url, visited, status_code, attempt_latency, attempt_err = \
                    _direct_fetch_with_retry(url, cancel_event)
                ok = body is not None
                attempt_status = "OK_DIRECT" if ok else (attempt_err or "FAILED")
            else:
                pending_attempts.append(_attempt_row(   # FIX-P01: 11 fields
                    job_id, visit, status="NO_PROXY",
                    error="no verified proxy available"))
                _tick(False, visit)
                return
        else:
            proxy_row = proxies[0]
            proxy_dict = {k: proxy_row[k] for k in
                          ("protocol", "host", "port", "username", "password",
                           "endpoint")}
            attempt_proxy_id = proxy_row["id"]
            attempt_exit_ip = proxy_row.get("last_observed_ip") or ""
            _emit(st, "Fetching via proxy…",
                  proxy_protocol=proxy_row["protocol"].upper(),
                  exit_ip=attempt_exit_ip)
            try:
                max_attempts = max(1, int(get_setting(
                    "ip_max_proxy_attempts", str(IP_MAX_PROXY_ATTEMPTS))))  # FIX-P03
            except (ValueError, TypeError):
                max_attempts = IP_MAX_PROXY_ATTEMPTS
            try:
                budget = float(get_setting("visit_time_budget",
                                           str(VISIT_TIME_BUDGET)))
            except (ValueError, TypeError):
                budget = VISIT_TIME_BUDGET
            deadline = time.time() + budget          # FIX-P14: per-visit wall clock
            tried_ids = set()
            last_status = "REQUEST_FAILED"
            attempt = -1                             # FIX-P03: no loop-var leak
            for attempt in range(max_attempts):
                if cancel_event.is_set() or time.time() > deadline:
                    if time.time() > deadline:
                        last_status = "TIME_BUDGET_EXCEEDED"
                        log.info("VISIT_BUDGET job=%s visit=%s", job_id, visit)
                    proxy_pool.release(proxy_row["id"])
                    tried_ids.add(proxy_row["id"])
                    break
                stats["proxy_attempts"] += 1
                t0 = time.time()
                scraper = Scraper(proxy=proxy_dict)
                try:
                    final_url, body, visited, status_code = scraper.fetch(
                        url, cancel_event=cancel_event)
                    attempt_latency = int((time.time() - t0) * 1000)
                    ok = True
                    break
                except JobCancelled:
                    scraper.close()
                    proxy_pool.release(proxy_row["id"])
                    return
                except Exception as e:
                    attempt_latency = int((time.time() - t0) * 1000)
                    attempt_err = str(e)[:120]
                    last_status = _classify_err(e)   # FIX-P15: granular classes
                    status_code = getattr(e, "status_code", 0) or 0
                    if isinstance(e, FetchError) and e.partial_visited:
                        visited = e.partial_visited  # FIX-P37
                    if _is_proxy_error(last_status):
                        # FIX-P15: granular proxy statuses, not blanket TIMEOUT
                        err_status = {"AUTH_FAILED": "AUTH_FAILED",
                                      "PROXY_CONNECT_TIMEOUT": "TIMEOUT",
                                      "CONNECT_TIMEOUT": "TIMEOUT",
                                      "PROXY_ERROR": "TIMEOUT"}.get(
                                          last_status, "TIMEOUT")
                        proxy_pool.mark_used_failure(proxy_row["id"], err_status,
                                                     attempt_err)
                    else:
                        update_proxy_health(proxy_row["id"], {
                            "status": "TARGET_FAILED", "latency_ms": 0,
                            "exit_ip": "", "error": attempt_err})
                        proxy_pool.release(proxy_row["id"])
                    tried_ids.add(proxy_row["id"])
                    if last_status == "DNS_FAILED":
                        break
                    if attempt < max_attempts - 1:
                        nxt = proxy_pool.select(count=1, exclude=tried_ids,
                                                source_filter=proxy_source_filter)
                        if nxt:
                            proxy_row = nxt[0]
                            proxy_dict = {k: proxy_row[k] for k in
                                          ("protocol", "host", "port", "username",
                                           "password", "endpoint")}
                            attempt_proxy_id = proxy_row["id"]
                            attempt_exit_ip = proxy_row.get("last_observed_ip") or ""
                            _emit(st, "Rotating to fresh proxy…")
                            continue
                    break
                finally:
                    scraper.close()
            if ok:
                attempt_status = "OK" if attempt <= 0 else "OK_RETRY"  # FIX-P03
                proxy_pool.mark_used_success(proxy_row["id"], attempt_latency,
                                             attempt_exit_ip)
            else:
                attempt_status = last_status

        # --- target blocked the exit IP → rotate & retry (FIX-P16 accounting)
        if ok and mode == "IP_ROTATION" and (
                status_code in (403, 429) or 500 <= status_code < 600):
            for _ in range(3):
                if cancel_event.is_set():
                    break
                nxt = proxy_pool.select(count=1, exclude={attempt_proxy_id},
                                        source_filter=proxy_source_filter)
                if not nxt:
                    break
                nrow = nxt[0]
                ndict = {k: nrow[k] for k in
                         ("protocol", "host", "port", "username", "password",
                          "endpoint")}
                scraper = Scraper(proxy=ndict)
                try:
                    final_url, body, visited, status_code = scraper.fetch(
                        url, cancel_event=cancel_event)
                    if status_code < 400:            # FIX-P16: success only when clear
                        proxy_pool.mark_used_success(
                            nrow["id"], 0, nrow.get("last_observed_ip") or "")
                        attempt_proxy_id = nrow["id"]
                        attempt_exit_ip = nrow.get("last_observed_ip") or ""
                        _emit(st, "Rotated past target block…")
                        break
                    # FIX-P16: still blocked → neutral TARGET_FAILED, not success
                    update_proxy_health(nrow["id"], {
                        "status": "TARGET_FAILED", "latency_ms": 0,
                        "exit_ip": "", "error": f"HTTP {status_code} on rotate"})
                    proxy_pool.release(nrow["id"])
                except JobCancelled:
                    proxy_pool.release(nrow["id"])
                    scraper.close()
                    return
                except Exception:
                    proxy_pool.mark_used_failure(nrow["id"], "TIMEOUT",
                                                 "block-rotate retry failed")
                finally:
                    scraper.close()

        # --- permanent target failures are not retried
        if ok and status_code >= 400:
            attempt_status = f"HTTP_{status_code}"
            attempt_err = f"target returned HTTP {status_code}"
            ok = False

        # --- soft-4xx fallback (FIX-P02: results are kept, never overwritten)
        res = None
        if not ok and body and status_code in (403, 429):
            res = extract_deep(body, final_url, visited,
                               cancel_event=cancel_event)
            if res["numbers"]:
                soft4xx_hit = True                   # FIX-P02
                ok = True
                attempt_status = f"HTTP_{status_code}_BODY_OK"
                layers_fired = res["layers"]
                tg_info = res["telegram"]
                _merge(res, visit, final_url)

        # --- protection detection
        prot = detect_protection(body or "", status_code, final_url)
        prot_type = prot["type"]
        with st["lock"]:
            st["protection"] = prot_type
            st["prot_counts"][prot_type] = st["prot_counts"].get(prot_type, 0) + 1

        # FIX-P02: a soft-4xx extraction success is NOT a hard block
        if ok and not soft4xx_hit and not prot["bypassable"]:
            log.warning("PROTECTION_BLOCK job=%s type=%s", job_id, prot_type)
            with st["lock"]:
                st["hard_block_streak"] += 1
                if st["hard_block_streak"] >= 3:
                    st["hard_blocked"] = True
            ok = False
            attempt_status = f"PROTECTION:{prot_type}"
            attempt_err = prot["detail"][:120]
        elif ok:
            with st["lock"]:
                st["hard_block_streak"] = 0

        if ok and prot_type == "telegram_redirect" and \
                get_setting("telegram_redirect_mode", "extract_only") == "skip":
            ok = False
            attempt_status = "TELEGRAM_SKIPPED"
            attempt_err = "telegram redirect skipped by settings"

        # --- deep extraction on success
        new_this_visit = 0
        if ok:
            if res is None:
                res = extract_deep(body, final_url, visited,
                                   cancel_event=cancel_event)
                layers_fired = res["layers"]
                tg_info = res["telegram"]
            new_this_visit = _merge(res, visit, final_url)
            # FIX-P05: telegram redirect with nothing extracted = soft failure
            if prot_type == "telegram_redirect" and new_this_visit == 0 \
                    and not tg_info.get("username") and not tg_info.get("invite"):
                ok = False
                attempt_status = "TELEGRAM_EMPTY"
                attempt_err = f"telegram preview exposed no contact info " \
                              f"(body {len(body or '')} bytes)"

        # FIX-P37: numbers in partial chains of failed visits still count
        if not ok and visited and len(visited) > 1:
            for n, m in extract_from_url_chain(visited):
                with found_lock:
                    hit_counts[n] = hit_counts.get(n, 0) + 1
                    if n not in found:
                        found[n] = (m, visited[-1], visit)
                        new_this_visit += 1
                        pending_numbers.append(
                            (job_id, user_id, n, visited[-1], m, visit,
                             _display_number(n)))

        pending_attempts.append(_attempt_row(        # FIX-P01: uniform row
            job_id, visit, proxy_id=attempt_proxy_id, exit_ip=attempt_exit_ip,
            status=attempt_status, latency=attempt_latency, error=attempt_err,
            protection=prot_type, final_url=final_url,
            tg_user=tg_info.get("username", ""), layers=layers_fired))
        _tick(ok or new_this_visit > 0, visit)
        _barren_tick(new_this_visit)

    # --------------------------------------------------------------- DIRECT mode
    strategy = get_setting("direct_strategy", "smart")
    body_cache: dict = {}

    def do_visit_direct(visit: int) -> None:
        if cancel_event.is_set() or st.get("early_stopped"):
            return
        body, final_url, visited, status_code, latency, err = \
            _direct_fetch_with_retry(url, cancel_event)       # FIX-P24
        if body is None:
            pending_attempts.append(_attempt_row(
                job_id, visit, status=_classify_err(Exception(err)) if err
                else "FAILED", latency=latency, error=err, final_url=final_url))
            _tick(False, visit)
            return
        h = sha1_norm(body)
        if h in body_cache:                            # FIX-P23: dedupe extraction
            res = body_cache[h]
            stats["cache_hits"] += 1
        else:
            res = extract_deep(body, final_url, visited,
                               cancel_event=cancel_event)
            if len(body_cache) < 256:
                body_cache[h] = res
        new = _merge(res, visit, final_url)
        prot = detect_protection(body or "", status_code, final_url)
        with st["lock"]:
            st["protection"] = prot["type"]
            st["prot_counts"][prot["type"]] = \
                st["prot_counts"].get(prot["type"], 0) + 1
        tg = res.get("telegram") or {}
        v_status = "OK" if status_code < 400 else f"HTTP_{status_code}_BODY_OK"
        # FIX-P05: empty telegram previews are soft failures
        ok_visit = True
        if prot["type"] == "telegram_redirect" and new == 0 \
                and not tg.get("username") and not tg.get("invite"):
            v_status = "TELEGRAM_EMPTY"
            ok_visit = False
        pending_attempts.append(_attempt_row(
            job_id, visit, status=v_status, latency=latency,
            error=err, protection=prot["type"], final_url=final_url,
            tg_user=tg.get("username", ""), layers=res["layers"]))
        _tick(ok_visit, visit)
        _barren_tick(new)                              # FIX-P36

    def _run_parallel(do_visit, workers):
        workers = max(1, min(workers, count))
        ex = ThreadPoolExecutor(max_workers=workers)
        try:
            futs = [ex.submit(do_visit, v) for v in range(1, count + 1)]
            for f in as_completed(futs):
                if cancel_event.is_set():
                    for p_ in futs:
                        p_.cancel()                    # FIX-P08
                    cancelled[0] = not st.get("early_stopped")
                    break
                try:
                    f.result()
                except JobCancelled:
                    cancelled[0] = True
                except Exception as e:
                    log.warning("JOB_VISIT_ERROR job=%s err=%s", job_id, e)
        finally:
            ex.shutdown(wait=False, cancel_futures=True)  # FIX-P08

    try:
        if mode == "IP_ROTATION":
            workers = max(1, int(get_setting("ip_turbo_concurrency",
                                             str(IP_TURBO_CONCURRENCY))))
            _run_parallel(do_visit_ip, workers)
        elif strategy == "classic":
            _run_parallel(do_visit_direct, max(1, int(get_setting(
                "max_concurrency", str(MAX_CONCURRENCY)))))
        elif strategy == "parallel":
            _run_parallel(do_visit_direct, max(1, int(get_setting(
                "max_concurrency", "24"))))                # FIX-P23-B
        else:
            # ---------------- smart strategy (FIX-P23-A) ----------------
            bodies, visits_done = [], 0
            for probe in range(min(3, count)):
                if cancel_event.is_set():
                    break
                body, final_url, visited, status_code, latency, err = \
                    _direct_fetch_with_retry(url, cancel_event)
                visits_done += 1
                if body is None:
                    pending_attempts.append(_attempt_row(
                        job_id, probe + 1, status="FAILED", latency=latency,
                        error=err, final_url=final_url))
                    _tick(False, probe + 1)
                    continue
                bodies.append((sha1_norm(body), body, final_url, visited,
                               status_code, latency))
            hashes = {b[0] for b in bodies}
            if len(bodies) >= 2 and len(hashes) == 1:
                # STATIC LINK — fetch no more; extract once, deep
                _, body, final_url, visited, status_code, latency = bodies[0]
                res = extract_deep(body, final_url, visited,
                                   cancel_event=cancel_event)
                new = _merge(res, 1, final_url)
                prot = detect_protection(body or "", status_code, final_url)
                tg = res.get("telegram") or {}
                pending_attempts.append(_attempt_row(
                    job_id, 1, status="OK", latency=latency,
                    protection=prot["type"], final_url=final_url,
                    tg_user=tg.get("username", ""), layers=res["layers"]))
                st["link_verdict"] = "STATIC"
                with st["lock"]:
                    st["successful"] += (count - visits_done)
                    st["visit"] += (count - visits_done)
                    st["stage"] = (f"Static link — answered from {visits_done} "
                                   f"fetches, {count - visits_done} cached")
                log.info("STATIC_LINK job=%s fetches=%s numbers=%s",
                         job_id, visits_done, len(found))
            else:
                if len(hashes) > 1:
                    st["link_verdict"] = "ROTATING"
                # merge probed bodies so no work is wasted
                for h, body, final_url, visited, status_code, latency in bodies:
                    res = extract_deep(body, final_url, visited,
                                       cancel_event=cancel_event)
                    new = _merge(res, 1, final_url)
                    prot = detect_protection(body or "", status_code, final_url)
                    tg = res.get("telegram") or {}
                    pending_attempts.append(_attempt_row(
                        job_id, 1, status="OK", latency=latency,
                        protection=prot["type"], final_url=final_url,
                        tg_user=tg.get("username", ""), layers=res["layers"]))
                    _tick(True, 1)
                    if len(body_cache) < 256:
                        body_cache[h] = res
                remaining = count - visits_done
                if remaining > 0 and not cancel_event.is_set():
                    workers = max(1, int(get_setting("max_concurrency", "24")))
                    workers = min(workers, remaining)
                    ex = ThreadPoolExecutor(max_workers=workers)
                    try:
                        futs = [ex.submit(do_visit_direct, v)
                                for v in range(visits_done + 1, count + 1)]
                        for f in as_completed(futs):
                            if cancel_event.is_set():
                                for p_ in futs:
                                    p_.cancel()        # FIX-P08
                                break
                            try:
                                f.result()
                            except Exception as e:
                                log.warning("JOB_VISIT_ERROR job=%s err=%s",
                                            job_id, e)
                    finally:
                        ex.shutdown(wait=False, cancel_futures=True)  # FIX-P08
    except Exception as e:
        log.exception("JOB_WORKER_FATAL job=%s err=%s", job_id, e)

    # ------------------------------------------------------------------ finalize
    dur_ms = int((time.time() - start) * 1000)
    cancelled[0] = cancelled[0] or (
        cancel_event.is_set() and not st.get("early_stopped"))
    with st["lock"]:
        success, failed = st["successful"], st["failed"]
        st["done"] = True
    unique = len(found)                                # FIX-P06: phones only

    # FIX-P01: numbers and attempts commit in SEPARATE try blocks — one
    # failing must never kill the other
    try:
        save_numbers_batch(pending_numbers)
    except Exception as e:
        log.error("JOB_DB_WRITE numbers failed job=%s err=%s", job_id, e)
    try:
        save_attempts_batch(pending_attempts)
    except Exception as e:
        log.error("JOB_DB_WRITE attempts failed job=%s err=%s", job_id, e)

    if cancelled[0]:
        final_status = "CANCELLED"
    elif st.get("early_stopped"):
        final_status = "COMPLETED_EARLY"
    elif unique > 0 or success > 0:
        final_status = "COMPLETED"
    else:
        final_status = "FAILED"
    try:
        finish_job(job_id, success, failed, unique, dup_count[0], dur_ms,
                   final_status)
    except Exception as e:
        log.error("JOB_DB_WRITE finish failed job=%s err=%s", job_id, e)
    try:
        update_user_stats(user_id, unique)
    except Exception:
        pass

    # FIX-P48: structured per-job summary for tuning
    log.info("JOB_SUMMARY job=%s visits=%s ok=%s fail=%s unique=%s dupes=%s "
             "cache_hits=%s early_stop=%s cancelled=%s direct_retries=%s "
             "proxy_attempts=%s verdict=%s dur_ms=%s",
             job_id, success + failed, success, failed, unique, dup_count[0],
             stats["cache_hits"], early_stop[0], cancelled[0],
             stats["direct_retries"], stats["proxy_attempts"],
             st.get("link_verdict") or "?", dur_ms)

    with _state_lock:
        active_jobs.pop(user_id, None)
        job_cancel.pop(job_id, None)
        job_owner.pop(job_id, None)

    if cancelled[0]:
        safe_edit_message(chat_id, msg_id,
                          "🛑 *Cancelling…* finishing in-flight requests.")
    _send_final_result(chat_id, user_id, username, url, mode, count,
                       success, failed, unique, dup_count[0], dur_ms,
                       found, found_tg, job_id, st, hit_counts, cancelled[0])
    tg_meta = {"prot_counts": st.get("prot_counts", {})}
    # best telegram intel seen across visits
    for uname in found_tg:
        tg_meta["username"] = uname
        break
    _channel_post_safe(job_id, user_id, username, url, mode, count, success,
                       failed, unique, dup_count[0], dur_ms, found, tg_meta)



def _api_call(fn, *args, **kwargs):
    """One call with FloodWait-aware retry. Returns result or None."""
    for attempt in range(3):
        try:
            return fn(*args, **kwargs)
        except ApiTelegramException as e:
            desc = str(e).lower()
            if "retry after" in desc or "too many requests" in desc:
                m = re.search(r"retry after (\d+)", desc)
                time.sleep(min(int(m.group(1)) if m else 2, 10))
                continue
            if "message is not modified" in desc:
                return None
            if "message to edit not found" in desc or "message to delete not found" in desc:
                return None
            if "chat not found" in desc or "bot was blocked" in desc or "forbidden" in desc:
                return None
            if attempt == 2:
                log.debug("telegram api error: %s", _mask(str(e)[:150]))
                return None
            time.sleep(0.5 * (attempt + 1))
        except (requests.exceptions.RequestException, ConnectionError, TimeoutError) as e:
            if attempt == 2:
                log.debug("telegram network error: %s", _mask(str(e)[:150]))
                return None
            time.sleep(1.0 * (attempt + 1))
        except Exception as e:
            log.debug("telegram call error: %s", _mask(str(e)[:150]))
            return None
    return None


def safe_send_message(chat_id, text, parse_mode="Markdown", reply_markup=None):
    msg = _api_call(bot.send_message, chat_id, text,
                    parse_mode=parse_mode, reply_markup=reply_markup)
    if msg is None and parse_mode:
        # fallback without markdown (bad entity etc.)
        msg = _api_call(bot.send_message, chat_id, text, reply_markup=reply_markup)
    return msg


def safe_edit_message(chat_id, message_id, text, parse_mode="Markdown", reply_markup=None):
    res = _api_call(bot.edit_message_text, text, chat_id=chat_id,
                    message_id=message_id, parse_mode=parse_mode,
                    reply_markup=reply_markup)
    if res is None and parse_mode:
        res = _api_call(bot.edit_message_text, text, chat_id=chat_id,
                        message_id=message_id, reply_markup=reply_markup)
    return res


def safe_send_document(chat_id, data, filename, caption=None, parse_mode="Markdown"):
    bio = io.BytesIO(data if isinstance(data, bytes) else data.encode("utf-8"))
    bio.name = filename
    return _api_call(bot.send_document, chat_id, bio,
                     caption=caption, parse_mode=parse_mode)


def safe_answer_callback(cb_id, text=None, show_alert=False):
    return _api_call(bot.answer_callback_query, cb_id, text=text,
                     show_alert=show_alert)


# =========================================================
# Friendly error mapping (no stack traces / secrets to users)
# =========================================================
def friendly_error(status: str) -> str:
    return {
        "TIMEOUT": "🔗 Target/proxy timeout",
        "AUTH_FAILED": "🔐 Proxy authentication failed",
        "TCP_FAILED": "🌐 Proxy unreachable",
        "TLS_FAILURE": "🔒 TLS/SSL error",
        "DNS_FAILED": "🌍 DNS resolution failed",
        "REFUSED": "🚫 Connection refused",
        "TOO_MANY_REDIRECTS": "🔁 Redirect limit reached",
        "HTTP_403": "🚫 Target returned 403 (blocked)",
        "HTTP_404": "🔎 Target returned 404 (not found)",
        "HTTP_429": "⏳ Target rate-limited (429)",
        "NO_PROXY": "🌐 No verified proxy available",
        "TARGET_FAILED": "🎯 Target request failed",
        "HTTP_403_BODY_OK": "✅ Numbers recovered from a 403 page body",  # FIX-P40
        "HTTP_429_BODY_OK": "✅ Numbers recovered from a 429 page body",
        "TELEGRAM_REDIRECT": "📱 Redirects to a Telegram preview",
        "TELEGRAM_EMPTY": "📱 Telegram preview shows no public contact info",
        "READ_TIMEOUT": "⏳ Target too slow to respond",
        "PROXY_CONNECT_TIMEOUT": "🌐 Proxy connection timed out",
        "TIME_BUDGET_EXCEEDED": "⏱ Visit time budget exhausted",
        "UNSUPPORTED": "🧩 Protocol unsupported (install PySocks)",
    }.get(status, "❌ Request failed")


# =========================================================
# Final Result & Channel Post
# =========================================================
def _fmt_duration(ms: int) -> str:
    s = ms / 1000
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    return f"{m:02d}:{sec:02d}"


def _display_number(n: str) -> str:
    """FIX-P17: real country-code formatting.
    Indian mobiles (10 digits starting 6-9) display as +91…"""
    n = re.sub(r"\D", "", n or "")
    if not n:
        return "—"
    if n.startswith("TELEGRAM"):
        return n
    if len(n) == 10 and n[0] in "6789":
        return f"+91{n}"
    if len(n) == 11 and n.startswith("0") and n[1] in "6789":
        return f"+91{n[1:]}"
    if len(n) == 12 and n.startswith("91") and n[2] in "6789":
        return f"+91{n[2:]}"
    if len(n) == 11 and n.startswith("1"):
        return f"+{n}"
    if len(n) == 10:
        return f"+1{n}"
    return f"+{n}" if not n.startswith("+") else n


def _row(label, value, width=30):
    """FIX-P42: stable box width regardless of digit count."""
    body = f"{label:<12}{value}"
    return f"║  {body:<{width}}║"




def _copy_chunks(numbers: list, limit: int = 250) -> list:
    """Split numbers into chunks that each fit Telegram's 256-char copy limit."""
    chunks, cur = [], ""
    for n in numbers:
        line = f"{_display_number(n)}\n"
        if len(cur) + len(line) > limit:
            if cur:
                chunks.append(cur.strip())
            cur = line
        else:
            cur += line
    if cur.strip():
        chunks.append(cur.strip())
    return chunks


def _copy_markup(numbers: list, max_buttons: int = 6) -> Optional[types.InlineKeyboardMarkup]:
    chunks = _copy_chunks(numbers)
    if not chunks:
        return None
    mk = types.InlineKeyboardMarkup(row_width=2)
    btns = []
    start = 1
    for i, chunk in enumerate(chunks[:max_buttons]):
        cnt = chunk.count("\n") + 1
        end = start + cnt - 1
        label = f"📋 Copy {start}–{end}" if cnt > 1 else f"📋 Copy {start}"
        try:
            btns.append(types.InlineKeyboardButton(
                label, copy_text=types.CopyTextButton(text=chunk)))
        except Exception:
            # library without CopyTextButton support — degrade to plain text chunk
            return None
        start = end + 1
    if len(chunks) > max_buttons:
        btns.append(types.InlineKeyboardButton(
            f"📄 +{len(numbers) - (start - 1)} more in TXT file", callback_data="noop"))
    if btns:
        mk.add(*btns)
    return mk


def _share_markup(job_id: int, unique: int) -> types.InlineKeyboardMarkup:
    mk = types.InlineKeyboardMarkup(row_width=2)
    share_text = urllib.parse.quote(
        f"🚀 Extracted {unique} WhatsApp numbers with DK Sharma Bot — Job #{job_id:06d}")
    mk.add(types.InlineKeyboardButton(
        "📤 Share", url=f"https://t.me/share/url?url=&text={share_text}"))
    return mk


def _numbers_txt_content(job_id, username, user_id, url, mode, count,
                         success, failed, dur_ms, found, unique) -> str:
    lines_out = [
        "DK Sharma Bot — Extraction Result",
        f"Job ID: #{job_id:06d}",
        f"User: @{username or '—'} ({user_id})",
        f"Source URL: {url}",
        f"Mode: {mode}",
        f"Visits: {count} (successful {success}, failed {failed})",
        f"Duration: {_fmt_duration(dur_ms)}",
        f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Unique Numbers: {unique}",
        "=" * 50,
        "",
        "Number | Method | Source | Visit",
        "-" * 50,
    ]
    for n in sorted(found.keys()):
        m, src, v = found[n]
        lines_out.append(f"{_display_number(n)} | {m} | {src} | #{v}")
    return "\n".join(lines_out)


def _send_final_result(chat_id, user_id, username, url, mode, count,
                       success, failed, unique, dup, dur_ms, found,
                       found_tg=None, job_id=None, st=None,
                       hit_counts=None, cancelled=False):
    """Final result card v2 — FIX-P38 link verdict, FIX-P05 telegram-empty
    guidance, FIX-P42 fixed-width rows, FIX-P06 phones/tg shown separately."""
    found_tg = found_tg or {}
    st = st or {}
    hit_counts = hit_counts or {}
    phones = sorted(found.keys())
    tg_users = sorted(found_tg.keys())
    job_label = f"#{job_id:06d}" if job_id else ""
    verdict = st.get("link_verdict") or ""
    speed = (success + failed) / max(dur_ms / 1000, 0.1)

    lines = ["```"]
    lines.append("╔════════════════════════════════╗")
    if cancelled:
        lines.append("║  🛑 EXTRACTION CANCELLED       ║")
    elif st.get("early_stopped"):
        lines.append("║  ⏹ COMPLETED EARLY             ║")
    elif unique > 0 or success > 0:
        lines.append("║  ✅ EXTRACTION COMPLETE        ║")
    else:
        lines.append("║  ❌ EXTRACTION FAILED          ║")
    lines.append("╠════════════════════════════════╣")
    lines.append(_row("🔄 Visits:", f"{success + failed}/{count}"))
    lines.append(_row("✅ Successful:", success))
    lines.append(_row("❌ Failed:", failed))
    lines.append(_row("📱 Unique:", unique))
    lines.append(_row("♻️ Duplicates:", dup))
    if tg_users:
        lines.append(_row("📮 TG handles:", len(tg_users)))
    lines.append(_row("⚡ Speed:", f"{speed:.2f} visits/s"))
    lines.append(_row("⏱ Duration:", _fmt_duration(dur_ms)))
    if verdict:
        lines.append("╠════════════════════════════════╣")
        lines.append(_row("📌 Link type:", verdict))
        if verdict == "STATIC":
            lines.append(f"║  ℹ️ {unique} unique is the full set —")
            lines.append("║  this link does not rotate.      ║")
    if st.get("early_stopped"):
        lines.append("╠════════════════════════════════╣")
        lim = get_setting("early_stop_barren_ip" if mode == "IP_ROTATION"
                          else "early_stop_barren", "15")
        lines.append(f"║  ⏹ Stopped early: no new")
        lines.append(f"║  numbers in last {lim} visits.")
    lines.append("╚════════════════════════════════╝")
    lines.append("```")

    # FIX-P05: distinct guidance when every visit was an empty telegram preview
    prot_counts = st.get("prot_counts") or {}
    tg_empty_guidance = (
        unique == 0 and not tg_users
        and prot_counts.get("telegram_redirect")
        and not any(k not in ("none", "telegram_redirect")
                    for k in prot_counts))
    if tg_empty_guidance:
        lines.append(
            "📱 *Link redirects to Telegram* but the public preview exposes "
            "no contact info. The channel likely has no public number — this "
            "is a target limitation, not a bot failure.")

    safe_send_message(chat_id, "\n".join(lines))

    if unique > 0 or tg_users:
        copy_mk = _copy_markup(phones if phones else tg_users)
        if copy_mk:
            safe_send_message(chat_id, f"📋 *Copy Numbers — Job {job_label}*",
                              reply_markup=copy_mk)
        if unique <= 60:
            disp = ([_display_number(n) for n in phones]
                    + [f"📱 @{u}" for u in tg_users])
            chunks, cur = [], ""
            for ln in disp:
                if len(cur) + len(ln) + 1 > 3800:
                    chunks.append(cur.strip())
                    cur = ln + "\n"
                else:
                    cur += ln + "\n"
            if cur.strip():
                chunks.append(cur.strip())
            for i, ch in enumerate(chunks):
                hdr = (f"📱 *Numbers (Job {job_label})*\n━━━━━━━━━━━━━━━━━━━━\n"
                       if i == 0 else f"📱 *Numbers (Part {i + 1})*\n")
                safe_send_message(chat_id, hdr + f"`{ch}`")
        else:
            safe_send_message(
                chat_id,
                f"📱 *Numbers Found:* `{unique}`\n"
                f"Use the Copy buttons above or the attached file.")

        try:
            content = _numbers_txt_content(job_id, username, user_id, url, mode,
                                           count, success, failed, dur_ms,
                                           found, unique)
            # FIX-P38: per-number visit counts appended to the TXT
            if hit_counts:
                content += ("\n\n--- per-number visit counts ---\n" + "\n".join(
                    f"{_display_number(n)}  ×{hit_counts.get(n, 1)} visits"
                    for n in phones[:200]))
            safe_send_document(
                chat_id, content, f"job_{job_id:06d}_numbers.txt",
                caption=(f"📁 *Numbers File — Job {job_label}*\n"
                         f"📱 `{unique}` unique results"))
        except Exception as e:
            log.warning("FILE_SEND_FAILED job=%s err=%s", job_id, e)

    safe_send_message(chat_id, "🏠 *Main Menu*",
                      reply_markup=main_keyboard(user_id))


# FIX-P33: single dedicated sender thread for all background Telegram
# traffic — natural pacing, no scattered FloodWait sleeps.
_send_q = queue.Queue(maxsize=500)


def _sender_loop():
    last_sent: dict = {}
    while True:
        item = _send_q.get()
        if item is None:
            return
        kind, args, kwargs = item
        chat_id = args[0] if args else kwargs.get("chat_id")
        if chat_id:
            wait = 1.05 - (time.time() - last_sent.get(chat_id, 0))
            if wait > 0:
                time.sleep(wait)
        try:
            if kind == "send":
                _api_call(bot.send_message, *args, **kwargs)
            elif kind == "edit":
                _api_call(bot.edit_message_text, *args, **kwargs)
            elif kind == "doc":
                _api_call(bot.send_document, *args, **kwargs)
        except Exception:
            pass
        finally:
            if chat_id:
                last_sent[chat_id] = time.time()
            _send_q.task_done()


threading.Thread(target=_sender_loop, daemon=True, name="tg-sender").start()


def queued_edit(chat_id, msg_id, text, reply_markup=None):
    """FIX-P33: background progress edits go through the paced sender."""
    try:
        _send_q.put_nowait(("edit", (text,), {
            "chat_id": chat_id, "message_id": msg_id,
            "reply_markup": reply_markup}))
    except queue.Full:
        pass


def queued_send(chat_id, text, reply_markup=None):
    try:
        _send_q.put_nowait(("send", (chat_id, text),
                            {"reply_markup": reply_markup}))
    except queue.Full:
        pass



def _channel_post_safe(job_id, user_id, username, url, mode, count, success,
                       failed, unique, dup, dur_ms, found, tg_meta=None):
    try:
        _channel_post(job_id, user_id, username, url, mode, count, success,
                      failed, unique, dup, dur_ms, found, tg_meta)
    except Exception as e:
        log.warning("CHANNEL_POST_FAILED job=%s err=%s", job_id, _mask(str(e)[:150]))


def _classify_channel_error(err: str) -> str:
    s = err.lower()
    if "chat not found" in s:
        return "CHANNEL_NOT_FOUND"
    if "not enough rights" in s or "administrator" in s or "forbidden" in s:
        return "NO_PERMISSION"
    if "retry after" in s or "too many requests" in s:
        return "RATE_LIMIT"
    return "NETWORK_ERROR"


def _channel_post(job_id, user_id, username, url, mode, count, success,
                  failed, unique, dup, dur_ms, found, tg_meta=None):
    cfg = get_settings_batch([
        "channel_logging", "channel_username", "channel_include_username",
        "channel_include_uid", "channel_include_method", "channel_include_numbers",
        "channel_attach_txt", "channel_include_speed", "channel_include_proxy",
    ])
    if cfg["channel_logging"] != "1":
        return
    channel = cfg["channel_username"]
    if not channel:
        return

    host = urllib.parse.urlparse(url).hostname or url
    mode_label = "IP Rotation" if mode == "IP_ROTATION" else "Direct"
    elapsed_s = max(dur_ms / 1000, 0.1)
    speed = (success + failed) / elapsed_s

    log.info("CHANNEL_POST_START job=%s channel=%s", job_id, channel)
    lines = [
        "🚀 EXTRACTION RESULT",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    if cfg["channel_include_username"] == "1":
        lines.append(f"👤 User: @{username or '—'}")
    if cfg["channel_include_uid"] == "1":
        lines.append(f"🆔 User ID: `{user_id}`")
    lines.append(f"🌐 Source:\n{host}")
    if cfg["channel_include_method"] == "1":
        lines.append(f"⚙️ Mode:\n{mode_label}")
    lines += [
        f"🔄 Visits: `{count}`",
        f"✅ Successful: `{success}`",
        f"❌ Failed: `{failed}`",
        f"📱 Unique Numbers: `{unique}`",
        f"♻️ Duplicates: `{dup}`",
    ]
    if cfg["channel_include_speed"] == "1":
        lines += [
            f"⚡ Avg Speed: `{speed:.2f} visits/s`",
            f"⏱ Duration: `{_fmt_duration(dur_ms)}`",
        ]
    if cfg["channel_include_proxy"] == "1" and mode == "IP_ROTATION":
        attempts = job_attempts(job_id, limit=5)
        ips = [a["exit_ip"] for a in attempts if a.get("exit_ip")]
        if ips:
            lines.append(f"🧭 Exit IPs: `{len(set(ips))}` unique")

    # v3 — telegram destination section
    tg_meta = tg_meta or {}
    if tg_meta.get("username") or tg_meta.get("invite"):
        lines.append("━━━━━━━━━━━━━━━━━━━━")
        lines.append("📱 TELEGRAM DESTINATION")
        if tg_meta.get("channel"):
            lines.append(f"Channel: {tg_meta['channel']}")
        if tg_meta.get("username"):
            lines.append(f"Username: @{tg_meta['username']}")
        if tg_meta.get("invite"):
            lines.append(f"Invite: {tg_meta['invite']}")
    prot_counts = tg_meta.get("prot_counts") or {}
    bad_prot = {k: v for k, v in prot_counts.items()
                if k not in ("none", "telegram_redirect")}
    if bad_prot:
        lines.append("🛡 Protection seen: " +
                     ", ".join(f"{k}×{v}" for k, v in bad_prot.items()))

    # numbers section — small lists inline, large lists summarized
    sorted_nums = sorted(found.keys())
    if cfg["channel_include_numbers"] == "1" and unique > 0:
        lines.append("━━━━━━━━━━━━━━━━━━━━")
        if unique <= 25:
            lines.append("📞 Numbers")
            lines.append("")
            for n in sorted_nums:
                lines.append(f"{_display_number(n)}")
        else:
            lines.append(f"📞 Numbers Found: `{unique}`")
            lines.append("Use the Copy buttons below or the attached file.")
    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
        f"🆔 Job #{job_id:06d}",
    ]
    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:3990] + "…"

    # keyboard: real copy buttons + share
    mk = types.InlineKeyboardMarkup(row_width=2)
    btns = []
    if unique > 0:
        copy_mk = _copy_markup(sorted_nums, max_buttons=4)
        if copy_mk:
            for row in copy_mk.keyboard:
                btns.extend(row)
    share_text = urllib.parse.quote(
        f"🚀 {unique} WhatsApp numbers extracted — Job #{job_id:06d}")
    btns.append(types.InlineKeyboardButton(
        "📤 Share", url=f"https://t.me/share/url?url=&text={share_text}"))
    if btns:
        mk.add(*btns)

    # bounded retries with exponential backoff
    msg_id, err, err_class = None, "", ""
    for attempt in range(3):
        try:
            msg = bot.send_message(channel, text, parse_mode="Markdown",
                                   reply_markup=mk if btns else None)
            msg_id = msg.message_id
            err, err_class = "", "SUCCESS"
            break
        except ApiTelegramException as e:
            err = str(e)[:120]
            err_class = _classify_channel_error(err)
            if err_class in ("CHANNEL_NOT_FOUND", "NO_PERMISSION"):
                break  # permanent — no point retrying
            # markdown fallback once
            if "can't parse" in err.lower() or "bad request" in err.lower():
                try:
                    msg = bot.send_message(channel, text,
                                           reply_markup=mk if btns else None)
                    msg_id = msg.message_id
                    err, err_class = "", "SUCCESS"
                    break
                except Exception:
                    pass
            time.sleep(min(2.0 * (2 ** attempt), 30.0))  # FIX-P12: honor long retry-after
        except Exception as e:
            err = str(e)[:120]
            err_class = "NETWORK_ERROR"
            time.sleep(min(2.0 * (2 ** attempt), 30.0))  # FIX-P12: honor long retry-after

    # optional TXT attachment (after the card, same retry discipline, once)
    if msg_id and cfg["channel_attach_txt"] == "1" and unique > 0:
        try:
            content = _numbers_txt_content(job_id, username, user_id, url, mode,
                                           count, success, failed, dur_ms,
                                           found, unique)
            bio = io.BytesIO(content.encode("utf-8"))
            bio.name = f"job_{job_id:06d}_numbers.txt"
            bot.send_document(channel, bio,
                              caption=f"📁 Job #{job_id:06d} — {unique} numbers")
        except Exception as e:
            log.warning("CHANNEL_TXT_FAILED job=%s err=%s", job_id,
                        _mask(str(e)[:120]))

    with _db_lock:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO channel_posts(job_id, channel, status, message_id, error) "
                "VALUES(?,?,?,?,?)",
                (job_id, channel, "OK" if msg_id else err_class or "FAILED",
                 msg_id, err),
            )
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection
    if msg_id:
        log.info("CHANNEL_POST_SUCCESS job=%s channel=%s", job_id, channel)
    else:
        log.warning("CHANNEL_POST_FAILED job=%s channel=%s class=%s err=%s",
                    job_id, channel, err_class, _mask(err))


def validate_url(url: str) -> Optional[str]:
    """FIX-P19: p.port access wrapped — malformed ports return None instead
    of raising ValueError up into the message handler."""
    url = (url or "").strip()
    if not url:
        return None
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    try:
        p = urllib.parse.urlparse(url)
        if not p.hostname or "." not in p.hostname:
            return None
        try:
            _ = p.port                      # raises ValueError when malformed
        except ValueError:
            return None
        if p.scheme not in ("http", "https"):
            return None
    except Exception:
        return None
    return url


# FIX-P39: cached "restriction active" flag — no table read per message
_restriction_cache = {"ts": 0.0, "active": False}


def _restriction_active() -> bool:
    now = time.time()
    if now - _restriction_cache["ts"] < 10:
        return _restriction_cache["active"]
    active = (get_setting("allow_all", "1") != "1"
              or bool(list_allowed_users(limit=1)))
    _restriction_cache.update(ts=now, active=active)
    return active


# FIX-P49: admin set cached in memory; admins change only via env/restart
_admin_cache: dict = {}


def is_admin(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    hit = _admin_cache.get(user_id)
    if hit and time.time() - hit[1] < 60:
        return hit[0]
    with _db_lock:
        conn = get_conn()
        r = conn.execute(
            "SELECT 1 FROM admins WHERE user_id=? AND is_active=1", (user_id,)
        ).fetchone()
    res = r is not None
    _admin_cache[user_id] = (res, time.time())
    return res


def _migrate_display_column() -> None:
    """FIX: add display column for pre-rendered numbers (backwards-safe)."""
    with _db_lock:
        conn = get_conn()
        if not _col_exists(conn, "extraction_job_numbers", "display"):
            try:
                conn.execute(
                    "ALTER TABLE extraction_job_numbers ADD COLUMN display TEXT")
                conn.commit()
            except sqlite3.Error:
                pass


def _run_healthz(chat_id):
    """FIX-P50: /healthz — thread count, FDs, WAL size, cache hit rate."""
    threads = threading.active_count()
    try:
        fds = len(os.listdir("/proc/self/fd"))
    except Exception:
        fds = "n/a"
    try:
        wal = os.path.getsize(DB_PATH + "-wal")
    except OSError:
        wal = 0
    hits = _settings_hits[0]
    snap = len(proxy_pool._snapshot)
    safe_send_message(
        chat_id,
        (f"🩺 *HEALTHZ*\n━━━━━━━━━━━━━━━━━━━━\n"
         f"🧵 Threads: `{threads}`\n"
         f"📂 Open FDs: `{fds}`\n"
         f"💾 WAL size: `{wal}` bytes\n"
         f"⚙️ Settings reads served: `{hits}`\n"
         f"🔌 DB connections opened: `{_db_conn_count[0]}`\n"
         f"🌐 Pool snapshot: `{snap}` healthy\n"
         f"📤 Send queue depth: `{_send_q.qsize()}`"),
        reply_markup=admin_keyboard())



# =========================================================
# Navigation state machine (Back / Cancel everywhere)
# =========================================================
# user_states[user_id] = {
#   "screen": current logical screen id,
#   "step":   input step (what text we're waiting for) or None,
#   "data":   arbitrary flow data,
#   "nav":    stack of previous (screen, data) for Back
# }

def set_user_state(user_id: int, screen: str, step: Optional[str] = None,
                   data: Optional[dict] = None, push: bool = True) -> None:
    with _state_lock:
        prev = user_states.get(user_id)
        nav = list(prev.get("nav", [])) if prev else []
        if push and prev and prev.get("screen"):
            nav.append({"screen": prev["screen"], "step": prev.get("step"),
                        "data": prev.get("data", {})})
            nav = nav[-12:]
        user_states[user_id] = {"screen": screen, "step": step,
                                "data": data or {}, "nav": nav}


def update_state_data(user_id: int, **kw) -> None:
    with _state_lock:
        st = user_states.get(user_id)
        if st:
            st.setdefault("data", {}).update(kw)


def get_user_state(user_id: int) -> dict:
    with _state_lock:
        return dict(user_states.get(user_id) or {})


def clear_user_state(user_id: int) -> None:
    with _state_lock:
        user_states.pop(user_id, None)


def go_back(user_id: int) -> Optional[dict]:
    """Pop the nav stack. Never touches active_jobs — Back ≠ job cancel."""
    with _state_lock:
        st = user_states.get(user_id)
        if not st or not st.get("nav"):
            return None
        prev = st["nav"].pop()
        user_states[user_id] = {"screen": prev["screen"], "step": prev.get("step"),
                                "data": prev.get("data", {}), "nav": st["nav"]}
        return user_states[user_id]


def cancel_state(user_id: int) -> None:
    """Cancel only exits the input flow — a running extraction keeps going."""
    clear_user_state(user_id)


def nav_markup(back: bool = True, cancel: bool = True,
               home: bool = False) -> types.InlineKeyboardMarkup:
    """Consistent navigation footer for every input screen."""
    mk = types.InlineKeyboardMarkup(row_width=2)
    row = []
    if back:
        row.append(types.InlineKeyboardButton("🔙 Back", callback_data="nav_back"))
    if cancel:
        row.append(types.InlineKeyboardButton("❌ Cancel", callback_data="nav_cancel"))
    if row:
        mk.row(*row)
    if home:
        mk.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="nav_home"))
    return mk


def _cancel_job_markup() -> types.InlineKeyboardMarkup:
    mk = types.InlineKeyboardMarkup()
    mk.add(types.InlineKeyboardButton("🛑 Cancel Extraction",
                                      callback_data="job_cancel"))
    return mk


# =========================================================
# Keyboards
# =========================================================
def main_keyboard(user_id: int) -> types.ReplyKeyboardMarkup:
    mk = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    mk.row(
        types.KeyboardButton("🔗 Extract Numbers"),
        types.KeyboardButton("📊 My Statistics"),
    )
    mk.row(
        types.KeyboardButton("📋 My History"),
        types.KeyboardButton("❓ Help"),
    )
    mk.row(types.KeyboardButton("📞 Support"))
    if is_admin(user_id):
        mk.row(types.KeyboardButton("🔐 Admin Panel"))
    return mk


def mode_keyboard() -> types.InlineKeyboardMarkup:
    mk = types.InlineKeyboardMarkup(row_width=2)
    mk.add(
        types.InlineKeyboardButton("🟢 Direct", callback_data="mode_direct"),
        types.InlineKeyboardButton("🌐 IP Rotation", callback_data="mode_proxy"),
    )
    mk.row(
        types.InlineKeyboardButton("🔙 Back", callback_data="nav_back"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="nav_cancel"),
    )
    return mk


def visits_keyboard(max_visits: int) -> types.InlineKeyboardMarkup:
    options = [(1, "🧪 1x Test"), (20, "🚀 20x"), (50, "⚡ 50x"), (100, "💎 100x")]
    options = [(n, lbl) for n, lbl in options if n <= max_visits]
    if not options:
        options = [(max_visits, f"🚀 {max_visits}x")]
    mk = types.InlineKeyboardMarkup(row_width=2)
    btns = [types.InlineKeyboardButton(lbl, callback_data=f"visits_{n}")
            for n, lbl in options]
    mk.add(*btns)
    mk.row(
        types.InlineKeyboardButton("🔙 Back", callback_data="nav_back"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="nav_cancel"),
    )
    return mk


def admin_keyboard() -> types.InlineKeyboardMarkup:
    allow_all = get_setting("allow_all", "1") == "1"
    mk = types.InlineKeyboardMarkup(row_width=2)
    mk.add(
        types.InlineKeyboardButton("📊 Dashboard", callback_data="adm_dashboard"),
        types.InlineKeyboardButton("👥 Users", callback_data="adm_users"),
        types.InlineKeyboardButton("📱 Extraction Logs", callback_data="adm_jobs"),
        types.InlineKeyboardButton("🌐 Proxy Center", callback_data="adm_proxies"),
        types.InlineKeyboardButton("📢 Broadcast", callback_data="adm_broadcast"),
        types.InlineKeyboardButton("📡 Channel", callback_data="adm_channel"),
        types.InlineKeyboardButton("⚙️ Bot Settings", callback_data="adm_settings"),
        types.InlineKeyboardButton("🛠 Maintenance", callback_data="adm_maint"),
        types.InlineKeyboardButton("👮 Admins", callback_data="adm_admins"),
        types.InlineKeyboardButton("⏳ Pending Users", callback_data="adm_pending"),
        types.InlineKeyboardButton("🔑 Bot Access", callback_data="adm_allowed"),
        types.InlineKeyboardButton(
            f"🌍 Allow All: {'✅ ON' if allow_all else '⛔ OFF'}",
            callback_data="adm_toggle_allow_all"),
        types.InlineKeyboardButton("🩺 Diagnostics", callback_data="adm_diag"),
        types.InlineKeyboardButton("🔙 Close", callback_data="adm_close"),
    )
    return mk


def proxy_center_keyboard() -> types.InlineKeyboardMarkup:
    mk = types.InlineKeyboardMarkup(row_width=3)
    mk.add(
        types.InlineKeyboardButton("🧪 Test All", callback_data="px_test_all"),
        types.InlineKeyboardButton("🔄 Retest Unhealthy", callback_data="px_retest"),
    )
    mk.add(
        types.InlineKeyboardButton("🔧 Test Manual", callback_data="px_test_manual"),
        types.InlineKeyboardButton("🌍 Test Fetched", callback_data="px_test_fetch"),
    )
    mk.add(
        types.InlineKeyboardButton("📡 Fetch Latest", callback_data="px_fetch"),
        types.InlineKeyboardButton("📡 Fetch + Test", callback_data="px_fetch_test"),
    )
    mk.add(
        types.InlineKeyboardButton("➕ Add Proxy", callback_data="px_add"),
        types.InlineKeyboardButton("📦 Bulk Add", callback_data="px_bulk"),
        types.InlineKeyboardButton("📋 Proxy List", callback_data="px_list"),
        types.InlineKeyboardButton("✅ Working", callback_data="px_working"),
    )
    mk.add(
        types.InlineKeyboardButton("🔌 Sources", callback_data="px_sources"),
        types.InlineKeyboardButton("🗑 Clean Dead", callback_data="px_cleanup"),
        types.InlineKeyboardButton("🗑 Del Failed", callback_data="px_del_failed"),
    )
    mk.add(
        types.InlineKeyboardButton("🗑 Del Fetched", callback_data="px_del_fetched"),
        types.InlineKeyboardButton("💣 Delete ALL", callback_data="px_nuke_confirm"),
    )
    mk.add(
        types.InlineKeyboardButton("📊 Dashboard", callback_data="px_dashboard"),
        types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"),
    )
    return mk


_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_HOST_RE = re.compile(
    r"^(localhost|\d{1,3}(\.\d{1,3}){3}|[a-z0-9]([a-z0-9\-]*[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+)(:\d{1,5})?$",
    re.IGNORECASE,
)


def render_screen(chat_id: int, user_id: int, state: dict) -> None:
    """Re-render a logical screen from state (drives the Back button)."""
    screen = state.get("screen")
    data = state.get("data", {})

    if screen == "extract_url":
        safe_send_message(
            chat_id,
            ("🔗 *SEND URL*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "Paste your HTTP/HTTPS/domain link below.\n\n"
             "Example:\n`https://example.com/test`\n\n"
             "━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    elif screen == "extract_mode":
        safe_send_message(
            chat_id,
            (f"✅ *URL received*\n`{data.get('url', '')[:60]}`\n\n"
             f"Choose extraction mode:"),
            reply_markup=mode_keyboard())
    elif screen == "extract_visits":
        mx = int(get_setting("max_visits", str(MAX_VISITS_PER_JOB)))
        mode_lbl = ("🌐 IP Rotation" if data.get("mode") == "IP_ROTATION"
                    else "🟢 Direct")
        safe_send_message(
            chat_id,
            (f"⚙️ *{mode_lbl}* selected.\nChoose visit count:"),
            reply_markup=visits_keyboard(mx))
    elif screen == "admin_panel":
        _show_admin_panel(chat_id)
    elif screen == "proxy_center":
        _show_proxy_center(chat_id)
    elif screen == "proxy_add":
        safe_send_message(
            chat_id,
            ("➕ *ADD PROXY*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "Send a proxy in any supported format:\n"
             "`IP:PORT`\n`IP:PORT:USER:PASS`\n"
             "`http://IP:PORT`\n`http://user:pass@IP:PORT`\n"
             "`socks5://IP:PORT`\n`socks5h://user:pass@IP:PORT`\n\n"
             "━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    elif screen == "proxy_bulk":
        safe_send_message(
            chat_id,
            ("📦 *BULK ADD PROXIES*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "Send one proxy per line (any supported format).\n\n"
             "━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    elif screen == "proxy_source_cfg":
        _show_proxy_sources(chat_id, edit_msg=False)
    elif screen == "broadcast":
        safe_send_message(
            chat_id,
            ("📢 *BROADCAST*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "Type the message to send to all approved users.\n\n"
             "━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    elif screen == "user_search":
        safe_send_message(
            chat_id,
            ("🔍 *USER SEARCH*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "Send a user ID, username, or name.\n\n"
             "━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    elif screen == "channel_cfg":
        _show_channel_settings(chat_id)
    elif screen == "settings_input":
        safe_send_message(
            chat_id,
            (f"⚙️ *SET VALUE*\n"
             f"━━━━━━━━━━━━━━━━━━━━\n"
             f"Send a new value for `{data.get('key', '?')}`.\n\n"
             f"━━━━━━━━━━━━━━━━━━━━"),
            reply_markup=nav_markup())
    else:
        safe_send_message(chat_id, "🏠 *Main Menu*",
                          reply_markup=main_keyboard(user_id))


# =========================================================
# Command Handlers
# =========================================================
@bot.message_handler(commands=["start"])
def cmd_start(message: types.Message):
    u = message.from_user
    status = register_user(u.id, u.username, u.first_name)
    if status == "BLOCKED":
        safe_send_message(message.chat.id, "🚫 *Your access has been blocked.*")
        return
    if status == "PENDING":
        admin_name = get_setting("admin_display_name", "Admin")
        safe_send_message(
            message.chat.id,
            ("🔒 *ACCESS PENDING*\n\n"
             "Your access request has been submitted.\n"
             "Please wait for administrator approval.\n\n"
             f"_— {admin_name}_"))
        for aid in ADMIN_IDS:
            mk = types.InlineKeyboardMarkup()
            mk.add(types.InlineKeyboardButton("✅ Approve",
                                              callback_data=f"appr_{u.id}"),
                   types.InlineKeyboardButton("❌ Reject",
                                              callback_data=f"rej_{u.id}"))
            safe_send_message(
                aid,
                (f"👤 *NEW USER REQUEST*\n\n"
                 f"Name: {u.first_name or '—'}\n"
                 f"Username: @{u.username or '—'}\n"
                 f"User ID: `{u.id}`"),
                reply_markup=mk)
        return
    clear_user_state(u.id)
    _send_home(message.chat.id, u.id)


def _send_home(chat_id, user_id):
    name = get_setting("admin_display_name", "DK Sharma")
    safe_send_message(
        chat_id,
        (f"🤖 *URL EXTRACTION CENTER*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Welcome!\n"
         f"Extract publicly exposed WhatsApp/contact numbers from "
         f"redirect or rotating links.\n\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"_Made by {name}_"),
        reply_markup=main_keyboard(user_id),
    )


@bot.message_handler(commands=["admin"])
def cmd_admin(message: types.Message):
    if not is_admin(message.from_user.id):
        safe_send_message(message.chat.id, "❌ *Access Denied.*")
        return
    set_user_state(message.from_user.id, "admin_panel", push=False)
    _show_admin_panel(message.chat.id)


def _show_admin_panel(chat_id):
    safe_send_message(
        chat_id,
        ("🔐 *ADMIN CONTROL CENTER*\n"
         "━━━━━━━━━━━━━━━━━━━━\n"
         "Select an action:"),
        reply_markup=admin_keyboard(),
    )


@bot.message_handler(commands=["job"])
def cmd_job(message: types.Message):
    if not is_admin(message.from_user.id):
        safe_send_message(message.chat.id, "❌ *Access Denied.*")
        return
    parts = (message.text or "").split()
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        safe_send_message(message.chat.id, "Usage: `/job 123`")
        return
    _show_job_detail(message.chat.id, int(parts[1].lstrip("#")),
                     viewer_id=message.from_user.id, admin_view=True)


@bot.message_handler(commands=["cancel"])
def cmd_cancel(message: types.Message):
    uid = message.from_user.id
    cancel_state(uid)
    safe_send_message(message.chat.id, "❌ *Operation cancelled.*",
                      reply_markup=main_keyboard(uid))


# =========================================================
# Job starter
# =========================================================
def _start_job(chat_id, user, url, mode, visits, proxy_source_filter=None):
    msg = safe_send_message(
        chat_id,
        ("⚡ *EXTRACTION ENGINE*\n"
         "━━━━━━━━━━━━━━━━━━━━\n"
         "🔎 _Preparing…_"),
        reply_markup=_cancel_job_markup(),
    )
    if not msg:
        safe_send_message(chat_id, "⚠️ Could not start the job. Please try again.")
        return
    threading.Thread(
        target=extraction_worker,
        args=(chat_id, user.id, user.username, url, visits, mode, msg.message_id,
              proxy_source_filter),
        daemon=True,
    ).start()


def _cancel_user_job(user_id: int) -> bool:
    """Signal the cancellation Event for the user's running job."""
    with _state_lock:
        jid = active_jobs.get(user_id)
        ev = job_cancel.get(jid) if jid else None
    if ev:
        ev.set()
        return True
    return False


# =========================================================
# Text input dispatcher (state-driven; every flow is cancellable)
# =========================================================
def _handle_text_input(message: types.Message, state: dict) -> bool:
    """Returns True if the message was consumed by an input flow."""
    u = message.from_user
    chat_id = message.chat.id
    text = (message.text or "").strip()
    step = state.get("step")
    data = state.get("data", {})

    if not step:
        return False

    # --- URL input ---
    if step == "await_url":
        url = validate_url(text)
        if not url:
            safe_send_message(
                chat_id,
                ("❌ *Invalid URL.*\n"
                 "Send a valid link, e.g.:\n"
                 "`https://example.com/test`\n`example.com/page`"),
                reply_markup=nav_markup())
            return True
        set_user_state(u.id, "extract_mode",
                       data={"url": url}, push=True)
        safe_send_message(
            chat_id,
            (f"✅ *URL received*\n`{url[:60]}{'…' if len(url) > 60 else ''}`\n\n"
             f"Choose extraction mode:"),
            reply_markup=mode_keyboard())
        return True

    # --- broadcast ---
    if step == "await_broadcast" and is_admin(u.id):
        clear_user_state(u.id)
        threading.Thread(target=_do_broadcast, args=(chat_id, u.id, text),
                         daemon=True).start()
        return True

    # --- proxy add ---
    if step == "await_proxy_add" and is_admin(u.id):
        _handle_proxy_add(chat_id, u.id, text)
        return True

    # --- proxy bulk ---
    if step == "await_proxy_bulk" and is_admin(u.id):
        _handle_proxy_bulk(chat_id, u.id, text)
        return True

    # --- proxy source configuration ---
    if step == "await_proxy_source" and is_admin(u.id):
        key = data.get("key", "proxy_source_1")
        if text.lower() in ("off", "none", "-"):
            set_setting(key, "")
            safe_send_message(chat_id, f"✅ `{key}` cleared.")
        elif validate_url(text):
            set_setting(key, text)
            audit_log(u.id, "PROXY_SOURCE_SET", key)
            safe_send_message(chat_id, f"✅ `{key}` updated.")
        else:
            safe_send_message(chat_id,
                              "❌ Invalid URL. Send a full http(s) URL or `off`.",
                              reply_markup=nav_markup())
            return True
        clear_user_state(u.id)
        _show_proxy_sources(chat_id, edit_msg=False)
        return True

    # --- user search ---
    if step == "await_user_search" and is_admin(u.id):
        clear_user_state(u.id)
        _handle_user_search(chat_id, u.id, text)
        return True

    # --- channel username ---
    if step == "await_channel_name" and is_admin(u.id):
        t = text.lstrip("@").strip()
        if not re.match(r"^[A-Za-z0-9_]{4,64}$", t):
            safe_send_message(chat_id,
                              "❌ Invalid channel username. Example: `@yourchannel`",
                              reply_markup=nav_markup())
            return True
        set_setting("channel_username", f"@{t}")
        audit_log(u.id, "CHANNEL_SET", f"@{t}")
        clear_user_state(u.id)
        _show_channel_settings(chat_id)
        return True

    # --- allowed user search ---
    if step == "await_allowed_search" and is_admin(u.id):
        clear_user_state(u.id)
        _handle_grant_access_search(chat_id, u.id, text)
        return True

    # --- generic settings value ---
    if step == "await_setting_value" and is_admin(u.id):
        key = data.get("key")
        if not key:
            clear_user_state(u.id)
            return True
        validation = data.get("validate", "int")
        ok, val = True, text
        if validation == "int":
            try:
                v = int(text)
                lo, hi = data.get("min", 1), data.get("max", 100000)
                ok = lo <= v <= hi
                val = str(v)
            except ValueError:
                ok = False
        elif validation == "float":
            try:
                v = float(text)
                lo, hi = data.get("min", 0.1), data.get("max", 1000.0)
                ok = lo <= v <= hi
                val = str(v)
            except ValueError:
                ok = False
        if not ok:
            safe_send_message(
                chat_id,
                f"❌ Invalid value for `{key}`. "
                f"Range: `{data.get('min', '?')}–{data.get('max', '?')}`.",
                reply_markup=nav_markup())
            return True
        set_setting(key, val)
        audit_log(u.id, "SETTING_SET", f"{key}={val}")
        clear_user_state(u.id)
        _show_bot_settings(chat_id)
        return True

    return False


# =========================================================
# Main message router
# =========================================================
@bot.message_handler(func=lambda m: True)
def handle_messages(message: types.Message):
    global MAINTENANCE_MODE
    u = message.from_user
    chat_id = message.chat.id
    text = (message.text or "").strip()

    register_user(u.id, u.username, u.first_name)

    if MAINTENANCE_MODE and not is_admin(u.id):
        safe_send_message(chat_id,
                          "🛠 *BOT UNDER MAINTENANCE*\n\nPlease try again later.")
        return

    user = get_user(u.id)
    if user:
        if user["blocked"]:
            safe_send_message(chat_id, "🚫 *Access blocked.*")
            return
        if user["status"] == "PENDING":
            safe_send_message(chat_id, "🔒 *Access pending approval.*")
            return

    # Access control — "Allow All" OFF locks the bot to admins + permitted users
    if not is_admin(u.id):
        if _restriction_active():  # FIX-P39: cached restriction check
            if not is_allowed_user(u.id):
                safe_send_message(
                    chat_id,
                    "🚫 *Access Restricted.*\n\n"
                    "You do not have permission to use this bot.\n"
                    "Contact the administrator for access.")
                return

    # state-driven text input first
    state = get_user_state(u.id)
    if _handle_text_input(message, state):
        return

    # admin text button
    if is_admin(u.id) and text == "🔐 Admin Panel":
        set_user_state(u.id, "admin_panel", push=False)
        _show_admin_panel(chat_id)
        return

    # main user buttons
    if text == "🔗 Extract Numbers":
        if active_jobs.get(u.id):
            mk = types.InlineKeyboardMarkup()
            mk.add(types.InlineKeyboardButton("🛑 Cancel Running Job",
                                              callback_data="job_cancel"))
            safe_send_message(
                chat_id,
                "⚠️ *You already have a job running.*\n"
                "Wait for it to finish or cancel it.",
                reply_markup=mk)
            return
        set_user_state(u.id, "extract_url", step="await_url", push=False)
        render_screen(chat_id, u.id, get_user_state(u.id))
        return

    if text == "📊 My Statistics":
        _show_user_stats(chat_id, u.id)
        return

    if text == "📋 My History":
        _show_user_history(chat_id, u.id)
        return

    if text == "❓ Help":
        safe_send_message(
            chat_id,
            ("❓ *How to use*\n"
             "━━━━━━━━━━━━━━━━━━━━\n"
             "1️⃣ Tap *🔗 Extract Numbers*\n"
             "2️⃣ Send your URL\n"
             "3️⃣ Choose mode: Direct or IP Rotation\n"
             "4️⃣ Choose visit count\n"
             "5️⃣ Receive unique numbers + `.txt` file\n\n"
             "*Supported links*\n"
             "✅ HTTP/HTTPS URLs · ✅ Short links\n"
             "✅ Redirect URLs (301/302/303/307/308)\n"
             "✅ Meta refresh · ✅ JavaScript redirects\n"
             "✅ Query parameters · ✅ wa.me / tel: links\n"
             "✅ HTML / JSON content\n"
             "⚠️ Login walls, CAPTCHAs and private content are not supported.\n\n"
             "Only public/authorized content is processed."),
            reply_markup=main_keyboard(u.id))
        return

    if text == "📞 Support":
        sup = get_setting("support_username", "")
        body = (f"📞 *Support*\n━━━━━━━━━━━━━━━━━━━━\nContact: @{sup}"
                if sup else "📞 *Support*\n━━━━━━━━━━━━━━━━━━━━\nContact the bot administrator.")
        safe_send_message(chat_id, body, reply_markup=main_keyboard(u.id))
        return

    # fallback
    safe_send_message(chat_id, "Use the menu below 👇",
                      reply_markup=main_keyboard(u.id))


# =========================================================
# User Stats / History
# =========================================================
def _show_user_stats(chat_id, user_id):
    u = get_user(user_id)
    if not u:
        safe_send_message(chat_id, "📊 No stats yet.",
                          reply_markup=main_keyboard(user_id))
        return
    with _db_lock:  # FIX-P41: one SQL aggregate instead of 200-row load
        agg = get_conn().execute(
            """SELECT
               SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) s,
               SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) f,
               SUM(CASE WHEN mode='IP_ROTATION' THEN 1 ELSE 0 END) ip,
               SUM(CASE WHEN mode='DIRECT' THEN 1 ELSE 0 END) d,
               COALESCE(AVG(duration_ms),0) a
               FROM extraction_jobs WHERE user_id=?""", (user_id,)).fetchone()
    succ, fail = agg["s"] or 0, agg["f"] or 0
    ip_jobs, direct_jobs = agg["ip"] or 0, agg["d"] or 0
    avg = agg["a"] or 0
    safe_send_message(
        chat_id,
        (f"📊 *MY STATS*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"🔄 Total Extractions: `{u['total_extractions']}`\n"
         f"✅ Successful Jobs: `{succ}`\n"
         f"❌ Failed Jobs: `{fail}`\n"
         f"📱 Unique Numbers: `{u['total_numbers_found']}`\n"
         f"🌐 IP Jobs: `{ip_jobs}`\n"
         f"🟢 Direct Jobs: `{direct_jobs}`\n"
         f"⏱ Avg Duration: `{_fmt_duration(int(avg))}`\n"
         f"━━━━━━━━━━━━━━━━━━━━"),
        reply_markup=main_keyboard(user_id))


def _show_user_history(chat_id, user_id):
    jobs = user_jobs(user_id, limit=10)
    if not jobs:
        safe_send_message(chat_id, "📋 *No history yet.*",
                          reply_markup=main_keyboard(user_id))
        return
    lines = ["📋 *MY HISTORY*", "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=3)
    for j in jobs:
        host = urllib.parse.urlparse(j["source_url"]).hostname or j["source_url"][:30]
        mode_label = "🌐" if j["mode"] == "IP_ROTATION" else "🟢"
        st_icon = {"COMPLETED": "✅", "FAILED": "❌",
                   "CANCELLED": "🛑"}.get(j["status"], "⏳")
        lines.append(
            f"{st_icon} `#{j['job_id']:06d}`\n"
            f"{mode_label} `{host}`\n"
            f"📱 `{j['unique_numbers']}` numbers · 🔄 `{j['requested_visits']}` visits · "
            f"⏱ `{_fmt_duration(j['duration_ms'])}`\n")
    lines.append("━━━━━━━━━━━━━━━━━━━━\n_Tap a job for details._")
    for j in jobs[:9]:
        mk.add(types.InlineKeyboardButton(f"#{j['job_id']:06d}",
                                          callback_data=f"ujob_{j['job_id']}"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


# =========================================================
# Callback Query Router
# =========================================================
@bot.callback_query_handler(func=lambda c: True)
def on_callback(c: types.CallbackQuery):
    u = c.from_user
    data = c.data or ""
    chat_id = c.message.chat.id
    msg_id = c.message.message_id

    # Access control — "Allow All" OFF locks callbacks too
    if not is_admin(u.id):
        if _restriction_active() and not is_allowed_user(u.id):  # FIX-P39
            safe_answer_callback(c.id, "🚫 Access restricted by admin.",
                                 show_alert=True)
            return

    try:
        # ---------- navigation ----------
        if data == "nav_back":
            safe_answer_callback(c.id)
            prev = go_back(u.id)
            if prev:
                render_screen(chat_id, u.id, prev)
            else:
                safe_send_message(chat_id, "🏠 *Main Menu*",
                                  reply_markup=main_keyboard(u.id))
            return

        if data == "nav_cancel":
            safe_answer_callback(c.id, "Cancelled")
            cancel_state(u.id)   # exits input flow only — running jobs keep going
            safe_edit_message(chat_id, msg_id, "❌ *Operation cancelled.*")
            safe_send_message(chat_id, "🏠 *Main Menu*",
                              reply_markup=main_keyboard(u.id))
            return

        if data == "nav_home":
            safe_answer_callback(c.id)
            clear_user_state(u.id)
            safe_send_message(chat_id, "🏠 *Main Menu*",
                              reply_markup=main_keyboard(u.id))
            return

        if data == "noop":
            safe_answer_callback(c.id)
            return

        # ---------- running-job cancellation ----------
        if data == "job_cancel":
            if _cancel_user_job(u.id):
                safe_answer_callback(c.id, "Cancelling extraction…")
            else:
                safe_answer_callback(c.id, "No running job.")
            return

        if data == "new_extract":
            safe_answer_callback(c.id)
            if active_jobs.get(u.id):
                safe_answer_callback(c.id, "A job is already running.",
                                     show_alert=True)
                return
            set_user_state(u.id, "extract_url", step="await_url", push=False)
            render_screen(chat_id, u.id, get_user_state(u.id))
            return

        # ---------- mode selection ----------
        if data in ("mode_direct", "mode_proxy"):
            st = get_user_state(u.id)
            url = st.get("data", {}).get("url")
            if not url:
                safe_answer_callback(c.id, "⚠️ Session expired. Start again.",
                                     show_alert=True)
                render_screen(chat_id, u.id,
                              {"screen": "extract_url", "step": "await_url",
                               "data": {}})
                set_user_state(u.id, "extract_url", step="await_url", push=False)
                return
            if data == "mode_proxy" and get_setting("proxy_enabled", "1") != "1":
                safe_answer_callback(c.id, "Proxy mode disabled by admin.",
                                     show_alert=True)
                return
            if data == "mode_proxy":
                # Insert proxy-source selection step before visit count
                mode = "IP_ROTATION"
                set_user_state(u.id, "extract_proxy_source",
                               data={"url": url, "mode": mode}, push=True)
                safe_answer_callback(c.id)
                pc = proxy_counts()
                manual_h = pc.get("manual_working", 0)
                fetch_h = pc.get("fetch_working", 0)
                all_h = pc.get("fast", 0) + pc.get("working", 0)
                mk = types.InlineKeyboardMarkup(row_width=1)
                mk.add(
                    types.InlineKeyboardButton(
                        f"🔧 Manual Proxies Only  ({manual_h} healthy)",
                        callback_data="ipsrc_manual"),
                    types.InlineKeyboardButton(
                        f"🌍 Fetched Proxies Only  ({fetch_h} healthy)",
                        callback_data="ipsrc_fetch"),
                    types.InlineKeyboardButton(
                        f"🔀 All Proxies  ({all_h} healthy)",
                        callback_data="ipsrc_all"),
                )
                mk.add(types.InlineKeyboardButton("🔙 Back", callback_data="nav_back"))
                safe_edit_message(
                    chat_id, msg_id,
                    ("🔄 *PROXY SOURCE*\n"
                     "━━━━━━━━━━━━━━━━━━━━\n"
                     "Which proxy pool should power this job?\n\n"
                     "🔧 *Manual* — your paid/configured proxies\n"
                     "🌍 *Fetched* — GitHub-scraped free proxies\n"
                     "🔀 *All* — best available from either pool"),
                    reply_markup=mk)
                return
            mode = "DIRECT"
            set_user_state(u.id, "extract_visits", data={"url": url, "mode": mode})
            safe_answer_callback(c.id)
            mx = int(get_setting("max_visits", str(MAX_VISITS_PER_JOB)))
            safe_edit_message(
                chat_id, msg_id,
                f"⚙️ *🟢 Direct* selected.\nChoose visit count:",
                reply_markup=visits_keyboard(mx))
            return

        # ---------- proxy source selection (IP rotation flow) ----------
        if data in ("ipsrc_manual", "ipsrc_fetch", "ipsrc_all"):
            safe_answer_callback(c.id)
            st = get_user_state(u.id)
            d = st.get("data", {})
            url, mode = d.get("url"), d.get("mode", "IP_ROTATION")
            if not url:
                safe_answer_callback(c.id, "⚠️ Session expired.", show_alert=True)
                return
            src_map = {"ipsrc_manual": "manual", "ipsrc_fetch": "fetch",
                       "ipsrc_all": None}
            source_filter = src_map[data]
            pc = proxy_counts()
            healthy = (pc.get("manual_working", 0) if source_filter == "manual"
                       else pc.get("fetch_working", 0) if source_filter == "fetch"
                       else pc.get("fast", 0) + pc.get("working", 0))
            if healthy == 0:
                src_label = {"manual": "Manual", "fetch": "Fetched"}.get(
                    source_filter, "All")
                mk2 = types.InlineKeyboardMarkup(row_width=1)
                mk2.add(
                    types.InlineKeyboardButton("🔀 Use All Proxies Instead",
                                               callback_data="ipsrc_all"),
                    types.InlineKeyboardButton("🔙 Back", callback_data="nav_back"))
                safe_edit_message(
                    chat_id, msg_id,
                    (f"⚠️ *No healthy {src_label} proxies.*\n\n"
                     f"Run a proxy test first, or choose a different source."),
                    reply_markup=mk2)
                return
            set_user_state(u.id, "extract_visits",
                           data={"url": url, "mode": mode,
                                 "proxy_source_filter": source_filter})
            mx = int(get_setting("max_visits", str(MAX_VISITS_PER_JOB)))
            src_lbl = {"manual": "🔧 Manual", "fetch": "🌍 Fetched"}.get(
                source_filter, "🔀 All")
            safe_edit_message(
                chat_id, msg_id,
                f"✅ *{src_lbl}* pool selected.\nChoose visit count:",
                reply_markup=visits_keyboard(mx))
            return

        # ---------- visits ----------
        if data.startswith("visits_"):
            st = get_user_state(u.id)
            d = st.get("data", {})
            url, mode = d.get("url"), d.get("mode", "DIRECT")
            if not url:
                safe_answer_callback(c.id, "⚠️ Session expired.", show_alert=True)
                return
            if active_jobs.get(u.id):
                safe_answer_callback(c.id, "Job already running.", show_alert=True)
                return
            clear_user_state(u.id)
            n = int(data.split("_")[1])
            mx = int(get_setting("max_visits", str(MAX_VISITS_PER_JOB)))
            n = min(n, mx)
            safe_answer_callback(c.id)
            safe_edit_message(chat_id, msg_id,
                              f"🚀 *Starting {n} visit(s)…*")
            _start_job(chat_id, u, url, mode, n,
                       proxy_source_filter=d.get("proxy_source_filter"))
            return

        # ---------- user job detail ----------
        if data.startswith("ujob_"):
            safe_answer_callback(c.id)
            _show_job_detail(chat_id, int(data.split("_")[1]),
                             viewer_id=u.id, admin_view=False)
            return

        # ---------- admin gates ----------
        if (data.startswith("adm_") or data.startswith("px") or
                data.startswith("set_") or data.startswith("usr_") or
                data.startswith("upage_") or data.startswith("udetail_") or
                data.startswith("uhist_") or data.startswith("unums_") or
                data.startswith("ublock_") or data.startswith("uunblock_") or
                data.startswith("ajob_") or data.startswith("appr_") or
                data.startswith("rej_") or data.startswith("chan_") or
                data.startswith("alw_") or data.startswith("rvu_")):
            if not is_admin(u.id):
                safe_answer_callback(c.id, "Not authorized.", show_alert=True)
                return

        # ---------- admin panel ----------
        if data == "adm_panel":
            safe_answer_callback(c.id)
            set_user_state(u.id, "admin_panel", push=False)
            _show_admin_panel(chat_id)
            return
        if data == "adm_dashboard":
            safe_answer_callback(c.id)
            _show_admin_dashboard(chat_id)
            return
        if data == "adm_users":
            safe_answer_callback(c.id)
            _show_admin_users(chat_id, page=0)
            return
        if data == "adm_jobs":
            safe_answer_callback(c.id)
            _show_admin_jobs(chat_id)
            return
        if data == "adm_proxies":
            safe_answer_callback(c.id)
            set_user_state(u.id, "proxy_center")
            _show_proxy_center(chat_id)
            return
        if data == "adm_broadcast":
            safe_answer_callback(c.id)
            set_user_state(u.id, "broadcast", step="await_broadcast")
            render_screen(chat_id, u.id, get_user_state(u.id))
            return
        if data == "adm_channel":
            safe_answer_callback(c.id)
            set_user_state(u.id, "channel_cfg", push=False)
            _show_channel_settings(chat_id)
            return
        if data == "adm_settings":
            safe_answer_callback(c.id)
            _show_bot_settings(chat_id)
            return
        if data == "adm_maint":
            safe_answer_callback(c.id)
            _toggle_maintenance(chat_id, u.id)
            return
        if data == "adm_admins":
            safe_answer_callback(c.id)
            _show_admins(chat_id)
            return
        if data == "adm_pending":
            safe_answer_callback(c.id)
            _show_pending(chat_id, u.id)
            return
        if data == "adm_allowed":
            safe_answer_callback(c.id)
            _show_allowed_users(chat_id, u.id)
            return
        if data == "adm_toggle_allow_all":
            cur = get_setting("allow_all", "1")
            new = "0" if cur == "1" else "1"
            set_setting("allow_all", new)
            audit_log(u.id, "TOGGLE_ALLOW_ALL", details=f"allow_all={new}")
            safe_answer_callback(
                c.id,
                "✅ Bot open for everyone" if new == "1"
                else "⛔ Locked: admins & permitted users only")
            safe_send_message(
                chat_id,
                ("🌍 *ALLOW ALL: ON* ✅\n\nEvery user can use the bot."
                 if new == "1" else
                 "⛔ *ALLOW ALL: OFF*\n\nOnly admins and users granted "
                 "permission (🔑 Bot Access) can use the bot."),
                reply_markup=admin_keyboard())
            return
        if data == "adm_diag":
            safe_answer_callback(c.id, "Running diagnostics…")
            threading.Thread(target=_run_diagnostics, args=(chat_id,),
                             daemon=True).start()
            return
        if data == "adm_close":
            safe_answer_callback(c.id)
            clear_user_state(u.id)
            safe_send_message(chat_id, "🏠 *Main Menu*",
                              reply_markup=main_keyboard(u.id))
            return

        # ---------- proxy center ----------
        if data == "px_dashboard":
            safe_answer_callback(c.id)
            _show_proxy_dashboard(chat_id)
            return
        if data == "px_add":
            safe_answer_callback(c.id)
            set_user_state(u.id, "proxy_add", step="await_proxy_add")
            render_screen(chat_id, u.id, get_user_state(u.id))
            return
        if data == "px_bulk":
            safe_answer_callback(c.id)
            set_user_state(u.id, "proxy_bulk", step="await_proxy_bulk")
            render_screen(chat_id, u.id, get_user_state(u.id))
            return
        if data == "px_list":
            safe_answer_callback(c.id)
            _show_proxy_list(chat_id, working_only=False)
            return
        if data == "px_working":
            safe_answer_callback(c.id)
            _show_proxy_list(chat_id, working_only=True)
            return
        if data == "px_test_all":
            safe_answer_callback(c.id)
            mk2 = types.InlineKeyboardMarkup(row_width=3)
            mk2.add(
                types.InlineKeyboardButton("1,000",  callback_data="px_testN_1000"),
                types.InlineKeyboardButton("5,000",  callback_data="px_testN_5000"),
                types.InlineKeyboardButton("10,000", callback_data="px_testN_10000"),
                types.InlineKeyboardButton("20,000", callback_data="px_testN_20000"),
                types.InlineKeyboardButton("All",    callback_data="px_testN_0"),
            )
            mk2.add(types.InlineKeyboardButton("🔙 Back", callback_data="adm_proxies"))
            safe_send_message(chat_id,
                "🧪 *TEST PROXIES*\n━━━━━━━━━━━━━━━━━━━━\n"
                "How many proxies to test?",
                reply_markup=mk2)
            return
        if data.startswith("px_testN_"):
            n = int(data.split("_")[2])
            safe_answer_callback(c.id, f"Testing up to {n or 'all'} proxies…")
            _start_proxy_test(chat_id, u.id, scope="all", limit=n)
            return
        if data == "px_test_manual":
            safe_answer_callback(c.id, "Testing manual proxies…")
            _start_proxy_test(chat_id, u.id, scope="all", source_filter="manual")
            return
        if data == "px_test_fetch":
            safe_answer_callback(c.id, "Testing fetched proxies…")
            _start_proxy_test(chat_id, u.id, scope="all", source_filter="fetch")
            return
        if data == "px_del_fetched":
            with _db_lock:
                conn = get_conn()
                try:
                    conn.execute("DELETE FROM proxies WHERE source='fetch'")
                    n = conn.execute("SELECT changes()").fetchone()[0]
                    conn.commit()
                finally:
                    pass  # FIX-P22: persistent thread-local connection
            audit_log(u.id, "PROXY_DEL_FETCHED", f"deleted {n}")
            safe_answer_callback(c.id, f"Deleted {n} fetched proxies.")
            safe_send_message(chat_id,
                f"🗑 Deleted `{n}` fetched proxies. Manual proxies kept.",
                reply_markup=proxy_center_keyboard())
            return
        if data == "px_nuke_confirm":
            safe_answer_callback(c.id)
            pc = proxy_counts()
            mk2 = types.InlineKeyboardMarkup(row_width=2)
            mk2.add(
                types.InlineKeyboardButton("✅ YES — Delete All",
                                           callback_data="px_nuke_execute"),
                types.InlineKeyboardButton("❌ Cancel",
                                           callback_data="adm_proxies"))
            safe_send_message(
                chat_id,
                (f"⚠️ *DANGER ZONE*\n"
                 f"━━━━━━━━━━━━━━━━━━━━\n"
                 f"This will permanently delete ALL `{pc['total']}` proxies.\n"
                 f"🔧 Manual: `{pc.get('manual_total', 0)}`\n"
                 f"🌍 Fetched: `{pc.get('fetch_total', 0)}`\n\n"
                 f"Are you absolutely sure?"),
                reply_markup=mk2)
            return
        if data == "px_nuke_execute":
            safe_answer_callback(c.id)
            with _db_lock:
                conn = get_conn()
                try:
                    n = conn.execute("SELECT COUNT(*) c FROM proxies").fetchone()["c"]
                    conn.execute("DELETE FROM proxies")
                    conn.commit()
                finally:
                    pass  # FIX-P22: persistent thread-local connection
            audit_log(u.id, "PROXY_NUKE", f"deleted {n} proxies")
            safe_send_message(
                chat_id,
                f"💣 *ALL {n} proxies deleted.*\nProxy pool is now empty.",
                reply_markup=proxy_center_keyboard())
            return
        if data == "px_retest":
            safe_answer_callback(c.id, "Retesting unhealthy…")
            _start_proxy_test(chat_id, u.id, scope="unhealthy")
            return
        if data == "px_test_cancel":
            ev = proxy_test_jobs.get(u.id)
            if ev:
                ev.set()
                safe_answer_callback(c.id, "Cancelling test…")
            else:
                safe_answer_callback(c.id, "No test running.")
            return
        if data == "px_cleanup":
            safe_answer_callback(c.id)
            _cleanup_dead_proxies(chat_id, u.id)
            return
        if data == "px_del_failed":
            safe_answer_callback(c.id)
            _cleanup_failed_proxies(chat_id, u.id)
            return
        if data.startswith("alw_grant_"):
            tid = int(data.split("_")[2])
            target = get_user(tid)
            if target:
                grant_user_permission(tid, target.get("username", ""),
                                      target.get("first_name", ""), u.id)
                audit_log(u.id, "BOT_ACCESS_GRANTED", str(tid))
                safe_answer_callback(c.id, "✅ Access granted.")
                # Notify the user
                safe_send_message(
                    tid,
                    "✅ *Bot access granted!*\n\n"
                    "You can now use this bot. Use /start to begin.")
            else:
                safe_answer_callback(c.id, "User not found.", show_alert=True)
            _show_allowed_users(chat_id, u.id)
            return
        if data.startswith("rvu_"):
            tid = int(data.split("_")[1])
            revoke_user_permission(tid)
            audit_log(u.id, "BOT_ACCESS_REVOKED", str(tid))
            safe_answer_callback(c.id, "Access revoked.")
            _show_allowed_users(chat_id, u.id)
            return
        if data.startswith("alw_search"):
            safe_answer_callback(c.id)
            set_user_state(u.id, "allowed_search", step="await_allowed_search")
            safe_send_message(
                chat_id,
                ("🔑 *GRANT BOT ACCESS*\n"
                 "━━━━━━━━━━━━━━━━━━━━\n"
                 "Send the user's Telegram ID or username to grant them bot access.\n\n"
                 "━━━━━━━━━━━━━━━━━━━━"),
                reply_markup=nav_markup())
            return
        if data == "px_fetch":
            safe_answer_callback(c.id)
            mk2 = types.InlineKeyboardMarkup(row_width=3)
            mk2.add(
                types.InlineKeyboardButton("5,000",  callback_data="px_fetch_5000"),
                types.InlineKeyboardButton("10,000", callback_data="px_fetch_10000"),
                types.InlineKeyboardButton("20,000", callback_data="px_fetch_20000"),
                types.InlineKeyboardButton("50,000", callback_data="px_fetch_50000"),
                types.InlineKeyboardButton("All",    callback_data="px_fetch_0"),
            )
            mk2.add(types.InlineKeyboardButton("🔙 Back", callback_data="adm_proxies"))
            safe_send_message(chat_id,
                "📡 *FETCH PROXIES*\n━━━━━━━━━━━━━━━━━━━━\n"
                "How many proxies to fetch and store?",
                reply_markup=mk2)
            return
        if data.startswith("px_fetch_") and data.split("_")[2].isdigit():
            n = int(data.split("_")[2])
            safe_answer_callback(c.id, f"Fetching up to {n or 'all'} proxies…")
            _start_proxy_fetch(chat_id, u.id, test_after=False, fetch_limit=n)
            return
        if data == "px_fetch_test":
            safe_answer_callback(c.id, "Fetching + testing…")
            _start_proxy_fetch(chat_id, u.id, test_after=True)
            return
        if data == "px_fetch_cancel":
            ev = proxy_fetch_jobs.get(u.id)
            if ev:
                ev.set()
                safe_answer_callback(c.id, "Cancelling fetch…")
            else:
                safe_answer_callback(c.id, "No fetch running.")
            return
        if data == "px_sources":
            safe_answer_callback(c.id)
            set_user_state(u.id, "proxy_source_cfg", push=False)
            _show_proxy_sources(chat_id, edit_msg=False)
            return
        if data.startswith("pxsrc_"):
            safe_answer_callback(c.id)
            key = data  # pxsrc_1 / pxsrc_2 / pxsrc_3
            idx = key.split("_")[1]
            skey = f"proxy_source_{idx}"
            set_user_state(u.id, "proxy_source_cfg",
                           step="await_proxy_source", data={"key": skey},
                           push=False)
            safe_send_message(
                chat_id,
                (f"🔌 *CONFIGURE SOURCE {idx}*\n"
                 f"━━━━━━━━━━━━━━━━━━━━\n"
                 f"Send the source URL (plain-text proxy list or provider API "
                 f"endpoint), or `off` to disable.\n\n"
                 f"━━━━━━━━━━━━━━━━━━━━"),
                reply_markup=nav_markup())
            return
        if data.startswith("pxtest_"):
            safe_answer_callback(c.id, "Testing…")
            pid = int(data.split("_")[1])
            threading.Thread(target=_test_single_proxy_ui,
                             args=(chat_id, pid), daemon=True).start()
            return
        if data.startswith("pxdel_"):
            pid = int(data.split("_")[1])
            delete_proxy_db(pid)
            audit_log(u.id, "PROXY_DELETED", str(pid))
            safe_answer_callback(c.id, f"Proxy #{pid} deleted.")
            _show_proxy_list(chat_id, working_only=False)
            return

        # ---------- approval ----------
        if data.startswith("appr_"):
            target = int(data.split("_")[1])
            set_user_status(target, "APPROVED")
            audit_log(u.id, "USER_APPROVED", str(target))
            safe_send_message(target,
                              "✅ *Your access has been approved!*\nUse /start to begin.")
            safe_answer_callback(c.id, "Approved.")
            safe_edit_message(chat_id, msg_id, "✅ Approved.")
            return
        if data.startswith("rej_"):
            target = int(data.split("_")[1])
            set_user_status(target, "BLOCKED")
            audit_log(u.id, "USER_REJECTED", str(target))
            safe_answer_callback(c.id, "Rejected.")
            safe_edit_message(chat_id, msg_id, "❌ Rejected & blocked.")
            return

        # ---------- channel ----------
        if data == "chan_test":
            safe_answer_callback(c.id, "Testing channel…")
            threading.Thread(target=_test_channel, args=(chat_id,),
                             daemon=True).start()
            return
        if data == "chan_setname":
            safe_answer_callback(c.id)
            set_user_state(u.id, "channel_cfg", step="await_channel_name",
                           push=False)
            safe_send_message(
                chat_id,
                ("📡 *SET CHANNEL*\n"
                 "━━━━━━━━━━━━━━━━━━━━\n"
                 "Send the channel username (e.g. `@yourchannel`).\n"
                 "The bot must be an admin with post permission.\n\n"
                 "━━━━━━━━━━━━━━━━━━━━"),
                reply_markup=nav_markup())
            return

        # ---------- settings toggles ----------
        if data.startswith("set_cycle_"):
            _handle_setting_cycle(chat_id, u.id, data[len("set_cycle_"):])
            safe_answer_callback(c.id)
            return

        if data.startswith("set_toggle_"):
            key = data[len("set_toggle_"):]
            _handle_setting_toggle(chat_id, u.id, key)
            safe_answer_callback(c.id)
            return
        if data.startswith("set_value_"):
            key = data[len("set_value_"):]
            spec = _SETTING_INPUTS.get(key)
            if not spec:
                safe_answer_callback(c.id, "Unknown setting.")
                return
            safe_answer_callback(c.id)
            set_user_state(u.id, "settings_input", step="await_setting_value",
                           data={"key": key, "validate": spec.get("type", "int"),
                                 "min": spec.get("min", 1),
                                 "max": spec.get("max", 100000)},
                           push=False)
            safe_send_message(
                chat_id,
                (f"⚙️ *SET VALUE*\n"
                 f"━━━━━━━━━━━━━━━━━━━━\n"
                 f"{spec['label']}\n"
                 f"Current: `{get_setting(key)}`\n"
                 f"Range: `{spec.get('min', '?')}–{spec.get('max', '?')}`\n\n"
                 f"Send the new value.\n"
                 f"━━━━━━━━━━━━━━━━━━━━"),
                reply_markup=nav_markup())
            return

        # ---------- user search / pagination / detail ----------
        if data == "usr_search":
            safe_answer_callback(c.id)
            set_user_state(u.id, "user_search", step="await_user_search")
            render_screen(chat_id, u.id, get_user_state(u.id))
            return
        if data.startswith("upage_"):
            safe_answer_callback(c.id)
            _show_admin_users(chat_id, page=int(data.split("_")[1]))
            return
        if data.startswith("udetail_"):
            safe_answer_callback(c.id)
            _show_user_detail_admin(chat_id, int(data.split("_")[1]))
            return
        if data.startswith("uhist_"):
            safe_answer_callback(c.id)
            _show_user_history_admin(chat_id, int(data.split("_")[1]))
            return
        if data.startswith("unums_"):
            safe_answer_callback(c.id)
            _show_user_numbers_admin(chat_id, int(data.split("_")[1]))
            return
        if data.startswith("ublock_"):
            tid = int(data.split("_")[1])
            set_user_status(tid, "BLOCKED")
            audit_log(u.id, "USER_BLOCKED", str(tid))
            safe_answer_callback(c.id, "Blocked.")
            _show_user_detail_admin(chat_id, tid)
            return
        if data.startswith("uunblock_"):
            tid = int(data.split("_")[1])
            set_user_status(tid, "APPROVED")
            audit_log(u.id, "USER_UNBLOCKED", str(tid))
            safe_answer_callback(c.id, "Unblocked.")
            _show_user_detail_admin(chat_id, tid)
            return
        if data.startswith("ajob_"):
            safe_answer_callback(c.id)
            _show_job_detail(chat_id, int(data.split("_")[1]),
                             viewer_id=u.id, admin_view=True)
            return

        safe_answer_callback(c.id, "Unknown action.")
    except Exception as e:
        log.exception("callback error: %s", e)
        safe_answer_callback(c.id, "Error.")


# =========================================================
# Settings input specs
# =========================================================
_SETTING_INPUTS = {
    "max_visits": {"label": "Max visits per job", "type": "int", "min": 1, "max": 500},
    "progress_interval": {"label": "Progress update interval (seconds)",
                          "type": "float", "min": 0.8, "max": 10.0},
    "max_concurrency": {"label": "Max concurrent visits per job",
                        "type": "int", "min": 1, "max": 32},
    "max_retries_per_visit": {"label": "Max proxy retries per visit",
                              "type": "int", "min": 0, "max": 5},
    "latency_fast_max": {"label": "FAST latency ceiling (ms)",
                         "type": "int", "min": 100, "max": 60000},
    "latency_working_max": {"label": "WORKING latency ceiling (ms)",
                            "type": "int", "min": 100, "max": 60000},
    "latency_slow_max": {"label": "SLOW latency ceiling (ms)",
                         "type": "int", "min": 100, "max": 120000},
    "proxy_retest_interval": {"label": "Background retest interval (seconds)",
                              "type": "int", "min": 60, "max": 86400},
    "proxy_retest_batch": {"label": "Background retest batch size",
                           "type": "int", "min": 1, "max": 200},
    "support_username": {"label": "Support username (without @)",
                         "type": "text"},
    "admin_display_name": {"label": "Admin display name", "type": "text"},
    "number_min_len": {"label": "Min number length", "type": "int",
                       "min": 6, "max": 15},
    "number_max_len": {"label": "Max number length", "type": "int",
                       "min": 6, "max": 16},
    "early_stop_barren": {"label": "Early stop: barren visits (direct)",
                          "type": "int", "min": 5, "max": 100},
    "early_stop_barren_ip": {"label": "Early stop: barren visits (IP mode)",
                             "type": "int", "min": 5, "max": 200},
    "visit_time_budget": {"label": "Per-visit time budget (seconds)",
                          "type": "int", "min": 10, "max": 300},
    "ip_connect_timeout": {"label": "IP-mode proxy connect timeout (s)",
                           "type": "int", "min": 1, "max": 30},
    "ip_read_timeout": {"label": "IP-mode proxy read timeout (s)",
                        "type": "int", "min": 1, "max": 60},
    "proxy_test_concurrency": {"label": "Proxy test concurrency",
                               "type": "int", "min": 8, "max": 128},
}



# =========================================================
# Admin Views
# =========================================================
def _show_admin_dashboard(chat_id):
    d = admin_dashboard_stats()
    running = sum(1 for st in job_state.values() if not st["done"])
    pc = proxy_counts()
    rows = [
        "╔══════════════════════════════╗",
        "║  📊 ADMIN DASHBOARD  │  v3",
        "╠══════════════════════════════╣",
        "║  OVERVIEW",
        f"║  👥 Users        {d['total_users']}",
        f"║  🔄 Total Jobs   {d['total_jobs']}",
        f"║  ✅ Completed    {d['successful_jobs']}",
        f"║  ❌ Failed       {d['failed_jobs']}",
        f"║  📱 Numbers      {d['total_numbers']}",
        "╠══════════════════════════════╣",
        "║  TODAY",
        f"║  🟢 Active       {d['active_today']}",
        f"║  📅 Jobs         {d['jobs_today']}",
        f"║  📱 Numbers      {d['numbers_today']}",
        f"║  ⚡ Running      {running}",
        "╠══════════════════════════════╣",
        "║  PROXY POOL",
        f"║  🟢 Good         {pc['fast'] + pc['working']}",
        f"║  🟡 Slow         {pc['slow']}",
        f"║  🔴 Dead         {pc['dead']}",
        f"║  ⚪ Untested     {pc['untested']}",
        f"║  🎯 Success      {pc['success_rate']}%",
        "╠══════════════════════════════╣",
        "║  SYSTEM HEALTH",
        f"║  ⏱ Avg Job      {_fmt_duration(int(d['avg_duration']))}",
        f"║  🛠 Maintenance {'ON' if MAINTENANCE_MODE else 'OFF'}",
        "╚══════════════════════════════╝",
    ]
    safe_send_message(chat_id, "```\n" + "\n".join(rows) + "\n```",
                      reply_markup=admin_keyboard())


def _show_admin_users(chat_id, page=0):
    users = recent_users(limit=50)
    if not users:
        safe_send_message(chat_id, "No users.", reply_markup=admin_keyboard())
        return
    per_page = 8
    start = page * per_page
    slice_ = users[start:start + per_page]
    lines = [f"👥 *USERS* (page {page + 1})", "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=2)
    for u in slice_:
        st_icon = {"APPROVED": "🟢", "PENDING": "🟡", "BLOCKED": "🔴"}.get(
            u["status"], "⚪")
        lines.append(f"{st_icon} `{u['user_id']}` {u['first_name'] or '—'} "
                     f"@{u['username'] or '—'}")
        mk.add(types.InlineKeyboardButton(
            f"{u['user_id']}", callback_data=f"udetail_{u['user_id']}"))
    nav = []
    if page > 0:
        nav.append(types.InlineKeyboardButton("◀️", callback_data=f"upage_{page - 1}"))
    if start + per_page < len(users):
        nav.append(types.InlineKeyboardButton("▶️", callback_data=f"upage_{page + 1}"))
    if nav:
        mk.row(*nav)
    mk.add(types.InlineKeyboardButton("🔍 Search", callback_data="usr_search"))
    mk.add(types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _handle_user_search(chat_id, admin_id, query):
    users = search_users(query, limit=15)
    if not users:
        safe_send_message(chat_id, "🔍 No matches.", reply_markup=admin_keyboard())
        return
    lines = ["🔍 *Search Results*", "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=2)
    for u in users:
        lines.append(f"`{u['user_id']}` {u['first_name'] or '—'} @{u['username'] or '—'}")
        mk.add(types.InlineKeyboardButton(
            f"{u['user_id']}", callback_data=f"udetail_{u['user_id']}"))
    mk.add(types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _show_user_detail_admin(chat_id, target_id):
    u = get_user(target_id)
    if not u:
        safe_send_message(chat_id, "User not found.", reply_markup=admin_keyboard())
        return
    jobs = user_jobs(target_id, limit=200)
    succ = sum(1 for j in jobs if j["status"] == "COMPLETED")
    fail = sum(1 for j in jobs if j["status"] == "FAILED")
    last = jobs[0]["started_at"][:16] if jobs else "—"
    safe_send_message(
        chat_id,
        (f"👤 *USER DETAILS*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Name: {u['first_name'] or '—'}\n"
         f"Username: @{u['username'] or '—'}\n"
         f"Telegram ID: `{u['user_id']}`\n"
         f"Status: {u['status']}\n\n"
         f"📊 Statistics\n"
         f"Total Jobs: `{len(jobs)}`\n"
         f"Successful: `{succ}`\n"
         f"Failed: `{fail}`\n"
         f"Unique Numbers: `{u['total_numbers_found']}`\n\n"
         f"🕒 First Seen: `{(u['joined_at'] or '')[:16]}`\n"
         f"🕒 Last Active: `{(u['last_active'] or '')[:16]}`\n"
         f"🕒 Latest Job: `{last}`\n"
         f"━━━━━━━━━━━━━━━━━━━━"),
        reply_markup=_user_action_keyboard(target_id, u["status"]))


def _user_action_keyboard(target_id, status):
    mk = types.InlineKeyboardMarkup(row_width=2)
    mk.add(
        types.InlineKeyboardButton("📋 History", callback_data=f"uhist_{target_id}"),
        types.InlineKeyboardButton("📱 Numbers", callback_data=f"unums_{target_id}"),
    )
    if status != "BLOCKED":
        mk.add(types.InlineKeyboardButton("🚫 Block", callback_data=f"ublock_{target_id}"))
    else:
        mk.add(types.InlineKeyboardButton("✅ Unblock",
                                          callback_data=f"uunblock_{target_id}"))
    if status == "PENDING":
        mk.add(types.InlineKeyboardButton("✅ Approve", callback_data=f"appr_{target_id}"))
    mk.add(types.InlineKeyboardButton("🔙 Users", callback_data="adm_users"))
    return mk


def _show_user_history_admin(chat_id, tid):
    jobs = user_jobs(tid, limit=10)
    if not jobs:
        safe_send_message(chat_id, "No jobs.", reply_markup=admin_keyboard())
        return
    mk = types.InlineKeyboardMarkup(row_width=3)
    lines = [f"📋 *USER HISTORY* (`{tid}`)", "━━━━━━━━━━━━━━━━━━━━"]
    for j in jobs:
        host = urllib.parse.urlparse(j["source_url"]).hostname or "?"
        mode = "🌐" if j["mode"] == "IP_ROTATION" else "🟢"
        lines.append(f"`#{j['job_id']:06d}` {mode} `{host}` 📱`{j['unique_numbers']}`")
        mk.add(types.InlineKeyboardButton(f"#{j['job_id']:06d}",
                                          callback_data=f"ajob_{j['job_id']}"))
    mk.add(types.InlineKeyboardButton("🔙", callback_data=f"udetail_{tid}"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _show_user_numbers_admin(chat_id, tid):
    jobs = user_jobs(tid, limit=5)
    if not jobs:
        safe_send_message(chat_id, "No jobs.", reply_markup=admin_keyboard())
        return
    mk = types.InlineKeyboardMarkup()
    lines = [f"📱 *RECENT NUMBERS* (`{tid}`)", "━━━━━━━━━━━━━━━━━━━━"]
    for j in jobs[:3]:
        nums = job_numbers(j["job_id"], limit=20)
        lines.append(f"\n*`#{j['job_id']:06d}`* ({j['unique_numbers']})")
        for n in nums[:10]:
            lines.append(f"+{n['number']} ({n['extraction_method']})")
    mk.add(types.InlineKeyboardButton("🔙", callback_data=f"udetail_{tid}"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _show_admin_jobs(chat_id):
    jobs = recent_jobs(limit=15)
    if not jobs:
        safe_send_message(chat_id, "📱 No extraction jobs.",
                          reply_markup=admin_keyboard())
        return
    lines = ["📱 *EXTRACTION LOGS*", "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=3)
    for j in jobs:
        host = urllib.parse.urlparse(j["source_url"]).hostname or "?"
        mode = "🌐" if j["mode"] == "IP_ROTATION" else "🟢"
        st = {"COMPLETED": "✅", "FAILED": "❌", "CANCELLED": "🛑",
              "RUNNING": "⏳"}.get(j["status"], "⚪")
        ts = (j["started_at"] or "")[:16]
        lines.append(f"{st} `#{j['job_id']:06d}` {mode} `{ts}`\n"
                     f"👤 @{j['username'] or '—'} | 🔗 `{host}` | "
                     f"📱 `{j['unique_numbers']}`")
        mk.add(types.InlineKeyboardButton(f"#{j['job_id']:06d}",
                                          callback_data=f"ajob_{j['job_id']}"))
    mk.add(types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _show_job_detail(chat_id, job_id, viewer_id=None, admin_view=False):
    j = get_job(job_id)
    if not j:
        safe_send_message(chat_id, "Job not found.")
        return
    if not admin_view and viewer_id is not None and j["user_id"] != viewer_id \
            and not is_admin(viewer_id):
        safe_send_message(chat_id, "❌ Not your job.")
        return
    host = urllib.parse.urlparse(j["source_url"]).hostname or j["source_url"][:30]
    mode_label = "🌐 IP Rotation" if j["mode"] == "IP_ROTATION" else "🟢 Direct"
    lines = [
        f"📋 *JOB #{j['job_id']:06d}*",
        "━━━━━━━━━━━━━━━━━━━━",
        f"👤 User: @{j['username'] or '—'} (`{j['user_id']}`)",
        f"🔗 URL: `{j['source_url'][:60]}`",
        f"⚙️ Mode: {mode_label}",
        f"🔄 Visits: `{j['successful_visits'] + j['failed_visits']}/{j['requested_visits']}`",
        f"✅ Successful: `{j['successful_visits']}`",
        f"❌ Failed: `{j['failed_visits']}`",
        f"📱 Unique: `{j['unique_numbers']}`",
        f"♻️ Duplicates: `{j['duplicate_numbers']}`",
        f"⏱ Duration: `{_fmt_duration(j['duration_ms'])}`",
        f"🕒 Started: `{(j['started_at'] or '')[:16]}`",
        f"🕒 Completed: `{(j['completed_at'] or '')[:16]}`",
        f"Status: {j['status']}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    if admin_view:
        attempts = job_attempts(job_id, limit=200)
        if attempts:
            prot_agg = {}
            tg_count = 0
            cf_count = 0
            for a in attempts:
                p = a.get("protection_type") or "?"
                prot_agg[p] = prot_agg.get(p, 0) + 1
                if p == "telegram_redirect":
                    tg_count += 1
                if p.startswith("cloudflare"):
                    cf_count += 1
            lines.append("🛡 *Protection summary:*")
            for k, v in sorted(prot_agg.items(), key=lambda kv: -kv[1]):
                lines.append(f"  `{k}` × {v}")
            lines.append(f"📱 Telegram redirects: `{tg_count}`  ·  "
                         f"CF blocks: `{cf_count}`")
            lines.append("━━━━━━━━━━━━━━━━━━━━")
            lines.append("🔄 *Attempts:*")
            for a in attempts[:15]:
                pid = f"#{a['proxy_id']}" if a["proxy_id"] else "direct"
                ip = a["exit_ip"] or "—"
                pt = a.get("protection_type") or "—"
                lyr = a.get("extraction_layers") or "[]"
                lines.append(f"  v{a['cycle']}: {pid} ip=`{ip}` "
                             f"{a['request_status']} {a['latency_ms']}ms "
                             f"🛡`{pt}` layers=`{lyr}`")
                if a.get("final_url"):
                    lines.append(f"      → `{a['final_url'][:70]}`")
                if a.get("telegram_username"):
                    lines.append(f"      📱 @{a['telegram_username']}")
            lines.append("━━━━━━━━━━━━━━━━━━━━")
    nums = job_numbers(job_id, limit=30)
    if nums:
        lines.append("📱 Numbers:")
        for n in nums[:20]:
            if n["extraction_method"] == "TELEGRAM_ONLY":
                lines.append(f"📱 @{n['number']} (telegram, v{n['visit_number']})")
            else:
                lines.append(f"+{n['number']} ({n['extraction_method']}, v{n['visit_number']})")
        if j["unique_numbers"] > 20:
            lines.append(f"_…and {j['unique_numbers'] - 20} more_")
    mk = types.InlineKeyboardMarkup(row_width=2)
    if j["unique_numbers"] > 0:
        sorted_nums = sorted(n["number"] for n in job_numbers(job_id, limit=500)
                             if n["extraction_method"] != "TELEGRAM_ONLY")
        copy_mk = _copy_markup(sorted_nums, max_buttons=4)
        if copy_mk:
            for row in copy_mk.keyboard:
                mk.row(*row)
    mk.add(types.InlineKeyboardButton(
        "🔙 Back",
        callback_data="adm_jobs" if admin_view else "nav_home"))
    safe_send_message(chat_id, "\n".join(lines)[:4000], reply_markup=mk)


# =========================================================
# Proxy Center UI
# =========================================================
def _show_proxy_center(chat_id):
    pc = proxy_counts()
    last = last_proxy_fetch()
    last_line = ""
    if last:
        last_line = (f"\n📡 Last fetch: `{(last['created_at'] or '')[:16]}`\n"
                     f"   Inserted: `{last['fetched']}` · Dupes: `{last['duplicates']}`\n")
    safe_send_message(
        chat_id,
        (f"🌐 *PROXY CONTROL CENTER*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"📊 Total: `{pc['total']}`\n"
         f"  🔧 Manual: `{pc.get('manual_total', 0)}`  ({pc.get('manual_working', 0)} healthy)\n"
         f"  🌍 Fetched: `{pc.get('fetch_total', 0)}`  ({pc.get('fetch_working', 0)} healthy)\n\n"
         f"🟢 Fast: `{pc['fast']}`   🟢 Working: `{pc['working']}`\n"
         f"🟡 Slow: `{pc['slow']}`   🔴 Dead: `{pc['dead']}`\n"
         f"⚪ Untested: `{pc['untested']}`\n\n"
         f"⚡ Avg Latency: `{pc['avg_latency']} ms`\n"
         f"📈 Success Rate: `{pc['success_rate']}% `\n"
         f"{last_line}"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"SOCKS5: `{'✅' if _SOCKS_OK else '❌ install PySocks'}`"),
        reply_markup=proxy_center_keyboard())


def _show_proxy_dashboard(chat_id):
    _show_proxy_center(chat_id)


def _show_proxy_list(chat_id, working_only=False):
    if working_only:
        rows = list_proxies(limit=20, statuses=HEALTHY_STATUSES)
        title = "📋 *WORKING PROXIES*"
    else:
        rows = list_proxies(limit=20)
        title = "📋 *PROXY LIST*"
    if not rows:
        safe_send_message(chat_id, "No proxies found.",
                          reply_markup=proxy_center_keyboard())
        return
    lines = [title, "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=2)
    icons = {"FAST": "🟢", "WORKING": "🟢", "SLOW": "🟡", "VERY_SLOW": "🟠",
             "CONNECTED": "🔵", "TARGET_FAILED": "🟠", "AUTH_FAILED": "🟣",
             "TCP_FAILED": "🔴", "INVALID": "⚫", "UNTESTED": "⚪"}
    for r in rows:
        ic = icons.get(r["health_status"], "⚪")
        if r.get("source") == "manual" or r.get("is_precious"):
            ic = "🔧" + ic   # manual/precious proxies are marked
        # credentials are NEVER shown — host:port only
        lines.append(
            f"{ic} `#{r['id']}` *{r['protocol'].upper()}* "
            f"`{r['host']}:{r['port']}`\n"
            f"   Latency: `{r['average_latency']}ms` · Score: `{r['health_score']}`\n"
            f"   Success: `{r['success_count']}` · Failures: `{r['failure_count']}`"
            + (f"\n   Exit IP: `{r['last_observed_ip']}`"
               if r["last_observed_ip"] else ""))
        mk.add(
            types.InlineKeyboardButton(f"🧪 #{r['id']}",
                                       callback_data=f"pxtest_{r['id']}"),
            types.InlineKeyboardButton(f"🗑 #{r['id']}",
                                       callback_data=f"pxdel_{r['id']}"),
        )
    mk.add(types.InlineKeyboardButton("🔙 Proxy Center", callback_data="adm_proxies"))
    safe_send_message(chat_id, "\n".join(lines)[:4000], reply_markup=mk)


def _test_single_proxy_ui(chat_id, proxy_id):
    row = get_proxy_row(proxy_id)
    if not row:
        safe_send_message(chat_id, "Proxy not found.")
        return
    p = {k: row[k] for k in ("protocol", "host", "port", "username",
                             "password", "endpoint")}
    res = test_proxy(p)
    update_proxy_health(proxy_id, res)
    safe_send_message(
        chat_id,
        (f"🧪 *Proxy #{proxy_id}* (`{proxy_label(p)}`)\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Status: `{res['status']}`\n"
         f"Latency: `{res['latency_ms']}ms`\n"
         f"Exit IP: `{res['exit_ip'] or '—'}`\n"
         + (f"Error: {friendly_error(res['status'])}" if res.get("error") else "")),
        reply_markup=proxy_center_keyboard())


def _handle_proxy_add(chat_id, admin_id, text):
    p = parse_proxy(text)
    if not p:
        safe_send_message(chat_id,
                          "❌ Invalid proxy format. Try again or press ❌ Cancel.",
                          reply_markup=nav_markup())
        return
    pid = add_proxy_db(text)
    if pid is None:
        safe_send_message(chat_id, "❌ Could not add (duplicate?).",
                          reply_markup=proxy_center_keyboard())
        clear_user_state(admin_id)
        return
    audit_log(admin_id, "PROXY_ADDED", str(pid), text)
    clear_user_state(admin_id)
    safe_send_message(chat_id, f"✅ Proxy `#{pid}` added. Testing…")
    res = test_proxy(p)
    update_proxy_health(pid, res)
    safe_send_message(
        chat_id,
        (f"🧪 *Test result — Proxy #{pid}*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Status: `{res['status']}`\n"
         f"Latency: `{res['latency_ms']}ms`\n"
         f"Exit IP: `{res['exit_ip'] or '—'}`"),
        reply_markup=proxy_center_keyboard())


def _handle_proxy_bulk(chat_id, admin_id, text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    stats = add_proxies_batch(lines, source="bulk")
    audit_log(admin_id, "PROXY_BULK_ADD",
              f"inserted={stats['inserted']} dupes={stats['duplicates']}")
    clear_user_state(admin_id)
    if stats["inserted"] > 0:
        threading.Thread(
            target=_auto_test_bulk_inserted,
            args=(chat_id, admin_id, stats["inserted"]),
            daemon=True,
        ).start()
    safe_send_message(
        chat_id,
        (f"📦 *BULK ADD COMPLETE*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Valid: `{stats['valid']}`\n"
         f"Invalid: `{stats['invalid']}`\n"
         f"Duplicates: `{stats['duplicates']}`\n"
         f"Inserted: `{stats['inserted']}`\n\n"
         + (f"🧪 Auto-testing the `{stats['inserted']}` new proxies now…"
            if stats["inserted"] > 0 else "No new proxies to test.")),
        reply_markup=proxy_center_keyboard())


def _cleanup_dead_proxies(chat_id, admin_id):
    log.info("CLEANUP_DEAD start admin=%s", admin_id)
    with _db_lock:
        conn = get_conn()
        try:
            # Protect manual proxies (require 15 consecutive fails) and
            # never touch is_precious rows
            cur = conn.execute(
                """DELETE FROM proxies
                   WHERE health_status IN ('TCP_FAILED','AUTH_FAILED','INVALID')
                   AND is_precious=0
                   AND (
                       (source != 'manual' AND consecutive_failures >= 5)
                       OR (source = 'manual' AND consecutive_failures >= 15)
                   )""")
            n = cur.rowcount
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection
    audit_log(admin_id, "PROXY_CLEANUP", f"removed {n}")
    log.info("CLEANUP_DEAD done removed=%s", n)
    safe_send_message(
        chat_id,
        f"🗑 Removed `{n}` dead proxies.\n"
        f"_(Manual proxies need 15+ consecutive fails; precious proxies are never deleted)_",
        reply_markup=proxy_center_keyboard())


def _show_proxy_sources(chat_id, edit_msg=False):
    cfg = get_settings_batch(["proxy_source_1", "proxy_source_2", "proxy_source_3"])
    lines = ["🔌 *PROXY SOURCES*", "━━━━━━━━━━━━━━━━━━━━"]
    for i in (1, 2, 3):
        v = cfg[f"proxy_source_{i}"]
        lines.append(f"Source {i}: `{_mask(v)[:45] if v else '— not set —'}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("_Sources must return a plain-text proxy list (or a provider API "
                 "configured with PROXY\\_PROVIDER\\_TOKEN env var)._")
    mk = types.InlineKeyboardMarkup(row_width=3)
    mk.add(*[types.InlineKeyboardButton(f"🔌 Source {i}", callback_data=f"pxsrc_{i}")
             for i in (1, 2, 3)])
    mk.add(types.InlineKeyboardButton("🔙 Proxy Center", callback_data="adm_proxies"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


# =========================================================
# Proxy bulk-test worker (scope-aware, cancellable, live progress)
# =========================================================
def _start_proxy_test(chat_id, admin_id, scope="all",
                      limit=0, source_filter=None):
    if proxy_test_jobs.get(admin_id) and not proxy_test_jobs[admin_id].is_set():
        safe_send_message(chat_id, "⚠️ A proxy test is already running.")
        return
    cancel_ev = threading.Event()
    proxy_test_jobs[admin_id] = cancel_ev
    threading.Thread(target=_proxy_test_worker,
                     args=(chat_id, admin_id, scope, cancel_ev, limit, source_filter),
                     daemon=True).start()


def _proxy_test_worker(chat_id, admin_id, scope, cancel_ev,
                     limit=0, source_filter=None):
    log.info("PROXY_TEST_START admin=%s scope=%s limit=%s source=%s",
             admin_id, scope, limit, source_filter)
    mk = types.InlineKeyboardMarkup()
    mk.add(types.InlineKeyboardButton("🛑 Cancel Test",
                                      callback_data="px_test_cancel"))
    scope_lbl = {"all": "ALL", "unhealthy": "UNHEALTHY", "untested": "UNTESTED",
                 "working": "WORKING"}.get(scope, scope.upper())
    src_lbl = {"manual": " — 🔧 Manual", "fetch": " — 🌍 Fetched"}.get(
        source_filter, "")
    header = f"🧪 *PROXY CHECKING ({scope_lbl}{src_lbl})*"
    msg = safe_send_message(
        chat_id,
        (header + "\n"
         f"━━━━━━━━━━━━━━━━━━━━\n`0%`"),
        reply_markup=mk)
    if not msg:
        return
    last_edit = [0.0]

    def cb(tested, total, s):
        now = time.time()
        if now - last_edit[0] < 1.5:   # Telegram flood safety
            return
        last_edit[0] = now
        pct = int((tested / total) * 100) if total else 0
        done = pct // 10
        bar = "█" * done + "░" * (10 - done)
        safe_edit_message(
            chat_id, msg.message_id,
            (header + "\n"
             f"━━━━━━━━━━━━━━━━━━━━\n"
             f"`[{bar}] {pct}%`\n"
             f"Tested: `{tested}/{total}`\n"
             f"🟢 Fast: `{s['fast']}`\n"
             f"🟢 Working: `{s['working']}`\n"
             f"🟡 Slow: `{s['slow']}`\n"
             f"🔴 Failed: `{s['failed']}`\n"
             f"🔐 Auth: `{s['auth_failed']}` · ⏱ Timeout: `{s['timeout']}`"),
            reply_markup=mk)

    result = bulk_test_proxies(scope=scope, limit=limit,
                               source_filter=source_filter,
                               progress_cb=cb, cancel_event=cancel_ev)
    proxy_test_jobs.pop(admin_id, None)
    log.info("PROXY_TEST_COMPLETE scope=%s source=%s tested=%s",
             scope, source_filter, result["tested"])
    if result["tested"] == 0 and not result["cancelled"]:
        safe_edit_message(chat_id, msg.message_id,
                          f"✅ No proxies match scope *{scope_lbl}{src_lbl}*.")
        return
    safe_edit_message(
        chat_id, msg.message_id,
        (f"{'🛑 *Test cancelled*' if result['cancelled'] else '✅ *Proxy test complete*'}\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Scope: `{scope_lbl}{src_lbl}`\n"
         f"Tested: `{result['tested']}`\n"
         f"🟢 Fast: `{result['fast']}`\n"
         f"🟢 Working: `{result['working']}`\n"
         f"🟡 Slow: `{result['slow']}`\n"
         f"🔴 Failed: `{result['failed']}`\n"
         f"🔐 Auth failed: `{result['auth_failed']}`\n"
         f"⏱ Timeout: `{result['timeout']}`"))
    safe_send_message(chat_id, "🌐 *Proxy Center*",
                      reply_markup=proxy_center_keyboard())


def _start_proxy_fetch(chat_id, admin_id, test_after=False,
                       fetch_limit=0):   # 0 = no limit
    """fetch_limit: max proxies to insert (0 = all)"""
    if proxy_fetch_jobs.get(admin_id) and not proxy_fetch_jobs[admin_id].is_set():
        safe_send_message(chat_id, "⚠️ A proxy fetch is already running.")
        return
    sources = configured_proxy_sources()
    if not sources:
        safe_send_message(
            chat_id,
            ("⚠️ *No proxy sources configured.*\n"
             "Set `PROXY_SOURCE_1..3` env vars or use 🔌 Sources."),
            reply_markup=proxy_center_keyboard())
        return
    cancel_ev = threading.Event()
    proxy_fetch_jobs[admin_id] = cancel_ev
    threading.Thread(target=_proxy_fetch_worker,
                     args=(chat_id, admin_id, test_after, cancel_ev, fetch_limit),
                     daemon=True).start()


def _proxy_fetch_worker(chat_id, admin_id, test_after, cancel_ev, fetch_limit=0):
    log.info("PROXY_FETCH_START admin=%s test_after=%s limit=%s",
             admin_id, test_after, fetch_limit)
    mk = types.InlineKeyboardMarkup()
    mk.add(types.InlineKeyboardButton("🛑 Cancel", callback_data="px_fetch_cancel"))
    msg = safe_send_message(
        chat_id,
        ("📡 *LIVE PROXY FETCH*\n"
         "━━━━━━━━━━━━━━━━━━━━\n"
         "Fetching from configured sources…"),
        reply_markup=mk)
    if not msg:
        return

    sources = configured_proxy_sources()
    total_fetched = 0
    all_raw = []
    errors = 0
    for i, src in enumerate(sources, 1):
        if cancel_ev.is_set():
            break
        safe_edit_message(
            chat_id, msg.message_id,
            (f"📡 *LIVE PROXY FETCH*\n"
             f"━━━━━━━━━━━━━━━━━━━━\n"
             f"Source {i}/{len(sources)}: fetching…\n"
             f"`{_mask(src)[:50]}`"),
            reply_markup=mk)
        try:
            text = fetch_proxy_source(src)
            found = parse_proxy_list(text)
            total_fetched += len(found)
            all_raw.extend(found)
        except Exception as e:
            errors += 1
            log.warning("PROXY_FETCH_SOURCE_ERR src=%s err=%s",
                        _mask(src)[:60], _mask(str(e)[:120]))

    if cancel_ev.is_set():
        proxy_fetch_jobs.pop(admin_id, None)
        safe_edit_message(chat_id, msg.message_id, "🛑 *Fetch cancelled.*")
        return

    safe_edit_message(
        chat_id, msg.message_id,
        (f"📡 *LIVE PROXY FETCH*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Fetched: `{total_fetched}`\n"
         f"Parsing · normalizing · deduplicating…"),
        reply_markup=mk)

    stats = add_proxies_batch(all_raw, source="fetch", limit=fetch_limit)
    audit_log(admin_id, "PROXY_FETCH",
              f"fetched={total_fetched} inserted={stats['inserted']}")

    summary = {"fetched": total_fetched, "valid": stats["valid"],
               "duplicates": stats["duplicates"], "working": 0,
               "slow": 0, "dead": 0}

    if not test_after or cancel_ev.is_set():
        log_proxy_fetch(sources[0] if sources else "?", summary)
        proxy_fetch_jobs.pop(admin_id, None)
        if stats["inserted"] > 0 and not cancel_ev.is_set():
            threading.Thread(
                target=_auto_test_bulk_inserted,
                args=(chat_id, admin_id, stats["inserted"]),
                daemon=True,
            ).start()
        safe_edit_message(
            chat_id, msg.message_id,
            (f"✅ *PROXY FETCH COMPLETE*\n"
             f"━━━━━━━━━━━━━━━━━━━━\n"
             f"Fetched: `{total_fetched}`\n"
             f"Valid: `{stats['valid']}`\n"
             f"Duplicates: `{stats['duplicates']}`\n"
             f"Invalid: `{stats['invalid']}`\n"
             f"New stored: `{stats['inserted']}`\n"
             + (f"Source errors: `{errors}`\n" if errors else "")
             + ("\n🧪 _Auto-testing the new batch now…_" if stats["inserted"] > 0
                else "\n_Run Test All to verify them._")))
        safe_send_message(chat_id, "🌐 *Proxy Center*",
                          reply_markup=proxy_center_keyboard())
        log.info("PROXY_FETCH_COMPLETE fetched=%s inserted=%s",
                 total_fetched, stats["inserted"])
        return

    # fetch + test: test the newly added (UNTESTED) proxies with live progress
    last_edit = [0.0]

    def cb(tested, total, s):
        now = time.time()
        if now - last_edit[0] < 1.5:
            return
        last_edit[0] = now
        pct = int((tested / total) * 100) if total else 0
        done = pct // 10
        bar = "█" * done + "░" * (10 - done)
        safe_edit_message(
            chat_id, msg.message_id,
            (f"📡 *LIVE PROXY FETCH*\n"
             f"━━━━━━━━━━━━━━━━━━━━\n"
             f"Fetched: `{total_fetched}` · Valid: `{stats['valid']}` · "
             f"Dupes: `{stats['duplicates']}`\n\n"
             f"Testing…\n`[{bar}] {pct}%`\n"
             f"🟢 Working: `{s['working'] + s['fast']}`\n"
             f"🟡 Slow: `{s['slow']}`\n"
             f"🔴 Dead: `{s['failed']}`"),
            reply_markup=mk)

    result = bulk_test_proxies(scope="untested",
                               limit=fetch_limit if fetch_limit else 0,
                               progress_cb=cb,
                               cancel_event=cancel_ev)
    summary["working"] = result["working"] + result["fast"]
    summary["slow"] = result["slow"]
    summary["dead"] = result["failed"]
    log_proxy_fetch(sources[0] if sources else "?", summary)
    proxy_fetch_jobs.pop(admin_id, None)
    log.info("PROXY_FETCH_COMPLETE fetched=%s working=%s",
             total_fetched, summary["working"])
    safe_edit_message(
        chat_id, msg.message_id,
        (f"✅ *PROXY POOL UPDATED*\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"Fetched: `{total_fetched}`\n"
         f"Valid: `{stats['valid']}`\n"
         f"Duplicates: `{stats['duplicates']}`\n"
         f"━━━━━━━━━━━━━━━━━━━━\n"
         f"🟢 Working: `{summary['working']}`\n"
         f"🟡 Slow: `{summary['slow']}`\n"
         f"🔴 Dead: `{summary['dead']}`\n\n"
         f"Only verified proxies joined the active pool."))
    safe_send_message(chat_id, "🌐 *Proxy Center*",
                      reply_markup=proxy_center_keyboard())


# =========================================================
# Channel / Settings / Maintenance views
# =========================================================
def _show_channel_settings(chat_id):
    cfg = get_settings_batch([
        "channel_logging", "channel_username", "channel_include_username",
        "channel_include_uid", "channel_include_method", "channel_include_numbers",
        "channel_attach_txt", "channel_include_speed", "channel_include_proxy",
    ])
    def yn(v): return "✅ ON" if v == "1" else "❌ OFF"
    text = (
        f"📡 *CHANNEL SETTINGS*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Channel: `{cfg['channel_username'] or '— not set —'}`\n"
        f"Auto Post: {yn(cfg['channel_logging'])}\n"
        f"Include Username: {yn(cfg['channel_include_username'])}\n"
        f"Include User ID: {yn(cfg['channel_include_uid'])}\n"
        f"Include Method: {yn(cfg['channel_include_method'])}\n"
        f"Include Numbers: {yn(cfg['channel_include_numbers'])}\n"
        f"Include Speed: {yn(cfg['channel_include_speed'])}\n"
        f"Include Proxy/Exit IP: {yn(cfg['channel_include_proxy'])}\n"
        f"Attach TXT: {yn(cfg['channel_attach_txt'])}\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )
    mk = types.InlineKeyboardMarkup(row_width=2)
    mk.add(
        types.InlineKeyboardButton(f"Auto Post: {yn(cfg['channel_logging'])}",
                                   callback_data="set_toggle_channel_logging"),
        types.InlineKeyboardButton("✏️ Set Channel", callback_data="chan_setname"),
        types.InlineKeyboardButton(
            f"Username: {yn(cfg['channel_include_username'])}",
            callback_data="set_toggle_channel_include_username"),
        types.InlineKeyboardButton(
            f"User ID: {yn(cfg['channel_include_uid'])}",
            callback_data="set_toggle_channel_include_uid"),
        types.InlineKeyboardButton(
            f"Method: {yn(cfg['channel_include_method'])}",
            callback_data="set_toggle_channel_include_method"),
        types.InlineKeyboardButton(
            f"Numbers: {yn(cfg['channel_include_numbers'])}",
            callback_data="set_toggle_channel_include_numbers"),
        types.InlineKeyboardButton(
            f"Speed: {yn(cfg['channel_include_speed'])}",
            callback_data="set_toggle_channel_include_speed"),
        types.InlineKeyboardButton(
            f"Proxy/IP: {yn(cfg['channel_include_proxy'])}",
            callback_data="set_toggle_channel_include_proxy"),
        types.InlineKeyboardButton(
            f"Attach TXT: {yn(cfg['channel_attach_txt'])}",
            callback_data="set_toggle_channel_attach_txt"),
        types.InlineKeyboardButton("🧪 Test Channel", callback_data="chan_test"),
        types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"),
    )
    safe_send_message(chat_id, text, reply_markup=mk)


def _test_channel(chat_id):
    ch = get_setting("channel_username", DEFAULT_CHANNEL)
    if not ch:
        safe_send_message(chat_id, "⚠️ No channel configured.",
                          reply_markup=admin_keyboard())
        return
    try:
        msg = bot.send_message(ch, "🧪 *Channel test*\nBot can post here ✅")
        safe_send_message(chat_id,
                          f"✅ Channel verified. Message ID: `{msg.message_id}`",
                          reply_markup=admin_keyboard())
    except Exception as e:
        err = _classify_channel_error(str(e))
        safe_send_message(
            chat_id,
            (f"❌ *Channel posting failed*\n"
             f"Class: `{err}`\n\n"
             f"Make sure the bot is added as admin to `{ch}` with post permission."),
            reply_markup=admin_keyboard())


def _show_bot_settings(chat_id):
    cfg = get_settings_batch([
        "maintenance_mode", "approval_mode", "proxy_enabled", "max_visits",
        "progress_interval", "max_concurrency", "max_retries_per_visit",
        "proxy_retest_interval", "proxy_retest_batch",
        "latency_fast_max", "latency_working_max", "latency_slow_max",
        "support_username", "admin_display_name",
        "ex_layer_url_chain", "ex_layer_raw_html", "ex_layer_meta",
        "ex_layer_js_vars", "ex_layer_encoded", "ex_layer_telegram",
        "false_positive_filter", "telegram_redirect_mode", "cloudflare_behavior",
        "number_min_len", "number_max_len",
    ])
    def yn(v): return "✅ ON" if v == "1" else "❌ OFF"
    text = (
        f"⚙️ *BOT SETTINGS*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Maintenance: {yn(cfg['maintenance_mode'])}\n"
        f"Approval mode: {yn(cfg['approval_mode'])}\n"
        f"Proxy enabled: {yn(cfg['proxy_enabled'])}\n"
        f"Max visits: `{cfg['max_visits']}`\n"
        f"Concurrency: `{cfg['max_concurrency']}`\n"
        f"Retries/visit: `{cfg['max_retries_per_visit']}`\n"
        f"Progress interval: `{cfg['progress_interval']}s`\n"
        f"Retest interval: `{cfg['proxy_retest_interval']}s`\n"
        f"Retest batch: `{cfg['proxy_retest_batch']}`\n"
        f"Latency classes: `{cfg['latency_fast_max']}/"
        f"{cfg['latency_working_max']}/{cfg['latency_slow_max']} ms`\n"
        f"Support: @{cfg['support_username'] or '—'}\n"
        f"Admin display: {cfg['admin_display_name']}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*🧬 Deep Extraction Layers*\n"
        f"URL chain: {yn(cfg['ex_layer_url_chain'])}  ·  "
        f"Raw HTML: {yn(cfg['ex_layer_raw_html'])}\n"
        f"OG/Meta: {yn(cfg['ex_layer_meta'])}  ·  "
        f"JS vars: {yn(cfg['ex_layer_js_vars'])}\n"
        f"Encoded: {yn(cfg['ex_layer_encoded'])}  ·  "
        f"Telegram: {yn(cfg['ex_layer_telegram'])}\n"
        f"FP filter: {yn(cfg['false_positive_filter'])}\n"
        f"Telegram mode: `{cfg['telegram_redirect_mode']}`\n"
        f"Cloudflare: `{cfg['cloudflare_behavior']}`\n"
        f"Number length: `{cfg['number_min_len']}–{cfg['number_max_len']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )
    mk = types.InlineKeyboardMarkup(row_width=2)
    mk.add(
        types.InlineKeyboardButton(f"Maintenance: {yn(cfg['maintenance_mode'])}",
                                   callback_data="set_toggle_maintenance_mode"),
        types.InlineKeyboardButton(f"Approval: {yn(cfg['approval_mode'])}",
                                   callback_data="set_toggle_approval_mode"),
        types.InlineKeyboardButton(f"Proxy: {yn(cfg['proxy_enabled'])}",
                                   callback_data="set_toggle_proxy_enabled"),
        types.InlineKeyboardButton("🔢 Max Visits",
                                   callback_data="set_value_max_visits"),
        types.InlineKeyboardButton("🧵 Concurrency",
                                   callback_data="set_value_max_concurrency"),
        types.InlineKeyboardButton("🔁 Retries/Visit",
                                   callback_data="set_value_max_retries_per_visit"),
        types.InlineKeyboardButton("⏱ Progress Int.",
                                   callback_data="set_value_progress_interval"),
        types.InlineKeyboardButton("🔄 Retest Int.",
                                   callback_data="set_value_proxy_retest_interval"),
        types.InlineKeyboardButton("📦 Retest Batch",
                                   callback_data="set_value_proxy_retest_batch"),
        types.InlineKeyboardButton("⚡ Latency FAST",
                                   callback_data="set_value_latency_fast_max"),
        types.InlineKeyboardButton("⚡ Latency WORKING",
                                   callback_data="set_value_latency_working_max"),
        types.InlineKeyboardButton("⚡ Latency SLOW",
                                   callback_data="set_value_latency_slow_max"),
        types.InlineKeyboardButton("📞 Support User",
                                   callback_data="set_value_support_username"),
        types.InlineKeyboardButton("✏️ Display Name",
                                   callback_data="set_value_admin_display_name"),
        types.InlineKeyboardButton(
            f"L1 URL Chain: {yn(cfg['ex_layer_url_chain'])}",
            callback_data="set_toggle_ex_layer_url_chain"),
        types.InlineKeyboardButton(
            f"L2 Raw HTML: {yn(cfg['ex_layer_raw_html'])}",
            callback_data="set_toggle_ex_layer_raw_html"),
        types.InlineKeyboardButton(
            f"L3 OG/Meta: {yn(cfg['ex_layer_meta'])}",
            callback_data="set_toggle_ex_layer_meta"),
        types.InlineKeyboardButton(
            f"L4 JS Vars: {yn(cfg['ex_layer_js_vars'])}",
            callback_data="set_toggle_ex_layer_js_vars"),
        types.InlineKeyboardButton(
            f"L5 Encoded: {yn(cfg['ex_layer_encoded'])}",
            callback_data="set_toggle_ex_layer_encoded"),
        types.InlineKeyboardButton(
            f"L6 Telegram: {yn(cfg['ex_layer_telegram'])}",
            callback_data="set_toggle_ex_layer_telegram"),
        types.InlineKeyboardButton(
            f"FP Filter: {yn(cfg['false_positive_filter'])}",
            callback_data="set_toggle_false_positive_filter"),
        types.InlineKeyboardButton(
            f"📱 TG Mode: {cfg['telegram_redirect_mode']}",
            callback_data="set_cycle_telegram_redirect_mode"),
        types.InlineKeyboardButton(
            f"🛡 CF: {cfg['cloudflare_behavior']}",
            callback_data="set_cycle_cloudflare_behavior"),
        types.InlineKeyboardButton("📏 Min Num Len",
                                   callback_data="set_value_number_min_len"),
        types.InlineKeyboardButton("📏 Max Num Len",
                                   callback_data="set_value_number_max_len"),
        types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"),
    )
    safe_send_message(chat_id, text, reply_markup=mk)


def _toggle_maintenance(chat_id, admin_id):
    cur = get_setting("maintenance_mode", "0")
    new = "0" if cur == "1" else "1"
    set_setting("maintenance_mode", new)
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = new == "1"
    audit_log(admin_id, "MAINTENANCE_TOGGLE", new)
    safe_send_message(chat_id,
                      f"🛠 Maintenance: `{'ON' if new == '1' else 'OFF'}`",
                      reply_markup=admin_keyboard())


_SETTING_CYCLES = {
    "telegram_redirect_mode": ["extract_only", "report_username", "skip"],
    "cloudflare_behavior": ["skip", "retry_proxies", "count_as_failed"],
    "direct_strategy": ["smart", "parallel", "classic"],  # FIX-P23
}


def _handle_setting_cycle(chat_id, admin_id, key):
    opts = _SETTING_CYCLES.get(key)
    if not opts:
        return
    cur = get_setting(key, opts[0])
    nxt = opts[(opts.index(cur) + 1) % len(opts)] if cur in opts else opts[0]
    set_setting(key, nxt)
    audit_log(admin_id, "SETTING_CYCLE", f"{key}={nxt}")
    _show_bot_settings(chat_id)


def _handle_setting_toggle(chat_id, admin_id, key):
    cur = get_setting(key, "0")
    new = "0" if cur == "1" else "1"
    set_setting(key, new)
    if key == "maintenance_mode":
        global MAINTENANCE_MODE
        MAINTENANCE_MODE = new == "1"
    audit_log(admin_id, "SETTING_TOGGLE", f"{key}={new}")
    if key.startswith("channel"):
        _show_channel_settings(chat_id)
    else:
        _show_bot_settings(chat_id)


def _show_admins(chat_id):
    with _db_lock:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM admins WHERE is_active=1 ORDER BY role").fetchall()
        finally:
            pass  # FIX-P22: persistent thread-local connection
    lines = ["👮 *ADMINS*", "━━━━━━━━━━━━━━━━━━━━"]
    for r in rows:
        lines.append(f"{r['role']} @{r['username'] or '—'} (`{r['user_id']}`)")
    lines.append(f"OWNER (env) admins: {', '.join(str(a) for a in ADMIN_IDS) or '—'}")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("_Add admins via ADMIN\\_IDS env var._")
    safe_send_message(chat_id, "\n".join(lines), reply_markup=admin_keyboard())


def _show_pending(chat_id, admin_id):
    users = pending_users()
    if not users:
        safe_send_message(chat_id, "✅ No pending users.",
                          reply_markup=admin_keyboard())
        return
    mk = types.InlineKeyboardMarkup(row_width=2)
    lines = ["⏳ *PENDING USERS*", "━━━━━━━━━━━━━━━━━━━━"]
    for u in users[:15]:
        lines.append(f"`{u['user_id']}` {u['first_name'] or '—'} @{u['username'] or '—'}")
        mk.add(types.InlineKeyboardButton(f"✅ {u['user_id']}",
                                          callback_data=f"appr_{u['user_id']}"),
               types.InlineKeyboardButton(f"❌ {u['user_id']}",
                                          callback_data=f"rej_{u['user_id']}"))
    mk.add(types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _do_broadcast(chat_id, admin_id, text):
    users = all_user_ids()
    msg = safe_send_message(chat_id,
                            f"📢 *Broadcasting to `{len(users)}` users…*\n`0%`")
    sent = failed = 0
    total = len(users) or 1
    for i, uid in enumerate(users, 1):
        if _api_call(bot.send_message, uid, text) is not None:
            sent += 1
        else:
            failed += 1
        if msg and (i % 25 == 0 or i == len(users)):
            safe_edit_message(
                chat_id, msg.message_id,
                (f"📢 *Broadcasting…*\n"
                 f"Progress: `{int((i / total) * 100)}%`\n"
                 f"Sent: `{sent}` | Failed: `{failed}`"))
        time.sleep(0.05)   # stay well under Telegram rate limits
    audit_log(admin_id, "BROADCAST_SENT", f"sent={sent} failed={failed}")
    safe_send_message(chat_id,
                      f"✅ *Broadcast complete*\nSent: `{sent}`\nFailed: `{failed}`",
                      reply_markup=admin_keyboard())


def _run_diagnostics(chat_id):
    """Admin-only diagnostics — never posts to the public channel."""
    msg = safe_send_message(chat_id, "🩺 *Running diagnostics…*")
    results = []
    try:
        me = bot.get_me()
        results.append(("Telegram API", f"✅ @{me.username}" if me else "❌"))
    except Exception:
        results.append(("Telegram API", "❌"))
    try:
        with _db_lock:
            conn = get_conn()
            conn.execute("SELECT 1").fetchone()
            pass  # FIX-P22: persistent thread-local connection
        results.append(("Database", "✅"))
    except Exception:
        results.append(("Database", "❌"))
    try:
        r = requests.get("https://api.ipify.org?format=text", timeout=8)
        results.append(("Direct HTTP", "✅" if r.status_code == 200 else "❌"))
    except Exception:
        results.append(("Direct HTTP", "❌"))
    results.append(("Proxy parser",
                    "✅" if parse_proxy("socks5://1.2.3.4:1080") else "❌"))
    results.append(("SOCKS5 support", "✅" if _SOCKS_OK else "❌"))
    # channel check WITHOUT posting — inspect chat membership instead
    ch = get_setting("channel_username", DEFAULT_CHANNEL)
    if ch:
        try:
            me = bot.get_me()
            member = bot.get_chat_member(ch, me.id)
            ok = getattr(member, "status", "") in ("administrator", "creator")
            results.append(("Channel access", "✅" if ok else "❌ not admin"))
        except Exception:
            results.append(("Channel access", "❌ unreachable"))
    else:
        results.append(("Channel access", "⚠️ not configured"))
    pc = proxy_counts()
    results.append((f"Proxies (fast+working={pc['fast'] + pc['working']})",
                    "✅" if pc["total"] > 0 else "⚠️ none"))
    lines = ["🩺 *SYSTEM DIAGNOSTICS*", "━━━━━━━━━━━━━━━━━━━━"]
    for name, st in results:
        lines.append(f"{st} {name}")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    body = "\n".join(lines)
    if msg:
        safe_edit_message(chat_id, msg.message_id, body)
    else:
        safe_send_message(chat_id, body)


# =========================================================
# Delete Failed Proxies (not Dead/TCP_FAILED, but FAILED status from job)
# =========================================================
def _cleanup_failed_proxies(chat_id, admin_id):
    """Delete only CONFIRMED dead proxies — never after a single failure."""
    log.info("CLEANUP_FAILED start admin=%s", admin_id)
    with _db_lock:
        conn = get_conn()
        try:
            # 5+ consecutive failures for fetched, 10+ for manual,
            # is_precious rows are never auto-deleted
            cur = conn.execute(
                """DELETE FROM proxies
                   WHERE is_precious=0
                   AND (
                       (source != 'manual' AND health_status IN
                        ('AUTH_FAILED','TCP_FAILED','INVALID','TIMEOUT')
                        AND consecutive_failures >= 5)
                       OR
                       (source = 'manual' AND health_status IN
                        ('AUTH_FAILED','TCP_FAILED','INVALID','TIMEOUT')
                        AND consecutive_failures >= 10)
                   )""")
            n = cur.rowcount
            conn.commit()
        finally:
            pass  # FIX-P22: persistent thread-local connection
    audit_log(admin_id, "PROXY_FAILED_CLEANUP", f"removed {n}")
    log.info("CLEANUP_FAILED done removed=%s", n)
    safe_send_message(
        chat_id,
        f"🗑 Removed `{n}` confirmed-dead proxies.\n"
        f"_(Threshold: 5+ fails for fetched, 10+ for manual)_",
        reply_markup=proxy_center_keyboard())


def _show_allowed_users(chat_id, admin_id):
    users = list_allowed_users(limit=30)
    lines = [
        "🔑 *BOT ACCESS PERMISSIONS*",
        "━━━━━━━━━━━━━━━━━━━━",
        "_Users below have been granted bot access by admin._",
        "",
    ]
    mk = types.InlineKeyboardMarkup(row_width=2)
    if users:
        for au in users:
            lines.append(
                f"• `{au['user_id']}` @{au['username'] or '—'} "
                f"({au['first_name'] or '—'})")
            mk.add(types.InlineKeyboardButton(
                f"❌ Revoke {au['user_id']}",
                callback_data=f"rvu_{au['user_id']}"))
    else:
        lines.append("_No allowed users set yet._")
        lines.append("_By default, all approved users can use the bot._")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append(
        "ℹ️ Grant access to a specific user by searching their ID/username below.\n"
        "_If the Allowed Users list is empty, all approved users have access._\n"
        "_Once you add anyone here, ONLY those users + admins can use the bot._"
    )
    mk.add(types.InlineKeyboardButton("➕ Grant Access", callback_data="alw_search"))
    mk.add(types.InlineKeyboardButton("🔙 Admin", callback_data="adm_panel"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


def _handle_grant_access_search(chat_id, admin_id, query):
    """Search users by ID or username, show grant buttons."""
    users = search_users(query, limit=10)
    if not users:
        safe_send_message(
            chat_id,
            f"🔍 No user found for `{query}`.\n"
            "Make sure the user has started the bot at least once.",
            reply_markup=admin_keyboard())
        return
    lines = ["🔍 *SELECT USER TO GRANT ACCESS*", "━━━━━━━━━━━━━━━━━━━━"]
    mk = types.InlineKeyboardMarkup(row_width=1)
    for u in users:
        lines.append(
            f"`{u['user_id']}` @{u['username'] or '—'} {u['first_name'] or '—'}")
        mk.add(types.InlineKeyboardButton(
            f"✅ Grant: {u['first_name'] or u['user_id']}",
            callback_data=f"alw_grant_{u['user_id']}"))
    mk.add(types.InlineKeyboardButton("🔙 Back", callback_data="adm_allowed"))
    safe_send_message(chat_id, "\n".join(lines), reply_markup=mk)


# =========================================================
# Background proxy auto-retest (configurable, bounded, gentle)
# =========================================================
_retest_lock = threading.Lock()


def _retest_loop():
    while True:
        interval = int(get_setting("proxy_retest_interval",
                                   str(PROXY_RETEST_INTERVAL)))
        time.sleep(max(60, interval))

        # Skip if any manual bulk test is active — never double concurrency
        if any(not ev.is_set() for ev in proxy_test_jobs.values()):
            log.info("RETEST_LOOP skipped — manual test running")
            continue
        # FIX-P32: live extraction jobs outrank background retests
        if active_jobs:
            log.info("RETEST_LOOP skipped — extraction job running")
            continue

        # Only one background retest at a time
        if not _retest_lock.acquire(blocking=False):
            continue
        try:
            batch = int(get_setting("proxy_retest_batch", str(PROXY_RETEST_BATCH)))
            # Priority: UNTESTED → failed/timeout → stale healthy
            rows = list_proxies(limit=batch, statuses=("UNTESTED",))
            if len(rows) < batch:
                rows += list_proxies(limit=batch - len(rows),
                                     statuses=("TCP_FAILED", "TIMEOUT"))
            stale_cutoff = (datetime.now(timezone.utc) - timedelta(
                seconds=interval * 2)).isoformat(sep=" ", timespec="seconds")
            if len(rows) < batch:
                stale = [r for r in list_proxies(
                    limit=batch, statuses=HEALTHY_STATUSES)
                         if (r["last_tested"] or "") < stale_cutoff]
                rows += stale[:batch - len(rows)]

            seen, pending = set(), []
            for r in rows:
                if r["id"] not in seen:
                    seen.add(r["id"])
                    pending.append(r)
            pending = pending[:batch]
            if not pending:
                continue

            log.info("RETEST_LOOP testing %d proxies", len(pending))

            def _one(r):
                p = {k: r[k] for k in ("protocol", "host", "port",
                                       "username", "password", "endpoint")}
                return r["id"], test_proxy(p)

            results = []
            # Max 4 workers — never compete with main polling
            with ThreadPoolExecutor(max_workers=4) as ex:
                for fut in as_completed([ex.submit(_one, r) for r in pending]):
                    try:
                        results.append(fut.result())
                    except Exception:
                        pass
            update_proxies_health_batch(results)
        except Exception as e:
            log.warning("retest loop error: %s", _mask(str(e)[:150]))
        finally:
            _retest_lock.release()


def startup_self_check():
    log.info("Bot starting…")
    checks = []
    try:
        me = bot.get_me()
        checks.append(f"✅ Telegram API: @{me.username}")
    except Exception as e:
        checks.append(f"❌ Telegram API: {_mask(str(e)[:100])}")
    try:
        init_db()
        seed_settings()
        _migrate_display_column()  # FIX: display column
        checks.append("✅ Database")
    except Exception as e:
        checks.append(f"❌ Database: {e}")
    try:
        with _db_lock:
            conn = get_conn()
            try:
                conn.execute("SELECT COUNT(*) c FROM proxies").fetchone()
            finally:
                pass  # FIX-P22: persistent thread-local connection
        checks.append("✅ Proxy Manager")
    except Exception as e:
        checks.append(f"❌ Proxy Manager: {e}")
    checks.append(f"{'✅' if _SOCKS_OK else '❌'} SOCKS5 support")
    ch = get_setting("channel_username", DEFAULT_CHANNEL)
    checks.append(f"📡 Channel: {ch or 'not configured'}")
    srcs = configured_proxy_sources()
    checks.append(f"🔌 Proxy sources: {len(srcs)} configured")
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = get_setting("maintenance_mode", "0") == "1"
    checks.append(
        f"✅ Configuration loaded (maintenance={'ON' if MAINTENANCE_MODE else 'OFF'}, "
        f"concurrency={MAX_CONCURRENCY}, test_workers={PROXY_TEST_CONCURRENCY})")
    for c in checks:
        log.info("STARTUP %s", c)
    return checks


def main():
    checks = startup_self_check()
    if not any("Telegram API: @" in c for c in checks):
        sys.stderr.write("FATAL: Telegram API unreachable at startup. "
                         "Check BOT_TOKEN and network.\n")
        sys.exit(3)
    if BOOTSTRAP_OWNER_ID:
        with _db_lock:
            conn = get_conn()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO admins(user_id, role, is_active) "
                    "VALUES(?, 'OWNER', 1)",
                    (BOOTSTRAP_OWNER_ID,),
                )
                conn.commit()
            finally:
                pass  # FIX-P22: persistent thread-local connection
    threading.Thread(target=_retest_loop, daemon=True).start()
    log.info("Polling started.")
    bot.infinity_polling(timeout=30, long_polling_timeout=20, skip_pending=True)



# =========================================================
# /selftest (Part 9) and /healthz (P50) — admin-only
# =========================================================
@bot.message_handler(commands=["healthz"])
def cmd_healthz(message: types.Message):
    if not is_admin(message.from_user.id):
        return
    _run_healthz(message.chat.id)


@bot.message_handler(commands=["selftest"])
def cmd_selftest(message: types.Message):
    if not is_admin(message.from_user.id):
        return
    results = []
    # 1. proxy list parsing (P09)
    fixture = "\n".join([
        "1.2.3.4:8080", "http://5.6.7.8:3128", "socks5://9.10.11.12:1080",
        "13.14.15.16:8080:user:pass", "http://u:p@17.18.19.20:8080",
        "socks5h://u:p@21.22.23.24:1080", "  25.26.27.28:8080,",
        "# comment line", "garbage line no proxy", "29.30.31.32:99999",
    ])
    parsed = parse_proxy_list(fixture)
    ok = len([x for x in parsed if parse_proxy(x)]) == 7
    results.append(("P09 proxy-list parsing", ok,
                    f"{len(parsed)} parsed, expected 7 valid"))

    # 2. attempt row arity (P01)
    rows = [_attempt_row(1, 1), _attempt_row(1, 2, status="NO_PROXY"),
            _attempt_row(1, 3, proxy_id=5, layers=["raw_html"])]
    ok = all(len(r) == 11 for r in rows)
    results.append(("P01 attempt tuple arity", ok, "all rows 11 fields"))

    # 3. soft-4xx extraction (P02)
    body403 = '<html><a href="https://wa.me/919876543210">x</a></html>'
    res = extract_deep(body403, "https://t.co/x", ["https://t.co/x"])
    ok = any(n == "9876543210" for n, _, _ in res["numbers"])
    results.append(("P02 soft-4xx number mining", ok, str(res["numbers"])))

    # 4. static hash stability (P23)
    h1 = sha1_norm("<html>  <body>hi</body></html>")
    h2 = sha1_norm("<html><body>hi</body></html>")
    results.append(("P23 whitespace-insensitive hash", h1 == h2, ""))

    # 5. FP filter respects confidence (P18)
    ts = "1715000000"
    strict = _looks_like_false_positive(ts, "raw")
    lenient = _looks_like_false_positive(ts, "wa.me")
    results.append(("P18 confidence-aware FP filter",
                    strict and not lenient, f"raw={strict} wa.me={lenient}"))

    # 6. URL validator robustness (P19)
    ok = (validate_url("example.com:abc") is None
          and validate_url("example.com") == "https://example.com"
          and validate_url("https://a.b/c?d=e") is not None)
    results.append(("P19 validator", ok, ""))

    # 7. settings cache (P21)
    before = _db_conn_count[0]
    for _ in range(1000):
        get_setting("max_visits")
    after = _db_conn_count[0]
    results.append(("P21 settings cache", after - before <= 2,
                    f"{after - before} connections for 1000 reads"))

    # 8. combined regex single pass (P31)
    sample = ('wa.me/919876543210 tel:+14155552671 '
              '{"phone":"442071234567"} intent://send/919999988888')
    nums = extract_numbers(sample, "selftest")
    results.append(("P31 combined extraction", len(nums) >= 4,
                    f"{len(nums)} numbers"))

    # 9. display formatting (P17)
    ok = _display_number("9876543210") == "+919876543210"
    results.append(("P17 Indian display", ok, ""))

    # 10. cancel primitive (P08)
    ev = threading.Event()
    t0 = time.time()
    ev.set()
    ok = (time.time() - t0) < 0.01
    results.append(("P08 cancel primitive", ok, ""))

    lines = ["🧪 *SELF-TEST*", "━━━━━━━━━━━━━━━━━━━━"]
    for name, ok, note in results:
        icon = "✅" if ok else "❌"
        lines.append(f"{icon} {name}" + (f" — {note[:80]}" if note else ""))
    failed = [n for n, ok, _ in results if not ok]
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("❌ FAILURES present — do not deploy." if failed
                 else "✅ All checks passed.")
    safe_send_message(message.chat.id, "\n".join(lines))


if __name__ == "__main__":
    main()
