import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "mimotion.db")

DEFAULT_SETTINGS = {
    "min_step": 18000,
    "max_step": 25000,
    "push_plus_token": "",
    "push_plus_hour": "",
    "push_plus_max": 30,
    "push_wechat_webhook_key": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "sleep_gap": 5,
    "use_concurrent": 0,
    "random_delay_max": 58,
    "server_timezone": "Asia/Shanghai",
    "cron_expression": "0 1,4,7,10,12,23 * * *",
    "cron_command": "docker compose -f /path/to/docker-compose.yml exec -T mimotion env RUN_TRIGGER=cron python /app/run_once.py",
}


def _beijing_tz():
    if ZoneInfo is None:
        return timezone(timedelta(hours=8))
    try:
        return ZoneInfo("Asia/Shanghai")
    except Exception:
        return timezone(timedelta(hours=8))


def _now():
    return datetime.now(_beijing_tz()).strftime("%Y-%m-%d %H:%M:%S")


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _table_columns(conn, table_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _ensure_column(conn, table_name, column_name, ddl):
    if column_name in _table_columns(conn, table_name):
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")


def _ensure_settings_columns(conn):
    _ensure_column(
        conn,
        "settings",
        "random_delay_max",
        f"random_delay_max INTEGER NOT NULL DEFAULT {DEFAULT_SETTINGS['random_delay_max']}",
    )
    _ensure_column(
        conn,
        "settings",
        "server_timezone",
        f"server_timezone TEXT NOT NULL DEFAULT '{DEFAULT_SETTINGS['server_timezone']}'",
    )
    _ensure_column(
        conn,
        "settings",
        "cron_expression",
        f"cron_expression TEXT NOT NULL DEFAULT '{DEFAULT_SETTINGS['cron_expression']}'",
    )
    _ensure_column(
        conn,
        "settings",
        "cron_command",
        f"cron_command TEXT NOT NULL DEFAULT '{DEFAULT_SETTINGS['cron_command']}'",
    )


def _ensure_accounts_columns(conn):
    _ensure_column(conn, "accounts", "source_info", "source_info TEXT")
    _ensure_column(conn, "accounts", "fixed_step", "fixed_step INTEGER")
    _ensure_column(conn, "accounts", "min_step_override", "min_step_override INTEGER")
    _ensure_column(conn, "accounts", "max_step_override", "max_step_override INTEGER")
    _ensure_column(conn, "accounts", "expires_at", "expires_at TEXT")


def _ensure_runs_columns(conn):
    _ensure_column(conn, "runs", "account_name", "account_name TEXT")
    _ensure_column(conn, "runs", "step_count", "step_count INTEGER")

@contextmanager
def get_db():
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                source_info TEXT,
                fixed_step INTEGER,
                min_step_override INTEGER,
                max_step_override INTEGER,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                min_step INTEGER NOT NULL,
                max_step INTEGER NOT NULL,
                push_plus_token TEXT,
                push_plus_hour TEXT,
                push_plus_max INTEGER NOT NULL,
                push_wechat_webhook_key TEXT,
                telegram_bot_token TEXT,
                telegram_chat_id TEXT,
                sleep_gap REAL NOT NULL,
                use_concurrent INTEGER NOT NULL,
                random_delay_max INTEGER NOT NULL,
                server_timezone TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                cron_command TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                exit_code INTEGER,
                output TEXT
            )
            """
        )
        _ensure_settings_columns(conn)
        _ensure_accounts_columns(conn)
        _ensure_runs_columns(conn)
        row = conn.execute("SELECT id FROM settings WHERE id = 1").fetchone()
        if row is None:
            now = _now()
            conn.execute(
                """
                INSERT INTO settings (
                    id, min_step, max_step, push_plus_token, push_plus_hour, push_plus_max,
                    push_wechat_webhook_key, telegram_bot_token, telegram_chat_id,
                    sleep_gap, use_concurrent, random_delay_max, cron_expression, cron_command,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    1,
                    DEFAULT_SETTINGS["min_step"],
                    DEFAULT_SETTINGS["max_step"],
                    DEFAULT_SETTINGS["push_plus_token"],
                    DEFAULT_SETTINGS["push_plus_hour"],
                    DEFAULT_SETTINGS["push_plus_max"],
                    DEFAULT_SETTINGS["push_wechat_webhook_key"],
                    DEFAULT_SETTINGS["telegram_bot_token"],
                    DEFAULT_SETTINGS["telegram_chat_id"],
                    DEFAULT_SETTINGS["sleep_gap"],
                    DEFAULT_SETTINGS["use_concurrent"],
                    DEFAULT_SETTINGS["random_delay_max"],
                    DEFAULT_SETTINGS["server_timezone"],
                    DEFAULT_SETTINGS["cron_expression"],
                    DEFAULT_SETTINGS["cron_command"],
                    now,
                ),
            )


def count_accounts():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM accounts").fetchone()
        return row["cnt"] if row else 0


def count_accounts_enabled():
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM accounts WHERE enabled = 1"
        ).fetchone()
        return row["cnt"] if row else 0


def count_accounts_disabled():
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM accounts WHERE enabled = 0"
        ).fetchone()
        return row["cnt"] if row else 0


def count_accounts_filtered(query):
    like = f"%{query}%"
    account_id = int(query) if query and query.isdigit() else None
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM accounts WHERE username LIKE ? OR source_info LIKE ? OR id = ?",
            (like, like, account_id),
        ).fetchone()
        return row["cnt"] if row else 0


def list_accounts(limit=None, offset=0):
    with get_db() as conn:
        if limit is None:
            rows = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM accounts ORDER BY id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]


def list_accounts_filtered(query, limit=None, offset=0):
    like = f"%{query}%"
    account_id = int(query) if query and query.isdigit() else None
    with get_db() as conn:
        if limit is None:
            rows = conn.execute(
                "SELECT * FROM accounts WHERE username LIKE ? OR source_info LIKE ? OR id = ? ORDER BY id",
                (like, like, account_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM accounts WHERE username LIKE ? OR source_info LIKE ? OR id = ? ORDER BY id LIMIT ? OFFSET ?",
                (like, like, account_id, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]


def list_enabled_accounts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM accounts WHERE enabled = 1 ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def get_account(account_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        return dict(row) if row else None


def get_account_by_name(username):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def create_account(
    username,
    password_enc,
    enabled,
    source_info,
    fixed_step,
    min_step_override,
    max_step_override,
    expires_at,
):
    with get_db() as conn:
        now = _now()
        conn.execute(
            """
            INSERT INTO accounts (
                username, password_enc, enabled, source_info,
                fixed_step, min_step_override, max_step_override, expires_at,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                password_enc,
                enabled,
                source_info,
                fixed_step,
                min_step_override,
                max_step_override,
                expires_at,
                now,
                now,
            ),
        )


def update_account(
    account_id,
    username,
    password_enc,
    enabled,
    source_info,
    fixed_step,
    min_step_override,
    max_step_override,
    expires_at,
):
    with get_db() as conn:
        now = _now()
        if password_enc is None:
            conn.execute(
                """
                UPDATE accounts
                SET username = ?, enabled = ?, source_info = ?,
                    fixed_step = ?, min_step_override = ?, max_step_override = ?,
                    expires_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    username,
                    enabled,
                    source_info,
                    fixed_step,
                    min_step_override,
                    max_step_override,
                    expires_at,
                    now,
                    account_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE accounts
                SET username = ?, password_enc = ?, enabled = ?, source_info = ?,
                    fixed_step = ?, min_step_override = ?, max_step_override = ?,
                    expires_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    username,
                    password_enc,
                    enabled,
                    source_info,
                    fixed_step,
                    min_step_override,
                    max_step_override,
                    expires_at,
                    now,
                    account_id,
                ),
            )


def delete_account(account_id):
    with get_db() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))


def toggle_account(account_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT enabled FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            return None
        enabled = 0 if row["enabled"] else 1
        conn.execute(
            "UPDATE accounts SET enabled = ?, updated_at = ? WHERE id = ?",
            (enabled, _now(), account_id),
        )
        return enabled


def set_account_enabled(account_id, enabled):
    with get_db() as conn:
        conn.execute(
            "UPDATE accounts SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, _now(), account_id),
        )


def get_settings():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return dict(row)


def update_settings(values):
    with get_db() as conn:
        conn.execute(
            """
            UPDATE settings
            SET min_step = ?, max_step = ?, push_plus_token = ?, push_plus_hour = ?,
                push_plus_max = ?, push_wechat_webhook_key = ?, telegram_bot_token = ?,
                telegram_chat_id = ?, sleep_gap = ?, use_concurrent = ?, random_delay_max = ?,
                server_timezone = ?, cron_expression = ?, cron_command = ?, updated_at = ?
            WHERE id = 1
            """,
            (
                values["min_step"],
                values["max_step"],
                values["push_plus_token"],
                values["push_plus_hour"],
                values["push_plus_max"],
                values["push_wechat_webhook_key"],
                values["telegram_bot_token"],
                values["telegram_chat_id"],
                values["sleep_gap"],
                values["use_concurrent"],
                values["random_delay_max"],
                values["server_timezone"],
                values["cron_expression"],
                values["cron_command"],
                _now(),
            ),
        )


def count_runs():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM runs").fetchone()
        return row["cnt"] if row else 0


def count_runs_success():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM runs WHERE exit_code = 0").fetchone()
        return row["cnt"] if row else 0


def count_runs_fail():
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM runs WHERE exit_code IS NOT NULL AND exit_code != 0"
        ).fetchone()
        return row["cnt"] if row else 0


def count_runs_by_range(start_iso, end_iso, success=None):
    with get_db() as conn:
        if success is None:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM runs WHERE started_at >= ? AND started_at < ?",
                (start_iso, end_iso),
            ).fetchone()
        elif success:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM runs WHERE started_at >= ? AND started_at < ? AND exit_code = 0",
                (start_iso, end_iso),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM runs WHERE started_at >= ? AND started_at < ? AND exit_code IS NOT NULL AND exit_code != 0",
                (start_iso, end_iso),
            ).fetchone()
        return row["cnt"] if row else 0


def list_runs_by_range(start_iso, end_iso, limit=None):
    with get_db() as conn:
        if limit is None:
            rows = conn.execute(
                "SELECT * FROM runs WHERE started_at >= ? AND started_at < ? ORDER BY started_at ASC",
                (start_iso, end_iso),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM runs WHERE started_at >= ? AND started_at < ? ORDER BY started_at ASC LIMIT ?",
                (start_iso, end_iso, limit),
            ).fetchall()
        return [dict(row) for row in rows]


def list_runs(limit=20, offset=0):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(row) for row in rows]


def get_run(run_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None


def insert_run(trigger, account_name=None):
    with get_db() as conn:
        now = _now()
        cur = conn.execute(
            "INSERT INTO runs (trigger, started_at, account_name) VALUES (?, ?, ?)",
            (trigger, now, account_name),
        )
        return cur.lastrowid


def update_run(run_id, exit_code, output, step_count=None):
    with get_db() as conn:
        conn.execute(
            """
            UPDATE runs
            SET finished_at = ?, exit_code = ?, output = ?, step_count = ?
            WHERE id = ?
            """,
            (_now(), exit_code, output, step_count, run_id),
        )
