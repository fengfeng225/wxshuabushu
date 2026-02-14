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
    "register_proxy": "",
    "register_proxy_enabled": 0,
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
    _ensure_column(
        conn,
        "settings",
        "register_proxy",
        f"register_proxy TEXT NOT NULL DEFAULT ''",
    )
    _ensure_column(
        conn,
        "settings",
        "register_proxy_enabled",
        f"register_proxy_enabled INTEGER NOT NULL DEFAULT 0",
    )


def _ensure_accounts_columns(conn):
    _ensure_column(conn, "accounts", "source_info", "source_info TEXT")
    _ensure_column(conn, "accounts", "fixed_step", "fixed_step INTEGER")
    _ensure_column(conn, "accounts", "min_step_override", "min_step_override INTEGER")
    _ensure_column(conn, "accounts", "max_step_override", "max_step_override INTEGER")
    _ensure_column(conn, "accounts", "expires_at", "expires_at TEXT")


def _ensure_account_sessions_columns(conn):
    _ensure_column(conn, "account_sessions", "zepp_user_id", "zepp_user_id TEXT")
    _ensure_column(conn, "account_sessions", "zepp_device_id", "zepp_device_id TEXT")
    _ensure_column(conn, "account_sessions", "access_token_enc", "access_token_enc TEXT")
    _ensure_column(conn, "account_sessions", "login_token_enc", "login_token_enc TEXT")
    _ensure_column(conn, "account_sessions", "app_token_enc", "app_token_enc TEXT")
    _ensure_column(conn, "account_sessions", "token_data", "token_data TEXT")
    _ensure_column(conn, "account_sessions", "token_refreshed_at", "token_refreshed_at TEXT")
    _ensure_column(conn, "account_sessions", "token_last_error", "token_last_error TEXT")


def _cleanup_legacy_accounts_token_data_column(conn):
    columns = _table_columns(conn, "accounts")
    if "token_data" not in columns:
        return

    rows = conn.execute(
        """
        SELECT id, token_data
        FROM accounts
        WHERE token_data IS NOT NULL AND token_data != ''
        """
    ).fetchall()
    if rows:
        now = _now()
        for row in rows:
            conn.execute(
                """
                INSERT INTO account_sessions (
                    account_id, token_data, created_at, updated_at
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    token_data = COALESCE(account_sessions.token_data, excluded.token_data),
                    updated_at = excluded.updated_at
                """,
                (row["id"], row["token_data"], now, now),
            )

    try:
        conn.execute("ALTER TABLE accounts DROP COLUMN token_data")
    except Exception:
        # 低版本 SQLite 可能不支持 DROP COLUMN，回退为重建表。
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts_new (
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
                INSERT INTO accounts_new (
                    id, username, password_enc, enabled, source_info,
                    fixed_step, min_step_override, max_step_override, expires_at,
                    created_at, updated_at
                )
                SELECT
                    id, username, password_enc, enabled, source_info,
                    fixed_step, min_step_override, max_step_override, expires_at,
                    created_at, updated_at
                FROM accounts
                """
            )
            conn.execute("DROP TABLE accounts")
            conn.execute("ALTER TABLE accounts_new RENAME TO accounts")
        except Exception:
            pass
        finally:
            conn.execute("PRAGMA foreign_keys = ON")


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
                register_proxy TEXT NOT NULL DEFAULT '',
                register_proxy_enabled INTEGER NOT NULL DEFAULT 0,
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_sessions (
                account_id INTEGER PRIMARY KEY,
                zepp_user_id TEXT,
                zepp_device_id TEXT,
                access_token_enc TEXT,
                login_token_enc TEXT,
                app_token_enc TEXT,
                token_data TEXT,
                token_refreshed_at TEXT,
                token_last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
            """
        )
        _ensure_settings_columns(conn)
        _ensure_accounts_columns(conn)
        _ensure_account_sessions_columns(conn)
        _cleanup_legacy_accounts_token_data_column(conn)
        conn.execute("DROP TABLE IF EXISTS register_sessions")
        _ensure_runs_columns(conn)
        row = conn.execute("SELECT id FROM settings WHERE id = 1").fetchone()
        if row is None:
            now = _now()
            conn.execute(
                """
                INSERT INTO settings (
                    id, min_step, max_step, push_plus_token, push_plus_hour, push_plus_max,
                    push_wechat_webhook_key, telegram_bot_token, telegram_chat_id,
                    sleep_gap, use_concurrent, random_delay_max, server_timezone,
                    cron_expression, cron_command, register_proxy, register_proxy_enabled,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    DEFAULT_SETTINGS["register_proxy"],
                    DEFAULT_SETTINGS["register_proxy_enabled"],
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
        cursor = conn.execute(
            """
            INSERT INTO accounts (
                username, password_enc, enabled, source_info,
                fixed_step, min_step_override, max_step_override, expires_at,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        return cursor.lastrowid


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
        conn.execute("DELETE FROM account_sessions WHERE account_id = ?", (account_id,))
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


def get_account_session(account_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM account_sessions WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        return dict(row) if row else None


def upsert_account_session(
    account_id,
    zepp_user_id=None,
    zepp_device_id=None,
    access_token_enc=None,
    login_token_enc=None,
    app_token_enc=None,
    token_data=None,
    token_refreshed_at=None,
    token_last_error=None,
):
    with get_db() as conn:
        now = _now()
        conn.execute(
            """
            INSERT INTO account_sessions (
                account_id,
                zepp_user_id,
                zepp_device_id,
                access_token_enc,
                login_token_enc,
                app_token_enc,
                token_data,
                token_refreshed_at,
                token_last_error,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                zepp_user_id = excluded.zepp_user_id,
                zepp_device_id = excluded.zepp_device_id,
                access_token_enc = excluded.access_token_enc,
                login_token_enc = excluded.login_token_enc,
                app_token_enc = excluded.app_token_enc,
                token_data = COALESCE(excluded.token_data, account_sessions.token_data),
                token_refreshed_at = excluded.token_refreshed_at,
                token_last_error = excluded.token_last_error,
                updated_at = excluded.updated_at
            """,
            (
                account_id,
                zepp_user_id,
                zepp_device_id,
                access_token_enc,
                login_token_enc,
                app_token_enc,
                token_data,
                token_refreshed_at,
                token_last_error,
                now,
                now,
            ),
        )


def upsert_account_session_token_data(account_id, token_data):
    with get_db() as conn:
        now = _now()
        conn.execute(
            """
            INSERT INTO account_sessions (
                account_id, token_data, created_at, updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                token_data = excluded.token_data,
                updated_at = excluded.updated_at
            """,
            (account_id, token_data, now, now),
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
                server_timezone = ?, cron_expression = ?, cron_command = ?,
                register_proxy = ?, register_proxy_enabled = ?, updated_at = ?
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
                values.get("register_proxy", ""),
                values.get("register_proxy_enabled", 0),
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


def _build_runs_filter(account, status, date_start, date_end):
    clauses = []
    params = []
    if account:
        clauses.append("account_name LIKE ?")
        params.append(f"%{account}%")
    if status == "success":
        clauses.append("exit_code = 0")
    elif status == "fail":
        clauses.append("exit_code IS NOT NULL AND exit_code != 0")
    elif status == "pending":
        clauses.append("exit_code IS NULL")
    if date_start:
        clauses.append("started_at >= ?")
        params.append(f"{date_start} 00:00:00")
    if date_end:
        clauses.append("started_at < ?")
        params.append(f"{date_end} 23:59:60")
    where = " AND ".join(clauses)
    return where, params


def count_runs_filtered(account=None, status=None, date_start=None, date_end=None):
    where, params = _build_runs_filter(account, status, date_start, date_end)
    sql = "SELECT COUNT(*) AS cnt FROM runs"
    if where:
        sql += " WHERE " + where
    with get_db() as conn:
        row = conn.execute(sql, params).fetchone()
        return row["cnt"] if row else 0


def list_runs_filtered(account=None, status=None, date_start=None, date_end=None, limit=20, offset=0):
    where, params = _build_runs_filter(account, status, date_start, date_end)
    sql = "SELECT * FROM runs"
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
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
