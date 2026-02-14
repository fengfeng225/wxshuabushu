import json
import os
import random
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone

from app.crypto import decrypt_text, encrypt_text
from app.db import (
    get_account_session,
    get_account,
    get_settings,
    init_db,
    insert_run,
    list_enabled_accounts,
    set_account_enabled,
    update_run,
    upsert_account_session,
    upsert_account_session_token_data,
)

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

_MIMOTION_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mimotion")
if _MIMOTION_DIR not in sys.path:
    sys.path.insert(0, _MIMOTION_DIR)


def _build_config(
    accounts,
    settings,
    fixed_step=None,
    min_step_override=None,
    max_step_override=None,
    fixed_step_exact=False,
):
    users = "#".join([acct["username"] for acct in accounts])
    passwords = "#".join([decrypt_text(acct["password_enc"]) for acct in accounts])
    config = {
        "USER": users,
        "PWD": passwords,
        "MIN_STEP": str(settings["min_step"]),
        "MAX_STEP": str(settings["max_step"]),
        "CRON_EXPRESSION": settings.get("cron_expression") or "",
        "PUSH_PLUS_TOKEN": settings.get("push_plus_token") or "",
        "PUSH_PLUS_HOUR": settings.get("push_plus_hour") or "",
        "PUSH_PLUS_MAX": str(settings.get("push_plus_max") or 30),
        "PUSH_WECHAT_WEBHOOK_KEY": settings.get("push_wechat_webhook_key") or "",
        "TELEGRAM_BOT_TOKEN": settings.get("telegram_bot_token") or "",
        "TELEGRAM_CHAT_ID": settings.get("telegram_chat_id") or "",
        "SLEEP_GAP": "0",
        "USE_CONCURRENT": "False",
    }
    if min_step_override is not None:
        config["MIN_STEP"] = str(min_step_override)
    if max_step_override is not None:
        config["MAX_STEP"] = str(max_step_override)
    if fixed_step is not None:
        config["FIXED_STEP"] = str(fixed_step)
        if fixed_step_exact:
            config["FIXED_STEP_EXACT"] = "1"
    return config


def _build_env(
    accounts,
    settings,
    fixed_step=None,
    min_step_override=None,
    max_step_override=None,
    fixed_step_exact=False,
):
    config = _build_config(
        accounts,
        settings,
        fixed_step,
        min_step_override,
        max_step_override,
        fixed_step_exact,
    )
    env = os.environ.copy()
    env["CONFIG"] = json.dumps(config, ensure_ascii=True)
    if "AES_KEY" in env and not env["AES_KEY"].strip():
        env.pop("AES_KEY")
    # 从账号会话传递 token 缓存
    token_data = None
    if accounts:
        account_id = accounts[0].get("id")
        if account_id:
            session = get_account_session(account_id)
            if session:
                token_data = session.get("token_data")
    if token_data:
        env["TOKEN_DATA"] = token_data
    elif "TOKEN_DATA" in env:
        env.pop("TOKEN_DATA")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _extract_result(output):
    step_value, success_value, token_data = None, None, None
    for line in output.splitlines():
        if line.startswith("MM_RESULT|"):
            parts = line.split("|")
            if len(parts) >= 4:
                step_value = int(parts[2]) if parts[2].isdigit() else None
                success_value = parts[3] == "1"
        elif line.startswith("MM_TOKEN|"):
            token_data = line.split("|", 1)[1] if "|" in line else None
    return step_value, success_value, token_data


def _normalize_zepp_login_user(username: str) -> str:
    user = (username or "").strip()
    if user and (user.startswith("+86") or "@" in user):
        return user
    if user:
        return f"+86{user}"
    return user


def _now_bj_str() -> str:
    tz = timezone(timedelta(hours=8))
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")


def _extract_session_snapshot_from_token_data(username: str, token_data: str) -> dict | None:
    if not token_data:
        return None
    aes_key_raw = os.environ.get("AES_KEY") or ""
    if not aes_key_raw:
        return None
    try:
        aes_key = aes_key_raw.encode("utf-8")
    except Exception:
        return None
    if len(aes_key) != 16:
        return None

    try:
        from util.aes_help import base64_to_bytes, decrypt_data
    except Exception:
        return None

    try:
        cipher_bytes = base64_to_bytes(token_data)
        plain_bytes = decrypt_data(cipher_bytes, aes_key, None)
        payload = json.loads(plain_bytes.decode("utf-8", errors="strict"))
    except Exception:
        return None

    if not isinstance(payload, dict) or not payload:
        return None

    normalized_user = _normalize_zepp_login_user(username)
    node = payload.get(normalized_user)
    if not isinstance(node, dict):
        node = payload.get((username or "").strip())
    if not isinstance(node, dict):
        node = next((value for value in payload.values() if isinstance(value, dict)), None)
    if not isinstance(node, dict):
        return None

    access_token = node.get("access_token")
    login_token = node.get("login_token")
    app_token = node.get("app_token")
    user_id = node.get("user_id")
    device_id = node.get("device_id")
    if not (access_token and login_token and app_token and user_id and device_id):
        return None

    return {
        "access_token": str(access_token),
        "login_token": str(login_token),
        "app_token": str(app_token),
        "zepp_user_id": str(user_id),
        "zepp_device_id": str(device_id),
    }


def _normalize_step(value):
    try:
        step_value = int(value)
    except Exception:
        return None
    if step_value <= 0 or step_value > 99999:
        return None
    return step_value


def _resolve_step_config(account, fixed_step_override=None, fixed_step_exact=False):
    if fixed_step_override is not None:
        return fixed_step_override, None, None, fixed_step_exact
    fixed_step = _normalize_step(account.get("fixed_step"))
    if fixed_step is not None:
        return fixed_step, None, None, False
    min_override = _normalize_step(account.get("min_step_override"))
    max_override = _normalize_step(account.get("max_step_override"))
    if min_override is not None and max_override is not None and min_override <= max_override:
        return None, min_override, max_override, False
    return None, None, None, False


def _safe_timezone(name: str):
    if ZoneInfo is None:
        return timezone(timedelta(hours=8))
    try:
        return ZoneInfo("Asia/Shanghai")
    except Exception:
        return timezone(timedelta(hours=8))


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def _filter_expired_accounts(accounts, settings):
    if not accounts:
        return []
    tz = _safe_timezone(settings.get("server_timezone") or "Asia/Shanghai")
    today = datetime.now(tz).date()
    active = []
    for account in accounts:
        expires_at = (account.get("expires_at") or "").strip()
        if not expires_at:
            active.append(account)
            continue
        expires_date = _parse_date(expires_at)
        if not expires_date:
            active.append(account)
            continue
        if today > expires_date:
            set_account_enabled(account.get("id"), False)
            continue
        active.append(account)
    return active


def _run_account(
    account,
    settings,
    trigger,
    prefix_output="",
    fixed_step=None,
    fixed_step_exact=False,
):
    run_id = insert_run(trigger, account.get("username"))
    try:
        resolved_fixed, min_override, max_override, resolved_exact = _resolve_step_config(
            account, fixed_step, fixed_step_exact
        )
        env = _build_env(
            [account],
            settings,
            resolved_fixed,
            min_override,
            max_override,
            resolved_exact,
        )
        mimotion_path = env.get("MIMOTION_PATH", "/app/mimotion/main.py")
        data_dir = env.get("DATA_DIR", "/data")
        os.makedirs(data_dir, exist_ok=True)
        result = subprocess.run(
            [sys.executable, mimotion_path],
            cwd=data_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        output = prefix_output + (result.stdout or "")
        if result.stderr:
            output += "\n" + result.stderr
        step_count, success_flag, token_data = _extract_result(output)
        # 从日志中移除敏感的 token 数据行
        clean_lines = [l for l in output.splitlines() if not l.startswith("MM_TOKEN|")]
        output = "\n".join(clean_lines)
        exit_code = 0
        if result.returncode != 0 or success_flag is not True:
            exit_code = 1
        update_run(run_id, exit_code, output, step_count)
        # 回写 token 到数据库（只要拿到有效 token 就回写，避免失败场景下丢失刷新后的 token）
        if token_data:
            account_id = account.get("id")
            if account_id:
                snapshot = _extract_session_snapshot_from_token_data(account.get("username") or "", token_data)
                if snapshot:
                    try:
                        upsert_account_session(
                            account_id=account_id,
                            zepp_user_id=snapshot.get("zepp_user_id"),
                            zepp_device_id=snapshot.get("zepp_device_id"),
                            access_token_enc=encrypt_text(snapshot.get("access_token")),
                            login_token_enc=encrypt_text(snapshot.get("login_token")),
                            app_token_enc=encrypt_text(snapshot.get("app_token")),
                            token_data=token_data,
                            token_refreshed_at=_now_bj_str(),
                            token_last_error=None,
                        )
                    except Exception:
                        upsert_account_session_token_data(account_id, token_data)
                else:
                    upsert_account_session_token_data(account_id, token_data)
        return exit_code == 0
    except Exception:
        update_run(run_id, 1, prefix_output + traceback.format_exc(), None)
        return False

def _get_delay_window_seconds(trigger, settings):
    if trigger != "cron":
        return 0
    max_minutes = settings.get("random_delay_max")
    try:
        max_minutes = int(max_minutes)
    except Exception:
        try:
            max_minutes = int(os.environ.get("RANDOM_DELAY_MAX", "58"))
        except Exception:
            max_minutes = 0
    if max_minutes <= 0:
        return 0
    return max_minutes * 60


def _build_spread_schedule(accounts, delay_window_seconds):
    if not accounts:
        return []
    if delay_window_seconds <= 0:
        return [(0.0, account) for account in accounts]
    window = float(delay_window_seconds)
    count = len(accounts)
    accounts = list(accounts)
    random.shuffle(accounts)
    segment = window / count
    schedule = []
    for idx, account in enumerate(accounts):
        start = segment * idx
        end = segment * (idx + 1)
        offset = random.uniform(start, end)
        schedule.append((offset, account))
    schedule.sort(key=lambda item: item[0])
    return schedule


def run(trigger="manual"):
    init_db()
    settings = get_settings()
    delay_window_seconds = _get_delay_window_seconds(trigger, settings)
    prefix_output = ""
    try:
        accounts = list_enabled_accounts()
        if trigger == "cron":
            accounts = _filter_expired_accounts(accounts, settings)
        if not accounts:
            return False
        if trigger == "cron":
            schedule = _build_spread_schedule(accounts, delay_window_seconds)
        else:
            schedule = [(0.0, account) for account in accounts]
        start_ts = time.monotonic()
        success = True
        for offset, account in schedule:
            wait_seconds = (start_ts + offset) - time.monotonic()
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            ok = _run_account(account, settings, trigger, prefix_output)
            success = success and ok
        return success
    except Exception:
        run_id = insert_run(trigger, None)
        update_run(run_id, 1, prefix_output + traceback.format_exc(), None)
        return False


def run_account_test(account_id, step, trigger="test"):
    init_db()
    settings = get_settings()
    account = get_account(account_id)
    if not account:
        raise RuntimeError("Account not found.")
    step_value = None
    try:
        step_value = int(step)
    except Exception:
        step_value = None
    if step_value is None or step_value < 0 or step_value > 99999:
        raise RuntimeError("Invalid step value.")
    return _run_account(account, settings, trigger, "", step_value, True)
