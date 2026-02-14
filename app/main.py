import os
import sys
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.crypto import decrypt_text, encrypt_text
from app.db import (
    count_accounts,
    count_accounts_filtered,
    count_accounts_disabled,
    count_accounts_enabled,
    count_runs,
    count_runs_fail,
    count_runs_filtered,
    count_runs_success,
    count_runs_by_range,
    list_runs_by_range,
    create_account,
    delete_account,
    get_account,
    get_account_by_name,
    get_account_session,
    get_run,
    get_settings,
    init_db,
    list_accounts,
    list_accounts_filtered,
    list_runs,
    list_runs_filtered,
    toggle_account,
    update_account,
    upsert_account_session,
    update_settings,
)
from app.step_api import call_step_api

app = FastAPI()

BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

APP_SECRET = os.environ.get("APP_SECRET", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
VIEW_PASSWORD_KEY = os.environ.get("VIEW_PASSWORD_KEY", "")

@app.get("/favicon.ico")
def favicon():
    return FileResponse(
        os.path.join(BASE_DIR, "static", "favicon.svg"),
        media_type="image/svg+xml",
    )


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path == "/login":
            return await call_next(request)
        wants_json = (
            request.headers.get("x-requested-with") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("accept") or "")
        )
        session = request.scope.get("session")
        if session and session.get("user"):
            return await call_next(request)
        if wants_json:
            return JSONResponse({"ok": False, "detail": "未登录"}, status_code=401)
        return RedirectResponse("/login", status_code=303)


class NoStoreMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type") or ""
        if content_type.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response


app.add_middleware(AuthMiddleware)
app.add_middleware(NoStoreMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=APP_SECRET,
    same_site="lax",
    session_cookie="mimotion_session",
)


@app.on_event("startup")
def startup():
    if not APP_SECRET:
        raise RuntimeError("APP_SECRET 未配置，请在 .env 中设置")
    if not VIEW_PASSWORD_KEY:
        raise RuntimeError("VIEW_PASSWORD_KEY 未配置，请在 .env 中设置")
    init_db()


def _to_int(value, default):
    try:
        return int(value)
    except Exception:
        return default


def _to_float(value, default):
    try:
        return float(value)
    except Exception:
        return default


def _normalize_step(value):
    step_value = _to_int(value, None)
    if step_value is None or step_value <= 0 or step_value > 99999:
        return None
    return step_value


def _mask_password(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _format_ts(value):
    if not value:
        return "-"
    if not isinstance(value, str):
        return str(value)
    raw = value.strip()
    try:
        if raw.endswith("Z"):
            dt = (
                datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc)
                .astimezone(_beijing_tz())
            )
        else:
            dt = datetime.fromisoformat(raw.replace("Z", ""))
            if dt.tzinfo is not None:
                dt = dt.astimezone(_beijing_tz())
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw.replace("T", " ").replace("Z", "")


def _trigger_label(value):
    mapping = {"manual": "手动", "cron": "自动", "test": "测试"}
    return mapping.get(value or "", value or "-")


def _paginate(total, page, per_page):
    total_pages = max(1, (total + per_page - 1) // per_page) if total else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page
    start = max(1, page - 2)
    end = min(total_pages, page + 2)
    page_numbers = list(range(start, end + 1))
    return page, total_pages, offset, page_numbers


def _normalize_per_page(value, default=50):
    per_page = _to_int(value, default)
    if per_page not in (10, 20, 50, 100):
        return default
    return per_page


def _static_version():
    path = os.path.join(BASE_DIR, "static", "styles.css")
    try:
        return str(int(os.path.getmtime(path)))
    except Exception:
        return "0"


def _template_context(request: Request, **extra):
    context = {"request": request, "static_version": _static_version()}
    context.update(extra)
    return context


def _beijing_tz():
    if ZoneInfo is None:
        return timezone(timedelta(hours=8))
    try:
        return ZoneInfo("Asia/Shanghai")
    except Exception:
        return timezone(timedelta(hours=8))


def _safe_timezone(name: str):
    return _beijing_tz()


def _to_bj_str(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=_beijing_tz())
    return value.astimezone(_beijing_tz()).strftime("%Y-%m-%d %H:%M:%S")


def _today_range(tz_name: str):
    tz = _safe_timezone(tz_name or "Asia/Shanghai")
    now = datetime.now(tz)
    start = datetime(now.year, now.month, now.day, tzinfo=tz)
    end = start + timedelta(days=1)
    return _to_bj_str(start), _to_bj_str(end)


def _today_date(tz_name: str):
    tz = _safe_timezone(tz_name or "Asia/Shanghai")
    return datetime.now(tz).date()


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


@app.get("/login", response_class=HTMLResponse)
def login(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        _template_context(request, title="登录"),
    )


@app.post("/login")
async def login_post(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="请输入用户名和密码")
    valid = secrets.compare_digest(username, ADMIN_USER) and secrets.compare_digest(
        password, ADMIN_PASS
    )
    if not valid:
        raise HTTPException(status_code=400, detail="用户名或密码错误")
    request.session["user"] = username
    return {"ok": True, "message": "登录成功", "redirect": "/"}


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True, "message": "已退出登录", "redirect": "/login"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    per_page = _normalize_per_page(request.query_params.get("per_page"), 50)
    q = (request.query_params.get("q") or "").strip()
    page = _to_int(request.query_params.get("page"), 1)
    if q:
        total = count_accounts_filtered(q)
        page, total_pages, offset, page_numbers = _paginate(total, page, per_page)
        accounts = list_accounts_filtered(q, per_page, offset)
    else:
        total = count_accounts()
        page, total_pages, offset, page_numbers = _paginate(total, page, per_page)
        accounts = list_accounts(per_page, offset)
    for account in accounts:
        account["updated_at_fmt"] = _format_ts(account.get("updated_at"))
        account["created_at_fmt"] = _format_ts(account.get("created_at"))
        expires_at = (account.get("expires_at") or "").strip()
        account["expires_at_label"] = expires_at if expires_at else "从不"
    total_accounts = count_accounts()
    enabled_accounts = count_accounts_enabled()
    disabled_accounts = count_accounts_disabled()
    return templates.TemplateResponse(
        "index.html",
        _template_context(
            request,
            accounts=accounts,
            title="账号管理",
            q=q,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            page_numbers=page_numbers,
            total_accounts=total_accounts,
            enabled_accounts=enabled_accounts,
            disabled_accounts=disabled_accounts,
        ),
    )


@app.get("/accounts/new", response_class=HTMLResponse)
def new_account(request: Request):
    return templates.TemplateResponse(
        "account_form.html",
        _template_context(
            request,
            account=None,
            title="添加账号",
            action="/accounts",
            message=None,
        ),
    )


@app.post("/accounts")
async def create_account_post(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()
    source_info = (form.get("source_info") or "").strip()
    fixed_step = _normalize_step(form.get("fixed_step"))
    min_step_override = _normalize_step(form.get("min_step_override"))
    max_step_override = _normalize_step(form.get("max_step_override"))
    enabled = 1
    if "enabled" in form:
        enabled = 1 if form.get("enabled") == "on" else 0
    never_expires = form.get("never_expires") == "on"
    expires_at = (form.get("expires_at") or "").strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="请输入账号和密码")
    settings_data = get_settings()
    today = _today_date(settings_data.get("server_timezone"))
    if never_expires:
        expires_at = None
    else:
        expires_date = _parse_date(expires_at)
        if not expires_date:
            raise HTTPException(status_code=400, detail="请选择过期时间")
        if expires_date <= today:
            raise HTTPException(status_code=400, detail="过期时间需大于今天")
        expires_at = expires_date.strftime("%Y-%m-%d")
    existing = get_account_by_name(username)
    if existing:
        raise HTTPException(status_code=400, detail="账号已存在")
    account_id = create_account(
        username,
        encrypt_text(password),
        enabled,
        source_info,
        fixed_step,
        min_step_override,
        max_step_override,
        expires_at,
    )

    return {
        "ok": True,
        "message": "账号添加成功",
        "redirect": "/",
    }


@app.get("/accounts/{account_id}/edit", response_class=HTMLResponse)
def edit_account(account_id: int, request: Request):
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    return templates.TemplateResponse(
        "account_form.html",
        _template_context(
            request,
            account=account,
            title="编辑账号",
            action=f"/accounts/{account_id}",
            message=None,
        ),
    )


@app.post("/accounts/{account_id}")
async def update_account_post(account_id: int, request: Request):
    form = await request.form()
    current_account = get_account(account_id)
    if not current_account:
        raise HTTPException(status_code=404, detail="账号不存在")
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()
    source_info = (form.get("source_info") or "").strip()
    fixed_step = _normalize_step(form.get("fixed_step"))
    min_step_override = _normalize_step(form.get("min_step_override"))
    max_step_override = _normalize_step(form.get("max_step_override"))
    enabled = current_account.get("enabled", 0)
    if "enabled" in form:
        enabled = 1 if form.get("enabled") == "on" else 0
    never_expires = form.get("never_expires") == "on"
    expires_at = (form.get("expires_at") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="请输入账号")
    settings_data = get_settings()
    today = _today_date(settings_data.get("server_timezone"))
    if never_expires:
        expires_at = None
    else:
        expires_date = _parse_date(expires_at)
        if not expires_date:
            raise HTTPException(status_code=400, detail="请选择过期时间")
        if expires_date <= today:
            raise HTTPException(status_code=400, detail="过期时间需大于今天")
        expires_at = expires_date.strftime("%Y-%m-%d")
    existing = get_account_by_name(username)
    if existing and existing.get("id") != account_id:
        raise HTTPException(status_code=400, detail="账号已存在")
    password_enc = encrypt_text(password) if password else None
    update_account(
        account_id,
        username,
        password_enc,
        enabled,
        source_info,
        fixed_step,
        min_step_override,
        max_step_override,
        expires_at,
    )
    return {"ok": True, "message": "更新成功", "redirect": "/"}


@app.post("/accounts/{account_id}/toggle")
def toggle_account_post(account_id: int):
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    enabled = toggle_account(account_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    state_label = "启用" if enabled else "停用"
    return {
        "ok": True,
        "message": f"账号{account.get('username') or ''}已{state_label}",
        "enabled": bool(enabled),
        "account_name": account.get("username") or "",
    }


@app.post("/accounts/{account_id}/delete")
def delete_account_post(account_id: int):
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    delete_account(account_id)
    return {
        "ok": True,
        "message": f"账号{account.get('username') or ''}删除成功",
    }


@app.post("/accounts/{account_id}/test")
async def test_account_post(account_id: int, request: Request):
    form = await request.form()
    step = (form.get("step") or "").strip()
    step_value = _to_int(step, None)
    if step_value is None or step_value < 0 or step_value > 99999:
        raise HTTPException(status_code=400, detail="步数范围应为 0-99999")
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    try:
        password = decrypt_text(account.get("password_enc") or "")
    except Exception:
        raise HTTPException(status_code=500, detail="账号解密失败")
    ok, message, _data = call_step_api(account.get("username") or "", password, step_value)
    if not ok:
        raise HTTPException(status_code=400, detail=message or "执行失败")
    return {"ok": True, "message": "success", "data": _data or {}}


@app.post("/accounts/{account_id}/password")
async def view_account_password(account_id: int, request: Request):
    form = await request.form()
    key = (form.get("key") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="请输入密钥")
    if not secrets.compare_digest(key, VIEW_PASSWORD_KEY):
        raise HTTPException(status_code=403, detail="密钥不正确")
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    try:
        password = decrypt_text(account.get("password_enc") or "")
    except Exception:
        raise HTTPException(status_code=500, detail="账号解密失败")
    return {
        "ok": True,
        "message": "success",
        "password": password,
        "masked": _mask_password(password),
    }


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    settings_data = get_settings()
    cron_expression = settings_data.get("cron_expression") or ""
    cron_command = settings_data.get("cron_command") or ""
    cron_preview = f"{cron_expression} {cron_command}".strip()
    return templates.TemplateResponse(
        "settings.html",
        _template_context(
            request,
            settings=settings_data,
            cron_preview=cron_preview,
            title="系统设置",
        ),
    )


@app.post("/settings")
async def update_settings_post(request: Request):
    form = await request.form()
    current = get_settings()
    register_proxy_raw = form.get("register_proxy")
    if register_proxy_raw is None:
        register_proxy = _normalize_proxy_url(current.get("register_proxy") or "")
    else:
        register_proxy = _normalize_proxy_url(register_proxy_raw)
    register_proxy_enabled = 1 if form.get("register_proxy_enabled") else 0
    if register_proxy_enabled and not register_proxy:
        raise HTTPException(status_code=400, detail="启用代理时请填写代理地址")
    values = {
        "min_step": _to_int(form.get("min_step"), current["min_step"]),
        "max_step": _to_int(form.get("max_step"), current["max_step"]),
        "push_plus_token": (form.get("push_plus_token") or "").strip(),
        "push_plus_hour": (form.get("push_plus_hour") or "").strip(),
        "push_plus_max": _to_int(form.get("push_plus_max"), current["push_plus_max"]),
        "push_wechat_webhook_key": (form.get("push_wechat_webhook_key") or "").strip(),
        "telegram_bot_token": (form.get("telegram_bot_token") or "").strip(),
        "telegram_chat_id": (form.get("telegram_chat_id") or "").strip(),
        "sleep_gap": _to_float(form.get("sleep_gap"), current["sleep_gap"]),
        "use_concurrent": 0,
        "random_delay_max": _to_int(form.get("random_delay_max"), current["random_delay_max"]),
        "server_timezone": (form.get("server_timezone") or current.get("server_timezone") or "Asia/Shanghai").strip(),
        "cron_expression": (form.get("cron_expression") or current["cron_expression"]).strip(),
        "cron_command": (form.get("cron_command") or current["cron_command"]).strip(),
        "register_proxy": register_proxy,
        "register_proxy_enabled": register_proxy_enabled,
    }
    update_settings(values)
    return {"ok": True, "message": "保存成功"}


@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    per_page = _normalize_per_page(request.query_params.get("per_page"), 50)
    page = _to_int(request.query_params.get("page"), 1)
    q = (request.query_params.get("q") or "").strip()
    filter_status = (request.query_params.get("status") or "").strip()
    filter_date_start = (request.query_params.get("date_start") or "").strip()
    filter_date_end = (request.query_params.get("date_end") or "").strip()
    has_filter = q or filter_status or filter_date_start or filter_date_end
    if has_filter:
        total = count_runs_filtered(account=q or None, status=filter_status or None, date_start=filter_date_start or None, date_end=filter_date_end or None)
        page, total_pages, offset, page_numbers = _paginate(total, page, per_page)
        runs = list_runs_filtered(account=q or None, status=filter_status or None, date_start=filter_date_start or None, date_end=filter_date_end or None, limit=per_page, offset=offset)
    else:
        total = count_runs()
        page, total_pages, offset, page_numbers = _paginate(total, page, per_page)
        runs = list_runs(limit=per_page, offset=offset)
    settings_data = get_settings()
    day_start, day_end = _today_range(settings_data.get("server_timezone"))
    today_success = count_runs_by_range(day_start, day_end, success=True)
    today_fail = count_runs_by_range(day_start, day_end, success=False)
    today_total = today_success + today_fail
    today_rate_num = round((today_success / today_total) * 100, 1) if today_total else 0.0
    latest_run = list_runs(limit=1, offset=0)
    latest_started = latest_run[0].get("started_at") if latest_run else None
    today_runs = list_runs_by_range(day_start, day_end)
    today_timeline = []
    for item in today_runs:
        exit_code = item.get("exit_code")
        if exit_code is None:
            status = "pending"
            status_label = "进行中"
        elif exit_code == 0:
            status = "success"
            status_label = "成功"
        else:
            status = "fail"
            status_label = "失败"
        today_timeline.append(
            {
                "status": status,
                "status_label": status_label,
                "started_at": _format_ts(item.get("started_at")),
                "account": item.get("account_name") or "-",
                "step_count": item.get("step_count"),
                "started_at_raw": item.get("started_at") or "",
            }
        )
    for run in runs:
        run["account_label"] = run.get("account_name") or "-"
        run["step_label"] = run.get("step_count") if run.get("step_count") is not None else "-"
        run["trigger_label"] = _trigger_label(run.get("trigger"))
        run["started_at_fmt"] = _format_ts(run.get("started_at"))
        run["finished_at_fmt"] = _format_ts(run.get("finished_at"))
    return templates.TemplateResponse(
        "logs.html",
        _template_context(
            request,
            runs=runs,
            title="执行记录",
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            page_numbers=page_numbers,
            q=q,
            filter_status=filter_status,
            filter_date_start=filter_date_start,
            filter_date_end=filter_date_end,
            success_total=count_runs_success(),
            fail_total=count_runs_fail(),
            today_success=today_success,
            today_fail=today_fail,
            today_total=today_total,
            today_success_rate=f"{today_rate_num:.1f}%" if today_total else "-",
            today_success_rate_num=today_rate_num,
            last_run_at=_format_ts(latest_started),
            today_timeline=today_timeline,
        ),
    )


@app.get("/logs/{run_id}", response_class=HTMLResponse)
def log_detail(run_id: int, request: Request):
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="记录不存在")
    run["account_label"] = run.get("account_name") or "-"
    run["source_info"] = "-"
    if run.get("account_name"):
        account = get_account_by_name(run.get("account_name"))
        if account:
            run["source_info"] = account.get("source_info") or "-"
    run["step_label"] = run.get("step_count") if run.get("step_count") is not None else "-"
    run["trigger_label"] = _trigger_label(run.get("trigger"))
    run["started_at_fmt"] = _format_ts(run.get("started_at"))
    run["finished_at_fmt"] = _format_ts(run.get("finished_at"))
    return templates.TemplateResponse(
        "log_detail.html",
        _template_context(
            request,
            run=run,
            message=None,
            title="执行记录",
        ),
    )


# ------ 注册账号 ------

# 将 mimotion 根目录加入 sys.path，以便直接导入 zepp_helper
_MIMOTION_DIR = os.path.join(os.path.dirname(BASE_DIR), "mimotion")
if _MIMOTION_DIR not in sys.path:
    sys.path.insert(0, _MIMOTION_DIR)

def _normalize_proxy_url(value: str) -> str:
    proxy = (value or "").strip()
    if not proxy:
        return ""
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    return proxy


def _get_register_proxy():
    """从数据库设置中读取注册代理地址，未启用则返回 None"""
    settings_data = get_settings()
    proxy = _normalize_proxy_url(settings_data.get("register_proxy") or "")
    if settings_data.get("register_proxy_enabled") and proxy:
        return proxy
    return None


def _normalize_zepp_login_user(username: str) -> tuple[str, bool]:
    user = (username or "").strip()
    if user and (user.startswith("+86") or "@" in user):
        normalized = user
    elif user:
        normalized = f"+86{user}"
    else:
        normalized = user
    return normalized, normalized.startswith("+86")


def _decrypt_session_token(token_enc: str | None) -> str | None:
    if not token_enc:
        return None
    try:
        return decrypt_text(token_enc)
    except Exception:
        return None


def _encrypt_session_token(token_plain: str | None) -> str | None:
    if not token_plain:
        return None
    try:
        return encrypt_text(token_plain)
    except Exception:
        return None


def _build_account_token_data(
    username: str,
    access_token: str | None,
    login_token: str | None,
    app_token: str | None,
    zepp_user_id: str | None,
    zepp_device_id: str | None,
) -> str | None:
    if not (access_token and login_token and app_token and zepp_user_id and zepp_device_id):
        return None

    aes_key_raw = os.environ.get("AES_KEY")
    if not aes_key_raw:
        return None

    try:
        aes_key = aes_key_raw.encode("utf-8")
    except Exception:
        return None
    if len(aes_key) != 16:
        return None

    try:
        from util.aes_help import bytes_to_base64, encrypt_data
        from util.zepp_helper import get_time
    except Exception:
        return None

    login_user, _ = _normalize_zepp_login_user(username)
    now_ms = get_time()
    payload = {
        login_user: {
            "access_token": access_token,
            "login_token": login_token,
            "app_token": app_token,
            "user_id": str(zepp_user_id),
            "device_id": zepp_device_id,
            "access_token_time": now_ms,
            "login_token_time": now_ms,
            "app_token_time": now_ms,
        }
    }
    try:
        origin = json.dumps(payload, ensure_ascii=False)
        cipher_data = encrypt_data(origin.encode("utf-8"), aes_key, None)
        return bytes_to_base64(cipher_data)
    except Exception:
        return None


def _persist_account_session_state(
    account_id: int,
    username: str,
    zepp_user_id: str | None,
    zepp_device_id: str | None,
    access_token: str | None,
    login_token: str | None,
    app_token: str | None,
    token_last_error: str | None,
):
    token_data = _build_account_token_data(
        username=username,
        access_token=access_token,
        login_token=login_token,
        app_token=app_token,
        zepp_user_id=zepp_user_id,
        zepp_device_id=zepp_device_id,
    )
    token_refreshed_at = _to_bj_str(datetime.now(_beijing_tz())) if app_token else None
    upsert_account_session(
        account_id=account_id,
        zepp_user_id=str(zepp_user_id) if zepp_user_id else None,
        zepp_device_id=zepp_device_id,
        access_token_enc=_encrypt_session_token(access_token),
        login_token_enc=_encrypt_session_token(login_token),
        app_token_enc=_encrypt_session_token(app_token),
        token_data=token_data,
        token_refreshed_at=token_refreshed_at,
        token_last_error=token_last_error,
    )


def _build_register_session_snapshot(
    username: str,
    password: str,
    preferred_access_token: str | None = None,
) -> dict:
    from util.zepp_helper import grant_login_tokens, login_access_token

    login_user, is_phone = _normalize_zepp_login_user(username)
    zepp_device_id = str(uuid.uuid4())

    access_token = preferred_access_token
    login_token = None
    app_token = None
    zepp_user_id = None
    token_last_error = None

    if access_token:
        login_token_new, app_token_new, user_id_new, token_err = grant_login_tokens(access_token, zepp_device_id, is_phone)
        if login_token_new and app_token_new and user_id_new:
            login_token = login_token_new
            app_token = app_token_new
            zepp_user_id = str(user_id_new)
        else:
            token_last_error = token_err or "客户端登录失败"

    if not (login_token and app_token and zepp_user_id):
        access_token_new, login_err = login_access_token(login_user, password)
        if access_token_new:
            access_token = access_token_new
            login_token_new, app_token_new, user_id_new, token_err = grant_login_tokens(access_token, zepp_device_id, is_phone)
            if login_token_new and app_token_new and user_id_new:
                login_token = login_token_new
                app_token = app_token_new
                zepp_user_id = str(user_id_new)
                token_last_error = None
            else:
                token_last_error = token_err or "客户端登录失败"
        else:
            token_last_error = login_err or token_last_error or "账号登录失败"

    token_data = _build_account_token_data(
        username=username,
        access_token=access_token,
        login_token=login_token,
        app_token=app_token,
        zepp_user_id=zepp_user_id,
        zepp_device_id=zepp_device_id,
    )

    token_refreshed_at = _to_bj_str(datetime.now(_beijing_tz())) if app_token else None
    return {
        "zepp_user_id": zepp_user_id,
        "zepp_device_id": zepp_device_id,
        "access_token": access_token,
        "login_token": login_token,
        "app_token": app_token,
        "token_data": token_data,
        "token_refreshed_at": token_refreshed_at,
        "token_last_error": token_last_error,
    }


def _resolve_account_weixin_payload(
    account_id: int,
    username: str,
    password: str,
    include_qr: bool,
) -> dict:
    from util.zepp_helper import (
        _WEIXIN_THIRD_PARTY_ID,
        check_weixin_bind_status,
        get_weixin_bind_qr_url,
        grant_app_token,
        grant_login_tokens,
        login_access_token,
    )

    session = get_account_session(account_id) or {}
    login_user, is_phone = _normalize_zepp_login_user(username)
    zepp_user_id = (session.get("zepp_user_id") or "").strip() or None
    zepp_device_id = (session.get("zepp_device_id") or "").strip() or str(uuid.uuid4())
    access_token = _decrypt_session_token(session.get("access_token_enc"))
    login_token = _decrypt_session_token(session.get("login_token_enc"))
    app_token = _decrypt_session_token(session.get("app_token_enc"))
    last_error = None

    def _query_with_app_token(curr_app_token: str | None, curr_user_id: str | None):
        if not curr_app_token or not curr_user_id:
            return None, "会话信息不完整"
        is_bind, status_err = check_weixin_bind_status(curr_app_token, curr_user_id, _WEIXIN_THIRD_PARTY_ID)
        if status_err is not None:
            return None, status_err

        payload = {
            "available": True,
            "account_id": account_id,
            "is_bind": bool(is_bind),
            "qr_url": None,
            "qr_refreshed": False,
            "needs_qr_refresh_when_unbound": True,
        }
        if not is_bind and include_qr:
            qr_url, qr_err = get_weixin_bind_qr_url(curr_app_token, curr_user_id, _WEIXIN_THIRD_PARTY_ID)
            if qr_err is not None:
                return None, qr_err
            payload["qr_url"] = qr_url
            payload["qr_refreshed"] = True
        return payload, None

    if app_token and zepp_user_id:
        payload, err = _query_with_app_token(app_token, zepp_user_id)
        if payload:
            _persist_account_session_state(
                account_id,
                username,
                zepp_user_id,
                zepp_device_id,
                access_token,
                login_token,
                app_token,
                None,
            )
            return payload
        last_error = err

    if login_token and zepp_user_id:
        app_token_new, app_err = grant_app_token(login_token)
        if app_token_new:
            app_token = app_token_new
            payload, err = _query_with_app_token(app_token, zepp_user_id)
            if payload:
                _persist_account_session_state(
                    account_id,
                    username,
                    zepp_user_id,
                    zepp_device_id,
                    access_token,
                    login_token,
                    app_token,
                    None,
                )
                return payload
            last_error = err or app_err
        else:
            last_error = app_err or last_error

    if access_token:
        login_token_new, app_token_new, user_id_new, token_err = grant_login_tokens(access_token, zepp_device_id, is_phone)
        if login_token_new and app_token_new and user_id_new:
            login_token = login_token_new
            app_token = app_token_new
            zepp_user_id = str(user_id_new)
            payload, err = _query_with_app_token(app_token, zepp_user_id)
            if payload:
                _persist_account_session_state(
                    account_id,
                    username,
                    zepp_user_id,
                    zepp_device_id,
                    access_token,
                    login_token,
                    app_token,
                    None,
                )
                return payload
            last_error = err or token_err
        else:
            last_error = token_err or last_error

    access_token_new, login_err = login_access_token(login_user, password)
    if not access_token_new:
        _persist_account_session_state(
            account_id,
            username,
            zepp_user_id,
            zepp_device_id,
            access_token,
            login_token,
            app_token,
            login_err or last_error or "账号登录失败",
        )
        return {
            "available": False,
            "account_id": account_id,
            "error": login_err or last_error or "账号登录失败",
        }

    access_token = access_token_new
    login_token_new, app_token_new, user_id_new, token_err = grant_login_tokens(access_token, zepp_device_id, is_phone)
    if not (login_token_new and app_token_new and user_id_new):
        _persist_account_session_state(
            account_id,
            username,
            zepp_user_id,
            zepp_device_id,
            access_token,
            login_token,
            app_token,
            token_err or last_error or "客户端登录失败",
        )
        return {
            "available": False,
            "account_id": account_id,
            "error": token_err or last_error or "客户端登录失败",
        }

    login_token = login_token_new
    app_token = app_token_new
    zepp_user_id = str(user_id_new)
    payload, err = _query_with_app_token(app_token, zepp_user_id)
    if payload:
        _persist_account_session_state(
            account_id,
            username,
            zepp_user_id,
            zepp_device_id,
            access_token,
            login_token,
            app_token,
            None,
        )
        return payload

    _persist_account_session_state(
        account_id,
        username,
        zepp_user_id,
        zepp_device_id,
        access_token,
        login_token,
        app_token,
        err or last_error or "微信绑定状态检测失败",
    )
    return {
        "available": False,
        "account_id": account_id,
        "error": err or last_error or "微信绑定状态检测失败",
    }


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        _template_context(request, title="注册账号"),
    )


@app.get("/register/captcha")
def register_captcha():
    from util.zepp_helper import get_register_captcha

    image_bytes, captcha_key, err = get_register_captcha(proxy=_get_register_proxy())
    if err or image_bytes is None:
        raise HTTPException(status_code=500, detail=err or "获取验证码失败")
    from fastapi.responses import Response

    return Response(
        content=image_bytes,
        media_type="image/png",
        headers={"X-Captcha-Key": captcha_key or ""},
    )


@app.post("/register")
async def register_post(request: Request):
    from util.zepp_helper import register_account

    form = await request.form()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    captcha_code = (form.get("captcha_code") or "").strip()
    captcha_key = (form.get("captcha_key") or "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="请输入邮箱")
    if not password:
        raise HTTPException(status_code=400, detail="请输入密码")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码长度至少8位")
    import re as _re
    if not _re.search(r'[a-zA-Z]', password) or not _re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="密码必须包含字母和数字")
    if not captcha_code:
        raise HTTPException(status_code=400, detail="请输入验证码")
    if not captcha_key:
        raise HTTPException(status_code=400, detail="验证码未加载，请刷新后重试")

    existing = get_account_by_name(email)
    if existing:
        raise HTTPException(status_code=400, detail="账号已存在")

    access_token, err = register_account(email, password, captcha_code, captcha_key, proxy=_get_register_proxy())
    if err:
        raise HTTPException(status_code=400, detail=err)

    settings_data = get_settings()
    expires_at = (_today_date(settings_data.get("server_timezone")) + timedelta(days=30)).strftime("%Y-%m-%d")
    account_id = create_account(
        email,
        encrypt_text(password),
        1,
        "",
        None,
        None,
        None,
        expires_at,
    )

    session_snapshot = _build_register_session_snapshot(
        username=email,
        password=password,
        preferred_access_token=access_token,
    )
    session_error = session_snapshot.get("token_last_error")
    _persist_account_session_state(
        account_id=account_id,
        username=email,
        zepp_user_id=session_snapshot.get("zepp_user_id"),
        zepp_device_id=session_snapshot.get("zepp_device_id"),
        access_token=session_snapshot.get("access_token"),
        login_token=session_snapshot.get("login_token"),
        app_token=session_snapshot.get("app_token"),
        token_last_error=session_error,
    )

    return {
        "ok": True,
        "message": "注册成功",
        "session_ready": session_error is None,
        "session_error": session_error,
        "account_id": account_id,
        "redirect": f"/accounts/{account_id}/edit",
    }


@app.post("/accounts/{account_id}/binding/status")
def account_binding_status(account_id: int):
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    try:
        password = decrypt_text(account.get("password_enc") or "")
    except Exception:
        raise HTTPException(status_code=500, detail="账号解密失败")

    binding_payload = _resolve_account_weixin_payload(
        account_id=account_id,
        username=account.get("username") or "",
        password=password,
        include_qr=False,
    )
    return {
        "ok": True,
        "binding": binding_payload,
    }


@app.post("/accounts/{account_id}/binding/qrcode")
def account_binding_qrcode(account_id: int):
    account = get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    try:
        password = decrypt_text(account.get("password_enc") or "")
    except Exception:
        raise HTTPException(status_code=500, detail="账号解密失败")

    binding_payload = _resolve_account_weixin_payload(
        account_id=account_id,
        username=account.get("username") or "",
        password=password,
        include_qr=True,
    )
    return {
        "ok": True,
        "binding": binding_payload,
    }
