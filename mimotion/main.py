# -*- coding: utf8 -*-
import math
import traceback
from datetime import datetime
import pytz
import uuid
import hashlib

import json
import random
import re
import time
import os

from util.aes_help import encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper
import util.push_util as push_util

fixed_step = None
fixed_step_exact = False
cron_last_minutes = None
cron_schedule_minutes = None

# 获取默认值转int
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))


# cron 解析（仅分钟与小时字段）
def _parse_cron_field(field, min_value, max_value):
    field = str(field or "").strip()
    if field in ("*", "?"):
        return list(range(min_value, max_value + 1))
    values = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            try:
                step = int(step_str)
            except Exception:
                continue
        else:
            base = part
        if base in ("*", "?") or base == "":
            start, end = min_value, max_value
        elif "-" in base:
            try:
                start_str, end_str = base.split("-", 1)
                start, end = int(start_str), int(end_str)
            except Exception:
                continue
        else:
            try:
                start = end = int(base)
            except Exception:
                continue
        start = max(min_value, start)
        end = min(max_value, end)
        if step <= 0:
            step = 1
        for value in range(start, end + 1, step):
            values.add(value)
    return sorted(v for v in values if min_value <= v <= max_value)


def _get_cron_last_minutes(expression):
    if not expression:
        return 22 * 60
    parts = str(expression).split()
    if len(parts) < 2:
        return 22 * 60
    minutes = _parse_cron_field(parts[0], 0, 59)
    hours = _parse_cron_field(parts[1], 0, 23)
    if not minutes or not hours:
        return 22 * 60
    return max(hour * 60 + minute for hour in hours for minute in minutes)


def _get_cron_schedule_minutes(expression):
    if not expression:
        return [22 * 60]
    parts = str(expression).split()
    if len(parts) < 2:
        return [22 * 60]
    minutes = _parse_cron_field(parts[0], 0, 59)
    hours = _parse_cron_field(parts[1], 0, 23)
    if not minutes or not hours:
        return [22 * 60]
    schedule = sorted({hour * 60 + minute for hour in hours for minute in minutes})
    return schedule if schedule else [22 * 60]


def _get_schedule_slot_index(schedule_minutes, hour, minute):
    if not schedule_minutes:
        return 0
    now_minutes = hour * 60 + minute
    idx = 0
    for i, schedule_minute in enumerate(schedule_minutes):
        if now_minutes >= schedule_minute:
            idx = i
        else:
            break
    return idx


def get_time_rate(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    max_minutes = cron_last_minutes if cron_last_minutes else 22 * 60
    if max_minutes <= 0:
        max_minutes = 1
    return min((hour * 60 + minute) / max_minutes, 1)


def get_min_max_config():
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    min_step = max(0, min(99999, min_step))
    max_step = max(0, min(99999, max_step))
    if min_step > max_step:
        min_step, max_step = max_step, min_step
    return min_step, max_step


# 获取当前时间对应的最大和最小步数
def get_min_max_by_time(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    time_rate = get_time_rate(hour, minute)
    min_step, max_step = get_min_max_config()
    return int(time_rate * min_step), int(time_rate * max_step)


def _seed_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _resolve_daily_target_and_curve(user, min_step, max_step, date_str):
    seed = _seed_hex(f"{date_str}_{user}")
    try:
        seed_target = int(seed[:8], 16)
        seed_curve = int(seed[8:10], 16)
        seed_param = int(seed[10:12], 16)
    except Exception:
        seed_target = random.randint(0, 2**31 - 1)
        seed_curve = random.randint(0, 255)
        seed_param = random.randint(0, 255)
    span = max_step - min_step + 1
    if span <= 0:
        target = min_step
    else:
        target = min_step + (seed_target % span)
    curve_id = seed_curve % 5
    ratio = seed_param / 255
    gamma = 1.2 + (ratio * 0.8)
    gamma_fast = 0.85 + (ratio * 0.2)
    return target, curve_id, gamma, gamma_fast


def _curve_linear(p):
    return p


def _curve_ease_in(p, gamma):
    return p ** gamma


def _curve_ease_out(p, gamma):
    return 1 - ((1 - p) ** gamma)


def _curve_smoothstep(p):
    return (3 * p * p) - (2 * p * p * p)


def _curve_slow_flat_fast(p, gamma_slow, gamma_fast):
    if p <= 0.4:
        return 0.4 * ((p / 0.4) ** gamma_slow)
    if p <= 0.75:
        return 0.4 + (0.35 * ((p - 0.4) / 0.35))
    return 0.75 + (0.25 * (((p - 0.75) / 0.25) ** gamma_fast))


def _calc_curve_step(user, min_step, max_step, hour, minute):
    date_str = time_bj.strftime("%Y-%m-%d")
    schedule = cron_schedule_minutes or []
    total_slots = len(schedule)
    if total_slots <= 0:
        total_slots = 1
    slot_index = _get_schedule_slot_index(schedule, hour, minute)
    if slot_index < 0:
        slot_index = 0
    if slot_index >= total_slots:
        slot_index = total_slots - 1
    target, curve_id, gamma, gamma_fast = _resolve_daily_target_and_curve(user, min_step, max_step, date_str)
    p0 = slot_index / total_slots
    p1 = (slot_index + 1) / total_slots
    if curve_id == 0:
        f0 = _curve_linear(p0)
        f1 = _curve_linear(p1)
    elif curve_id == 1:
        f0 = _curve_ease_in(p0, gamma)
        f1 = _curve_ease_in(p1, gamma)
    elif curve_id == 2:
        f0 = _curve_ease_out(p0, gamma)
        f1 = _curve_ease_out(p1, gamma)
    elif curve_id == 3:
        f0 = _curve_smoothstep(p0)
        f1 = _curve_smoothstep(p1)
    else:
        f0 = _curve_slow_flat_fast(p0, gamma, gamma_fast)
        f1 = _curve_slow_flat_fast(p1, gamma, gamma_fast)
    f0 = max(0.0, min(1.0, f0))
    f1 = max(0.0, min(1.0, f1))
    low = int(round(target * f0))
    high = int(round(target * f1))
    if low > high:
        low, high = high, low
    low = max(min_step, low)
    high = min(max_step, high)
    if low > high:
        low = high = min_step
    step_value = random.randint(low, high)
    return step_value, {
        "target": target,
        "slot_index": slot_index,
        "slot_total": total_slots,
        "low": low,
        "high": high,
    }


# 虚拟ip地址
def fake_ip():
    # 随便找的国内IP段：223.64.0.0 - 223.117.255.255
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


# 账号脱敏
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'


# 获取北京时间
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    # 获取当前时间
    return datetime.now().astimezone(target_timezone)


# 格式化时间
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


# 获取时间戳
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)


# 获取登录code
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None
        self.device_id = str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            pass
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user
        if user.startswith("+86"):
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user
        # self.fake_ip_addr = fake_ip()
        # self.log_str += f"创建虚拟ip地址：{self.fake_ip_addr}\n"

    # 登录
    def login(self):
        user_token_info = user_tokens.get(self.user)
        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")
            self.user_id = user_token_info.get("user_id")
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id
            self.log_str += "[认证] 检测到缓存token，验证app_token有效性...\n"
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "[认证] app_token有效，复用缓存token\n"
                return app_token
            else:
                self.log_str += f"[认证] app_token已失效，尝试用login_token刷新...\n"
                # 检查login_token是否可用
                app_token, msg = zeppHelper.grant_app_token(login_token)
                if app_token is None:
                    self.log_str += f"[认证] login_token已失效，尝试用access_token刷新...\n"
                    login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id,
                                                                                         self.is_phone)
                    if login_token is None:
                        self.log_str += f"[认证] access_token已失效（{msg}），需要重新登录\n"
                    else:
                        self.log_str += "[认证] 通过access_token刷新成功\n"
                        user_token_info["login_token"] = login_token
                        user_token_info["app_token"] = app_token
                        user_token_info["user_id"] = user_id
                        user_token_info["login_token_time"] = get_time()
                        user_token_info["app_token_time"] = get_time()
                        self.user_id = user_id
                        return app_token
                else:
                    self.log_str += "[认证] 通过login_token刷新app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token
        else:
            self.log_str += "[认证] 无缓存token\n"

        # access_token 失效 或者没有保存加密数据
        self.log_str += "[认证] 使用账号密码登录...\n"
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "[认证] 登录失败：%s\n" % msg
            return None
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id,
                                                                             self.is_phone)
        if login_token is None:
            self.log_str += f"[认证] 登录后获取token失败：{msg}\n"
            return None

        self.log_str += "[认证] 登录成功，已获取全部token\n"
        user_token_info = dict()
        user_token_info["access_token"] = access_token
        user_token_info["login_token"] = login_token
        user_token_info["app_token"] = app_token
        user_token_info["user_id"] = user_id
        user_token_info["access_token_time"] = get_time()
        user_token_info["login_token_time"] = get_time()
        user_token_info["app_token_time"] = get_time()
        if self.device_id is None:
            self.device_id = uuid.uuid4()
        user_token_info["device_id"] = self.device_id
        user_tokens[self.user] = user_token_info
        return app_token

    # 主函数
    def login_and_post_step(self, min_step, max_step):
        if self.invalid:
            return "账号或密码配置有误", False, None
        app_token = self.login()
        if app_token is None:
            return "登陆失败！", False, None

        if fixed_step is not None:
            if fixed_step_exact:
                step_value = fixed_step
            else:
                step_value = int(fixed_step * get_time_rate())
                if step_value < 1:
                    step_value = 1
            bounded_step = max(min_step, min(max_step, step_value))
            if bounded_step != step_value:
                self.log_str += f"\u6b65\u6570\u8d85\u51fa\u8303\u56f4\uff0c\u5df2\u4fee\u6b63\u4e3a{bounded_step}\n"
            step_value = bounded_step
            step = str(step_value)
            self.log_str += f"\u5df2\u8bbe\u7f6e\u4e3a\u56fa\u5b9a\u6b65\u6570{step}\n"
        else:
            step_value, meta = _calc_curve_step(self.user, min_step, max_step, time_bj.hour, time_bj.minute)
            bounded_step = max(min_step, min(max_step, step_value))
            if bounded_step != step_value:
                self.log_str += f"\u6b65\u6570\u8d85\u51fa\u8303\u56f4\uff0c\u5df2\u4fee\u6b63\u4e3a{bounded_step}\n"
            step_value = bounded_step
            step = str(step_value)
            self.log_str += (
                f"\u5df2\u8bbe\u7f6e\u4e3a\u66f2\u7ebf\u6b65\u6570\u76ee\u6807({meta['target']}) "
                f"\u69fd\u4f4d({meta['slot_index'] + 1}/{meta['slot_total']}) "
                f"\u533a\u95f4({meta['low']}~{meta['high']}) \u503c:{step}\n"
            )
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数（{step}）[" + msg + "]", ok, step


def run_single_account(total, idx, user_mi, passwd_mi):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    step = None
    try:
        runner = MiMotionRunner(user_mi, passwd_mi)
        exec_msg, success, step = runner.login_and_post_step(min_step, max_step)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success,
                       "msg": exec_msg}
    except Exception as exc:
        log_str += f"执行异常:{traceback.format_exc()}\n"
        exec_result = {"user": user_mi, "success": False,
                       "msg": f"执行异常:{exc}"}
    print(log_str)
    print(f"MM_RESULT|{user_mi}|{step or ''}|{1 if exec_result.get('success') else 0}")
    return exec_result


def execute():
    user_value = str(users or "").strip()
    passwd_value = str(passwords or "")
    if not user_value or passwd_value == "":
        print("Missing account or password, skip execution")
        exit(1)

    exec_results = [run_single_account(1, 0, user_value, passwd_value)]
    if encrypt_support:
        persist_user_tokens()

    success_count = 0
    push_results = []
    for result in exec_results:
        push_results.append(result)
        if result['success'] is True:
            success_count += 1

    total = len(exec_results)
    summary = f"\nAccounts: {total}, success: {success_count}, failed: {total - success_count}"
    print(summary)
    push_util.push_results(push_results, summary, push_config)

def prepare_user_tokens() -> dict:
    # Only read TOKEN_DATA from env (passed from parent process)
    token_data_env = os.environ.get("TOKEN_DATA")
    if not token_data_env:
        return dict()

    try:
        from util.aes_help import base64_to_bytes
        cipher_bytes = base64_to_bytes(token_data_env)
        decrypted_data = decrypt_data(cipher_bytes, aes_key, None)
        return json.loads(decrypted_data.decode('utf-8', errors='strict'))
    except Exception as exc:
        print(f"TOKEN_DATA decrypt failed, ignore cached token: {exc}")
        return dict()

def persist_user_tokens():
    # 输出到 stdout，由父进程 run_once.py 解析并回写数据库
    from util.aes_help import bytes_to_base64
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    print(f"MM_TOKEN|{bytes_to_base64(cipher_data)}")


if __name__ == "__main__":
    # 北京时间
    time_bj = get_beijing_time()
    encrypt_support = False
    user_tokens = dict()
    if os.environ.__contains__("AES_KEY") is True:
        aes_key = os.environ.get("AES_KEY")
        if aes_key is not None:
            aes_key = aes_key.encode('utf-8')
            if len(aes_key) == 16:
                encrypt_support = True
        if encrypt_support:
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY未设置或者无效 无法使用加密保存功能")
    if os.environ.__contains__("CONFIG") is False:
        print("未配置CONFIG变量，无法执行")
        exit(1)
    else:
        # region 初始化参数
        config = dict()
        try:
            config = dict(json.loads(os.environ.get("CONFIG")))
        except Exception as exc:
            print(f"Invalid CONFIG JSON: {exc}")
            traceback.print_exc()
            exit(1)
        push_config = push_util.PushConfig(
            push_plus_token=config.get('PUSH_PLUS_TOKEN'),
            push_plus_hour=config.get('PUSH_PLUS_HOUR'),
            push_plus_max=get_int_value_default(config, 'PUSH_PLUS_MAX', 30),
            push_wechat_webhook_key=config.get('PUSH_WECHAT_WEBHOOK_KEY'),
            telegram_bot_token=config.get('TELEGRAM_BOT_TOKEN'),
            telegram_chat_id=config.get('TELEGRAM_CHAT_ID')
        )
        sleep_seconds = config.get('SLEEP_GAP')
        if sleep_seconds is None or sleep_seconds == '':
            sleep_seconds = 5
        sleep_seconds = float(sleep_seconds)
        users = config.get('USER')
        passwords = config.get('PWD')
        if users is None or passwords is None:
            print("未正确配置账号密码，无法执行")
            exit(1)
        cron_expr = config.get('CRON_EXPRESSION') or ''
        cron_last_minutes = _get_cron_last_minutes(cron_expr)
        cron_schedule_minutes = _get_cron_schedule_minutes(cron_expr)
        fixed_value = config.get('FIXED_STEP')
        try:
            fixed_value = int(fixed_value)
        except Exception:
            fixed_value = None
        fixed_step_exact = str(config.get('FIXED_STEP_EXACT') or '') == '1'
        if fixed_value is None or fixed_value < 0 or fixed_value > 99999:
            fixed_step = None
            fixed_step_exact = False
        else:
            fixed_step = fixed_value
        min_step, max_step = get_min_max_config()
        # endregion
        execute()
