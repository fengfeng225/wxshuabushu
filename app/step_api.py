import base64
import json
import time
from typing import Any, Dict, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


_API_URL = "https://bs.yanwan.store/run4/mi20251001.php"
_AES_KEY = "Yx9#mK2$pL7@qN4^"
_AES_IV = "Bw5&hT8!vR3%jM6*"
_REQUEST_HEADERS = {
    "origin": "https://bs.yanwan.store",
    "referer": "https://bs.yanwan.store/run4/",
    "x-requested-with": "XMLHttpRequest",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "accept": "application/json, text/javascript, */*; q=0.01",
    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
}


def _encrypt_payload(payload: Dict[str, Any]) -> str:
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cipher = AES.new(_AES_KEY.encode("utf-8"), AES.MODE_CBC, iv=_AES_IV.encode("utf-8"))
    encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")


def build_encrypted_request(tel: str, psw: str, step: int) -> Dict[str, str]:
    step_value = int(step)
    if step_value < 0 or step_value > 100000:
        raise ValueError("step must be between 0 and 100000")
    payload = {
        "ups1": tel,
        "ups2": psw,
        "ups3": str(step_value),
        "timestamp": int(time.time() * 1000),
    }
    encrypted_data = _encrypt_payload(payload)
    return {"encrypted": encrypted_data}


def _is_success_response(data: Dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return False
    code = data.get("code")
    if code is not None and str(code) == "200":
        return True
    msg = data.get("msg") or data.get("message")
    return isinstance(msg, str) and "成功" in msg


def _post_request(body: Dict[str, str], timeout: float):
    return requests.post(_API_URL, data=body, headers=_REQUEST_HEADERS, timeout=timeout)


def call_step_api(
    tel: str,
    psw: str,
    step: int,
    timeout: float = 10,
) -> Tuple[bool, str, Dict[str, Any] | None]:
    body = build_encrypted_request(tel, psw, step)
    data = None
    resp = _post_request(body, timeout)
    try:
        data = resp.json()
    except Exception:
        data = None
    ok = resp.status_code == 200 and _is_success_response(data)
    if ok:
        return True, "success", data
    if data is not None:
        return False, data.get("msg") or data.get("message") or "request_failed", data
    return False, resp.text or f"http_{resp.status_code}", None
