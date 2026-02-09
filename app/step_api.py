import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


_API_URL = "https://step.wvuvw.top"
_KEY_PARTS = [
    "fanTui2024",
    "SecretKey",
    "1234567890",
    "1234567890",
    "1234567890",
    "1234567890",
]
_KEY_TAIL = "123456789012345678901234567890"
_IV = "1234567890123456"


def _build_key_material() -> str:
    return "".join(_KEY_PARTS) + _KEY_TAIL


def _random_base36(length: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_signature(tel: str, psw: str, step: str, timestamp: int, nonce: str) -> str:
    key_material = _build_key_material()
    payload = (
        f"tel={tel}&psw={psw}&step={step}&timestamp={timestamp}&nonce={nonce}&key={key_material}"
    )
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def _encrypt_payload(payload: Dict[str, Any]) -> str:
    key_material = _build_key_material()
    key_bytes = key_material[:32].encode("utf-8")
    iv_bytes = _IV.encode("utf-8")
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")


def build_encrypted_request(tel: str, psw: str, step: int) -> Dict[str, str]:
    step_value = int(step)
    if step_value < 0 or step_value > 100000:
        raise ValueError("step must be between 0 and 100000")
    step_str = str(step_value)
    timestamp = int(time.time())
    nonce = _random_base36(13) + _random_base36(13)
    signature = _build_signature(tel, psw, step_str, timestamp, nonce)
    payload = {
        "tel": tel,
        "psw": psw,
        "step": step_str,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }
    encrypted_data = _encrypt_payload(payload)
    return {"encrypted_data": encrypted_data}


def _is_success_response(data: Dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("message") != "success":
        return False
    inner = data.get("data")
    if not isinstance(inner, dict):
        return False
    return inner.get("code") == 1


def call_step_api(
    tel: str,
    psw: str,
    step: int,
    timeout: float = 10,
) -> Tuple[bool, str, Dict[str, Any] | None]:
    body = build_encrypted_request(tel, psw, step)
    resp = requests.post(_API_URL, json=body, timeout=timeout)
    data = None
    try:
        data = resp.json()
    except Exception:
        data = None
    ok = resp.status_code == 200 and _is_success_response(data)
    if ok:
        return True, "success", data
    if data is not None:
        return False, data.get("message") or "request_failed", data
    return False, resp.text or f"http_{resp.status_code}", None
