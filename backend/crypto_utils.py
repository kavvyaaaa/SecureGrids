# ---------------------------------------------------------
# CRYPTOGRAPHIC UTILITIES WITH DEFENSE MECHANISMS
# ---------------------------------------------------------


import hashlib
import hmac
import json
import time
from datetime import datetime
from collections import defaultdict
from config import Config


# ---------------------------------------------------------
# RATE-LIMIT TRACKER  (per-device failure history)
# ---------------------------------------------------------

_failure_log = defaultdict(list)


def _prune_failure_log(device_id):
    
    cutoff = time.time() - Config.CRYPTO_RATE_LIMIT_WINDOW_SECONDS
    _failure_log[device_id] = [
        ts for ts in _failure_log[device_id] if ts > cutoff
    ]


def is_device_rate_limited(device_id):
   
    _prune_failure_log(device_id)
    return len(_failure_log[device_id]) >= Config.CRYPTO_RATE_LIMIT_MAX_FAILURES


def record_failure(device_id):
  
    _failure_log[device_id].append(time.time())


def get_failure_count(device_id):
   
    _prune_failure_log(device_id)
    return len(_failure_log[device_id])


# ---------------------------------------------------------
# SIGNATURE GENERATION  (HMAC-SHA256)
# ---------------------------------------------------------
def generate_signature(data):
   
    payload = {k: v for k, v in data.items() if k != "signature"}
    payload_str = json.dumps(payload, sort_keys=True, default=str)

    signature = hmac.new(
        Config.SIGNATURE_SECRET.encode(),
        payload_str.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature


# ---------------------------------------------------------
# SIGNATURE VERIFICATION  (with replay & rate-limit checks)
# ---------------------------------------------------------
def verify_signature(data, signature):

    device_id = data.get("device_id", "unknown")

    # --- Defense 1: Rate Limiting --------------------------------
    if is_device_rate_limited(device_id):
        return False, "RATE_LIMITED"

    # --- Defense 2: Replay Attack Prevention ---------------------
    ts = data.get("timestamp")
    if ts is not None:
        try:
            if isinstance(ts, datetime):
                reading_time = ts
            else:
                reading_time = datetime.fromisoformat(str(ts))
            age_seconds = abs((datetime.now() - reading_time).total_seconds())
            if age_seconds > Config.REPLAY_WINDOW_SECONDS:
                record_failure(device_id)
                return False, "REPLAY_DETECTED"
        except (ValueError, TypeError):
            pass  # If timestamp can't be parsed, skip this check

    # --- Defense 3: HMAC Signature Verification ------------------
    expected = generate_signature(data)
    if not hmac.compare_digest(expected, signature if signature else ""):
        record_failure(device_id)
        return False, "SIGNATURE_MISMATCH"

    return True, "VERIFIED"
