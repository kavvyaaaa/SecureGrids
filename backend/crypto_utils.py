import hashlib
import json
from config import Config


def generate_signature(data):

    payload = {k: v for k, v in data.items() if k != "signature"}

    payload_str = json.dumps(payload, sort_keys=True, default=str)

    signature = hashlib.sha256(
        (payload_str + Config.SIGNATURE_SECRET).encode()
    ).hexdigest()

    return signature


def verify_signature(data, signature):

    expected = generate_signature(data)

    return expected == signature