import os
import base64
from sud.config import SecurityConfig


def test_security_config_reads_env_keys(tmp_path, monkeypatch):
    # Raw key string
    monkeypatch.setenv("SECURITY_PROVIDER_HMAC_KEY", "rawkey")
    cfg = SecurityConfig()
    assert cfg.provider_hmac_key == b"rawkey"

    # b64 key value
    key = base64.b64encode(b"mybinarykey")
    monkeypatch.setenv("SECURITY_AT_REST_KEY", f"b64:{key.decode('utf-8')}")
    cfg2 = SecurityConfig()
    assert cfg2.at_rest_key == b"mybinarykey"
