from orchestrator.battle_manager import BattleManager


async def _sink(_msg):
    return None


def _detect(log):
    manager = BattleManager(_sink)
    return manager._detect_attack_pattern([log])


def test_detect_sqli():
    log = {
        "path": "/api/products",
        "query": "q=%27%20UNION%20SELECT%20NULL--&id=%27%20OR%201%3D1--",
        "body": "",
        "ip": "127.0.0.1",
    }
    res = _detect(log)
    assert res["vuln"] == "SQL Injection"
    assert res["ip"] == "127.0.0.1"


def test_detect_ssrf():
    log = {
        "path": "/api/image-proxy",
        "query": "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
        "body": "",
        "ip": "10.0.0.5",
    }
    res = _detect(log)
    assert res["vuln"] == "SSRF"
    assert res["ip"] == "10.0.0.5"


def test_detect_xss():
    log = {
        "path": "/api/reviews",
        "query": "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "body": "",
        "ip": "192.168.1.10",
    }
    res = _detect(log)
    assert res["vuln"] == "Stored XSS"


def test_detect_path_traversal():
    log = {
        "path": "/api/download",
        "query": "file=..%2F..%2F..%2Fetc%2Fpasswd",
        "body": "",
        "ip": "127.0.0.1",
    }
    res = _detect(log)
    assert res["vuln"] == "Path Traversal"


def test_detect_cmdi():
    log = {
        "path": "/download",
        "query": "cmd=%3B%20whoami&file=%3B%20whoami",
        "body": "",
        "ip": "127.0.0.1",
    }
    res = _detect(log)
    assert res["vuln"] == "Command Injection"


def test_detect_auth_bypass():
    log = {
        "path": "/api/auth/login",
        "query": "",
        "body": "{\"username\": \"' OR 1=1--\", \"password\": \"anything\"}",
        "ip": "127.0.0.1",
    }
    res = _detect(log)
    assert res["vuln"] == "Broken Authentication (JWT bypass)"


def test_no_detection():
    log = {"path": "/api/products", "query": "q=mouse", "body": "", "ip": "127.0.0.1"}
    assert _detect(log) is None
