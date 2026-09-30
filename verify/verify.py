"""verify 服务：一次运行后退出，以状态码报告成败。

三段检查：
  1. 构建检查  —— 编译全部源码并导入服务模块
  2. 代码测试  —— unittest 套件（递归返回后才进入危险续点、悬空调用拒绝、
                  冻结回放等）
  3. HTTP 冒烟 —— 对运行中的服务打真实请求（健康路径、页面、提交、回放、
                  冲突拒绝、按标识读取）

用法：python -m verify.verify
环境变量：APP_URL（默认 http://localhost:8080）、SKIP_SMOKE=1 跳过冒烟。
退出码：0 全部通过；1 任一失败。
"""

import json
import os
import py_compile
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP_URL = os.environ.get("APP_URL", "http://localhost:8080").rstrip("/")

passed = []
failed = []


def report(ok, name, detail=""):
    (passed if ok else failed).append(name)
    mark = "PASS" if ok else "FAIL"
    line = "[%s] %s" % (mark, name)
    if detail and not ok:
        line += "\n       " + detail.replace("\n", "\n       ")
    print(line, flush=True)
    return ok


def check_build():
    try:
        for src in sorted(ROOT.glob("app/*.py")) + sorted(
                ROOT.glob("tests/*.py")) + sorted(ROOT.glob("verify/*.py")):
            py_compile.compile(str(src), doraise=True)
        import app.server  # noqa: F401
        import app.solver  # noqa: F401
        import app.store  # noqa: F401
        html = (ROOT / "app" / "static" / "index.html").read_text(
            encoding="utf-8")
        assert "轨道应急规程" in html and "/api/audits" in html
        return report(True, "构建检查：源码编译 + 模块导入 + 页面资产")
    except Exception as exc:  # noqa: BLE001
        return report(False, "构建检查", repr(exc))


def check_unit_tests():
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1)
    result = runner.run(suite)
    ok = result.wasSuccessful()
    detail = "failures=%d errors=%d" % (len(result.failures), len(result.errors))
    return report(ok, "代码测试：递归返回后进入危险续点 / 悬空调用拒绝 / 冻结回放 等",
                  detail)


def http(method, path, body=None, timeout=10):
    url = APP_URL + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def wait_healthy(retries=40, interval=0.5):
    for _ in range(retries):
        try:
            status, body = http("GET", "/health", timeout=3)
            if status == 200 and body.get("status") == "ok":
                return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(interval)
    return False


def smoke_payload(audit_id):
    return {
        "audit_id": audit_id,
        "root_entry": "launch",
        "procedures": [
            {"id": "launch", "entry": "l1", "nodes": [
                {"id": "l1", "type": "jump", "to": "l2"},
                {"id": "l2", "type": "call", "target": "vent",
                 "continuation": "l3"},
                {"id": "l3", "type": "return"},
            ]},
            {"id": "vent", "entry": "v1", "nodes": [
                {"id": "v1", "type": "jump", "to": ["v2", "v3"]},
                {"id": "v2", "type": "call", "target": "vent",
                 "continuation": "v4"},
                {"id": "v3", "type": "return"},
                {"id": "v4", "type": "jump", "to": "v5"},
                {"id": "v5", "type": "return", "danger": True},
            ]},
        ],
    }


def check_http_smoke():
    if os.environ.get("SKIP_SMOKE") == "1":
        return report(True, "HTTP 冒烟：按 SKIP_SMOKE=1 跳过")
    if not wait_healthy():
        return report(False, "HTTP 冒烟", "健康路径 %s/health 未就绪" % APP_URL)
    ok = report(True, "HTTP 冒烟：健康路径 /health 可用")
    run = uuid.uuid4().hex[:8]

    try:
        req = urllib.request.Request(APP_URL + "/", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8")
        assert resp.status == 200 and "轨道应急规程" in html
        ok &= report(True, "HTTP 冒烟：页面 / 可访问")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：页面", repr(exc))

    audit_id = "smoke-%s" % run
    payload = smoke_payload(audit_id)
    try:
        status, body = http("POST", "/api/audits", payload)
        assert status == 200 and body.get("verdict") == "danger", body
        assert body.get("danger_node") == "vent:v5"
        ops = [s["op"] for s in body["steps"]]
        assert "call" in ops and "return" in ops
        idx_v4 = next(i for i, s in enumerate(body["steps"])
                      if s["location"] == "vent:v4")
        assert body["steps"][idx_v4]["op"] == "return"
        assert any(s["stack"] == ["launch:l3", "vent:v4"]
                   for s in body["steps"])
        ok &= report(True, "HTTP 冒烟：递归返回后进入危险续点的证据链")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：危险证据链", repr(exc))
        return ok

    try:
        status, body = http("POST", "/api/audits", payload)
        assert status == 200 and body.get("replayed") is True
        ok &= report(True, "HTTP 冒烟：同标识同载荷回放冻结结论")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：冻结回放", repr(exc))

    try:
        changed = smoke_payload(audit_id)
        changed["procedures"][1]["nodes"][4]["danger"] = False
        status, body = http("POST", "/api/audits", changed)
        assert status == 409 and body.get("error") == "conflict"
        ok &= report(True, "HTTP 冒烟：同标识异载荷明确拒绝（409）")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：冲突拒绝", repr(exc))

    try:
        status, body = http("GET", "/api/audits/%s" % audit_id)
        assert status == 200
        assert body["result"]["verdict"] == "danger"
        assert body["result"]["steps"] is not None
        ok &= report(True, "HTTP 冒烟：刷新后按审计标识读取相同证据")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：按标识读取", repr(exc))

    try:
        bad = smoke_payload("smoke-bad-%s" % run)
        bad["procedures"][0]["nodes"][1]["target"] = "ghost"
        status, body = http("POST", "/api/audits", bad)
        assert status == 200 and body["verdict"] == "invalid"
        codes = {e["code"] for e in body["errors"]}
        assert "dangling_call_target" in codes
        ok &= report(True, "HTTP 冒烟：悬空调用拒绝")
    except Exception as exc:  # noqa: BLE001
        ok &= report(False, "HTTP 冒烟：悬空调用拒绝", repr(exc))

    return ok


def main():
    print("== verify 开始（目标 %s）==" % APP_URL, flush=True)
    check_build()
    check_unit_tests()
    check_http_smoke()
    print("== verify 结束：%d 通过，%d 失败 ==" % (len(passed), len(failed)),
          flush=True)
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
