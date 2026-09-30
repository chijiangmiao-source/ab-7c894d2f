"""HTTP 服务：页面 + 真实 API。

路由：
  GET  /health              健康路径，反映可用性
  GET  /                    录入/结果页面（静态）
  GET  /api/audits/{id}     按审计标识读取冻结证据（刷新后仍可读）
  POST /api/audits          提交审计：一次性报告全部校验错误；同标识同载荷
                            回放冻结结论；同标识异载荷明确拒绝（409）
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .solver import solve_payload, validate_payload
from .store import AuditStore, hash_payload

STATIC_DIR = Path(__file__).resolve().parent / "static"


def process_audit(store, payload):
    """核心提交逻辑，返回 (响应体, HTTP 状态码)。"""
    audit_id = payload.get("audit_id")
    usable_id = isinstance(audit_id, str) and bool(audit_id.strip())

    if usable_id:
        existing = store.get(audit_id)
        if existing is not None:
            if existing["payload_hash"] == hash_payload(payload):
                # 同标识同载荷：回放冻结结论
                out = dict(existing["result"])
                out["replayed"] = True
                out["audit_id"] = audit_id
                return out, 200
            # 同标识异载荷：明确拒绝
            return {
                "error": "conflict",
                "audit_id": audit_id,
                "message": "审计标识 %s 已冻结不同载荷的结论，拒绝改换载荷"
                           % audit_id,
            }, 409

    errors = validate_payload(payload)
    if errors:
        result = {"verdict": "invalid", "errors": errors}
    else:
        result = solve_payload(payload)

    if usable_id:
        store.put(audit_id, payload, result)
        result = dict(result)
        result["audit_id"] = audit_id
    return result, 200


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OrbitAudit/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # 静默访问日志
            pass

        def _send(self, code, body, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code,
                       json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/health":
                self._json(200, {"status": "ok"})
            elif path in ("/", "/index.html"):
                self._send(200,
                           (STATIC_DIR / "index.html").read_bytes(),
                           "text/html; charset=utf-8")
            elif path.startswith("/api/audits/"):
                audit_id = unquote(path[len("/api/audits/"):])
                record = store.get(audit_id)
                if record is None:
                    self._json(404, {"error": "not_found",
                                     "audit_id": audit_id,
                                     "message": "未找到该审计标识的冻结证据"})
                else:
                    self._json(200, record)
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/audits":
                self._json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            raw = self.rfile.read(max(length, 0))
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid_json",
                                 "message": "请求体不是合法 JSON"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"error": "invalid_payload",
                                 "message": "载荷必须是 JSON 对象"})
                return
            body, status = process_audit(store, payload)
            self._json(status, body)

    return Handler


def create_server(host="0.0.0.0", port=8000, db_path=None):
    if db_path is None:
        data_dir = os.environ.get("DATA_DIR", "./data")
        db_path = os.path.join(data_dir, "audits.db")
    store = AuditStore(db_path)
    server = ThreadingHTTPServer((host, port), make_handler(store))
    server.store = store
    return server


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = create_server(port=port)
    print("listening on :%d" % port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.store.close()


if __name__ == "__main__":
    main()
