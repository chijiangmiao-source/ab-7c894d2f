"""API 集成测试：真实 HTTP 往返，覆盖冻结回放、改载拒绝、刷新读取。"""

import http.client
import json
import threading
import unittest

from app.server import create_server


def danger_payload(audit_id="api-danger"):
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


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(host="127.0.0.1", port=0,
                                   db_path=":memory:")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.store.close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        headers = {}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        parsed = None
        if data:
            try:
                parsed = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = None
        return resp.status, parsed, data

    def test_health(self):
        status, body, _ = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_index_page_served(self):
        status, _, raw = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("轨道应急规程".encode("utf-8"), raw)

    def test_danger_verdict_with_steps(self):
        status, body, _ = self.request("POST", "/api/audits",
                                       danger_payload())
        self.assertEqual(status, 200)
        self.assertEqual(body["verdict"], "danger")
        self.assertEqual(body["danger_node"], "vent:v5")
        ops = [s["op"] for s in body["steps"]]
        self.assertIn("call", ops)
        self.assertIn("return", ops)
        self.assertTrue(all("stack" in s for s in body["steps"]))

    def test_frozen_replay_same_payload(self):
        payload = danger_payload("api-replay")
        status1, body1, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status1, 200)
        self.assertNotIn("replayed", body1)
        # 同标识同载荷重传：回放冻结结论
        status2, body2, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status2, 200)
        self.assertTrue(body2.get("replayed"))
        frozen = {k: v for k, v in body1.items() if k != "replayed"}
        replayed = {k: v for k, v in body2.items() if k != "replayed"}
        self.assertEqual(frozen, replayed)

    def test_changed_payload_rejected(self):
        payload = danger_payload("api-conflict")
        status1, _, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status1, 200)
        changed = danger_payload("api-conflict")
        changed["procedures"][1]["nodes"][4]["danger"] = False
        status2, body2, _ = self.request("POST", "/api/audits", changed)
        self.assertEqual(status2, 409)
        self.assertEqual(body2["error"], "conflict")

    def test_refresh_reads_same_evidence(self):
        payload = danger_payload("api-refresh")
        _, posted, _ = self.request("POST", "/api/audits", payload)
        # 模拟刷新：仅凭标识 GET 读取
        status, record, _ = self.request("GET", "/api/audits/api-refresh")
        self.assertEqual(status, 200)
        self.assertEqual(record["result"]["verdict"], "danger")
        self.assertEqual(record["result"]["steps"], posted["steps"])
        self.assertEqual(record["payload"], payload)

    def test_get_unknown_id_404(self):
        status, body, _ = self.request("GET", "/api/audits/no-such-id")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "not_found")

    def test_validation_errors_all_at_once(self):
        payload = {
            "audit_id": "api-invalid",
            "root_entry": "nowhere",
            "procedures": [
                {"id": "p", "entry": "ghost", "nodes": [
                    {"id": "n1", "type": "teleport"},
                    {"id": "n2", "type": "call", "target": "ghost-proc",
                     "continuation": "ghost-cont"},
                ]},
            ],
        }
        status, body, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["verdict"], "invalid")
        codes = {e["code"] for e in body["errors"]}
        self.assertIn("unknown_root_entry", codes)
        self.assertIn("dangling_entry", codes)
        self.assertIn("invalid_node_type", codes)
        self.assertIn("dangling_call_target", codes)
        self.assertIn("dangling_continuation", codes)
        # 无效结论同样被冻结，可回放
        status2, body2, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status2, 200)
        self.assertTrue(body2.get("replayed"))

    def test_missing_audit_id_not_stored(self):
        payload = danger_payload()
        del payload["audit_id"]
        status, body, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["verdict"], "invalid")
        codes = {e["code"] for e in body["errors"]}
        self.assertIn("missing_audit_id", codes)

    def test_safe_verdict(self):
        payload = {
            "audit_id": "api-safe",
            "root_entry": "main",
            "procedures": [
                {"id": "main", "entry": "m1", "nodes": [
                    {"id": "m1", "type": "jump", "to": "m2"},
                    {"id": "m2", "type": "return"},
                ]},
            ],
        }
        status, body, _ = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["verdict"], "safe")
        self.assertIn("main", body["reachable_procedures"])

    def test_malformed_json_400(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/audits", body=b"{not json",
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)


if __name__ == "__main__":
    unittest.main()
