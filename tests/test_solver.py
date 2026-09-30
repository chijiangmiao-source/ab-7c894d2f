"""求解器单元测试：摘要饱和、无界递归、witness 可重放性、校验错误分类。"""

import unittest

from app.solver import solve_payload, validate_payload


def danger_payload():
    """递归返回后才进入危险续点：vent 自递归，返回后的续点 v4 通往危险 v5。"""
    return {
        "audit_id": "t-danger",
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


def simulate(payload, steps):
    """用显式栈机逐步重放 witness，校验每步合法且栈记录精确。"""
    procs = {p["id"]: p for p in payload["procedures"]}
    nodes = {pid: {n["id"]: n for n in p["nodes"]}
             for pid, p in procs.items()}
    assert steps[0]["op"] == "start"
    proc, node = steps[0]["location"].split(":")
    assert proc == payload["root_entry"]
    assert node == procs[proc]["entry"]
    assert steps[0]["stack"] == []
    stack = []
    cur = (proc, node)
    for s in steps[1:]:
        p, n = cur
        node_obj = nodes[p][n]
        if s["op"] == "jump":
            assert node_obj["type"] == "jump"
            to = node_obj["to"]
            targets = to if isinstance(to, list) else [to]
            dst = s["location"].split(":")[1]
            assert s["proc"] == p and dst in targets
            cur = (p, dst)
        elif s["op"] == "call":
            assert node_obj["type"] == "call"
            assert s["detail"]["target"] == node_obj["target"]
            stack.append("%s:%s" % (p, node_obj["continuation"]))
            cur = (node_obj["target"], procs[node_obj["target"]]["entry"])
        elif s["op"] == "return":
            assert node_obj["type"] == "return"
            top = stack.pop()
            assert s["location"] == top
            cur = tuple(top.split(":"))
        elif s["op"] == "enter":
            assert s["location"] == "%s:%s" % cur
        else:
            raise AssertionError("unknown op %r" % s["op"])
        assert s["stack"] == stack, "栈记录与重放不一致"
        assert s["location"] == "%s:%s" % cur
    fp, fn = cur
    assert nodes[fp][fn].get("danger") is True
    return stack


class TestRecursionThenDangerContinuation(unittest.TestCase):
    """递归返回后才进入危险续点：摘要必须穿过自递归传播到续点。"""

    def test_verdict_and_danger_node(self):
        result = solve_payload(danger_payload())
        self.assertEqual(result["verdict"], "danger")
        self.assertEqual(result["danger_node"], "vent:v5")

    def test_return_precedes_danger_continuation(self):
        result = solve_payload(danger_payload())
        steps = result["steps"]
        ops = [s["op"] for s in steps]
        self.assertIn("call", ops)
        self.assertIn("return", ops)
        # 危险续点 vent:v4 必须由 return 步骤进入（递归返回后才进入）
        idx_v4 = next(i for i, s in enumerate(steps)
                      if s["location"] == "vent:v4")
        self.assertEqual(steps[idx_v4]["op"], "return")
        idx_call = next(i for i, s in enumerate(steps) if s["op"] == "call")
        self.assertLess(idx_call, idx_v4)
        # 递归调用期间栈曾加深到两层续点
        self.assertTrue(any(s["stack"] == ["launch:l3", "vent:v4"]
                            for s in steps))
        # 返回抵达续点 vent:v4 时，递归帧已弹出，只剩外层续点
        step_v4 = steps[idx_v4]
        self.assertEqual(step_v4["stack"], ["launch:l3"])
        # 末步即危险节点
        self.assertEqual(steps[-1]["location"], "vent:v5")
        self.assertTrue(steps[-1]["danger"])

    def test_witness_is_replayable(self):
        payload = danger_payload()
        result = solve_payload(payload)
        simulate(payload, result["steps"])

    def test_summaries_cover_recursion(self):
        result = solve_payload(danger_payload())
        # vent 的可返回摘要：直接返回 v3 与穿过递归的 v5
        self.assertEqual(result["summaries"]["vent"], ["v3", "v5"])
        self.assertEqual(result["summaries"]["launch"], ["l3"])


class TestUnboundedRecursion(unittest.TestCase):
    """无界递归不得截断：永不返回的递归不会误报，也不会漏报。"""

    def test_infinite_recursion_is_safe(self):
        # rec 入口即自调用，任何路径都到不了续点 r2 的危险节点
        payload = {
            "audit_id": "t-inf",
            "root_entry": "rec",
            "procedures": [
                {"id": "rec", "entry": "r1", "nodes": [
                    {"id": "r1", "type": "call", "target": "rec",
                     "continuation": "r2"},
                    {"id": "r2", "type": "return", "danger": True},
                ]},
            ],
        }
        result = solve_payload(payload)
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["summaries"]["rec"], [])

    def test_deep_but_returning_recursion_is_danger(self):
        # 直接递归与返回并存：任意深度展开都会漏掉，摘要饱和必须命中
        payload = {
            "audit_id": "t-deep",
            "root_entry": "rec",
            "procedures": [
                {"id": "rec", "entry": "r1", "nodes": [
                    {"id": "r1", "type": "jump", "to": ["r2", "r3"]},
                    {"id": "r2", "type": "call", "target": "rec",
                     "continuation": "r4"},
                    {"id": "r3", "type": "return"},
                    {"id": "r4", "type": "return", "danger": True},
                ]},
            ],
        }
        result = solve_payload(payload)
        self.assertEqual(result["verdict"], "danger")
        self.assertEqual(result["danger_node"], "rec:r4")
        simulate(payload, result["steps"])

    def test_mutual_recursion(self):
        payload = {
            "audit_id": "t-mutual",
            "root_entry": "a",
            "procedures": [
                {"id": "a", "entry": "a1", "nodes": [
                    {"id": "a1", "type": "jump", "to": ["a2", "a3"]},
                    {"id": "a2", "type": "call", "target": "b",
                     "continuation": "a4"},
                    {"id": "a3", "type": "return"},
                    {"id": "a4", "type": "return", "danger": True},
                ]},
                {"id": "b", "entry": "b1", "nodes": [
                    {"id": "b1", "type": "jump", "to": ["b2", "b3"]},
                    {"id": "b2", "type": "call", "target": "a",
                     "continuation": "b4"},
                    {"id": "b3", "type": "return"},
                    {"id": "b4", "type": "return"},
                ]},
            ],
        }
        result = solve_payload(payload)
        self.assertEqual(result["verdict"], "danger")
        self.assertEqual(result["danger_node"], "a:a4")
        simulate(payload, result["steps"])

    def test_call_chain_summaries(self):
        # A -> B -> C 调用链，C 返回后危险在 B 的续点
        payload = {
            "audit_id": "t-chain",
            "root_entry": "a",
            "procedures": [
                {"id": "a", "entry": "a1", "nodes": [
                    {"id": "a1", "type": "call", "target": "b",
                     "continuation": "a2"},
                    {"id": "a2", "type": "return"},
                ]},
                {"id": "b", "entry": "b1", "nodes": [
                    {"id": "b1", "type": "call", "target": "c",
                     "continuation": "b2"},
                    {"id": "b2", "type": "jump", "to": "b3"},
                    {"id": "b3", "type": "return", "danger": True},
                ]},
                {"id": "c", "entry": "c1", "nodes": [
                    {"id": "c1", "type": "return"},
                ]},
            ],
        }
        result = solve_payload(payload)
        self.assertEqual(result["verdict"], "danger")
        self.assertEqual(result["danger_node"], "b:b3")
        self.assertEqual(result["summaries"]["c"], ["c1"])
        self.assertEqual(result["summaries"]["b"], ["b3"])
        simulate(payload, result["steps"])

    def test_safe_when_danger_unreachable(self):
        payload = danger_payload()
        # 把危险标记挪到不可达节点
        for p in payload["procedures"]:
            for n in p["nodes"]:
                n.pop("danger", None)
        payload["procedures"][1]["nodes"].append(
            {"id": "v9", "type": "return", "danger": True})
        result = solve_payload(payload)
        self.assertEqual(result["verdict"], "safe")
        self.assertIn("vent", result["reachable_procedures"])


class TestValidation(unittest.TestCase):
    def codes(self, payload):
        return {e["code"] for e in validate_payload(payload)}

    def test_dangling_call_target_rejected(self):
        payload = {
            "audit_id": "t-dangle",
            "root_entry": "main",
            "procedures": [
                {"id": "main", "entry": "m1", "nodes": [
                    {"id": "m1", "type": "call", "target": "ghost",
                     "continuation": "m2"},
                    {"id": "m2", "type": "return"},
                ]},
            ],
        }
        codes = self.codes(payload)
        self.assertIn("dangling_call_target", codes)

    def test_all_error_categories_at_once(self):
        payload = {
            # 缺失审计标识
            "root_entry": "nowhere",  # 根入口错误：不存在
            "procedures": [
                {"id": "dup", "entry": "x", "nodes": [
                    {"id": "x", "type": "teleport"},  # 无效节点类型
                ]},
                {"id": "dup", "entry": "y", "nodes": [  # 重复标识
                    {"id": "y", "type": "return"},
                ]},
                {"id": "p2", "entry": "ghost-entry", "nodes": [  # 悬空入口
                    {"id": "n1", "type": "jump", "to": "ghost-jump"},  # 悬空目标
                    {"id": "n2", "type": "call", "target": "ghost-proc",
                     "continuation": "ghost-cont"},  # 悬空调用目标 + 悬空续点
                ]},
            ],
        }
        codes = self.codes(payload)
        self.assertIn("missing_audit_id", codes)
        self.assertIn("unknown_root_entry", codes)
        self.assertIn("duplicate_procedure_id", codes)
        self.assertIn("invalid_node_type", codes)
        self.assertIn("dangling_entry", codes)
        self.assertIn("dangling_jump_target", codes)
        self.assertIn("dangling_call_target", codes)
        self.assertIn("dangling_continuation", codes)

    def test_too_many_procedures(self):
        payload = {
            "audit_id": "t-many",
            "root_entry": "p0",
            "procedures": [
                {"id": "p%d" % i, "entry": "e",
                 "nodes": [{"id": "e", "type": "return"}]}
                for i in range(13)
            ],
        }
        self.assertIn("too_many_procedures", self.codes(payload))

    def test_twelve_procedures_ok(self):
        payload = {
            "audit_id": "t-12",
            "root_entry": "p0",
            "procedures": [
                {"id": "p%d" % i, "entry": "e",
                 "nodes": [{"id": "e", "type": "return"}]}
                for i in range(12)
            ],
        }
        self.assertEqual(validate_payload(payload), [])

    def test_valid_payload_passes(self):
        self.assertEqual(validate_payload(danger_payload()), [])


if __name__ == "__main__":
    unittest.main()
