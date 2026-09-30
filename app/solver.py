"""轨道应急规程可达性求解器。

模型：一份载荷包含至多 12 份规程，每份规程有入口节点与若干节点。
节点类型：
  - jump   普通跳转（to 可为单个节点 id 或 id 列表，列表表示非确定选择）
  - call   调用目标规程入口，并指定本规程内的返回续点 continuation
  - return 正常返回（弹出调用栈顶续点并跳转；栈空则整体停机）
任意节点可带 danger: true 标记。

求解：按调用栈精确计算每份规程的"可返回摘要"（从入口经可实现路径
——调用与返回严格配平——可达的 return 节点集合），用工作表法饱和
匹配调用与返回，覆盖无界递归；不截断栈、不规定递归深度、不把调用边
当普通图边。危险可达时产出一条可逐步重放的 witness 链。
"""

from collections import deque

NODE_TYPES = ("jump", "call", "return")
MAX_PROCEDURES = 12


def jump_targets(node):
    """归一化 jump 节点的目标集合（兼容单值与列表）。"""
    to = node.get("to")
    if isinstance(to, str):
        return [to] if to else []
    if isinstance(to, list):
        return [t for t in to if isinstance(t, str) and t]
    return []


def _bad_ident(value):
    """标识不得为空、不得含冒号或空白（位置编码使用 proc:node）。"""
    return (not isinstance(value, str) or not value.strip()
            or ":" in value or any(ch.isspace() for ch in value))


def validate_payload(payload):
    """一次性收集全部校验错误，返回错误列表（空列表表示通过）。"""
    errors = []

    def err(code, message, **kw):
        errors.append({"code": code, "message": message, **kw})

    if not isinstance(payload, dict):
        return [{"code": "invalid_payload", "message": "载荷必须是 JSON 对象"}]

    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not audit_id.strip():
        err("missing_audit_id", "缺失稳定审计标识 audit_id")

    root = payload.get("root_entry")
    if not isinstance(root, str) or not root.strip():
        err("missing_root_entry", "缺失根入口 root_entry")
        root = None

    procs = payload.get("procedures")
    if procs is None:
        procs = []
    if not isinstance(procs, list):
        err("invalid_procedures", "procedures 必须是数组")
        return errors
    if len(procs) > MAX_PROCEDURES:
        err("too_many_procedures",
            "规程数量 %d 超过上限 %d" % (len(procs), MAX_PROCEDURES),
            count=len(procs))

    proc_map = {}
    for i, p in enumerate(procs):
        if not isinstance(p, dict):
            err("invalid_procedure", "规程必须是对象", index=i)
            continue
        pid = p.get("id")
        if _bad_ident(pid):
            err("missing_procedure_id", "规程缺失或含非法字符的标识", index=i)
            continue
        if pid in proc_map:
            err("duplicate_procedure_id", "重复规程标识 %s" % pid, id=pid)
        else:
            proc_map[pid] = p

    for pid, p in proc_map.items():
        nodes = p.get("nodes")
        if nodes is None:
            nodes = []
        if not isinstance(nodes, list):
            err("invalid_nodes", "nodes 必须是数组", procedure=pid)
            continue
        node_map = {}
        for j, n in enumerate(nodes):
            if not isinstance(n, dict):
                err("invalid_node", "节点必须是对象", procedure=pid, index=j)
                continue
            nid = n.get("id")
            if _bad_ident(nid):
                err("missing_node_id", "节点缺失或含非法字符的标识",
                    procedure=pid, index=j)
                continue
            if nid in node_map:
                err("duplicate_node_id", "重复节点标识 %s" % nid,
                    procedure=pid, node=nid)
            else:
                node_map[nid] = n
            t = n.get("type")
            if t not in NODE_TYPES:
                err("invalid_node_type", "无效节点类型 %r" % (t,),
                    procedure=pid, node=nid, type=t)

        entry = p.get("entry")
        if _bad_ident(entry):
            err("missing_entry", "规程缺失入口节点 entry", procedure=pid)
        elif entry not in node_map:
            err("dangling_entry", "入口节点 %s 不存在于规程 %s" % (entry, pid),
                procedure=pid, entry=entry)

        for nid, n in node_map.items():
            t = n.get("type")
            if t == "jump":
                targets = jump_targets(n)
                raw = n.get("to")
                if not targets:
                    err("missing_jump_target", "跳转节点缺少目标 to",
                        procedure=pid, node=nid)
                else:
                    raw_list = raw if isinstance(raw, list) else [raw]
                    for tgt in raw_list:
                        if not isinstance(tgt, str) or not tgt:
                            err("invalid_jump_target", "跳转目标必须是节点标识",
                                procedure=pid, node=nid, target=tgt)
                        elif tgt not in node_map:
                            err("dangling_jump_target",
                                "跳转目标 %s 悬空" % tgt,
                                procedure=pid, node=nid, target=tgt)
            elif t == "call":
                tgt = n.get("target")
                cont = n.get("continuation")
                if _bad_ident(tgt):
                    err("missing_call_target", "调用节点缺少目标规程 target",
                        procedure=pid, node=nid)
                elif tgt not in proc_map:
                    err("dangling_call_target", "调用目标规程 %s 悬空" % tgt,
                        procedure=pid, node=nid, target=tgt)
                if _bad_ident(cont):
                    err("missing_continuation", "调用节点缺少返回续点 continuation",
                        procedure=pid, node=nid)
                elif cont not in node_map:
                    err("dangling_continuation", "返回续点 %s 悬空" % cont,
                        procedure=pid, node=nid, continuation=cont)

    if root is not None and root not in proc_map:
        err("unknown_root_entry", "根入口 %s 不是已登记规程" % root,
            root_entry=root)
    return errors


class Solver:
    """下推可达性求解器：可返回摘要 + 调用/返回饱和匹配。"""

    def __init__(self, procedures):
        self.proc_ids = [p["id"] for p in procedures]
        self.nodes = {p["id"]: {n["id"]: n for n in p.get("nodes", [])}
                      for p in procedures}
        self.entries = {p["id"]: p["entry"] for p in procedures}
        # 被调规程 -> [(调用方规程, 调用节点)]，用于摘要反向传播
        self.callers = {pid: [] for pid in self.proc_ids}
        for pid in self.proc_ids:
            for nid, n in self.nodes[pid].items():
                if n.get("type") == "call":
                    self.callers[n["target"]].append((pid, nid))
        # reach[pid]：从 pid 入口经可实现路径（调用/返回配平）可达的节点
        self.reach = {pid: set() for pid in self.proc_ids}
        # summaries[pid]：可返回摘要 = reach 中类型为 return 的节点
        self.summaries = {pid: set() for pid in self.proc_ids}
        # parent[pid][nid]：可达性来源，用于 witness 重建
        self.parent = {pid: {} for pid in self.proc_ids}

    def _add(self, pid, nid, parent):
        if nid in self.reach[pid]:
            return False
        self.reach[pid].add(nid)
        self.parent[pid][nid] = parent
        return True

    def saturate(self):
        """工作表饱和：jump 沿规程内边传播；call 应用目标规程已有摘要；
        新摘要出现时反向应用到所有可达调用点的续点。有限节点集保证终止，
        递归无需任何深度上限。"""
        work = deque()
        for pid in self.proc_ids:
            entry = self.entries[pid]
            if self._add(pid, entry, ("entry",)):
                work.append((pid, entry))
        while work:
            pid, nid = work.popleft()
            node = self.nodes[pid][nid]
            t = node.get("type")
            if t == "jump":
                for tgt in jump_targets(node):
                    if self._add(pid, tgt, ("jump", nid)):
                        work.append((pid, tgt))
            elif t == "call":
                cont = node["continuation"]
                for ret in sorted(self.summaries[node["target"]]):
                    if self._add(pid, cont, ("callret", nid, ret)):
                        work.append((pid, cont))
            elif t == "return":
                if nid not in self.summaries[pid]:
                    self.summaries[pid].add(nid)
                    for cp, cnid in self.callers[pid]:
                        if cnid in self.reach[cp]:
                            cont = self.nodes[cp][cnid]["continuation"]
                            if self._add(cp, cont, ("callret", cnid, nid)):
                                work.append((cp, cont))
        return self

    def analyze(self, root):
        """从根入口做规程级 BFS；返回危险命中 (proc, node, proc_parent)
        或安全结论所需的可达规程集。"""
        queue = deque([root])
        proc_parent = {root: None}  # 规程 -> (调用方规程, 调用节点)
        while queue:
            proc = queue.popleft()
            for nid in sorted(self.reach[proc]):
                if self.nodes[proc][nid].get("danger"):
                    return (proc, nid, proc_parent)
            for nid in sorted(self.reach[proc]):
                n = self.nodes[proc][nid]
                if n.get("type") == "call" and n["target"] not in proc_parent:
                    proc_parent[n["target"]] = (proc, nid)
                    queue.append(n["target"])
        return (None, None, proc_parent)

    def _emit_path(self, proc, target_nid, emit):
        """按 parent 链重建从 proc 入口到 target_nid 的可实现路径并发射步骤；
        途经的调用以 摘要子路径 + 返回 递归展开，保持栈精确配平。"""
        transitions = []
        cur = target_nid
        while True:
            par = self.parent[proc][cur]
            if par[0] == "entry":
                break
            if par[0] == "jump":
                transitions.append(("jump", par[1], cur))
                cur = par[1]
            else:  # callret: 经调用点 par[1] 调用，被调方在 par[2] 返回
                _, call_node, ret_node = par
                transitions.append(("callret", call_node, ret_node, cur))
                cur = call_node
        transitions.reverse()
        for tr in transitions:
            if tr[0] == "jump":
                _, src, dst = tr
                emit(proc, dst, "jump", {"from": src, "to": dst},
                     "%s:%s" % (proc, dst))
            else:
                _, call_node, ret_node, cont = tr
                target = self.nodes[proc][call_node]["target"]
                emit(proc, call_node, "call",
                     {"target": target, "continuation": cont},
                     "%s:%s" % (target, self.entries[target]),
                     push="%s:%s" % (proc, cont))
                self._emit_path(target, ret_node, emit)
                emit(target, ret_node, "return",
                     {"to": "%s:%s" % (proc, cont)},
                     "%s:%s" % (proc, cont), pop=True)

    def witness(self, root, danger_proc, danger_node, proc_parent):
        """产出从根入口到危险节点的可重放步骤链，每步记录调用栈。"""
        chain = []  # 根到危险规程的调用链 [(调用方规程, 调用节点)]
        proc = danger_proc
        while proc_parent[proc] is not None:
            caller, call_node = proc_parent[proc]
            chain.append((caller, call_node))
            proc = caller
        chain.reverse()

        steps = []
        stack = []

        def emit(proc, nid, op, detail, location, push=None, pop=False):
            if push is not None:
                stack.append(push)
            if pop and stack:
                stack.pop()
            steps.append({
                "seq": len(steps),
                "op": op,
                "proc": proc,
                "node": nid,
                "detail": detail,
                "location": location,
                "stack": list(stack),
                "danger": False,
            })

        entry_loc = "%s:%s" % (root, self.entries[root])
        steps.append({"seq": 0, "op": "start", "proc": root,
                      "node": self.entries[root], "detail": {},
                      "location": entry_loc, "stack": [], "danger": False})

        for caller, call_node in chain:
            self._emit_path(caller, call_node, emit)
            cnode = self.nodes[caller][call_node]
            target, cont = cnode["target"], cnode["continuation"]
            emit(caller, call_node, "call",
                 {"target": target, "continuation": cont},
                 "%s:%s" % (target, self.entries[target]),
                 push="%s:%s" % (caller, cont))
        self._emit_path(danger_proc, danger_node, emit)

        danger_loc = "%s:%s" % (danger_proc, danger_node)
        if steps[-1]["location"] == danger_loc:
            steps[-1]["danger"] = True
        else:
            # 危险节点即当前规程入口，无需任何转移即抵达
            steps.append({"seq": len(steps), "op": "enter",
                          "proc": danger_proc, "node": danger_node,
                          "detail": {}, "location": danger_loc,
                          "stack": list(stack), "danger": True})
        danger_set = {(p, n) for p in self.proc_ids
                      for n in self.reach[p] if self.nodes[p][n].get("danger")}
        for s in steps:
            loc = s["location"].split(":", 1)
            if (loc[0], loc[1]) in danger_set:
                s["danger"] = True
        return steps


def solve_payload(payload):
    """对已通过校验的载荷求解，返回结论字典（safe / danger）。"""
    root = payload["root_entry"]
    solver = Solver(payload["procedures"]).saturate()
    danger_proc, danger_node, proc_parent = solver.analyze(root)
    summaries = {pid: sorted(solver.summaries[pid]) for pid in solver.proc_ids}
    if danger_proc is None:
        return {
            "verdict": "safe",
            "root_entry": root,
            "message": "根入口 %s 经任意嵌套层数均无法抵达危险节点" % root,
            "reachable_procedures": sorted(proc_parent.keys()),
            "summaries": summaries,
        }
    steps = solver.witness(root, danger_proc, danger_node, proc_parent)
    return {
        "verdict": "danger",
        "root_entry": root,
        "danger_node": "%s:%s" % (danger_proc, danger_node),
        "message": "根入口 %s 可经调用链抵达危险节点 %s:%s"
                   % (root, danger_proc, danger_node),
        "steps": steps,
        "summaries": summaries,
    }
