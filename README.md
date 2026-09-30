# 轨道应急规程安全审计服务

安全官在上行前提交应急规程载荷，服务按**调用栈精确**求解：根入口是否能
经任意嵌套层数的调用抵达危险节点。求解器基于**可返回摘要饱和**
（pushdown reachability），调用与返回严格配平，覆盖无界递归——不截断
栈、不规定递归深度、不把调用边当普通图边。

## 模型

- 一次提交：稳定审计标识 `audit_id`、根入口 `root_entry`、至多 **12** 份规程。
- 每份规程：`id`、`entry`（入口节点）、`nodes`。
- 节点类型：
  - `jump` 普通跳转，`to` 为节点 id 或 id 列表（列表 = 非确定选择）；
  - `call` 调用目标规程入口，`target` + 本规程内返回续点 `continuation`；
  - `return` 正常返回（弹出栈顶续点）。
- 任意节点可标 `"danger": true`，危险节点可分布在任一规程。

## 行为

- `POST /api/audits` 一次性指出全部问题：缺失/重复标识、悬空入口/续点/
  目标、无效节点类型、根入口错误。
- 危险可达：返回可逐步重放的跳转/调用/返回链，每步带调用栈。
- 不可达：返回根入口的安全结论（可达规程 + 各规程可返回摘要）。
- 同标识同载荷重传 → 回放冻结结论（`replayed: true`）；
  同标识异载荷 → **409 明确拒绝**。
- `GET /api/audits/{audit_id}` 按标识读取冻结证据，刷新后结果不变。
- `GET /health` 健康路径；`GET /` 录入页面（草稿改变即清除旧显示）。

## 运行（Docker Compose）

```bash
# 启动页面 + API（宿主端口可配置，默认 8080）
HOST_PORT=8080 docker compose up -d app

# 健康检查
curl http://localhost:8080/health

# 一次运行 verify：构建检查 + 代码测试 + HTTP 冒烟，以状态码报告
docker compose up --exit-code-from verify verify
echo $?   # 0 = 全部通过
```

## 本地运行（无 Docker）

```bash
python3 -m app.server &                 # PORT=8000 DATA_DIR=./data
APP_URL=http://localhost:8000 python3 -m verify.verify
```

## 目录

```
app/solver.py    校验 + 摘要饱和求解 + witness 重建
app/store.py     SQLite 冻结存储（审计标识 → 载荷哈希 + 结论）
app/server.py    HTTP API 与静态页面
app/static/      录入/结果页面
tests/           单元测试（递归返回后进入危险续点、悬空调用拒绝、冻结回放…）
verify/          verify 服务：构建检查 + 代码测试 + HTTP 冒烟，退出码报告
```
