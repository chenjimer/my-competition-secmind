# SecMind

SecMind 是面向"具备自主决策能力的通用网络安全智能体"赛题的 A 组 Agent 核心。它基于 LangGraph 状态机构建，集成了 MITRE ATT&CK 知识库、Qdrant 向量检索、代码审计、日志分析、渗透测试等能力。

---

## 功能

### Phase 0 — 基础平台

| 功能 | 状态 |
|------|------|
| LangGraph 监督式状态图（输入→分类→规划→执行→验证→报告） | ✅ |
| R0-R3 分级自治与 `interrupt()` 人工审批恢复 | ✅ |
| 千问 Qwen 网关（结构化输出、超时重试、熔断、主备路由） | ✅ |
| 工具注册协议与 Tool Broker | ✅ |
| FastAPI + WebSocket 事件推送 | ✅ |
| SQLite/PostgreSQL 持久化 + append-only 哈希链账本 | ✅ |
| Docker Compose 编排（API + PostgreSQL + Qdrant） | ✅ |

### Phase 0 — ATT&CK 知识库 & Qdrant 向量库

| 功能 | 状态 |
|------|------|
| MITRE ATT&CK 框架集成（战术/技术/子技术） | ✅ |
| STIX 数据自动下载与缓存 (`mitreattack-python`) | ✅ |
| Qdrant 向量库增删改查 | ✅ |
| 千问 `text-embedding-v3` 真实语义嵌入入库 | ✅ |
| 语义搜索脚本（支持过滤、交互模式） | ✅ |
| 每次搜索自动留存查询记录（包含问题和结果） | ✅ |
| 查看/导出查询历史 | ✅ |

### Phase 1 — 代码审计

| 功能 | 状态 |
|------|------|
| Bandit CLI 调用与 JSON 解析 | ✅ |
| 端到端流程：上传→规划→审计→报告 | ✅ |
| 证据引用链校验 | ✅ |

### Phase 2 — 日志分析

| 功能 | 状态 |
|------|------|
| 自动识别日志格式（web_access / syslog / json_log） | ✅ |
| 检测 SQL 注入、XSS、路径穿越、暴力破解等 8 类异常模式 | ✅ |
| 暴力破解聚合检测（同一 IP 5 次失败自动告警） | ✅ |
| 严重级别分级过滤 | ✅ |

### Phase 2 — 渗透测试

| 功能 | 状态 |
|------|------|
| nmap 端口扫描（Docker 沙箱） | ✅ |
| nuclei 漏洞扫描（Docker 沙箱） | ✅ |
| gobuster 目录枚举（Docker 沙箱） | ✅ |
| whatweb 技术识别（Docker 沙箱） | ✅ |
| searchsploit 漏洞搜索（Docker 沙箱） | ✅ |
| SandboxExecutor 隔离执行环境 | ✅ |

---

## 快速开始

### 前置条件

- Python >= 3.11, < 3.14
- [uv](https://docs.astral.sh/uv/) 包管理器
- Docker（运行 Qdrant 和渗透测试沙箱）

### 安装与运行

```powershell
# 安装依赖
uv sync --all-extras

# 配置环境变量
Copy-Item .env.example .env
# 编辑 .env，按需配置 Qwen API Key

# 启动 Qdrant（后台）
docker compose up -d qdrant

# 启动 API 服务
uv run secmind-api
```

访问 `http://127.0.0.1:8000/docs` 查看 Swagger 接口文档。

### 知识库入库

```powershell
# 确保 .env 配置了 SECMIND_QWEN_API_KEY
# 将 ATT&CK 技术/子技术/战术写入 Qdrant（873条）
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py

# 清空旧数据后重新入库
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --clear

# 仅预览不写入
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --dry-run

# 低成本验证：只预览 Enterprise 前20条
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --domain enterprise --limit 20 --dry-run

# 三域入库；同一参数重跑时从 data/ingest_checkpoint.json 断点继续
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py `
  --domain enterprise --domain mobile --domain ics
```

ATT&CK 文档 ID 由“域 + ATT&CK ID + 类型”稳定生成，因此重复执行使用 Qdrant upsert，
不会产生重复知识。更换 Embedding 模型、向量维度或域组合时会自动使用新的 checkpoint 指纹；
使用 `--clear` 会清空 Collection 和 checkpoint。

### 语义搜索

```powershell
# 单次搜索
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "SQL注入"

# 指定返回条数
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "端口扫描" --top-k 10

# 交互模式
$env:PYTHONPATH="src"; python scripts/search_knowledge.py

# 查看查询历史
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --show-logs

# 导出查询历史为 JSON
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --export-logs logs.json
```

### 代码审计示例

```powershell
# 上传待审计文件
curl.exe -F "file=@sample.py" http://127.0.0.1:8000/api/v1/uploads

# 提交审计任务
curl.exe -X POST http://127.0.0.1:8000/api/v1/tasks `
  -H "Content-Type: application/json" `
  -d '{"objective":"审计 Python 代码并生成安全报告","attachments":[{"ref":"<上传返回的 ref>"}]}'

# 查询运行状态
curl.exe http://127.0.0.1:8000/api/v1/runs/<run_id>

# 获取审计报告
curl.exe http://127.0.0.1:8000/api/v1/runs/<run_id>/report

# 获取哈希链账本
curl.exe http://127.0.0.1:8000/api/v1/runs/<run_id>/ledger
```

### 查看查询日志

```powershell
# API 接口
curl.exe http://127.0.0.1:8000/api/v1/query-logs
curl.exe "http://127.0.0.1:8000/api/v1/query-logs?limit=50"
```

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/v1/uploads` | 上传文件 |
| POST | `/api/v1/tasks` | 创建审计任务 |
| GET | `/api/v1/runs/{run_id}` | 查询运行状态 |
| GET | `/api/v1/runs/{run_id}/report` | 获取审计报告 |
| GET | `/api/v1/runs/{run_id}/ledger` | 获取哈希事件账本 |
| GET | `/api/v1/runs/{run_id}/ledger/export` | 导出 JSONL 账本 |
| POST | `/api/v1/runs/{run_id}/approvals/{request_id}` | 审批操作 |
| GET | `/api/v1/query-logs` | 查询记录历史 |
| WS | `/api/v1/runs/{run_id}/events` | WebSocket 事件流 |

---

## 架构

- **orchestrator.py** — LangGraph 状态机（ingest → classify → retrieve → plan → guardrail → execute → analyze → verify → report）
- **agents.py** — 专用智能体节点（TaskInterpreter、Planner、Analyst、Verifier、Reporter）
- **tools.py / tools_pentagi.py** — 安全工具适配器（Bandit、LogInspector、nmap、nuclei 等）
- **memory.py** — Qdrant 向量库封装
- **attck.py** — MITRE ATT&CK 知识库
- **llm.py** — 千问 LLM + Embedding 网关
- **ledger.py** — 追加式哈希链账本 + 查询日志
- **guardrail.py** — R0-R3 分级策略引擎
- **sandbox.py** — Docker 沙箱执行器
- **schemas.py** — Pydantic 数据模型
- **service.py** — 运行服务 + 事件总线

---

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

生产环境必须覆盖 `POSTGRES_PASSWORD`，并通过 Secret 管理 `SECMIND_QWEN_API_KEY`。

---

## 渗透测试沙箱

渗透测试工具（nmap、nuclei 等）在 Docker 沙箱中隔离执行。构建沙箱镜像：

```bash
# 使用 sandbox.py 中内置的 Dockerfile 构建
docker build -t secmind-sandbox:latest - <<'DOCKERFILE'
FROM alpine:3.20
RUN apk add --no-cache nmap nmap-scripts curl wget bind-tools hydra jq python3 py3-pip git bash
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.deb \
    && apk add --no-cache --allow-untrusted nuclei_3.3.9_linux_amd64.deb \
    && rm nuclei_3.3.9_linux_amd64.deb
WORKDIR /workspace
ENTRYPOINT ["/bin/sh"]
DOCKERFILE
```

---

## 测试

```powershell
$env:PYTHONPATH="src"; python -m pytest tests/ -v
```

---

## 文档

- [操作指南](docs/operations-guide.md)
- [架构与状态图](docs/architecture.md)
- [B/C 组接口契约](docs/contracts.md)
- [后续 Agent 工作包](docs/work-packages.md)
