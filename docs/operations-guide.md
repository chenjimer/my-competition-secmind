# SecMind 操作指南

> 版本：1.0 | 最后更新：2026-07-19

---

## 目录

1. [环境准备与启动](#1-环境准备与启动)
2. [ATT&CK 知识库入库](#2-attck-知识库入库)
3. [知识语义搜索](#3-知识语义搜索)
4. [查询日志管理](#4-查询日志管理)
5. [代码审计（完整端到端流程）](#5-代码审计完整端到端流程)
6. [日志分析](#6-日志分析)
7. [渗透测试](#7-渗透测试)
8. [API 接口使用](#8-api-接口使用)
9. [测试与验证](#9-测试与验证)
10. [常见问题解答](#10-常见问题解答)
11. [附录：环境变量说明](#11-附录环境变量说明)

---

## 1. 环境准备与启动

### 1.1 前置条件

| 组件 | 要求 | 验证命令 |
|------|------|----------|
| Python | >= 3.11, < 3.14 | `python --version` |
| uv 包管理器 | 最新版 | `uv --version` |
| Docker | 任意版本 | `docker --version` |
| Qdrant | Docker 镜像 | 通过 Docker Compose 启动 |

### 1.2 首次安装

```powershell
# 克隆项目后，进入项目目录
cd d:\code\2026\tiaozhanbei\my-competition-secmind

# 安装所有依赖
uv sync --all-extras
```

**说明：** 使用 `--all-extras` 安装所有可选依赖（包括 Qdrant 客户端、HTTP 客户端等）。如果只安装核心依赖，去掉该参数即可。

### 1.3 配置环境变量

```powershell
# 复制示例配置文件
Copy-Item .env.example .env
```

打开 `.env` 文件，配置以下关键参数：

| 参数 | 必填 | 说明 |
|------|------|------|
| `SECMIND_QWEN_API_KEY` | 推荐 | 千问 API Key，配了才能用真实语义嵌入 |
| `SECMIND_QDRANT_URL` | 否 | Qdrant 地址，默认 `http://127.0.0.1:6333` |
| `SECMIND_QDRANT_COLLECTION` | 否 | 集合名称，默认 `secmind_knowledge` |
| `SECMIND_DATABASE_URL` | 否 | 数据库地址，默认 SQLite |

> **注意：** 如果不配 Qwen API Key，搜索功能会降级为随机向量模拟，返回的结果不具备语义相关性。

### 1.4 启动 Qdrant

```powershell
# 启动 Qdrant 向量数据库（后台运行）
docker compose up -d qdrant

# 验证 Qdrant 是否成功启动
docker ps --filter "name=qdrant"

# 查看 Qdrant 日志（如有异常）
docker logs secmind-qdrant-1
```

**验证方法：** 打开浏览器访问 `http://127.0.0.1:6333/dashboard`，应能看到 Qdrant UI 界面。

### 1.5 启动 API 服务

```powershell
# 启动 FastAPI 服务（默认端口 8000）
uv run secmind-api
```

**验证方法：** 打开浏览器访问 `http://127.0.0.1:8000/docs`，应能看到 Swagger API 文档界面。

---

## 2. ATT&CK 知识库入库

### 2.1 功能概述

将 MITRE ATT&CK 框架的战术（Tactic）、技术（Technique）、子技术（Sub-technique）数据，通过千问 `text-embedding-v3` 模型转换为向量，写入 Qdrant 向量数据库。入库后共约 **873 条**记录，支持语义检索。

### 2.2 操作步骤

**步骤 1：确保 Qdrant 在运行**

```powershell
docker ps --filter "name=qdrant"
```

**步骤 2：配置 API Key**

确保 `.env` 文件中 `SECMIND_QWEN_API_KEY` 已正确配置。

**步骤 3：执行入库脚本**

```powershell
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py
```

**步骤 4：验证入库结果**

```powershell
$env:PYTHONPATH="src"; python -c "
from secmind.memory import QdrantVectorStore
from secmind.config import get_settings
s = get_settings()
store = QdrantVectorStore(s.qdrant_url, s.qdrant_collection, 1024)
store.ensure_collection()
n = store.client.count(store.collection_name).count
print(f'向量库中共 {n} 条记录')
"
```

期望输出：`向量库中共 873 条记录`

### 2.3 高级用法

| 参数 | 说明 | 示例 |
|------|------|------|
| `--dry-run` | 仅预览文档数量，不实际写入 | `python scripts/ingest_knowledge.py --dry-run` |
| `--clear` | 清空集合中所有旧数据后重新入库 | `python scripts/ingest_knowledge.py --clear` |

**典型场景：重新入库**

```powershell
# 如果之前入库的是旧数据（如只有 365 条），需要清空后重新入库
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --clear
```

### 2.4 注意事项

- 首次运行会自动下载 MITRE ATT&CK STIX 数据（约 100MB），需要网络连接
- 入库速度取决于 Qwen API 响应时间，873 条数据约需 1-3 分钟
- `--clear` 会删除整个集合再重建，不可恢复
- 如果中途中断可重新运行，不会重复写入（Qdrant upsert 是幂等的）
- Windows 终端可能出现 GBK 编码警告，不影响入库结果

---

## 3. 知识语义搜索

### 3.1 功能概述

基于 Qdrant 向量库 + 千问 Embedding 模型，支持对 ATT&CK 知识库进行中文语义搜索。每次搜索自动留存查询记录（包含问题和结果）到 SQLite 数据库。

### 3.2 交互模式（推荐）

```powershell
$env:PYTHONPATH="src"; python scripts/search_knowledge.py
```

进入交互界面后：

```
ATT&CK 知识语义搜索 — 输入查询（支持中英文）| 输入 quit 退出

> SQL注入
```

交互模式下支持以下操作：

| 输入 | 说明 |
|------|------|
| `你的问题` | 输入任意问题，返回最相关的 ATT&CK 知识 |
| `--top-k 10` | 输入行首使用 `--top-k N` 临时修改返回条数 |
| `quit` / `exit` | 退出交互模式 |

### 3.3 单次搜索模式

```powershell
# 基本搜索
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "SQL注入"

# 指定返回条数
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "端口扫描" --top-k 10

# 过滤特定 ATT&CK ID
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "提权" --filter "attack_id:T1068"
```

### 3.4 输出说明

每次搜索结果包含：

```
====================================================================
  搜索: "SQL注入"                                            ← 查询问题
====================================================================
  嵌入模型: text-embedding-v3                                  ← 使用的模型
  耗时: 1234 ms                                                ← 查询耗时

结果 1/5 | 置信度: 0.892 | ID: secmind_knowledge_xxx          ← 命中结果
──────────────────────────────────────────────────
攻击技术: T1190 - 利用面向公众的应用程序漏洞                    ← ATT&CK ID 和名称
描述: Adversaries may exploit weaknesses in Internet-facing...  ← 内容摘要
来源: mitre-attack | 版本: v16                                 ← 来源信息
──────────────────────────────────────────────────

  [查询记录已留存, ID=42]                                      ← 记录 ID
====================================================================
```

### 3.5 注意事项

- 搜索默认返回 top-5 条最相似结果
- 未配置 Qwen Key 时使用随机向量，返回结果不具备语义相关性
- 过滤条件 `--filter` 格式为 `key:value`，目前支持 `attack_id` 字段

---

## 4. 查询日志管理

### 4.1 功能概述

每次知识检索都会自动留存记录到 SQLite 数据库的 `query_logs` 表中，包含查询问题、命中的知识条目、耗时等信息。支持查看和导出。

### 4.2 查看查询历史

```powershell
# 命令行查看最近 20 条记录
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --show-logs
```

输出示例：

```
============================================================
  最近的 20 条查询记录
============================================================

  [1] 时间: 2026-07-19T15:30:00+08:00
      查询: SQL注入有哪些常见技术
      结果数: 5
      耗时: 1234ms
      嵌入模型: text-embedding-v3

  [2] 时间: 2026-07-19T15:25:00+08:00
      查询: 端口扫描手法
      结果数: 5
      耗时: 987ms
      嵌入模型: text-embedding-v3
```

### 4.3 导出查询日志

```powershell
# 导出为 JSON 文件（默认 query_logs.json）
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --export-logs

# 指定导出文件名
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --export-logs my_logs.json
```

导出的 JSON 文件结构如下：

```json
{
  "exported_at": "2026-07-19T15:35:00",
  "total": 2,
  "logs": [
    {
      "id": 42,
      "run_id": null,
      "query_text": "SQL注入有哪些常见技术",
      "hit_count": 5,
      "hits": [
        {
          "memory_id": "secmind_knowledge_t1190",
          "content": "Tactic: Initial Access...",
          "source": "mitre-attack",
          "version": "v16",
          "confidence": 0.892,
          "metadata": {"attack_id": "T1190"}
        }
      ],
      "embedding_model": "text-embedding-v3",
      "timestamp": "2026-07-19T15:30:00+08:00",
      "duration_ms": 1234
    }
  ]
}
```

### 4.4 通过 API 查看

```powershell
# 查看所有记录
curl.exe http://127.0.0.1:8000/api/v1/query-logs

# 指定返回条数
curl.exe "http://127.0.0.1:8000/api/v1/query-logs?limit=50"

# 按 run_id 过滤
curl.exe "http://127.0.0.1:8000/api/v1/query-logs?run_id=xxx-xxx"
```

### 4.5 直接查询 SQLite

```powershell
$env:PYTHONPATH="src"; python -c "
from secmind.ledger import LedgerStore
from secmind.config import get_settings
store = LedgerStore(get_settings().database_url)
for log in store.query_logs(limit=5):
    print(f'[{log[\"id\"]}] {log[\"query_text\"][:50]} → {log[\"hit_count\"]} hits')
"
```

### 4.6 注意事项

- 查询日志存储在 SQLite 数据库中，默认路径为运行目录下的 `secmind.db`
- 日志不会自动清理，长期运行后需手动管理
- 查询日志记录不包含原始向量（`query_vector_json` 仅在编排器内部记录时存储）

---

## 5. 代码审计（完整端到端流程）

### 5.1 功能概述

基于 LangGraph 状态机，实现完整的代码审计流程：上传文件 → 场景分类 → ATT&CK 知识检索 → 规划 → Bandit 扫描 → 分析（ATT&CK 交叉关联）→ 验证 → 生成报告。

### 5.2 操作步骤

#### 步骤 1：启动 API 服务

```powershell
# 在终端 1 中运行
uv run secmind-api
```

保持终端 1 运行。

#### 步骤 2：准备测试文件

创建一个包含安全漏洞的测试文件 `sample.py`：

```powershell
# 在终端 2 中运行
@'
import os
import subprocess
from flask import request

@app.route('/exec')
def unsafe():
    cmd = request.args.get('cmd')
    os.system(cmd)
    return 'ok'

@app.route('/sql')
def sql_injection():
    uid = request.args.get('uid')
    query = f"SELECT * FROM users WHERE id = {uid}"
    return query
'@ | Out-File -Encoding utf8 sample.py
```

#### 步骤 3：上传文件

```powershell
# 上传待审计文件
$result = curl.exe -F "file=@sample.py" http://127.0.0.1:8000/api/v1/uploads | ConvertFrom-Json
$ref = $result.ref
Write-Host "文件引用标识: $ref"
```

#### 步骤 4：提交审计任务

```powershell
# 创建审计任务
$taskBody = @"
{
  "objective": "审计 Python 代码安全漏洞",
  "attachments": [{"ref": "$ref"}]
}
"@
$task = curl.exe -X POST http://127.0.0.1:8000/api/v1/tasks `
  -H "Content-Type: application/json" `
  -d $taskBody | ConvertFrom-Json
$run_id = $task.run_id
Write-Host "运行 ID: $run_id"
```

#### 步骤 5：等待审计完成

```powershell
# 轮询等待任务完成（约需 5-15 秒）
do {
    Start-Sleep -Seconds 3
    $status = curl.exe "http://127.0.0.1:8000/api/v1/runs/$run_id" | ConvertFrom-Json
    Write-Host "状态: $($status.status)"
} while ($status.status -in @("PENDING", "RUNNING"))
```

#### 步骤 6：查看审计报告

```powershell
# 获取完整报告
$report = curl.exe "http://127.0.0.1:8000/api/v1/runs/$run_id/report" | ConvertFrom-Json
$report | Format-List

# 查看所有发现的安全问题
$report.findings | ForEach-Object {
    Write-Host "------------------------"
    Write-Host "问题: $($_.title)"
    Write-Host "严重级别: $($_.severity)"
    Write-Host "描述: $($_.description)"

    # ATT&CK ID（如有交叉关联）
    if ($_.raw.attck_ids) {
        Write-Host "关联 ATT&CK: $($_.raw.attck_ids -join ', ')"
    }
}
```

#### 步骤 7：查看决策链

```powershell
# 查看完整决策链（含知识检索和引用记录）
curl.exe "http://127.0.0.1:8000/api/v1/runs/$run_id/ledger" | ConvertFrom-Json
```

### 5.3 审计报告解读

审计报告包含以下核心部分：

| 字段 | 说明 |
|------|------|
| `status` | 运行状态（COMPLETED / PARTIAL / FAILED） |
| `executive_summary` | 执行摘要（含 ATT&CK 引用统计） |
| `findings` | 发现的安全问题列表 |
| `evidence` | 证据记录列表 |
| `decisions` | 决策链记录（含 `knowledge_citation`） |
| `limitations` | 限制说明 |

每个 finding（安全问题）包含：

| 字段 | 说明 |
|------|------|
| `rule_id` | Bandit 规则 ID |
| `severity` | 严重级别（LOW / MEDIUM / HIGH / CRITICAL） |
| `path` | 文件路径 |
| `line` | 行号 |
| `title` | 问题标题 |
| `description` | 问题描述 |
| `remediation` | 修复建议 |
| `raw.attck_ids` | 关联的 ATT&CK ID（RAG 交叉关联结果） |

### 5.4 注意事项

- 代码审计只支持 Python 文件（Bandit 工具限制）
- 审计是只读操作，不会修改源代码
- 如果报告中没有 `attck_ids`，说明知识检索未匹配到相关 ATT&CK 技术（检查知识库是否已入库）
- 任务可能需要 5-15 秒完成，请使用轮询等待

---

## 6. 日志分析

### 6.1 功能概述

支持对多种格式的日志文件进行安全分析，自动识别日志格式、检测可疑模式并分级告警。

### 6.2 支持的日志格式

| 格式 | 识别方式 | 示例 |
|------|----------|------|
| Nginx/Apache 访问日志 | 包含 `GET`/`POST` 等 HTTP 方法 | `192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /index.php?id=1' OR '1'='1" 200 1234` |
| Syslog | 包含时间戳和进程名 | `Oct 10 13:55:36 server sshd[1234]: Failed password for root from 10.0.0.1` |
| JSON 日志 | 可解析为 JSON 对象 | `{"timestamp":"...","level":"error","message":"..."}` |
| 纯文本 | 逐行分析 | 任意文本 |

### 6.3 检测的异常模式

| 类别 | 严重级别 | 说明 |
|------|----------|------|
| SQL 注入（SQL Injection） | **CRITICAL** | 检测 SQL 语法特征如 `' OR '1'='1`、`UNION SELECT` 等 |
| XSS 攻击 | HIGH | 检测 `<script>`、`onerror`、`javascript:` 等特征 |
| 路径穿越（Path Traversal） | HIGH | 检测 `../`、`..\%5c` 等目录遍历特征 |
| 命令注入（Command Injection） | **CRITICAL** | 检测 `$(...)`、反引号、`|` 等命令执行特征 |
| 暴力破解（Brute Force） | MEDIUM | 同一 IP 5 次以上认证失败自动聚合 |
| Shellshock | **CRITICAL** | 检测 `() { :;}` 特征 |
| RFI/LFI | HIGH | 检测远程/本地文件包含特征 |

### 6.4 在编排器中使用

日志分析作为场景之一，由编排器自动路由。提交任务时 objective 包含"日志"关键词即可触发：

```powershell
# 上传日志文件
$ref = (curl.exe -F "file=@access.log" http://127.0.0.1:8000/api/v1/uploads | ConvertFrom-Json).ref

# 提交日志分析任务
curl.exe -X POST http://127.0.0.1:8000/api/v1/tasks `
  -H "Content-Type: application/json" `
  -d "{\"objective\":\"分析日志中的安全异常\",\"attachments\":[{\"ref\":\"$ref\"}]}"
```

### 6.5 直接在代码中使用

```python
from secmind.tools import LogAnalysisTool

tool = LogAnalysisTool()

# 分析单条日志
result = tool.run(inputs={"target": "path/to/access.log"})
print(result.data["anomalies"])
```

### 6.6 注意事项

- 日志分析最多扫描 20 个文件
- 暴力破解检测需要日志中包含 `Failed password`、`login failed` 等关键字
- 中文日志也支持检测（SQL 注入、XSS 等模式与语言无关）

---

## 7. 渗透测试

### 7.1 功能概述

提供 5 个渗透测试工具，均在 Docker 沙箱中隔离执行，确保主机安全。

### 7.2 工具列表

| 工具 | 工具 ID | 功能 | 风险等级 |
|------|---------|------|----------|
| Nmap | `nmap_scan` | 端口扫描和服务识别 | R2 |
| Nuclei | `nuclei_scan` | 漏洞扫描 | R2 |
| Gobuster | `gobuster_dir` | 目录枚举 | R2 |
| WhatWeb | `whatweb_identify` | Web 技术识别 | R1 |
| Searchsploit | `searchsploit` | 漏洞利用搜索 | R1 |

### 7.3 前置条件：构建沙箱镜像

```powershell
# 构建渗透测试沙箱 Docker 镜像
docker build -t secmind-sandbox:latest - <<'DOCKERFILE'
FROM alpine:3.20
RUN apk add --no-cache nmap nmap-scripts curl wget bind-tools hydra jq python3 py3-pip git bash
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.deb `
    && apk add --no-cache --allow-untrusted nuclei_3.3.9_linux_amd64.deb `
    && rm nuclei_3.3.9_linux_amd64.deb
WORKDIR /workspace
ENTRYPOINT ["/bin/sh"]
DOCKERFILE
```

### 7.4 通过 API 使用

提交渗透测试任务时，objective 包含"渗透"关键词即可触发：

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/tasks `
  -H "Content-Type: application/json" `
  -d '{"objective":"对目标进行渗透测试","autonomy_policy":"R2"}'
```

### 7.5 注意事项

- 渗透测试工具**强制在 Docker 沙箱中运行**，确保不污染宿主机
- 如果 Docker 未运行或沙箱镜像未构建，工具会返回错误
- `autonomy_policy` 建议设置为 `R2`（需人工审批）以减少风险
- 靶机必须是渗透测试者可访问的目标

---

## 8. API 接口使用

### 8.1 接口总览

| 方法 | 路径 | 说明 | 是否需要 Qdrant |
|------|------|------|-----------------|
| GET | `/health` | 健康检查 | 否 |
| POST | `/api/v1/uploads` | 上传文件 | 否 |
| POST | `/api/v1/tasks` | 创建审计任务 | 是 |
| GET | `/api/v1/runs/{run_id}` | 查询运行状态 | 否 |
| GET | `/api/v1/runs/{run_id}/report` | 获取审计报告 | 否 |
| GET | `/api/v1/runs/{run_id}/ledger` | 获取哈希事件账本 | 否 |
| GET | `/api/v1/runs/{run_id}/ledger/export` | 导出 JSONL 账本 | 否 |
| POST | `/api/v1/runs/{run_id}/approvals/{request_id}` | 审批操作 | 否 |
| GET | `/api/v1/query-logs` | 查询记录历史 | 否 |
| WS | `/api/v1/runs/{run_id}/events` | WebSocket 事件流 | 否 |

### 8.2 健康检查

```powershell
curl.exe http://127.0.0.1:8000/health
```

返回示例：
```json
{"status": "ok", "version": "1.0.0", "services": {"qdrant": true}}
```

### 8.3 上传文件

```powershell
curl.exe -F "file=@sample.py" http://127.0.0.1:8000/api/v1/uploads
```

返回示例（`ref` 用于后续提交任务）：
```json
{"ref": "uploads/a1b2c3d4/sample.py", "sha256": "abc...", "size": 1024}
```

### 8.4 创建审计任务

```json
POST /api/v1/tasks
Content-Type: application/json

{
  "objective": "审计 Python 代码安全漏洞",
  "attachments": [
    {"ref": "uploads/a1b2c3d4/sample.py"}
  ],
  "autonomy_policy": "R2"
}
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `objective` | 是 | 任务目标描述 |
| `attachments` | 否 | 上传文件的引用列表 |
| `autonomy_policy` | 否 | 自治策略（R0/R1/R2/R3） |

### 8.5 中断与审批

如果任务需要人工审批（R2 以上），API 会返回 `WAITING_APPROVAL` 状态，并在 ledger 中记录 `approval.requested` 事件。

```powershell
# 查看待审批信息
curl.exe http://127.0.0.1:8000/api/v1/runs/<run_id>

# 审批通过
curl.exe -X POST http://127.0.0.1:8000/api/v1/runs/<run_id>/approvals/<request_id> `
  -H "Content-Type: application/json" `
  -d '{"decision": "APPROVE"}'

# 审批拒绝
curl.exe -X POST http://127.0.0.1:8000/api/v1/runs/<run_id>/approvals/<request_id> `
  -H "Content-Type: application/json" `
  -d '{"decision": "DENY"}'

# 编辑参数后通过
curl.exe -X POST http://127.0.0.1:8000/api/v1/runs/<run_id>/approvals/<request_id> `
  -H "Content-Type: application/json" `
  -d '{"decision": "EDIT", "edited_parameters": {"target": "/safe/path"}}'
```

### 8.6 Swagger UI

启动 API 后访问 `http://127.0.0.1:8000/docs` 可在线测试所有接口。

---

## 9. 测试与验证

### 9.1 运行全部测试

```powershell
$env:PYTHONPATH="src"; python -m pytest tests/ -v
```

### 9.2 运行特定测试文件

```powershell
# 仅测试查询日志功能
$env:PYTHONPATH="src"; python -m pytest tests/test_query_log.py -v

# 仅测试渗透测试工具
$env:PYTHONPATH="src"; python -m pytest tests/test_pentagi.py -v

# 仅测试编排器
$env:PYTHONPATH="src"; python -m pytest tests/test_orchestrator.py -v
```

### 9.3 测试预期结果

| 测试文件 | 测试数 | 说明 |
|----------|--------|------|
| test_api.py | 1 | API 健康检查和任务流程 |
| test_guardrail.py | 2 | 守卫策略引擎 |
| test_ingest.py | 5 | 文件入库 |
| test_ledger.py | 3 | 账本功能 |
| test_llm.py | 5 | LLM 网关（1 个因环境跳过） |
| test_memory.py | 2 | Qdrant 向量库 |
| test_orchestrator.py | 5 | 编排器状态机 |
| test_pentagi.py | 14 | 渗透测试工具 |
| test_query_log.py | 3 | 查询日志 |
| test_tools.py | 2 | 工具注册 |

**总计：** 40 passed（1 failed 为预存的 Qwen Key 环境问题）

### 9.4 快速验证清单

```powershell
# 1. 检查 Python 版本
python --version   # 需 >= 3.11

# 2. 检查依赖
uv sync --all-extras

# 3. 检查 Qdrant 运行状态
docker ps --filter "name=qdrant"

# 4. 检查知识库数据量
$env:PYTHONPATH="src"; python -c "
from secmind.memory import QdrantVectorStore;
from secmind.config import get_settings;
s = get_settings();
store = QdrantVectorStore(s.qdrant_url, s.qdrant_collection, 1024);
store.ensure_collection();
print(f'{store.client.count(store.collection_name).count} vectors')
"

# 5. 测试一次搜索
$env:PYTHONPATH="src"; python scripts/search_knowledge.py "SQL注入" --top-k 1

# 6. 查看查询日志
$env:PYTHONPATH="src"; python scripts/search_knowledge.py --show-logs
```

---

## 10. 常见问题解答

### Q1: 为什么搜索返回的结果不相关？

**可能原因：**
1. **未配置 Qwen API Key**（最常见）— 搜索使用了随机向量模拟，结果无语义相关性。配置 `SECMIND_QWEN_API_KEY` 后重新入库即可。
2. **知识库数据不足** — 检查入库脚本输出的文档数量是否为 873 条。如果少于该值，使用 `--clear` 参数重新入库。
3. **查询问题过于模糊** — 尝试使用更具体的问题，如用"SQL注入攻击检测方法"代替"安全"。

### Q2: 为什么运行测试时提示 `DID NOT RAISE ModelGatewayError`？

这是因为你的 `.env` 文件中已配置了 `SECMIND_QWEN_API_KEY`，测试用例预期的错误不会触发。这不影响任何功能，可以忽略。

### Q3: 如何重新入库？

```powershell
# 清空旧数据后重新入库
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --clear
```

### Q4: 为什么向量库中只有 365 条记录？

早期版本的入库脚本只入库了顶层技术（Techniques），没有包含子技术（Sub-techniques）和战术（Tactics）。使用以下命令清空后重新入库：

```powershell
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --clear
```

重新入库后应为 873 条。

### Q5: Qdrant 连接失败怎么办？

```powershell
# 1. 检查 Qdrant 是否在运行
docker ps --filter "name=qdrant"

# 2. 检查端口
curl.exe http://127.0.0.1:6333/health

# 3. 重启 Qdrant
docker compose restart qdrant

# 4. 查看 Qdrant 日志
docker logs secmind-qdrant-1
```

### Q6: 如何清空查询日志？

查询日志存储在 SQLite 数据库中，暂无命令行清理功能。可以手动删除数据库文件（默认 `secmind.db`）：

```powershell
# 停止 API 服务后执行
Remove-Item secmind.db -ErrorAction SilentlyContinue
```

注意：这会同时删除其他数据（如运行状态、账本等）。

### Q7: 代码审计报告中没有 `attck_ids`？

1. 检查 Qdrant 是否在运行且有数据（第 2 步验证方法）
2. 检查 `.env` 中是否配置了 `SECMIND_QWEN_API_KEY`
3. 检查审计结果中的 finding 标题/描述是否包含匹配的关键词（如 "SQL injection"、"command injection" 等英文关键词）

### Q8: Windows 终端出现乱码？

部分 ATT&CK 描述包含特殊字符（如右单引号），Windows 终端使用 GBK 编码时可能出现乱码。这**不影响**向量入库和搜索功能，只是终端显示问题。可以：

```powershell
# 临时切换终端编码为 UTF-8
chcp 65001
```

### Q9: 接口返回 500 错误怎么办？

```powershell
# 1. 查看 API 终端输出获取详细错误信息
# 2. 检查 Qdrant 连接
# 3. 检查数据库路径权限
# 4. 重启 API 服务
```

### Q10: 如何升级 ATT&CK 数据版本？

MITRE ATT&CK 每年会发布新版本。升级步骤：

```powershell
# 1. 清空旧数据
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py --clear

# 2. 重新入库（会自动下载最新版本）
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py
```

---

## 11. 附录：环境变量说明

### 11.1 完整环境变量列表

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `SECMIND_ENV` | `development` | 运行环境（development / production） |
| `SECMIND_DEMO_MODE` | `false` | 演示模式（使用模拟 LLM） |
| `SECMIND_DATABASE_URL` | `sqlite:///./secmind.db` | 数据库连接地址 |
| `SECMIND_QDRANT_URL` | `http://127.0.0.1:6333` | Qdrant 服务地址 |
| `SECMIND_QDRANT_COLLECTION` | `secmind_knowledge` | Qdrant 集合名称 |
| `SECMIND_QWEN_API_KEY` | 空 | 千问 API Key |
| `SECMIND_QWEN_BASE_URL` | `https://dashscope.aliyuncs.com/compatible-mode/v1` | 千问 API 地址 |
| `SECMIND_EMBEDDING_MODEL` | `text-embedding-v3` | 嵌入模型名称 |
| `SECMIND_LLM_MODEL` | `qwen-plus` | LLM 模型名称 |
| `SECMIND_LOG_LEVEL` | `INFO` | 日志级别 |
| `SECMIND_HOST` | `0.0.0.0` | API 监听地址 |
| `SECMIND_PORT` | `8000` | API 监听端口 |
| `SECMIND_MAX_STEPS` | `10` | 最大步骤数 |
| `SECMIND_MAX_TOOL_CALLS` | `20` | 最大工具调用数 |
| `SECMIND_MAX_MODEL_CALLS` | `50` | 最大模型调用数 |
| `SECMIND_MAX_RUNTIME_SECONDS` | `600` | 最大运行时间（秒） |

### 11.2 典型配置文件

```ini
# .env — 最小配置
SECMIND_QWEN_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```ini
# .env — 完整配置
SECMIND_ENV=development
SECMIND_DEMO_MODE=false
SECMIND_DATABASE_URL=sqlite:///./secmind.db
SECMIND_QDRANT_URL=http://127.0.0.1:6333
SECMIND_QDRANT_COLLECTION=secmind_knowledge
SECMIND_QWEN_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SECMIND_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
SECMIND_EMBEDDING_MODEL=text-embedding-v3
SECMIND_LLM_MODEL=qwen-plus
SECMIND_LOG_LEVEL=INFO
SECMIND_HOST=0.0.0.0
SECMIND_PORT=8000
```

### 11.3 生产环境建议

- 使用 PostgreSQL 替代 SQLite：`SECMIND_DATABASE_URL=postgresql://user:password@host:5432/secmind`
- 设置 `SECMIND_ENV=production`
- 使用 Docker Secret 管理 API Key
- 配置 `SECMIND_LOG_LEVEL=WARNING` 减少日志量

---

> **提示：** 如果在使用过程中遇到本指南未覆盖的问题，请查看 [docs/architecture.md](architecture.md) 了解系统架构，或运行 `$env:PYTHONPATH="src"; python -m pytest tests/ -v` 检查系统状态。
