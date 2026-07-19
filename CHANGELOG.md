# Changelog

## Phase 1: Pentagi 工具整合 + 技能库加载器

### 新增的文件（3个）

- `src/secmind/sandbox.py` — Docker 沙箱执行器，隔离运行安全工具
- `src/secmind/tools_pentagi.py` — 5 个渗透测试工具 (nmap/nuclei/gobuster/whatweb/searchsploit)
- `src/secmind/skills_loader.py` — agentskills.io YAML 技能库解析器，支持动态加载自定义技能

### 修改的文件（2个）

- `src/secmind/tools.py` — `default_registry()` 自动注册 pentagi 工具和技能库
- `src/secmind/agents.py` — PlannerAgent 移除 CODE_AUDIT-only 限制，支持 PENETRATION_TEST 和 LOG_ANALYSIS 默认计划

### 新工具清单

| 工具 | 风险等级 | 场景 | 说明 |
| ---- | -------- | ---- | ---- |
| `nmap_scan` | R2 | penetration_test, log_analysis | 端口扫描 |
| `nuclei_scan` | R2 | penetration_test | 漏洞模板扫描 |
| `gobuster_dir` | R2 | penetration_test | 目录枚举 |
| `whatweb_identify` | R1 | penetration_test, log_analysis | Web 技术识别 |
| `searchsploit_query` | R1 | penetration_test | Exploit-DB 搜索 |

### 沙箱执行架构

```text
SecMind 编排器 → SandboxExecutor → Docker 容器 (临时, 用完即销毁)
                                      ├── 资源限制 (CPU/内存)
                                      ├── 网络隔离 (none / bridge)
                                      ├── 超时自动销毁
                                      └── 只读文件系统
```

### 技能库整合

- `SkillsLoader` 解析 agentskills.io 标准 YAML 文件
- 自动转换为 `ToolManifest` 并注册到 `ToolRegistry`
- 通过 `SECMIND_SKILLS_DIR` 环境变量指定技能目录
- 遵循 R0-R3 风险分级模型

---

## Phase 0: Qdrant 向量库启用

### 修改的文件（3个）

---

#### 1. `docker-compose.yml` — Qdrant 端口映射

**改动**: 为 Qdrant 服务添加 `ports` 配置

```yaml
ports:
  - "6333:6333"  # REST API + Web UI
  - "6334:6334"  # gRPC
```

**原因**: Qdrant 服务原缺少端口映射，宿主机无法访问 Web UI 和 API。

**效果**: 启动后可通过 `http://localhost:6333/dashboard` 访问 Qdrant 管理界面。

---

#### 2. `src/secmind/memory.py` — 新增 `QdrantVectorStore.delete()` 方法

**改动**: 在 `QdrantVectorStore` 类中新增 `delete(memory_id)` 方法

```python
def delete(self, memory_id: str) -> None:
    self.client.delete(
        collection_name=self.collection_name,
        points_selector=models.PointIdsList(points=[memory_id]),
        wait=True,
    )
```

**原因**: 原类只有 `upsert`（增/改）和 `search`（查），缺少按 ID 删除单条文档的能力。

**效果**: 补齐向量库的完整 CRUD（Create, Read, Delete），`Update` 由 `upsert` 覆盖。

---

#### 3. `src/secmind/schemas.py` — 修复 Pydantic 命名空间警告

**改动**: 为 `BudgetState` 和 `DecisionRecord` 添加 `model_config`

```python
class BudgetState(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    ...

class DecisionRecord(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    ...
```

**原因**: Pydantic v2 默认将 `model_` 前缀作为保留命名空间。`BudgetState.model_calls_used` 和 `DecisionRecord.model_id` 字段触发了 `UserWarning`。

**效果**: 消除运行时警告，日志更干净。

---

### 新增的文件（2个）

---

#### 4. `test_qdrant.py` — Qdrant CRUD 测试脚本

**作用**: 独立可运行的测试脚本，验证 Qdrant 完整操作流程。

**测试项**:

| 步骤 | 操作 | 验证点 |
| ---- | ---- | ------ |
| 1 | 连接 Qdrant | URL 可达 |
| 2 | 创建 Collection | `ensure_collection()` 成功 |
| 3 | 插入文档 | 3 条 ATT&CK 知识入库 |
| 4 | 语义搜索 | 按向量相似度返回 Top-K |
| 5 | 过滤搜索 | `metadata.tactic` 过滤生效 |
| 6 | 删除文档 | 按 `memory_id` 删除并确认消失 |
| 7 | 清理 | 删除测试 Collection |

**运行方式**:

```bash
$env:PYTHONPATH="src"; python test_qdrant.py
```

---

#### 5. `CHANGELOG.md` — 本文件

**作用**: 记录所有改动，方便 git 提交。

---

### Git 提交汇总

| 类型 | 文件 | 操作 |
| ---- | ---- | ---- |
| 🟡 修改 | `docker-compose.yml` | 添加 Qdrant 端口映射 |
| 🟡 修改 | `src/secmind/memory.py` | 新增 `delete()` 方法 |
| 🟡 修改 | `src/secmind/schemas.py` | 修复 Pydantic 警告 |
| 🟢 新增 | `test_qdrant.py` | Qdrant CRUD 测试脚本 |
| 🟢 新增 | `CHANGELOG.md` | 改动记录 |

---

## Phase 0: ATT&CK 知识库升级

### 修改的文件（1个）

---

#### 6. `src/secmind/attck.py` — ATT&CK 知识库模块（新文件）

**新增文件**: `src/secmind/attck.py`

**`AttackKnowledgeBase` 类提供的方法**:

| 方法 | 说明 |
| ---- | ---- |
| `get_tactics()` | 获取全部战术阶段（Tactic），含 ID、名称、描述 |
| `get_tactics_by_matrix()` | 按矩阵获取战术 |
| `get_techniques()` | 获取全部顶级技术（Technique），共 365 个 |
| `get_techniques_by_tactic("initial-access")` | 按战术查询技术，如 initial-access 下 25 个 |
| `get_techniques_by_platform("windows")` | 按平台查询技术 |
| `get_technique("T1190")` | 按 ATT&CK ID 查询单个技术详情 |
| `search_techniques("SQL")` | 按名称/描述搜索技术 |
| `get_subtechniques("T1059")` | 查询指定技术的子技术 |
| `get_mitigations("T1190")` | 查询技术的缓解措施 |
| `to_memory_documents(techniques)` | 将技术数据转为 `MemoryDocument`，用于 Qdrant 入库 |

**关键设计**:

- **延迟下载**: 首次使用自动从 MITRE GitHub 下载最新 STIX 数据（v19.1），缓存到 `data/attack-stix/`
- **版本校验**: 使用 `pooch` 进行 SHA256 哈希校验
- **入库就绪**: `to_memory_documents()` 输出可直接传入 `QdrantVectorStore.upsert()`

**涉及的概念解释**:

```text
Tactic (战术)     = 攻击阶段目标        例: TA0001 Initial Access
Technique (技术)  = 实现目标的方法       例: T1190 Exploit Public-Facing Application
Sub-technique    = 更具体的实现方式     例: T1190.001 SQL Injection
Procedure (步骤) = 实际工具/命令        例: sqlmap
```

### 新增的文件（1个）

---

#### 7. `test_attck.py` — ATT&CK 知识库测试脚本

**作用**: 验证 ATT&CK 模块的完整查询流程。

**测试项**:

| 步骤 | 操作 | 验证点 |
| ---- | ---- | ------ |
| 1 | 知识库摘要 | 15 个战术, 365 个技术 |
| 2 | 战术阶段列表 | TA0001-TA0043 |
| 3 | 按战术查技术 | initial-access 下 25 个技术 |
| 4 | 内容搜索 | SQL 相关技术 14 个 |
| 5 | 单个技术详情 | T1190 Exploit Public-Facing Application |
| 6 | 子技术查询 | T1059 下 13 个子技术 |
| 7 | 转 MemoryDocument | 可直入 Qdrant |

**运行方式**:

```bash
$env:PYTHONPATH="src"; python test_attck.py
```

---

### Git 提交汇总（两轮）

**第 1 轮 — Qdrant 基础**:

| 类型 | 文件 | 操作 |
| ---- | ---- | ---- |
| 🟡 修改 | `docker-compose.yml` | 添加 Qdrant 端口映射 |
| 🟡 修改 | `src/secmind/memory.py` | 新增 `delete()` 方法 |
| 🟡 修改 | `src/secmind/schemas.py` | 修复 Pydantic 警告 |
| 🟢 新增 | `test_qdrant.py` | Qdrant CRUD 测试脚本 |
| 🟢 新增 | `CHANGELOG.md` | 改动记录 |

```bash
git add docker-compose.yml src/secmind/memory.py src/secmind/schemas.py test_qdrant.py CHANGELOG.md
git commit -m "feat: Phase 0 Qdrant 向量库启用"
```

**第 2 轮 — ATT&CK 知识库**:

| 类型 | 文件 | 操作 |
| ---- | ---- | ---- |
| 🟢 新增 | `src/secmind/attck.py` | ATT&CK 知识库模块 |
| 🟢 新增 | `test_attck.py` | ATT&CK 查询测试脚本 |

```bash
git add src/secmind/attck.py test_attck.py CHANGELOG.md
git commit -m "feat: Phase 0 ATT&CK 知识库升级"
```

---

## Phase 0: 知识入库 & 检索激活

### 修改的文件（4个）

---

#### 8. `src/secmind/memory.py` — 新增 `batch_upsert()` 批量方法

**改动**: 在 `QdrantVectorStore` 中新增 `batch_upsert(documents, vectors)` 方法

```python
def batch_upsert(self, documents: list[MemoryDocument], vectors: list[list[float]]) -> None:
```

**原因**: 单条 `upsert()` 每次调用一次 API，批量操作可大幅提升 365 条 ATT&CK 知识的入库效率。

**效果**: 用一个 API 调用写入多条文档，365 条知识入库耗时仅 1.3 秒。

---

#### 9. `src/secmind/config.py` — 新增 `qdrant_vector_size` 配置

**改动**: 在 `Settings` 类中添加：

```python
qdrant_vector_size: int = Field(default=1024, ge=64, le=4096)
```

**原因**: QdrantVectorStore 初始化需要 `vector_size` 参数，此前硬编码不灵活。

---

#### 10. `src/secmind/schemas.py` — `AgentState` 新增 `knowledge_hits` 字段

**改动**: 在 `AgentState` 中添加：

```python
knowledge_hits: list[KnowledgeHit] = Field(default_factory=list)
```

**原因**: 编排器 `_retrieve_context` 节点检索到的 ATT&CK 知识需要存储在状态中，供后续分析和报告使用。

---

#### 11. `src/secmind/orchestrator.py` — 激活 `_retrieve_context` 节点

**改动**: 将原本的桩逻辑（空实现）替换为真实检索：

- 接受 `memory_store`（QdrantVectorStore）参数
- 用 `task.objective` + `scenario` + `target_scope` 构建查询文本
- 非 demo 模式 + 有 API_KEY：调用千问 Embedding 生成向量
- demo 模式：使用随机向量
- 从 Qdrant 搜索 Top-5 相关知识，存入 `state.knowledge_hits`
- 记录检索决策到账本

**之前**（空实现）:

```python
# 直接记录空检索结果
state.decisions.append(DecisionRecord(decision="knowledge_context_empty"))
```

**之后**:

```python
# 从 Qdrant 检索 ATT&CK 知识
query_vector = await self.gateway.embeddings([query_text])
hits = self.memory_store.search(query_vector, top_k=5)
state.knowledge_hits = hits
```

---

#### 12. `src/secmind/api.py` — 注入 `QdrantVectorStore`

**改动**: `build_runtime()` 中创建 `QdrantVectorStore` 实例并传入编排器

```python
memory_store = QdrantVectorStore(
    url=qdrant_url,
    collection_name=settings.qdrant_collection,
    vector_size=settings.qdrant_vector_size,
)
orchestrator = SecMindOrchestrator(
    settings, ledger, gateway, broker, hub.publish, memory_store=memory_store
)
```

---

### 新增的文件（1个）

---

#### 13. `scripts/ingest_knowledge.py` — ATT&CK 知识入库脚本

**作用**: 将 ATT&CK 框架全部 365 个技术向量化后写入 Qdrant。

**流程**:

1. 初始化 AttackKnowledgeBase + QdrantVectorStore
2. 获取全部 ATT&CK 技术数据
3. 转换为 MemoryDocument 格式
4. 分批（每批 10 条）调用千问 Embedding（或使用随机向量）
5. 通过 `batch_upsert` 写入 Qdrant

**运行方式**:

```bash
$env:PYTHONPATH="src"; python scripts/ingest_knowledge.py
```

**运行结果**: 365 条 ATT&CK 技术，37 批，1.3 秒完成入库。

---

### Git 提交汇总（第 3 轮）

| 类型 | 文件 | 操作 |
| ---- | ---- | ---- |
| 🟡 修改 | `src/secmind/memory.py` | 新增 `batch_upsert()` 批量方法 |
| 🟡 修改 | `src/secmind/config.py` | 新增 `qdrant_vector_size` 配置 |
| 🟡 修改 | `src/secmind/schemas.py` | AgentState 新增 `knowledge_hits` |
| 🟡 修改 | `src/secmind/orchestrator.py` | 激活 `_retrieve_context` 节点 + 注入 memory_store |
| 🟡 修改 | `src/secmind/api.py` | build_runtime 创建 QdrantVectorStore |
| 🟢 新增 | `scripts/ingest_knowledge.py` | ATT&CK 知识入库脚本 |

```bash
git add src/secmind/memory.py src/secmind/config.py src/secmind/schemas.py
git add src/secmind/orchestrator.py src/secmind/api.py scripts/ingest_knowledge.py
git add CHANGELOG.md
git commit -m "feat: Phase 0 知识入库 & 检索激活"
```
