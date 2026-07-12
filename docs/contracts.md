# 跨组接口契约

公共 Schema 位于 `secmind.schemas`，版本为 `1.0`。公共字段只能向后兼容地增加；删除、改名或改变语义必须升级主版本并增加架构决策记录。

## B 组

- `POST /api/v1/uploads` 上传文件并返回受控引用。
- `POST /api/v1/tasks` 创建任务。
- `GET /api/v1/runs/{run_id}` 查询状态。
- `GET /api/v1/runs/{run_id}/report` 获取报告。
- `GET /api/v1/runs/{run_id}/ledger` 获取事件和哈希链校验结果。
- `POST /api/v1/runs/{run_id}/approvals/{request_id}` 处理审批。
- `WS /api/v1/runs/{run_id}/events` 接收事件；可用 `after_sequence` 回放断线期间事件。

前端必须按 `run_id + sequence` 去重，不应依赖 WebSocket 到达时间排序。

## C 组

工具实现 `BaseTool.invoke(args, ToolContext) -> ToolResult`，并提供 `ToolManifest`。工具不得导入 `AgentState`，不得自行读取模型密钥，不得绕过工作区白名单。

发现项必须转换为 `Finding`，每条发现至少引用一个 `Evidence.evidence_id`。工具、规则库和知识库版本写入 Evidence 元数据。

接入新工具的最低测试包括：Schema 非法参数、目录越界、超时、非零退出、无发现、多个发现和证据引用完整性。

