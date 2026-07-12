# 后续编码 Agent 工作包

每个 Agent 只处理一个工作包；先读 `schemas.py` 与本文件，公共契约变化必须同时提交契约测试和 ADR。

| 工作包 | 输入 | 交付物 | 完成条件 |
|---|---|---|---|
| WP01 公共契约 | 当前 Schema | 错误码、OpenAPI 示例、Schema 快照 | B/C 组契约测试通过 |
| WP02 模型网关 | `QwenGateway` | Mock 故障测试、调用指标、Prompt 注册表 | 超时/429/主模型故障均切换或降级 |
| WP03 持久检查点 | 当前 Orchestrator | PostgreSQL LangGraph Checkpointer | 进程杀死后从准确节点恢复 |
| WP04 临时沙箱 | `BaseTool` | 单次工具容器运行器 | 无网络、非 root、资源限制和销毁验证通过 |
| WP05 C 组工具 | 工具协议 | ATT&CK、日志与其他审计适配器 | 全部输出统一 Finding/Evidence |
| WP06 专业 Agent | BaseAgent | LLM Analyst、Verifier、Reporter | 输出结构化且无证据结论被拒绝 |
| WP07 记忆 | Evidence/Decision | Qdrant 检索与写入门禁 | 仅完成且验证通过的记录可写入 |
| WP08 评测 | API 与样例 | 20 个固定用例、成功率与时延报告 | 连续三轮成功率不低于 90% |
| WP09 交付 | Compose | 离线部署包、用户手册、演示脚本 | 新机器一键部署并完成代码审计 |

统一要求：不得提交密钥、不得写死真实目标、不得用 `shell=True`、不得吞掉异常、不得把隐藏思维链作为解释材料。每个工作包必须同时包含测试、使用说明和已知限制。

