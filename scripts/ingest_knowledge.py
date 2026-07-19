"""ATT&CK 知识入库脚本 — 使用千问 text-embedding-v3 真实语意嵌入将 ATT&CK 技术写入 Qdrant。

使用方法:
    # 确保 .env 中配置了 SECMIND_QWEN_API_KEY
    $env:PYTHONPATH="src"; python scripts/ingest_knowledge.py

前提条件:
    - Qdrant 容器正在运行 (docker compose up qdrant -d)
    - .env 配置了 SECMIND_QWEN_API_KEY（使用千问 text-embedding-v3）
    - 或设置 SECMIND_DEMO_MODE=true 以随机向量写入（仅用于测试）
"""

from __future__ import annotations

import asyncio
import math
import sys
import time
from pathlib import Path

# 将项目根目录加入 sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secmind.attck import AttackKnowledgeBase  # noqa: E402
from secmind.config import get_settings  # noqa: E402
from secmind.llm import ModelGatewayError, QwenGateway  # noqa: E402
from secmind.memory import QdrantVectorStore  # noqa: E402

BATCH_SIZE = 10


async def generate_vectors(
    gateway: QwenGateway,
    texts: list[str],
) -> list[list[float]]:
    """使用千问 text-embedding-v3 生成真实语意嵌入向量。"""
    return await gateway.embeddings(texts)


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="ATT&CK 知识入库 — 使用千问 text-embedding-v3 写入 Qdrant"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="清空集合中所有旧数据后再重新入库",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅预览文档数量，不实际写入 Qdrant",
    )
    args = parser.parse_args()

    settings = get_settings()

    # ========== 前置检查：确保使用真实嵌入模型 ==========
    if not settings.demo_mode and not settings.qwen_api_key:
        print("[错误] 未配置 SECMIND_QWEN_API_KEY")
        print("  请创建 .env 文件并设置 SECMIND_QWEN_API_KEY=your_api_key_here")
        print("  或设置 SECMIND_DEMO_MODE=true 以 demo 模式运行（使用随机向量）")
        sys.exit(1)

    # 适配本地运行的 Qdrant URL
    qdrant_url = settings.qdrant_url
    if "qdrant:6333" in qdrant_url:
        qdrant_url = "http://localhost:6333"
        print(f"[配置] Qdrant URL 从容器地址切换为: {qdrant_url}")

    print(f"[配置] Qdrant Collection: {settings.qdrant_collection}")
    print(f"[配置] 向量维度: {settings.qdrant_vector_size}")
    print(f"[配置] Demo 模式: {settings.demo_mode}")
    print(f"[配置] 嵌入模型: {settings.embedding_model}")
    if settings.qwen_api_key:
        print(f"[配置] API Key: 已配置 [OK]")

    # ========== 初始化组件 ==========
    print("\n[初始化] ATT&CK 知识库...")
    kb = AttackKnowledgeBase()
    summary = kb.summary()
    print(f"  ATT&CK 版本: {summary['attack_version']}")
    print(f"  战术阶段: {summary['tactic_count']}")
    print(f"  顶层技术: {summary['technique_count']}")
    print(f"  子技术: {summary['subtechnique_count']}")
    print(f"  合计: {summary['total_count']} 条")

    print("\n[初始化] Qdrant 向量库...")
    store = QdrantVectorStore(
        url=qdrant_url,
        collection_name=settings.qdrant_collection,
        vector_size=settings.qdrant_vector_size,
    )
    store.ensure_collection()
    print(f"  Collection '{settings.qdrant_collection}' 就绪")

    # ========== 清空旧数据（可选） ==========
    if args.clear:
        print("\n[清理] 清空集合中所有旧数据...")
        count = store.client.count(collection_name=store.collection_name).count
        store.client.delete_collection(store.collection_name)
        store.ensure_collection()
        print(f"  已删除 {count} 条旧数据，重新创建集合")

    # 初始化千问 Embedding 网关（使用真实语意嵌入模型）
    if settings.demo_mode:
        print("\n[初始化] Demo 模式 — 使用随机向量（仅用于测试）")
        gateway = None
    else:
        print(f"\n[初始化] 千问 Embedding 网关 — 模型: {settings.embedding_model}")
        gateway = QwenGateway(settings)

    # ========== 获取全部 ATT&CK 条目 ==========
    print("\n[处理] 获取全部 ATT&CK 条目（技术 + 子技术 + 战术）...")
    all_docs = kb.all_documents()
    print(f"  共 {len(all_docs)} 条文档")
    print(f"  - 技术/子技术: {len(all_docs) - summary['tactic_count']} 条")
    print(f"  - 战术阶段: {summary['tactic_count']} 条")

    # ========== Dry-run：仅预览不写入 ==========
    if args.dry_run:
        print(f"\n[Dry-Run] 预览完成，未写入 Qdrant。去掉 --dry-run 执行实际入库。")
        return

    # ========== 分批向量化并写入 ==========
    total = len(all_docs)
    batches = math.ceil(total / BATCH_SIZE)
    print(f"\n[写入] 分 {batches} 批写入 Qdrant (每批 {BATCH_SIZE} 条)")

    if not settings.demo_mode:
        print(f"[写入] 使用千问 {settings.embedding_model} 生成真实语意向量")

    start_time = time.monotonic()
    for i in range(0, total, BATCH_SIZE):
        batch_docs = all_docs[i : i + BATCH_SIZE]
        batch_texts = [doc.content for doc in batch_docs]
        batch_num = i // BATCH_SIZE + 1

        print(f"\n  批次 {batch_num}/{batches} ({len(batch_docs)} 条)...")

        if gateway and not settings.demo_mode:
            try:
                vectors = await generate_vectors(gateway, batch_texts)
                print(f"    向量生成完成 (千问 {settings.embedding_model})")
            except ModelGatewayError as exc:
                print(f"    [错误] Embedding 生成失败: {exc}")
                sys.exit(1)
        else:
            import random

            vectors = [
                [random.random() for _ in range(settings.qdrant_vector_size)] for _ in batch_docs
            ]
            print(f"    向量生成完成 (随机向量 — demo 模式)")

        store.batch_upsert(batch_docs, vectors)
        print(f"    写入 Qdrant 完成")
        # 避免 API 限流
        if gateway and not settings.demo_mode:
            await asyncio.sleep(0.3)

    elapsed = time.monotonic() - start_time
    print(f"\n{'=' * 50}")
    print(f"[OK] 入库完成!")
    print(f"  ATT&CK 版本: {summary['attack_version']}")
    print(f"  文档总数: {total}")
    print(f"    ├─ 技术/子技术: {total - summary['tactic_count']} 条")
    print(f"    └─ 战术阶段: {summary['tactic_count']} 条")
    print(f"  嵌入模型: {settings.embedding_model if not settings.demo_mode else '(随机向量 — demo 模式)'}")
    print(f"  耗时: {elapsed:.1f} 秒")
    print(f"  向量库: {qdrant_url}")
    print(f"  Collection: {settings.qdrant_collection}")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    asyncio.run(main())
