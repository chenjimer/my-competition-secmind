"""ATT&CK 知识入库脚本 — 将 ATT&CK 技术数据向量化后写入 Qdrant。

使用方法:
    $env:PYTHONPATH="src"; python scripts/ingest_knowledge.py

前提条件:
    - Qdrant 容器正在运行 (docker compose up qdrant -d)
    - (可选) 配置 SECMIND_QWEN_API_KEY 以使用真实 embedding
    - 未配置 API_KEY 时使用随机向量 (demo 模式)
"""

from __future__ import annotations

import asyncio
import math
import random
import sys
import time
from pathlib import Path

# 将项目根目录加入 sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secmind.attck import AttackKnowledgeBase  # noqa: E402
from secmind.config import get_settings  # noqa: E402
from secmind.llm import QwenGateway  # noqa: E402
from secmind.memory import QdrantVectorStore  # noqa: E402

BATCH_SIZE = 10


async def generate_vectors(
    gateway: QwenGateway,
    texts: list[str],
    vector_size: int,
) -> list[list[float]]:
    """生成 embedding 向量，失败时回退到随机向量。"""
    try:
        return await gateway.embeddings(texts)
    except Exception as exc:
        print(f"  [回退] Embedding 失败 ({exc}), 使用随机向量")
        return [[random.random() for _ in range(vector_size)] for _ in texts]


async def main() -> None:
    settings = get_settings()

    # 适配本地运行的 Qdrant URL
    qdrant_url = settings.qdrant_url
    if "qdrant:6333" in qdrant_url:
        qdrant_url = "http://localhost:6333"
        print(f"[配置] Qdrant URL 从容器地址切换为: {qdrant_url}")

    print(f"[配置] Qdrant Collection: {settings.qdrant_collection}")
    print(f"[配置] 向量维度: {settings.qdrant_vector_size}")
    print(f"[配置] Demo 模式: {settings.demo_mode}")

    # ========== 初始化组件 ==========
    print("\n[初始化] ATT&CK 知识库...")
    kb = AttackKnowledgeBase()
    summary = kb.summary()
    print(f"  技术总数: {summary['technique_count']}")
    print(f"  战术阶段: {summary['tactic_count']}")

    print("\n[初始化] Qdrant 向量库...")
    store = QdrantVectorStore(
        url=qdrant_url,
        collection_name=settings.qdrant_collection,
        vector_size=settings.qdrant_vector_size,
    )
    store.ensure_collection()
    print(f"  Collection '{settings.qdrant_collection}' 就绪")

    gateway = QwenGateway(settings) if not settings.demo_mode else None
    if gateway and settings.qwen_api_key:
        print("[初始化] Qwen Embedding 网关就绪")
    else:
        print("[初始化] 使用随机向量（未配置 API_KEY 或 demo 模式）")

    # ========== 获取所有技术 ==========
    print("\n[处理] 获取全部 ATT&CK 技术...")
    all_techniques = kb.get_techniques()
    all_docs = kb.to_memory_documents(all_techniques)
    print(f"  共 {len(all_docs)} 条文档")

    # ========== 分批向量化并写入 ==========
    total = len(all_docs)
    batches = math.ceil(total / BATCH_SIZE)
    print(f"\n[写入] 分 {batches} 批写入 Qdrant (每批 {BATCH_SIZE} 条)")

    start_time = time.monotonic()
    for i in range(0, total, BATCH_SIZE):
        batch_docs = all_docs[i : i + BATCH_SIZE]
        batch_texts = [doc.content for doc in batch_docs]
        batch_num = i // BATCH_SIZE + 1

        print(f"\n  批次 {batch_num}/{batches} ({len(batch_docs)} 条)...")

        if gateway and settings.qwen_api_key:
            vectors = await generate_vectors(gateway, batch_texts, settings.qdrant_vector_size)
        else:
            vectors = [[random.random() for _ in range(settings.qdrant_vector_size)] for _ in batch_docs]

        store.batch_upsert(batch_docs, vectors)
        print(f"    写入完成")
        # 避免 API 限流（非 demo 模式时）
        if gateway and settings.qwen_api_key:
            await asyncio.sleep(0.2)

    elapsed = time.monotonic() - start_time
    print(f"\n{'='*50}")
    print(f"[OK] 入库完成!")
    print(f"  文档总数: {total}")
    print(f"  耗时: {elapsed:.1f} 秒")
    print(f"  向量库: {qdrant_url}")
    print(f"  Collection: {settings.qdrant_collection}")
    print(f"{'='*50}")


if __name__ == "__main__":
    asyncio.run(main())
