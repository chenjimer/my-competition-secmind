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
import json
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
    parser.add_argument(
        "--domain",
        action="append",
        choices=("enterprise", "mobile", "ics"),
        help="ATT&CK 域，可重复指定；默认 enterprise",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="只处理前 N 条，用于低成本链路验证",
    )
    parser.add_argument(
        "--checkpoint",
        default="data/ingest_checkpoint.json",
        help="断点记录文件",
    )
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit 必须是正整数")

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
        print("[配置] API Key: 已配置 [OK]")

    # ========== 初始化组件 ==========
    selected_domains = tuple(dict.fromkeys(args.domain or ["enterprise"]))
    print(f"\n[初始化] ATT&CK 知识库: {', '.join(selected_domains)}")
    all_docs = []
    summaries = []
    for domain in selected_domains:
        kb = AttackKnowledgeBase(domain=domain)
        summary = kb.summary()
        summaries.append(summary)
        domain_docs = kb.all_documents()
        all_docs.extend(domain_docs)
        print(
            f"  {domain}: v{summary['attack_version']}, "
            f"技术/子技术 {len(domain_docs) - summary['tactic_count']} 条, "
            f"战术 {summary['tactic_count']} 条"
        )
    if args.limit is not None:
        all_docs = all_docs[: args.limit]
    print(f"  本次候选文档: {len(all_docs)} 条")
    if args.dry_run:
        print("\n[Dry-Run] 预览完成，未连接 Qdrant、未调用 Embedding、未写入数据。")
        return

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
        Path(args.checkpoint).unlink(missing_ok=True)
        print(f"  已删除 {count} 条旧数据，重新创建集合")

    # 初始化千问 Embedding 网关（使用真实语意嵌入模型）
    if settings.demo_mode:
        print("\n[初始化] Demo 模式 — 使用随机向量（仅用于测试）")
        gateway = None
    else:
        print(f"\n[初始化] 千问 Embedding 网关 — 模型: {settings.embedding_model}")
        gateway = QwenGateway(settings)

    # ========== 断点恢复 ==========
    checkpoint_path = Path(args.checkpoint)
    completed_ids: set[str] = set()
    checkpoint_fingerprint = {
        "domains": list(selected_domains),
        "embedding_model": settings.embedding_model,
        "vector_size": settings.qdrant_vector_size,
    }
    if checkpoint_path.exists():
        checkpoint_data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if checkpoint_data.get("fingerprint") == checkpoint_fingerprint:
            completed_ids = set(checkpoint_data.get("completed_ids", []))
    pending_docs = [doc for doc in all_docs if doc.memory_id not in completed_ids]
    if completed_ids:
        print(f"\n[恢复] 已完成 {len(completed_ids)} 条，本次待处理 {len(pending_docs)} 条")

    # ========== 分批向量化并写入 ==========
    total = len(pending_docs)
    batches = math.ceil(total / BATCH_SIZE)
    print(f"\n[写入] 分 {batches} 批写入 Qdrant (每批 {BATCH_SIZE} 条)")

    if not settings.demo_mode:
        print(f"[写入] 使用千问 {settings.embedding_model} 生成真实语意向量")

    start_time = time.monotonic()
    for i in range(0, total, BATCH_SIZE):
        batch_docs = pending_docs[i : i + BATCH_SIZE]
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
            print("    向量生成完成 (随机向量 — demo 模式)")

        store.batch_upsert(batch_docs, vectors)
        completed_ids.update(doc.memory_id for doc in batch_docs)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_checkpoint = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
        temporary_checkpoint.write_text(
            json.dumps(
                {"fingerprint": checkpoint_fingerprint, "completed_ids": sorted(completed_ids)},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary_checkpoint.replace(checkpoint_path)
        print("    写入 Qdrant 完成")
        # 避免 API 限流
        if gateway and not settings.demo_mode:
            await asyncio.sleep(0.3)

    elapsed = time.monotonic() - start_time
    print(f"\n{'=' * 50}")
    print("[OK] 入库完成!")
    versions = ", ".join(f"{item['domain']}:v{item['attack_version']}" for item in summaries)
    print(f"  ATT&CK 版本: {versions}")
    print(f"  本次新增: {total}")
    print(f"  checkpoint累计: {len(completed_ids)}")
    print(f"  嵌入模型: {settings.embedding_model if not settings.demo_mode else '(随机向量 — demo 模式)'}")
    print(f"  耗时: {elapsed:.1f} 秒")
    print(f"  向量库: {qdrant_url}")
    print(f"  Collection: {settings.qdrant_collection}")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    asyncio.run(main())
