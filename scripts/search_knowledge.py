# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""ATT&CK 知识语义搜索工具 — 交互式搜索 Qdrant 向量库。

每次搜索都会在 SQLite 数据库中留存查询记录（包括问题与结果）。

使用方法:
    python search_knowledge.py                        # 交互模式
    python search_knowledge.py "SQL injection"         # 单次查询
    python search_knowledge.py "端口扫描" --top-k 10   # 指定条数
    python search_knowledge.py --show-logs             # 查看查询历史
    python search_knowledge.py --export-logs logs.json # 导出查询历史为 JSON 文件

前提条件:
    - Qdrant 容器正在运行 (docker compose up qdrant -d)
    - 知识已入库 (python scripts/ingest_knowledge.py)
    - .env 已配置 SECMIND_QWEN_API_KEY（否则使用随机向量）
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# 把项目 src 目录加入路径，这样就能 import secmind 了
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 强制 Qdrant URL 指向 localhost（兼容本地运行）
os.environ.setdefault("SECMIND_QDRANT_URL", "http://localhost:6333")

from secmind.config import get_settings  # noqa: E402
from secmind.ledger import LedgerStore  # noqa: E402
from secmind.llm import QwenGateway  # noqa: E402
from secmind.memory import QdrantVectorStore  # noqa: E402


async def _do_search(
    store: QdrantVectorStore,
    ledger: LedgerStore,
    gateway: QwenGateway | None,
    query: str,
    top_k: int,
    filter_str: str | None,
    use_real_embedding: bool,
) -> None:
    query_start = time.monotonic()

    print(f"\n{'=' * 60}")
    print(f'  搜索: "{query}"')
    print(f"{'=' * 60}")

    # 解析过滤条件
    filters = None
    if filter_str:
        parts = filter_str.split(":", 1)
        if len(parts) == 2:
            filters = {"metadata." + parts[0].strip(): parts[1].strip()}

    # 生成查询向量
    embedding_model = ""
    if use_real_embedding and gateway:
        try:
            vectors = await gateway.embeddings([query])
            query_vector = vectors[0]
            embedding_model = "text-embedding-v3"
            print(f"  向量: 千问 Embedding ({embedding_model})")
        except Exception as exc:
            print(f"  向量生成失败 ({exc}), 回退到随机向量")
            query_vector = [random.random() for _ in range(store.vector_size)]
            embedding_model = "random-fallback"
    else:
        query_vector = [random.random() for _ in range(store.vector_size)]
        embedding_model = "random"
        print(f"  向量: 随机 (demo 模式)")

    # 搜索
    try:
        hits = store.search(query_vector, filters=filters, top_k=top_k)
    except Exception as exc:
        print(f"\n  搜索失败: {exc}")
        # 留存查询记录（即使失败也记录）
        try:
            ledger.log_query(
                query_text=query,
                hits_json=json.dumps([]),
                hit_count=0,
                top_k=top_k,
                embedding_model=embedding_model,
                duration_ms=int((time.monotonic() - query_start) * 1000),
            )
        except Exception:
            pass
        return

    query_duration = int((time.monotonic() - query_start) * 1000)

    if not hits:
        print(f"\n  未找到匹配结果")
        # 留存空结果查询记录
        try:
            ledger.log_query(
                query_text=query,
                hits_json=json.dumps([]),
                hit_count=0,
                top_k=top_k,
                embedding_model=embedding_model,
                duration_ms=query_duration,
            )
        except Exception:
            pass
        return

    print(f"\n  找到 {len(hits)} 条结果:\n")
    for i, hit in enumerate(hits, 1):
        print(f"  [#{i}] (置信度: {hit.confidence:.4f})")
        print(f"       {hit.content[:100].replace(chr(10), ' ')}")
        if hit.metadata.get("attack_id"):
            print(f"       ATT&CK ID: {hit.metadata['attack_id']}")
        if hit.metadata.get("tactics"):
            tactics = hit.metadata["tactics"]
            if isinstance(tactics, list):
                tactics = ", ".join(tactics)
            print(f"       战术阶段: {tactics}")
        print(f"      [来源: {hit.source} | 版本: {hit.version}]")
        print()

    # 留存查询记录
    try:
        hits_data = [
            {
                "memory_id": h.memory_id,
                "content": h.content,
                "source": h.source,
                "version": h.version,
                "confidence": h.confidence,
                "metadata": h.metadata,
            }
            for h in hits
        ]
        log_id = ledger.log_query(
            query_text=query,
            hits_json=json.dumps(hits_data, ensure_ascii=False),
            hit_count=len(hits),
            top_k=top_k,
            embedding_model=embedding_model,
            duration_ms=query_duration,
        )
        print(f"  [查询记录已留存, ID={log_id}]")
    except Exception as exc:
        print(f"  [查询记录留存失败: {exc}]")


def _show_logs(ledger: LedgerStore, limit: int = 20) -> None:
    """显示最近的查询历史。"""
    logs = ledger.query_logs(limit=limit)
    if not logs:
        print("\n  暂无查询记录。\n")
        return

    print(f"\n{'=' * 60}")
    print(f"  最近的 {len(logs)} 条查询记录")
    print(f"{'=' * 60}\n")
    for i, entry in enumerate(logs, 1):
        print(f"  [{i}] 时间:     {entry['timestamp']}")
        print(f"      查询:     {entry['query_text'][:120]}")
        print(f"      结果数:   {entry['hit_count']}")
        if entry["duration_ms"] is not None:
            print(f"      耗时:     {entry['duration_ms']}ms")
        print(f"      嵌入模型: {entry['embedding_model']}")
        # 显示命中的结果摘要
        hits = entry.get("hits", [])
        if hits:
            for j, hit in enumerate(hits[:3], 1):
                content = hit.get("content", "")[:80].replace("\n", " ")
                attack_id = hit.get("metadata", {}).get("attack_id", "")
                tag = f" [{attack_id}]" if attack_id else ""
                print(f"      结果{j}:   {content}{tag}")
            if len(hits) > 3:
                print(f"       ... 还有 {len(hits)-3} 条结果")
        print()


def _export_logs(ledger: LedgerStore, output_path: str, limit: int = 500) -> None:
    """导出查询历史为 JSON 文件。"""
    logs = ledger.query_logs(limit=limit)
    if not logs:
        print("\n  暂无查询记录可导出。\n")
        return

    # 整理导出数据，每条记录包含 query_text 和完整的 hits
    export_data = {
        "exported_at": str(datetime.now(UTC)),
        "total": len(logs),
        "logs": logs,
    }

    path = Path(output_path)
    path.write_text(
        json.dumps(export_data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n  已导出 {len(logs)} 条查询记录到: {path.resolve()}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK 知识语义搜索（自动留存查询记录）")
    parser.add_argument("query", nargs="?", help="搜索关键词")
    parser.add_argument("--top-k", type=int, default=5, help="返回结果数量 (默认: 5)")
    parser.add_argument(
        "--filter",
        help="过滤条件, 格式: key:value, 如 attack_id:T1190",
    )
    parser.add_argument(
        "--show-logs",
        action="store_true",
        help="显示查询历史记录",
    )
    parser.add_argument(
        "--export-logs",
        type=str,
        nargs="?",
        const="query_logs.json",
        help="导出查询历史为 JSON 文件 (默认: query_logs.json)",
    )
    args = parser.parse_args()

    settings = get_settings()
    settings.qdrant_url = "http://localhost:6333"  # 强制本地地址

    api_key = settings.qwen_api_key or os.environ.get("SECMIND_QWEN_API_KEY", "")
    has_key = bool(api_key)

    # 初始化 LedgerStore（用于记录查询日志）
    ledger = LedgerStore(settings.database_url)

    # 如果只是查看日志，不初始化 Qdrant 和 gateway
    if args.show_logs:
        _show_logs(ledger)
        return

    # 导出查询历史
    if args.export_logs:
        _export_logs(ledger, args.export_logs)
        return

    print(f"\n{'=' * 60}")
    print(f"  ATT&CK 知识语义搜索")
    print(f"{'=' * 60}")
    print(f"  Qdrant:      http://localhost:6333")
    print(f"  Collection:  {settings.qdrant_collection}")
    print(f"  向量维度:    {settings.qdrant_vector_size}")
    print(f"  嵌入模型:    {settings.embedding_model if has_key else '无 (随机向量)'}")
    print(f"  API Key:     {'已配置' if has_key else '未配置'}")
    if has_key:
        print(f"  Embedding:   千问 {settings.embedding_model}")
    print(f"  查询日志:    SQLite ({settings.database_url})")

    # 初始化 Qdrant
    store = QdrantVectorStore(
        url="http://localhost:6333",
        collection_name=settings.qdrant_collection,
        vector_size=settings.qdrant_vector_size,
    )

    # 如果有 API Key，使用千问 Embedding
    gateway = None
    use_real_embedding = False
    if has_key:
        settings.qwen_api_key = api_key
        settings.demo_mode = False
        try:
            gateway = QwenGateway(settings)
            use_real_embedding = True
        except Exception as exc:
            print(f"  网关初始化失败: {exc}")

    query = args.query
    if not query:
        # 交互模式 — 整个循环共用一个事件循环
        print(f"\n  输入关键词搜索 (输入 q 退出)\n")
        while True:
            try:
                q = input("  搜索: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not q or q.lower() == "q":
                break
            await _do_search(store, ledger, gateway, q, args.top_k, args.filter, use_real_embedding)
            print()
        return

    await _do_search(store, ledger, gateway, query, args.top_k, args.filter, use_real_embedding)


if __name__ == "__main__":
    asyncio.run(main())
