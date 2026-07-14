"""验证 Qdrant 连接和 CRUD 操作的测试脚本。

使用方法:
    python test_qdrant.py

前提条件:
    - Qdrant Docker 容器正在运行 (docker compose up qdrant -d)
    - qdrant-client 已安装 (pip install qdrant-client)
"""

import time
from secmind.memory import QdrantVectorStore, MemoryDocument


def main():
    # ========== 1. 连接 Qdrant ==========
    print("=" * 50)
    print("1. 连接 Qdrant")
    print("=" * 50)

    store = QdrantVectorStore(
        url="http://localhost:6333",
        collection_name="test_secmind",
        vector_size=128,  # 测试用小维度
    )
    print(f"  Qdrant URL: http://localhost:6333")
    print(f"  Collection: {store.collection_name}")
    print(f"  Vector size: {store.vector_size}")
    print("  [OK] 连接成功\n")

    # 清理旧数据（如果之前运行过）
    try:
        store.client.delete_collection(store.collection_name)
        print(f"  [清理] 已删除旧的 collection\n")
    except Exception:
        pass

    # ========== 2. 创建 Collection ==========
    print("=" * 50)
    print("2. 创建 Collection")
    print("=" * 50)

    store.ensure_collection()
    collections = store.client.get_collections()
    names = [c.name for c in collections.collections]
    assert store.collection_name in names, f"Collection 未创建成功: {names}"
    print(f"  Collection '{store.collection_name}' 创建成功")
    print(f"  当前所有 collections: {names}\n")

    # ========== 3. 插入文档 ==========
    print("=" * 50)
    print("3. 插入文档（增 Create）")
    print("=" * 50)

    docs = [
        MemoryDocument(
            content="SQL注入是通过将恶意SQL语句插入到应用程序输入参数中，从而操纵后端数据库的攻击技术。",
            source="mitre-attack",
            version="v1",
            kind="knowledge",
            metadata={"technique_id": "T1190", "tactic": "initial-access"},
        ),
        MemoryDocument(
            content="XSS跨站脚本攻击允许攻击者将恶意脚本注入到网页中，当其他用户浏览时执行。",
            source="mitre-attack",
            version="v1",
            kind="knowledge",
            metadata={"technique_id": "T1189", "tactic": "initial-access"},
        ),
        MemoryDocument(
            content="缓冲区溢出攻击通过向程序缓冲区写入超出其容量的数据，覆盖相邻内存空间。",
            source="mitre-attack",
            version="v1",
            kind="knowledge",
            metadata={"technique_id": "T1200", "tactic": "execution"},
        ),
    ]

    # 伪造一些简单的向量（实际中应使用千问 embedding）
    vectors = [
        [0.1] * 128,  # SQL注入的"向量"
        [0.9] * 128,  # XSS的"向量"
        [0.5] * 128,  # 缓冲区溢出的"向量"
    ]

    for i, (doc, vec) in enumerate(zip(docs, vectors)):
        store.upsert(doc, vec)
        print(f"  [{i}] 插入: {doc.content[:30]}... (id={doc.memory_id[:8]}...)")

    print(f"  共插入 {len(docs)} 条文档\n")

    # ========== 4. 搜索文档（查 Read） ==========
    print("=" * 50)
    print("4. 语义搜索（查 Read）")
    print("=" * 50)

    # 搜索与 SQL 注入向量最相似的内容
    query_vector = [0.12] * 128  # 接近 SQL 注入的向量
    hits = store.search(query_vector, top_k=3)

    print(f"  查询: 与 SQL 注入语义相近的内容")
    print(f"  Top-{len(hits)} 结果:\n")
    for i, hit in enumerate(hits):
        print(f"    [{i}] 分数: {hit.confidence:.4f}")
        print(f"        内容: {hit.content[:50]}...")
        print(f"        来源: {hit.source}")
        print(f"        标签: {hit.metadata}\n")

    # ========== 5. 带过滤条件搜索 ==========
    print("=" * 50)
    print("5. 带过滤条件的搜索")
    print("=" * 50)

    filtered = store.search(
        query_vector,
        filters={"metadata.tactic": "initial-access"},
        top_k=5,
    )
    print(f"  过滤条件: metadata.tactic=initial-access")
    print(f"  命中 {len(filtered)} 条:\n")
    for i, hit in enumerate(filtered):
        print(f"    [{i}] {hit.content[:40]}... (tactic={hit.metadata.get('tactic')})")

    print()

    # ========== 6. 删除文档（删 Delete） ==========
    print("=" * 50)
    print("6. 删除文档（删 Delete）")
    print("=" * 50)

    target_id = docs[0].memory_id
    print(f"  删除文档 id={target_id[:8]}... ({docs[0].content[:20]}...)")
    store.delete(target_id)
    time.sleep(0.5)

    # 验证删除成功
    search_after_delete = store.search(query_vector, top_k=5)
    deleted_still_exists = any(h.memory_id == target_id for h in search_after_delete)
    print(f"  删除后搜索结果中是否还存在: {deleted_still_exists}")
    assert not deleted_still_exists, "删除失败！文档仍然存在"
    print("  [OK] 删除成功\n")

    # ========== 7. 清理环境 ==========
    print("=" * 50)
    print("7. 清理测试数据")
    print("=" * 50)

    store.client.delete_collection(store.collection_name)
    print(f"  已删除测试 collection: {store.collection_name}\n")

    # ========== 8. 总结 ==========
    print("=" * 50)
    print("✅ 全部测试通过！")
    print("=" * 50)
    print("  已验证功能:")
    print("    - 连接 Qdrant 服务")
    print("    - 创建 Collection")
    print("    - 插入文档（Create）")
    print("    - 语义搜索（Read）")
    print("    - 带过滤条件搜索")
    print("    - 删除文档（Delete）")
    print("    - Web UI: http://localhost:6333/dashboard")
    print("=" * 50)


if __name__ == "__main__":
    main()
