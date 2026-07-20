from __future__ import annotations

import pytest
from qdrant_client import QdrantClient

from secmind.memory import MemoryDocument, QdrantVectorStore


def test_qdrant_store_requires_verified_episodic_memory() -> None:
    store = QdrantVectorStore(
        url=":memory:",
        collection_name="test",
        vector_size=3,
        client=QdrantClient(":memory:"),
    )
    with pytest.raises(ValueError, match="verification"):
        store.upsert(
            MemoryDocument(
                content="unverified experience",
                source="run-1",
                version="1",
                kind="episodic",
            ),
            [1.0, 0.0, 0.0],
        )


def test_qdrant_store_upserts_searches_and_filters() -> None:
    store = QdrantVectorStore(
        url=":memory:",
        collection_name="test",
        vector_size=3,
        client=QdrantClient(":memory:"),
    )
    store.upsert(
        MemoryDocument(
            content="Bandit detects shell injection",
            source="ATT&CK",
            version="1",
            metadata={"topic": "code"},
        ),
        [1.0, 0.0, 0.0],
    )
    hits = store.search([1.0, 0.0, 0.0], filters={"source": "ATT&CK"}, top_k=2)
    assert len(hits) == 1
    assert hits[0].source == "ATT&CK"
    assert hits[0].confidence > 0
    with pytest.raises(ValueError, match="vector size"):
        store.search([1.0])


def test_qdrant_store_crud_scroll_and_collection_validation() -> None:
    store = QdrantVectorStore(
        url=":memory:",
        collection_name="crud",
        vector_size=3,
        client=QdrantClient(":memory:"),
    )
    memory_id = store.stable_memory_id("mitre-attack-enterprise", "T1110", "technique")
    document = MemoryDocument(
        memory_id=memory_id,
        content="Brute Force",
        source="mitre-attack",
        version="19.1",
        metadata={"domain": "enterprise"},
    )
    store.upsert(document, [1.0, 0.0, 0.0])

    assert store.get(memory_id) == document
    store.update_payload(memory_id, {"verified": True})
    assert store.get(memory_id).verified is True
    assert store.scroll(filters={"metadata.domain": "enterprise"})[0].memory_id == memory_id

    same_id = store.stable_memory_id("mitre-attack-enterprise", "T1110", "technique")
    assert same_id == memory_id
    store.delete(memory_id)
    assert store.get(memory_id) is None

    incompatible = QdrantVectorStore(
        url=":memory:", collection_name="crud", vector_size=4, client=store.client
    )
    with pytest.raises(ValueError, match="has vector size"):
        incompatible.ensure_collection()
