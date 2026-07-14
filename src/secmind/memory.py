from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from qdrant_client import QdrantClient, models

from secmind.schemas import KnowledgeHit


class MemoryDocument(BaseModel):
    memory_id: str = Field(default_factory=lambda: str(uuid4()))
    content: str = Field(min_length=1)
    source: str = Field(min_length=1)
    version: str = Field(min_length=1)
    kind: str = "knowledge"
    verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class QdrantVectorStore:
    """C-group boundary for versioned, source-backed vector knowledge and memory."""

    def __init__(
        self,
        url: str,
        collection_name: str,
        vector_size: int,
        client: QdrantClient | None = None,
    ) -> None:
        self.client = client or QdrantClient(url=url)
        self.collection_name = collection_name
        self.vector_size = vector_size

    def ensure_collection(self) -> None:
        if not self.client.collection_exists(self.collection_name):
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=self.vector_size,
                    distance=models.Distance.COSINE,
                ),
            )

    def delete(self, memory_id: str) -> None:
        self.client.delete(
            collection_name=self.collection_name,
            points_selector=models.PointIdsList(points=[memory_id]),
            wait=True,
        )

    def upsert(self, document: MemoryDocument, vector: list[float]) -> None:
        if len(vector) != self.vector_size:
            raise ValueError(f"Expected vector size {self.vector_size}, got {len(vector)}")
        if document.kind == "episodic" and not document.verified:
            raise ValueError("Episodic memory must pass verification before it can be stored")
        self.ensure_collection()
        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                models.PointStruct(
                    id=document.memory_id,
                    vector=vector,
                    payload=document.model_dump(mode="json"),
                )
            ],
            wait=True,
        )

    def batch_upsert(self, documents: list[MemoryDocument], vectors: list[list[float]]) -> None:
        """Upsert multiple documents in a single Qdrant API call."""
        if len(documents) != len(vectors):
            raise ValueError(f"Document count ({len(documents)}) does not match vector count ({len(vectors)})")
        validated: list[models.PointStruct] = []
        for doc, vec in zip(documents, vectors):
            if len(vec) != self.vector_size:
                raise ValueError(f"Expected vector size {self.vector_size}, got {len(vec)}")
            if doc.kind == "episodic" and not doc.verified:
                raise ValueError("Episodic memory must pass verification before it can be stored")
            validated.append(
                models.PointStruct(id=doc.memory_id, vector=vec, payload=doc.model_dump(mode="json"))
            )
        self.ensure_collection()
        self.client.upsert(collection_name=self.collection_name, points=validated, wait=True)

    def search(
        self,
        vector: list[float],
        filters: dict[str, str] | None = None,
        top_k: int = 5,
    ) -> list[KnowledgeHit]:
        if len(vector) != self.vector_size:
            raise ValueError(f"Expected vector size {self.vector_size}, got {len(vector)}")
        self.ensure_collection()
        query_filter = None
        if filters:
            query_filter = models.Filter(
                must=[
                    models.FieldCondition(key=key, match=models.MatchValue(value=value))
                    for key, value in filters.items()
                ]
            )
        response = self.client.query_points(
            collection_name=self.collection_name,
            query=vector,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True,
        )
        hits: list[KnowledgeHit] = []
        for point in response.points:
            payload = point.payload or {}
            hits.append(
                KnowledgeHit(
                    memory_id=str(payload.get("memory_id", point.id)),
                    content=str(payload.get("content", "")),
                    source=str(payload.get("source", "unknown")),
                    version=str(payload.get("version", "unknown")),
                    confidence=max(0.0, float(point.score)),
                    metadata=dict(payload.get("metadata", {})),
                )
            )
        return hits
