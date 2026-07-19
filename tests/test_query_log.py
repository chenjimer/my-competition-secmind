from __future__ import annotations

import json

from secmind.ledger import LedgerStore


def test_query_log_basic(settings) -> None:
    ledger = LedgerStore(settings.database_url)

    hits = [
        {"memory_id": "m1", "content": "SQL injection technique", "source": "mitre-attack", "version": "v16",
         "confidence": 0.95, "metadata": {"attack_id": "T1190"}},
        {"memory_id": "m2", "content": "XSS attack technique", "source": "mitre-attack", "version": "v16",
         "confidence": 0.85, "metadata": {"attack_id": "T1189"}},
    ]

    log_id = ledger.log_query(
        query_text="How to exploit SQL injection?",
        hits_json=json.dumps(hits, ensure_ascii=False),
        hit_count=2,
        top_k=5,
        embedding_model="text-embedding-v3",
        duration_ms=450,
    )
    assert log_id > 0

    logs = ledger.query_logs(limit=10)
    assert len(logs) == 1
    assert logs[0]["query_text"] == "How to exploit SQL injection?"
    assert logs[0]["hit_count"] == 2
    assert logs[0]["embedding_model"] == "text-embedding-v3"
    assert logs[0]["duration_ms"] == 450
    assert len(logs[0]["hits"]) == 2
    assert logs[0]["hits"][0]["metadata"]["attack_id"] == "T1190"


def test_query_log_with_run_id(settings) -> None:
    ledger = LedgerStore(settings.database_url)

    ledger.log_query(
        query_text="port scan techniques",
        hits_json=json.dumps([]),
        hit_count=0,
        run_id="run-001",
        top_k=3,
        embedding_model="text-embedding-v3",
    )
    ledger.log_query(
        query_text="log analysis methods",
        hits_json=json.dumps([]),
        hit_count=0,
        run_id="run-002",
        top_k=5,
        embedding_model="random",
    )

    logs_all = ledger.query_logs(limit=10)
    assert len(logs_all) == 2

    logs_run1 = ledger.query_logs(limit=10, run_id="run-001")
    assert len(logs_run1) == 1
    assert logs_run1[0]["query_text"] == "port scan techniques"

    logs_run2 = ledger.query_logs(limit=10, run_id="run-002")
    assert len(logs_run2) == 1
    assert logs_run2[0]["query_text"] == "log analysis methods"


def test_query_log_empty_result(settings) -> None:
    ledger = LedgerStore(settings.database_url)

    log_id = ledger.log_query(
        query_text="nonexistent technique",
        hits_json=json.dumps([]),
        hit_count=0,
        embedding_model="text-embedding-v3",
    )
    assert log_id > 0

    logs = ledger.query_logs(limit=10)
    assert len(logs) == 1
    assert logs[0]["hit_count"] == 0
    assert logs[0]["hits"] == []
