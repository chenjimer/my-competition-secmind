from __future__ import annotations

import time

from fastapi.testclient import TestClient

from secmind.api import create_app


def test_health_and_task_flow(settings) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        upload = client.post(
            "/api/v1/uploads",
            files={"file": ("bad.py", b"import subprocess\nsubprocess.Popen('x', shell=True)\n")},
        )
        assert upload.status_code == 201
        task = client.post(
            "/api/v1/tasks",
            json={
                "objective": "audit uploaded python code",
                "attachments": [{"ref": upload.json()["ref"]}],
            },
        )
        assert task.status_code == 202
        run_id = task.json()["run_id"]
        status = None
        for _ in range(100):
            response = client.get(f"/api/v1/runs/{run_id}")
            status = response.json()["status"]
            if status in {"completed", "partial", "failed", "denied"}:
                break
            time.sleep(0.02)
        assert status == "completed"
        report = client.get(f"/api/v1/runs/{run_id}/report")
        assert report.status_code == 200
        assert report.json()["findings"]
        ledger = client.get(f"/api/v1/runs/{run_id}/ledger")
        assert ledger.status_code == 200
        assert ledger.json()["chain_valid"] is True
