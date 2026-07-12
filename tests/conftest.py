from __future__ import annotations

from pathlib import Path

import pytest

from secmind.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        demo_mode=True,
        database_url=f"sqlite:///{(tmp_path / 'secmind.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        max_upload_bytes=1024 * 1024,
        max_extracted_bytes=2 * 1024 * 1024,
    )
