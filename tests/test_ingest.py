from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from secmind.ingest import IngestError, InputIngestor
from secmind.schemas import AttachmentRef


def test_ingest_file_and_hash(settings) -> None:
    settings.prepare_directories()
    source = settings.input_root / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    workspace, artifacts = InputIngestor(settings).ingest("run-1", [AttachmentRef(ref="app.py")])
    assert (workspace / "app.py").exists()
    assert len(artifacts) == 1
    assert len(artifacts[0].sha256) == 64


def test_rejects_zip_path_traversal(settings) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escaped.py", "print('bad')")
    with pytest.raises(IngestError, match="path traversal"):
        InputIngestor(settings).ingest("run-2", [AttachmentRef(ref="bad.zip")])


def test_rejects_reference_outside_roots(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    outside = tmp_path / "outside.py"
    outside.write_text("print('x')", encoding="utf-8")
    with pytest.raises(IngestError, match="escapes"):
        InputIngestor(settings).ingest("run-3", [AttachmentRef(ref=str(outside))])


def test_ingests_directory_and_valid_zip(settings) -> None:
    settings.prepare_directories()
    source_dir = settings.input_root / "project"
    source_dir.mkdir()
    (source_dir / "one.py").write_text("print(1)", encoding="utf-8")
    nested = source_dir / "nested"
    nested.mkdir()
    (nested / "two.py").write_text("print(2)", encoding="utf-8")
    _, directory_artifacts = InputIngestor(settings).ingest("run-directory", [AttachmentRef(ref="project")])
    assert len(directory_artifacts) == 2

    archive = settings.input_root / "good.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src/app.py", "print('ok')")
    workspace, archive_artifacts = InputIngestor(settings).ingest("run-archive", [AttachmentRef(ref="good.zip")])
    assert len(archive_artifacts) == 1
    assert (workspace / "good" / "src" / "app.py").exists()


def test_rejects_missing_attachment(settings) -> None:
    settings.prepare_directories()
    with pytest.raises(IngestError, match="does not exist"):
        InputIngestor(settings).ingest("missing", [AttachmentRef(ref="missing.py")])
