from __future__ import annotations

import hashlib
import mimetypes
import shutil
import zipfile
from pathlib import Path, PurePosixPath

from secmind.config import Settings
from secmind.schemas import AttachmentRef, InputArtifact


class IngestError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class InputIngestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def ingest(self, run_id: str, attachments: list[AttachmentRef]) -> tuple[Path, list[InputArtifact]]:
        workspace = (self.settings.run_root / run_id / "workspace").resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        artifacts: list[InputArtifact] = []
        for attachment in attachments:
            source = self._resolve_reference(attachment.ref)
            if source.is_symlink():
                raise IngestError(f"Symbolic links are not accepted: {attachment.ref}")
            if source.is_dir():
                artifacts.extend(self._copy_directory(source, workspace / self._safe_name(source.name)))
            elif source.suffix.lower() == ".zip":
                artifacts.extend(self._extract_zip(source, workspace / self._safe_name(source.stem)))
            elif source.is_file():
                if source.stat().st_size > self.settings.max_upload_bytes:
                    raise IngestError(f"File exceeds size limit: {attachment.ref}")
                target = workspace / self._safe_name(attachment.name or source.name)
                shutil.copy2(source, target)
                artifacts.append(self._artifact(target, workspace, source.name))
            else:
                raise IngestError(f"Attachment does not exist: {attachment.ref}")
        return workspace, artifacts

    def _resolve_reference(self, reference: str) -> Path:
        candidate = Path(reference)
        roots = [self.settings.input_root.resolve(), self.settings.upload_root.resolve()]
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.settings.input_root / candidate).resolve()
            if not resolved.exists():
                resolved = (self.settings.upload_root / candidate).resolve()
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise IngestError("Attachment reference escapes configured input roots")
        return resolved

    def _copy_directory(self, source: Path, destination: Path) -> list[InputArtifact]:
        files = [path for path in source.rglob("*") if path.is_file()]
        if len(files) > self.settings.max_files:
            raise IngestError("Directory contains too many files")
        total = sum(path.stat().st_size for path in files)
        if total > self.settings.max_extracted_bytes:
            raise IngestError("Directory exceeds extracted size limit")
        artifacts: list[InputArtifact] = []
        for source_file in files:
            if source_file.is_symlink():
                raise IngestError("Directories containing symbolic links are not accepted")
            relative = source_file.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)
            artifacts.append(self._artifact(target, destination.parent, source_file.name))
        return artifacts

    def _extract_zip(self, source: Path, destination: Path) -> list[InputArtifact]:
        if source.stat().st_size > self.settings.max_upload_bytes:
            raise IngestError("Archive exceeds upload size limit")
        with zipfile.ZipFile(source) as archive:
            entries = [item for item in archive.infolist() if not item.is_dir()]
            if len(entries) > self.settings.max_files:
                raise IngestError("Archive contains too many files")
            total = sum(item.file_size for item in entries)
            compressed = max(1, sum(item.compress_size for item in entries))
            if total > self.settings.max_extracted_bytes:
                raise IngestError("Archive exceeds extracted size limit")
            if total / compressed > self.settings.max_zip_ratio:
                raise IngestError("Suspicious archive compression ratio")
            for item in entries:
                normalized = PurePosixPath(item.filename.replace("\\", "/"))
                if normalized.is_absolute() or ".." in normalized.parts:
                    raise IngestError("Archive contains path traversal")
                if item.external_attr >> 16 & 0o170000 == 0o120000:
                    raise IngestError("Archive contains a symbolic link")
            artifacts: list[InputArtifact] = []
            for item in entries:
                normalized = PurePosixPath(item.filename.replace("\\", "/"))
                target = destination.joinpath(*normalized.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                artifacts.append(self._artifact(target, destination.parent, item.filename))
            return artifacts

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = Path(name).name.replace("\x00", "").strip()
        if not safe or safe in {".", ".."}:
            raise IngestError("Invalid attachment name")
        return safe

    @staticmethod
    def _artifact(path: Path, workspace: Path, original_name: str) -> InputArtifact:
        media_type, _ = mimetypes.guess_type(path.name)
        return InputArtifact(
            original_name=original_name,
            relative_path=path.relative_to(workspace).as_posix(),
            sha256=sha256_file(path),
            size_bytes=path.stat().st_size,
            media_type=media_type or "application/octet-stream",
        )
