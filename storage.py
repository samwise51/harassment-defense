"""Private evidence storage backends.

Only local storage is enabled in v0.2.0.  The protocol deliberately keeps
database records independent from a future S3-compatible implementation.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol


@dataclass(frozen=True)
class StoredObject:
    key: str
    sha256: str
    size: int


class StorageBackend(Protocol):
    def store(self, stream: BinaryIO, suffix: str, max_bytes: int) -> StoredObject: ...
    def open(self, key: str) -> BinaryIO: ...
    def path(self, key: str) -> Path: ...
    def delete(self, key: str) -> None: ...
    def verify(self, key: str, expected_sha256: str) -> bool: ...


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _safe_path(self, key: str) -> Path:
        if not key or Path(key).name != key or key in {'.', '..'}:
            raise ValueError('Unsafe storage key')
        candidate = (self.root / key).resolve()
        if candidate.parent != self.root:
            raise ValueError('Unsafe storage path')
        return candidate

    def store(self, stream: BinaryIO, suffix: str, max_bytes: int) -> StoredObject:
        suffix = suffix.lower()[:16] if suffix.startswith('.') else ''
        key = uuid.uuid4().hex + suffix
        target = self._safe_path(key)
        digest = hashlib.sha256()
        size = 0
        try:
            with target.open('xb') as output:
                os.chmod(target, 0o600)
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > max_bytes:
                        raise ValueError(f'Evidence file exceeds configured {max_bytes // (1024 * 1024)} MB limit')
                    digest.update(block)
                    output.write(block)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        return StoredObject(key, digest.hexdigest(), size)

    def open(self, key: str) -> BinaryIO:
        return self._safe_path(key).open('rb')

    def path(self, key: str) -> Path:
        return self._safe_path(key)

    def delete(self, key: str) -> None:
        self._safe_path(key).unlink(missing_ok=True)

    def verify(self, key: str, expected_sha256: str) -> bool:
        path = self._safe_path(key)
        if not path.is_file():
            return False
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        return digest.hexdigest() == expected_sha256


class S3CompatibleStorage:
    """Reserved contract; deliberately unavailable until credentials and policy exist."""
    def __init__(self, *args, **kwargs):
        raise NotImplementedError('S3-compatible storage is not enabled in v0.2.0')
