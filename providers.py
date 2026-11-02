"""Provider-independent, non-executing AI contracts for future integrations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol


ReviewState = Literal['unreviewed', 'approved', 'rejected', 'corrected']


@dataclass(frozen=True)
class Citation:
    artifact_id: int
    start_seconds: float | None = None
    end_seconds: float | None = None
    excerpt: str | None = None


@dataclass(frozen=True)
class AnalysisFinding:
    category: str
    statement: str
    is_allegation: bool
    confidence: float | None
    citations: tuple[Citation, ...]
    uncertainty: str = ''
    review_state: ReviewState = 'unreviewed'


@dataclass(frozen=True)
class AnalysisResult:
    provider: str
    model: str
    findings: tuple[AnalysisFinding, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


class AIProvider(Protocol):
    """Implementations must treat evidence as data, never as tool instructions."""
    name: str
    def transcribe(self, artifact_id: int, *, authorized: bool) -> AnalysisResult: ...
    def analyze_media(self, artifact_id: int, *, authorized: bool) -> AnalysisResult: ...
    def analyze_comments(self, text: str, *, authorized: bool) -> AnalysisResult: ...


def require_cloud_authorization(authorized: bool) -> None:
    if not authorized:
        raise PermissionError('Explicit authorization is required before private evidence is sent to a cloud AI provider')
