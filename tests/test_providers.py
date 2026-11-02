import pytest

from providers import AnalysisFinding, AnalysisResult, Citation, require_cloud_authorization


def test_ai_result_requires_explicit_citations_and_authorization():
    finding=AnalysisFinding('allegation','Entirely synthetic claim',True,0.5,(Citation(1,0,2,'Synthetic excerpt'),),'Requires human review')
    result=AnalysisResult('mock','mock-model',(finding,))
    assert result.findings[0].review_state=='unreviewed'
    with pytest.raises(PermissionError): require_cloud_authorization(False)
    require_cloud_authorization(True)
