import pytest
from raicb.checks import plugin_security
from raicb.config.schema import ProjectConfig, ProjectInfo, ComplianceConfig, Status

@pytest.fixture
def empty_config():
    return ProjectConfig(
        project=ProjectInfo(name="test", version="1.0", owners=[]),
        artifacts=None,
        compliance=ComplianceConfig(standards=[]),
        threats=[],
        controls=[],
        environments=[]
    )

def test_run_checks_empty(tmp_path, empty_config):
    findings = plugin_security.run_checks(empty_config, tmp_path, "dev")
    assert isinstance(findings, list)

