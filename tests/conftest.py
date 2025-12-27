import pytest
from typer.testing import CliRunner
from pathlib import Path

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture
def sample_config(tmp_path):
    config_file = tmp_path / "raicb.yaml"
    config_file.write_text("""
project:
  name: "Test Project"
  version: "1.0.0"
  owners: ["test@example.com"]

compliance:
  standards: ["owasp_ai", "iso_42001"]

threats: []
controls: []
environments: ["dev", "prod"]

artifacts:
  model_path: "model.pt"
    """)
    return config_file

