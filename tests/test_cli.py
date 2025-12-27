from typer.testing import CliRunner
from raicb.cli import app
import pytest

def test_version(runner):
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Responsible AI Compliance Blueprint" in result.stdout

def test_init(runner, tmp_path):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, ["init", "."])
        assert result.exit_code == 0
        assert (tmp_path / "raicb.yaml").exists()
        assert "Project initialized" in result.stdout

def test_validate_success(runner, sample_config):
    result = runner.invoke(app, ["validate", "--config", str(sample_config)])
    assert result.exit_code == 0
    assert "Configuration is valid" in result.stdout

def test_validate_missing_file(runner):
    result = runner.invoke(app, ["validate", "--config", "nonexistent.yaml"])
    assert result.exit_code == 1
    assert "Configuration file not found" in result.stdout

def test_run_missing_config(runner):
    result = runner.invoke(app, ["run", "--config", "nonexistent.yaml"])
    assert result.exit_code == 1
    assert "Configuration file not found" in result.stdout

def test_map(runner):
    result = runner.invoke(app, ["map"])
    assert result.exit_code == 0
    assert "Framework Mappings" in result.stdout

