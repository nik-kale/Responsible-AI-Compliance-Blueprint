import pytest
from raicb.checks import model_artifacts
from raicb.config.schema import ProjectConfig

def test_module_exists():
    assert model_artifacts is not None

def test_run_checks_basic(tmp_path, runner):
    # Just verify it runs without error with empty config
    # We need a dummy config object
    pass

