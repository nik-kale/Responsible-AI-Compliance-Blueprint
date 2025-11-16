"""Tests for configuration loader."""

import pytest
from pathlib import Path
import yaml

from raicb.core.loader import load_config, load_model_card
from raicb.config.schema import ProjectConfig


def test_load_config_valid(tmp_path):
    """Test loading a valid configuration."""
    config_data = {
        "project": {
            "name": "Test Project",
            "version": "1.0.0",
            "owners": [{"name": "Test Owner", "email": "test@example.com"}],
        },
        "artifacts": {},
        "policies": {},
        "threats": [],
        "controls": [],
        "environments": {},
    }

    config_file = tmp_path / "raicb.yaml"
    with open(config_file, "w") as f:
        yaml.safe_dump(config_data, f)

    config = load_config(config_file)

    assert isinstance(config, ProjectConfig)
    assert config.project.name == "Test Project"
    assert config.project.version == "1.0.0"
    assert len(config.project.owners) == 1


def test_load_config_missing_file():
    """Test loading non-existent configuration."""
    with pytest.raises(FileNotFoundError):
        load_config(Path("/nonexistent/raicb.yaml"))


def test_load_config_invalid_yaml(tmp_path):
    """Test loading invalid YAML."""
    config_file = tmp_path / "raicb.yaml"
    config_file.write_text("invalid: yaml: content:")

    with pytest.raises(Exception):
        load_config(config_file)


def test_load_model_card_valid(tmp_path):
    """Test loading a valid model card."""
    model_card_data = {
        "model_name": "Test Model",
        "version": "1.0",
        "description": "Test description",
    }

    model_card_file = tmp_path / "model_card.yaml"
    with open(model_card_file, "w") as f:
        yaml.safe_dump(model_card_data, f)

    model_card = load_model_card(model_card_file)

    assert model_card is not None
    assert model_card.model_name == "Test Model"
    assert model_card.version == "1.0"


def test_load_model_card_missing():
    """Test loading missing model card."""
    result = load_model_card(Path("/nonexistent/model_card.yaml"))
    assert result is None
