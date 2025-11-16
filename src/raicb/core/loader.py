"""Configuration and data loading utilities."""

import yaml
from pathlib import Path
from typing import Optional

from ..config.schema import ProjectConfig, ModelCard


def load_config(config_path: Path, validate: bool = True) -> ProjectConfig:
    """
    Load and validate project configuration from YAML.

    Args:
        config_path: Path to raicb.yaml
        validate: Whether to validate with Pydantic

    Returns:
        Validated ProjectConfig instance

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If YAML is invalid
        pydantic.ValidationError: If validation fails
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError("Configuration file is empty")

    if validate:
        config = ProjectConfig(**data)
    else:
        # For debugging - return raw dict
        return data  # type: ignore

    return config


def load_model_card(model_card_path: Path) -> Optional[ModelCard]:
    """
    Load model card from YAML.

    Args:
        model_card_path: Path to model_card.yaml

    Returns:
        ModelCard instance or None if file doesn't exist

    Raises:
        yaml.YAMLError: If YAML is invalid
        pydantic.ValidationError: If validation fails
    """
    if not model_card_path.exists():
        return None

    with open(model_card_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data:
        return None

    return ModelCard(**data)


def save_config(config: ProjectConfig, output_path: Path) -> None:
    """
    Save configuration to YAML file.

    Args:
        config: ProjectConfig instance
        output_path: Output file path
    """
    # Convert to dict
    data = config.model_dump(exclude_none=True)

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def load_yaml_safe(file_path: Path) -> dict:
    """
    Safely load any YAML file.

    Args:
        file_path: Path to YAML file

    Returns:
        Parsed YAML data as dict

    Raises:
        FileNotFoundError: If file doesn't exist
        yaml.YAMLError: If YAML is invalid
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_path(base_path: Path, relative_path: Optional[str]) -> Optional[Path]:
    """
    Resolve a relative path against a base path.

    Args:
        base_path: Base directory path
        relative_path: Relative path string

    Returns:
        Resolved absolute path, or None if relative_path is None
    """
    if not relative_path:
        return None

    path = Path(relative_path)
    if path.is_absolute():
        return path

    # Resolve relative to base_path
    return (base_path / path).resolve()
