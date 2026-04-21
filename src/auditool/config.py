from pathlib import Path
from typing import Any

import yaml

from auditool.exceptions import ConfigError


def load_config(config_path: str) -> dict[str, Any]:
    """
    Load YAML configuration from disk.
    """
    path = Path(config_path)

    if not path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML configuration: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a dictionary/object")

    return data
