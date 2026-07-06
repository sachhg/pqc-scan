"""Loading and representation of the ``.pqcscan.yml`` configuration file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from pqcscan.scanner.base import SEVERITY_LOW

DEFAULT_CONFIG_NAMES = (".pqcscan.yml", ".pqcscan.yaml", "pqcscan.yml")
ALL_LANGUAGES = ["python", "javascript", "java", "go"]

_VALID_SEVERITIES = ("critical", "high", "medium", "low")


class ConfigError(Exception):
    """Raised when an explicitly requested config file cannot be used."""

DEFAULT_EXCLUDES = [
    "**/tests/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/vendor/**",
    "**/dist/**",
    "**/build/**",
]


@dataclass
class PqcConfig:
    """Resolved configuration for a scan run."""

    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    severity_threshold: str = SEVERITY_LOW
    languages: list[str] = field(default_factory=lambda: list(ALL_LANGUAGES))
    scan_configs: bool = True
    scan_dependencies: bool = True
    disabled_rules: set[str] = field(default_factory=set)
    default_format: str = "console"
    cbom_path: str = "cbom.json"
    #: Path the config was loaded from (None when using built-in defaults).
    source_path: Optional[str] = None
    #: Non-fatal problem encountered while loading (malformed discovered
    #: config, unknown severity value, ...). The CLI prints it to stderr.
    load_warning: Optional[str] = None

    @classmethod
    def default(cls) -> "PqcConfig":
        return cls()

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Optional[str] = None) -> "PqcConfig":
        cfg = cls()
        cfg.source_path = source_path
        if not isinstance(data, dict):
            return cfg

        if isinstance(data.get("exclude"), list):
            cfg.exclude = [str(p) for p in data["exclude"]]
        if data.get("severity_threshold"):
            value = str(data["severity_threshold"]).lower()
            if value in _VALID_SEVERITIES:
                cfg.severity_threshold = value
            else:
                cfg.load_warning = (
                    f"Unknown severity_threshold '{value}' in config; "
                    f"using '{cfg.severity_threshold}'."
                )
        if isinstance(data.get("languages"), list):
            cfg.languages = [str(s).lower() for s in data["languages"]]
        if "scan_configs" in data:
            cfg.scan_configs = bool(data["scan_configs"])
        if "scan_dependencies" in data:
            cfg.scan_dependencies = bool(data["scan_dependencies"])

        rules = data.get("rules") or {}
        if isinstance(rules, dict) and isinstance(rules.get("disable"), list):
            cfg.disabled_rules = {str(r).upper() for r in rules["disable"]}

        output = data.get("output") or {}
        if isinstance(output, dict):
            if output.get("default_format"):
                cfg.default_format = str(output["default_format"]).lower()
            if output.get("cbom_path"):
                cfg.cbom_path = str(output["cbom_path"])
        return cfg

    @classmethod
    def load(cls, explicit_path: Optional[str] = None, start_dir: str | Path = ".") -> "PqcConfig":
        """Load config from *explicit_path*, else discover one near *start_dir*.

        A malformed *explicitly requested* config raises :class:`ConfigError`
        (silently ignoring it would scan with the wrong settings). A malformed
        *discovered* config falls back to defaults with ``load_warning`` set.
        """
        path = _resolve_config_path(explicit_path, start_dir)
        if path is None:
            return cls.default()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            if explicit_path:
                raise ConfigError(f"Could not read config file {path}: {exc}") from exc
            cfg = cls.default()
            cfg.load_warning = f"Ignoring malformed config {path}: {exc}"
            return cfg
        if not isinstance(data, dict):
            if explicit_path:
                raise ConfigError(
                    f"Config file {path} must contain a YAML mapping, "
                    f"got {type(data).__name__}."
                )
            cfg = cls.default()
            cfg.load_warning = f"Ignoring config {path}: not a YAML mapping."
            return cfg
        return cls.from_dict(data, source_path=str(path))


def _resolve_config_path(explicit_path: Optional[str], start_dir: str | Path) -> Optional[Path]:
    if explicit_path:
        p = Path(explicit_path)
        return p if p.is_file() else None
    base = Path(start_dir)
    if base.is_file():
        base = base.parent
    # Walk up from start_dir looking for a known config filename.
    for directory in [base, *base.resolve().parents]:
        for name in DEFAULT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None
