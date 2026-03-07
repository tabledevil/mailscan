"""MATT configuration system.

Provides a typed, validated configuration singleton via the ``flags`` object.
All settings have sensible defaults and can be overridden programmatically or
from a dict (e.g. parsed from a config file).
"""

from __future__ import annotations

__all__ = ["Flags", "flags"]

from dataclasses import dataclass, fields, asdict
from typing import Optional, List


@dataclass
class Flags:
    """Global configuration flags for MATT."""

    # --- General ---
    debug: bool = False

    # --- Analysis limits ---
    max_analysis_depth: int = 10
    max_file_size: int = 1024 * 1024 * 1024  # 1 GB
    max_compression_ratio: int = 100

    # --- MIME detection ---
    mime_provider_order: Optional[List[str]] = None
    mime_file_command_timeout: float = 2.0

    # --- Network policy: offline | passive | online ---
    network_policy: str = "passive"

    # --- Persistence ---
    cache_path: Optional[str] = None

    # --- YARA ---
    yara_rules_dir: Optional[str] = None

    # --- Output ---
    default_verbosity: int = 0
    default_format: str = "rich"

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Flags":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid})

    def update(self, data: dict) -> None:
        """Update flags from a dict, ignoring unknown keys."""
        valid = {f.name for f in fields(self)}
        for k, v in data.items():
            if k in valid:
                setattr(self, k, v)

    def __repr__(self) -> str:
        parts = ", ".join(f"{f.name}={getattr(self, f.name)!r}" for f in fields(self))
        return f"Flags({parts})"


flags = Flags()
