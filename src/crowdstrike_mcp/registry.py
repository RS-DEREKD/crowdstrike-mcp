"""
Module auto-discovery via pkgutil.

Scans the ``modules/`` package for classes that subclass ``BaseModule``
(excluding ``BaseModule`` itself). Each module is imported in a try/except
block so a single broken module doesn't prevent the server from starting.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import FalconClient
    from modules.base import BaseModule


def discover_module_classes() -> list[type[BaseModule]]:
    """Scan ``modules/`` and return all BaseModule subclasses.

    Returns:
        List of module classes (not instances), sorted by name.
    """
    import modules as _pkg
    from modules.base import BaseModule as _Base

    classes: list[type[_Base]] = []

    for finder, module_name, _is_pkg in pkgutil.iter_modules(_pkg.__path__):
        if module_name == "base":
            continue

        fqn = f"modules.{module_name}"
        try:
            mod = importlib.import_module(fqn)
        except Exception as exc:
            print(f"[registry] Failed to import {fqn}: {exc}", file=sys.stderr)
            continue

        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if isinstance(attr, type) and issubclass(attr, _Base) and attr is not _Base and attr_name.endswith("Module"):
                classes.append(attr)

    return sorted(classes, key=lambda c: c.__name__)


def get_available_modules(
    client: FalconClient,
    enabled: set[str] | None = None,
    allow_writes: bool = False,
) -> list[BaseModule]:
    """Discover, filter, and instantiate modules.

    Args:
        client: Shared FalconClient for credential access.
        enabled: Optional set of module names to load (e.g. ``{"ngsiem", "alerts"}``).
                 If ``None``, all discovered modules are loaded.
        allow_writes: Whether to enable write-tier tools on each module.
                      Defaults to ``False`` (read-only mode).

    Returns:
        List of instantiated module objects.
    """
    instances: list = []

    for cls in discover_module_classes():
        # Module name is the lowercase class name minus "Module" suffix
        mod_name = cls.__name__.replace("Module", "").lower()

        if enabled is not None and mod_name not in enabled:
            print(f"[registry] Skipping {cls.__name__} (not in enabled set)", file=sys.stderr)
            continue

        try:
            instance = cls(client)
            instance.allow_writes = allow_writes
            instances.append(instance)
            print(f"[registry] Loaded {cls.__name__}", file=sys.stderr)
        except Exception as exc:
            print(f"[registry] Failed to instantiate {cls.__name__}: {exc}", file=sys.stderr)

    return instances


def get_module_names() -> list[str]:
    """Return the names of all discoverable modules (without instantiating).

    Useful for ``--modules`` CLI help text.
    """
    return [cls.__name__.replace("Module", "").lower() for cls in discover_module_classes()]
