from __future__ import annotations

from .malware import MalwareModule
from .sentinels import SentinelsModule
from .siem import SiemModule

MODULE_CLASSES = (SentinelsModule, MalwareModule, SiemModule)
MODULE_MAP = {cls.id: cls for cls in MODULE_CLASSES}

__all__ = ["MODULE_CLASSES", "MODULE_MAP", "MalwareModule",
           "SentinelsModule", "SiemModule"]
