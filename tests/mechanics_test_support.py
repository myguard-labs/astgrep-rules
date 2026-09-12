"""Contracts for canonical plans and mechanical validation helpers."""

import contextlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

__all__ = [
    "CHANGED", "MECHANICS", "PLAN", "PROBE", "ROOT", "Path",
    "SimpleNamespace", "contextlib", "io", "json", "minimal_plan", "os",
    "patch", "stat", "subprocess", "sys", "tempfile", "time", "unittest",
    "yaml",
]

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLAN = load_tool("rule-plan")
MECHANICS = load_tool("rule-mechanics")
CHANGED = load_tool("test-changed")
PROBE = load_tool("rule-probe")


def minimal_plan(**updates):
    plan = {
        "version": 1,
        "id": "py-sample",
        "language": "python",
        "category": "security",
        "message": "sample message",
        "note": "sample note",
        "rule": {"pattern": "danger()"},
        "cases": {"invalid": ["danger()"], "valid": ["safe()"]},
    }
    plan.update(updates)
    return plan
