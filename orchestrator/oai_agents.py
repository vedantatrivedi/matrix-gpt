import importlib
import os
import sys
from typing import Any


def _import_sdk() -> Any:
    local_pkg = sys.modules.get("agents")
    local_path = os.path.join(os.path.dirname(__file__), "agents")
    if local_pkg and getattr(local_pkg, "__file__", "").startswith(local_path):
        del sys.modules["agents"]

    cwd = os.path.abspath(os.getcwd())
    local_paths = {cwd, os.path.dirname(__file__), ""}
    original = list(sys.path)
    try:
        sys.path = [p for p in sys.path if p not in local_paths]
        return importlib.import_module("agents")
    finally:
        sys.path = original


_sdk = _import_sdk()

Agent = _sdk.Agent
Runner = _sdk.Runner

# Wrap function_tool to disable strict schemas (workaround for Dict[str, Any] issues)
def function_tool(func=None, **kwargs):
    """Wrapper for function_tool that disables strict schemas by default"""
    # Set strict_mode=False by default unless explicitly provided
    if 'strict_mode' not in kwargs:
        kwargs['strict_mode'] = False

    if func is None:
        # Called with arguments: @function_tool(...)
        def decorator(f):
            return _sdk.function_tool(f, **kwargs)
        return decorator
    else:
        # Called without arguments: @function_tool
        return _sdk.function_tool(func, **kwargs)
