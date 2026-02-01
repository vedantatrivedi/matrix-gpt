"""
Minimal stub for agents SDK function_tool decorator.
This allows tests to run without the full Anthropic Agents SDK.
"""
from typing import Callable, Any


def function_tool(func: Callable) -> Callable:
    """Stub decorator that just returns the function unchanged."""
    return func


class Agent:
    """Stub Agent class."""
    pass


class Runner:
    """Stub Runner class."""
    pass
