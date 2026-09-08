"""Shared pytest configuration for the offline suite."""

import warnings

# Escalate FastMCP deprecations to test failures, but only where the warning
# class exists: the dependency floor (fastmcp 2.14.6) predates it, and a
# filterwarnings entry naming a missing class would crash pytest at startup.
_fastmcp_exceptions = __import__("fastmcp.exceptions", fromlist=[""])
_fastmcp_deprecation = getattr(_fastmcp_exceptions, "FastMCPDeprecationWarning", None)
if _fastmcp_deprecation is not None:
    warnings.filterwarnings("error", category=_fastmcp_deprecation)
