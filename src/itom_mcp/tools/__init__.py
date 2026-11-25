"""ITOM tool modules. Each exposes register(mcp, ctx)."""

from itom_mcp.tools import cmdb, discovery, events, generic, services

MODULES = (cmdb, discovery, events, services, generic)
