"""Safety policy for infrastructure-changing MCP tools."""

from __future__ import annotations

import os
from typing import Any


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


ALLOW_DESTRUCTIVE = _env_bool("PROXMOX_ALLOW_DESTRUCTIVE", False)

# Tool names which can irreversibly remove data/resources or materially alter
# security/networking. They stay visible, but calls are blocked unless the
# server owner explicitly enables destructive operations and the caller confirms.
DESTRUCTIVE_TOOLS = {
    "delete_vm",
    "delete_container",
    "delete_vm_snapshot",
    "delete_container_snapshot",
    "rollback_vm_snapshot",
    "rollback_container_snapshot",
    "delete_container_firewall_rule",
    "delete_vm_firewall_rule",
    "delete_firewall_rule",
    "delete_storage",
    "delete_pool",
    "delete_user",
    "delete_group",
    "delete_role",
    "delete_api_token",
    "delete_acme_account",
    "delete_acme_plugin",
    "delete_notification_endpoint",
    "delete_notification_matcher",
    "delete_sdn_zone",
    "delete_sdn_vnet",
    "delete_sdn_subnet",
}


def augment_schema(name: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Expose an explicit confirmation input on known destructive tools."""
    if name not in DESTRUCTIVE_TOOLS:
        return schema
    copied = dict(schema)
    props = dict(copied.get("properties", {}))
    props["confirm"] = {
        "type": "boolean",
        "description": "Required explicit confirmation for this destructive operation.",
    }
    copied["properties"] = props
    return copied


def enforce(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Block dangerous operations unless both owner policy and caller consent exist.

    The synthetic ``confirm`` field is removed before dispatch so it is never
    accidentally forwarded to the Proxmox API by a tool handler.
    """
    args = dict(arguments)
    if name not in DESTRUCTIVE_TOOLS:
        return args
    if not ALLOW_DESTRUCTIVE:
        raise PermissionError(
            f"{name} is disabled by server policy. Set PROXMOX_ALLOW_DESTRUCTIVE=true to enable destructive tools."
        )
    if args.pop("confirm", False) is not True:
        raise PermissionError(f"{name} requires confirm=true after reviewing the target and impact.")
    return args
