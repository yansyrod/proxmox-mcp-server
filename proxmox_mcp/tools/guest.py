"""Guarded SSH operations for Proxmox guests.

These tools intentionally use SSH rather than trying to tunnel arbitrary shell
commands through the Proxmox API. They work for both VMs and LXC containers as
long as the guest is reachable over SSH.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

import asyncssh

from ..client import ProxmoxClient


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


GUEST_OPS_ENABLED = _env_bool("PROXMOX_GUEST_OPS_ENABLED", False)
ALLOW_PUBLIC_HOSTS = _env_bool("PROXMOX_GUEST_ALLOW_PUBLIC", False)
STRICT_HOST_KEY = _env_bool("PROXMOX_GUEST_STRICT_HOST_KEY", True)
DEFAULT_USER = os.getenv("PROXMOX_GUEST_SSH_USER", "root")
DEFAULT_PORT = int(os.getenv("PROXMOX_GUEST_SSH_PORT", "22"))
DEFAULT_TIMEOUT = int(os.getenv("PROXMOX_GUEST_SSH_TIMEOUT", "30"))
DEFAULT_KEY = os.getenv("PROXMOX_GUEST_SSH_KEY", "")
KNOWN_HOSTS = os.getenv("PROXMOX_GUEST_KNOWN_HOSTS", str(Path.home() / ".ssh" / "known_hosts"))
ALLOWLIST = {x.strip().lower() for x in os.getenv("PROXMOX_GUEST_HOST_ALLOWLIST", "").split(",") if x.strip()}
MAX_OUTPUT = int(os.getenv("PROXMOX_GUEST_MAX_OUTPUT", "65536"))

# Commands matching these patterns require explicit confirm=true. This is a guard,
# not a sandbox; administrators should still use a dedicated SSH key/account.
DESTRUCTIVE_PATTERNS = [
    re.compile(r"(^|\s)rm\s+(-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b", re.I),
    re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.I),
    re.compile(r"\b(?:fdisk|sfdisk|parted|wipefs)\b", re.I),
    re.compile(r"\bdd\s+.*\bof=/dev/", re.I),
    re.compile(r"\b(?:shutdown|poweroff|halt|reboot)\b", re.I),
    re.compile(r"\b(?:userdel|deluser)\b", re.I),
    re.compile(r"\b(?:iptables|nft)\s+-F\b", re.I),
]

STR = lambda desc: {"type": "string", "description": desc}  # noqa: E731
INT = lambda desc: {"type": "integer", "description": desc}  # noqa: E731
BOOL = lambda desc: {"type": "boolean", "description": desc}  # noqa: E731

COMMON = {
    "host": STR("Guest hostname or IP address"),
    "user": STR(f"SSH username (default: {DEFAULT_USER})"),
    "port": INT(f"SSH port (default: {DEFAULT_PORT})"),
    "identity_file": STR("SSH private key path on the MCP server (optional)"),
    "timeout": INT(f"Timeout in seconds (default: {DEFAULT_TIMEOUT})"),
}

TOOLS = [
    {
        "name": "guest_exec",
        "description": "Execute a command inside a VM or LXC guest over SSH. Destructive commands require confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON,
                "command": STR("Command to execute"),
                "confirm": BOOL("Explicit confirmation for destructive commands"),
                "dry_run": BOOL("Validate and return what would run without connecting"),
            },
            "required": ["host", "command"],
        },
    },
    {
        "name": "guest_read_file",
        "description": "Read a UTF-8 text file from a VM or LXC guest over SFTP.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON, "path": STR("Absolute path in the guest"), "max_bytes": INT("Maximum bytes to read")},
            "required": ["host", "path"],
        },
    },
    {
        "name": "guest_write_file",
        "description": "Write a UTF-8 text file to a VM or LXC guest over SFTP. Existing files require overwrite=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON,
                "path": STR("Absolute path in the guest"),
                "content": STR("UTF-8 text content"),
                "overwrite": BOOL("Allow replacing an existing file"),
                "create_parents": BOOL("Create missing parent directories"),
                "dry_run": BOOL("Validate without connecting or writing"),
            },
            "required": ["host", "path", "content"],
        },
    },
    {
        "name": "guest_list_dir",
        "description": "List a directory inside a VM or LXC guest over SFTP.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON, "path": STR("Absolute directory path")},
            "required": ["host", "path"],
        },
    },
]


def _require_enabled() -> None:
    if not GUEST_OPS_ENABLED:
        raise PermissionError(
            "Guest operations are disabled. Set PROXMOX_GUEST_OPS_ENABLED=true after configuring SSH credentials."
        )


def _validate_host(host: str) -> str:
    value = host.strip()
    if not value:
        raise ValueError("host is required")
    if ALLOWLIST and value.lower() not in ALLOWLIST:
        raise PermissionError(f"Host {value!r} is not in PROXMOX_GUEST_HOST_ALLOWLIST")
    if not ALLOW_PUBLIC_HOSTS:
        try:
            ip = ipaddress.ip_address(value)
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                raise PermissionError("Public guest IPs are blocked; set PROXMOX_GUEST_ALLOW_PUBLIC=true to allow them")
        except ValueError:
            # Hostnames cannot be classified without DNS resolution. When an allowlist
            # exists it already acts as the boundary; otherwise permit local hostnames.
            if "." in value and not value.endswith((".local", ".lan", ".home", ".internal")) and not ALLOWLIST:
                raise PermissionError(
                    "FQDNs are blocked by default. Add the host to PROXMOX_GUEST_HOST_ALLOWLIST or enable public hosts."
                )
    return value


def _validate_path(path: str) -> str:
    p = PurePosixPath(path)
    if not p.is_absolute():
        raise ValueError("Guest path must be absolute")
    if ".." in p.parts:
        raise ValueError("Guest path must not contain '..'")
    return str(p)


def _needs_confirmation(command: str) -> bool:
    return any(pattern.search(command) for pattern in DESTRUCTIVE_PATTERNS)


def _conn_args(args: dict[str, Any]) -> dict[str, Any]:
    key = args.get("identity_file") or DEFAULT_KEY
    connect: dict[str, Any] = {
        "host": _validate_host(str(args["host"])),
        "username": args.get("user") or DEFAULT_USER,
        "port": int(args.get("port") or DEFAULT_PORT),
        "connect_timeout": int(args.get("timeout") or DEFAULT_TIMEOUT),
        "known_hosts": KNOWN_HOSTS if STRICT_HOST_KEY else None,
    }
    if key:
        connect["client_keys"] = [key]
    return connect


def _trim(value: str) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OUTPUT:
        return value, False
    clipped = encoded[:MAX_OUTPUT].decode("utf-8", errors="replace")
    return clipped, True


async def _connect(args: dict[str, Any]) -> asyncssh.SSHClientConnection:
    return await asyncssh.connect(**_conn_args(args))


async def handle(name: str, args: dict[str, Any], client: ProxmoxClient) -> Any:  # noqa: ARG001
    _require_enabled()

    if name == "guest_exec":
        command = str(args.get("command", "")).strip()
        if not command:
            raise ValueError("command is required")
        destructive = _needs_confirmation(command)
        if destructive and not args.get("confirm", False):
            raise PermissionError("Command matched a destructive-operation guard. Re-run with confirm=true after review.")
        if args.get("dry_run", False):
            return {"dry_run": True, "host": _validate_host(str(args["host"])), "command": command, "requires_confirmation": destructive}
        async with await _connect(args) as conn:
            result = await conn.run(command, check=False, timeout=int(args.get("timeout") or DEFAULT_TIMEOUT))
        stdout, out_truncated = _trim(result.stdout or "")
        stderr, err_truncated = _trim(result.stderr or "")
        return {
            "exit_status": result.exit_status,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": out_truncated or err_truncated,
        }

    if name == "guest_read_file":
        path = _validate_path(str(args["path"]))
        limit = min(int(args.get("max_bytes") or MAX_OUTPUT), MAX_OUTPUT)
        async with await _connect(args) as conn:
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(path, "rb") as fh:
                    data = await fh.read(limit + 1)
        truncated = len(data) > limit
        return {"path": path, "content": data[:limit].decode("utf-8", errors="replace"), "truncated": truncated}

    if name == "guest_write_file":
        path = _validate_path(str(args["path"]))
        content = str(args.get("content", ""))
        if args.get("dry_run", False):
            return {"dry_run": True, "host": _validate_host(str(args["host"])), "path": path, "bytes": len(content.encode("utf-8"))}
        async with await _connect(args) as conn:
            async with conn.start_sftp_client() as sftp:
                parent = str(PurePosixPath(path).parent)
                if args.get("create_parents", False):
                    await sftp.makedirs(parent, exist_ok=True)
                exists = False
                try:
                    await sftp.stat(path)
                    exists = True
                except (FileNotFoundError, asyncssh.SFTPNoSuchFile):
                    pass
                if exists and not args.get("overwrite", False):
                    raise FileExistsError("Remote file already exists; set overwrite=true to replace it")
                async with sftp.open(path, "w") as fh:
                    await fh.write(content)
        return {"written": True, "path": path, "bytes": len(content.encode("utf-8"))}

    if name == "guest_list_dir":
        path = _validate_path(str(args["path"]))
        async with await _connect(args) as conn:
            async with conn.start_sftp_client() as sftp:
                entries = await sftp.listdir(path)
        return {"path": path, "entries": sorted(entries)}

    raise ValueError(f"Unknown guest tool: {name}")
