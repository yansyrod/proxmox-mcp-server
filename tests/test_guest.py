from __future__ import annotations

import pytest

import proxmox_mcp.tools.guest as guest


def test_absolute_guest_path_required() -> None:
    with pytest.raises(ValueError):
        guest._validate_path("etc/hosts")


def test_parent_traversal_rejected() -> None:
    with pytest.raises(ValueError):
        guest._validate_path("/etc/../root/secret")


def test_private_ip_allowed_without_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guest, "ALLOWLIST", set())
    monkeypatch.setattr(guest, "ALLOW_PUBLIC_HOSTS", False)
    assert guest._validate_host("192.168.1.20") == "192.168.1.20"


def test_public_ip_blocked_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guest, "ALLOWLIST", set())
    monkeypatch.setattr(guest, "ALLOW_PUBLIC_HOSTS", False)
    with pytest.raises(PermissionError):
        guest._validate_host("8.8.8.8")


def test_allowlist_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guest, "ALLOWLIST", {"192.168.1.20"})
    assert guest._validate_host("192.168.1.20") == "192.168.1.20"
    with pytest.raises(PermissionError):
        guest._validate_host("192.168.1.21")


def test_destructive_command_detected() -> None:
    assert guest._needs_confirmation("rm -rf /tmp/test") is True
    assert guest._needs_confirmation("apt update") is False
