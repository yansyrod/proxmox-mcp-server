from __future__ import annotations

import pytest

import proxmox_mcp.safety as safety


def test_non_destructive_passthrough() -> None:
    args = {"node": "pve", "vmid": 100}
    assert safety.enforce("get_vm_status", args) == args


def test_destructive_blocked_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "ALLOW_DESTRUCTIVE", False)
    with pytest.raises(PermissionError):
        safety.enforce("delete_vm", {"node": "pve", "vmid": 100, "confirm": True})


def test_destructive_requires_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "ALLOW_DESTRUCTIVE", True)
    with pytest.raises(PermissionError):
        safety.enforce("delete_vm", {"node": "pve", "vmid": 100})


def test_confirmation_removed_before_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "ALLOW_DESTRUCTIVE", True)
    result = safety.enforce("delete_vm", {"node": "pve", "vmid": 100, "confirm": True})
    assert result == {"node": "pve", "vmid": 100}


def test_schema_gets_confirm_field() -> None:
    schema = {"type": "object", "properties": {"vmid": {"type": "integer"}}}
    result = safety.augment_schema("delete_vm", schema)
    assert "confirm" in result["properties"]
