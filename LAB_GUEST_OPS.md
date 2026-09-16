# Proxmox MCP — Lab Guest Operations

This fork already exposes broad Proxmox VE API coverage, including VM/LXC create, clone, delete, snapshots, migration, storage, backup/restore and QEMU guest-agent operations. This extension adds guarded SSH access so an MCP client can also configure Linux guests after they are created.

## Added tools

- `guest_exec` — execute a command in a reachable VM or LXC over SSH.
- `guest_read_file` — read a UTF-8 text file over SFTP.
- `guest_write_file` — create or replace a UTF-8 text file over SFTP.
- `guest_list_dir` — list a guest directory over SFTP.

These tools are **disabled by default**.

## Safety model

There are two independent permission layers:

1. **Proxmox API token** controls what the server can do to Proxmox itself.
2. **Guest SSH key/account** controls what the server can do inside a guest.

Do not reuse your personal/root SSH key. Create a dedicated key for this MCP. For a lab, root SSH can be convenient, but a dedicated sudo-enabled account with restricted access is safer.

Destructive Proxmox MCP tools are blocked unless:

```env
PROXMOX_ALLOW_DESTRUCTIVE=true
```

and each destructive call explicitly supplies `confirm=true`.

Guest commands matching destructive patterns (for example `rm -rf`, disk formatting or reboot commands) also require `confirm=true`.

## Recommended Proxmox identity

Create a dedicated Proxmox account and API token, for example:

```text
mcp@pve
mcp@pve!chatgpt
```

Grant only the privileges needed for your lab scope. Avoid using `root@pam` as the normal MCP credential.

## Guest SSH setup

Create a local directory beside `docker-compose.yaml`:

```bash
mkdir -p ssh
ssh-keygen -t ed25519 -f ssh/id_ed25519 -C proxmox-mcp
chmod 600 ssh/id_ed25519
```

Install `ssh/id_ed25519.pub` in the guests which the MCP may manage. Populate `known_hosts` before enabling strict host verification:

```bash
ssh-keyscan -H 192.168.1.50 >> ssh/known_hosts
```

Then uncomment this mount in `docker-compose.yaml`:

```yaml
volumes:
  - ./ssh:/run/proxmox-mcp-ssh:ro
```

Configure `.env`:

```env
PROXMOX_GUEST_OPS_ENABLED=true
PROXMOX_GUEST_SSH_USER=root
PROXMOX_GUEST_SSH_KEY=/run/proxmox-mcp-ssh/id_ed25519
PROXMOX_GUEST_KNOWN_HOSTS=/run/proxmox-mcp-ssh/known_hosts
PROXMOX_GUEST_STRICT_HOST_KEY=true
PROXMOX_GUEST_HOST_ALLOWLIST=192.168.1.50,192.168.1.51
PROXMOX_GUEST_ALLOW_PUBLIC=false
```

An allowlist is strongly recommended. Public IP destinations are denied by default.

## Typical AI lab workflow

A client can now perform a workflow such as:

1. inspect node/storage resources;
2. create or clone an LXC/VM with the existing Proxmox tools;
3. start it and determine its IP;
4. use `guest_exec` to update packages and install Docker/services;
5. use `guest_write_file` for configuration files;
6. use `guest_exec` to start the application and inspect logs;
7. create a Proxmox snapshot before risky changes;
8. roll back or delete only after explicit destructive confirmation.

## Dry-run

`guest_exec` and `guest_write_file` support `dry_run=true` so an MCP client can validate the target and intended action without opening an SSH connection or modifying the guest.

## Important limitations

- SSH guest operations require network reachability from the MCP server/container to the guest.
- SFTP tools are intended for text/configuration files, not large binary transfers.
- The command guard is a safety aid, not a complete shell sandbox.
- Do not expose this MCP server directly to the public internet.
- Keep Proxmox API tokens and SSH private keys out of Git.
