# OpenAccess MCP

OpenAccess MCP is a Python project for policy-checked remote-access operations (SSH, SFTP, rsync, tunnels, WireGuard toggles, and RDP broker helpers).

Current package version: `0.0.1` (alpha).

## Current state (important)

This repository currently provides three practical ways to use the project:

1. **As a Python library**, by creating `OpenAccessMCPServer` and calling its async handler methods (for example `ssh_exec`, `sftp_transfer`, `rsync_sync`, `tunnel_create`).
2. **As a CLI utility** for server bootstrap and audit tooling (`openaccess-mcp ...`, `openaccess-audit ...`).
3. **As an HTTP web API server** for MCP-compatible tool discovery/calls (`openaccess-mcp serve`).

### MCP integration status

The internal MCP server now registers MCP tools via `tools/list` and `tools/call` for:

- `ssh.exec`
- `sftp.transfer`
- `rsync.sync`
- `tunnel.create`
- `tunnel.close`
- `vpn.wireguard.toggle`
- `rdp.launch`

Other protocol handlers remain available through the Python API (`OpenAccessMCPServer` async methods).

## What is implemented

- Profile loading and validation from JSON files
- Secret resolution through the configured secret store
- Policy enforcement before remote operations
- Audit logging for tool calls
- Provider layers for:
  - SSH command execution
  - SFTP file transfer
  - rsync synchronization
  - SSH tunnel create/close
  - WireGuard toggle helpers
  - RDP connection brokering helpers

## Repository layout

- `openaccess_mcp/server.py` – main orchestration class and async handlers
- `openaccess_mcp/providers/` – protocol providers
- `openaccess_mcp/policy/` – policy engine
- `openaccess_mcp/secrets/` – secret providers/store
- `openaccess_mcp/audit/` – audit logger and audit CLI
- `examples/` – sample profiles and sample file-based secrets

## Install

```bash
cd openaccess-mcp
pip install -e ".[dev]"
```

## CLI usage

### Main CLI

```bash
openaccess-mcp --help
```

Commands currently available:

- `openaccess-mcp start`
- `openaccess-mcp serve`
- `openaccess-mcp profiles`
- `openaccess-mcp audit`
- `openaccess-mcp verify`
- `openaccess-mcp generate-keys`
- `openaccess-mcp version`

Web API endpoints provided by `openaccess-mcp serve`:

- `GET /health`
- `GET /api/v1/tools`
- `POST /api/v1/tools/call`
- `POST /api/v1/mcp`

### Audit CLI

```bash
openaccess-audit --help
```

Commands currently available:

- `openaccess-audit verify`
- `openaccess-audit stats`
- `openaccess-audit generate-keys`
- `openaccess-audit extract-records`

## Python usage (current practical interface)

```python
import asyncio
from pathlib import Path

from openaccess_mcp.server import OpenAccessMCPServer


async def main() -> None:
    server = OpenAccessMCPServer(
        profiles_dir=Path("./examples/profiles"),
        secrets_dir=Path("./examples/secrets"),
    )

    result = await server.ssh_exec(
        profile_id="dev-test-01",
        command="ls -la",
        caller="developer",
    )

    print(result)
    await server.cleanup()


asyncio.run(main())
```

See [API.md](API.md) for handler signatures and response format.
See [examples/setup_local_gemma_mcp.sh](examples/setup_local_gemma_mcp.sh) for a local Gemma setup example.

## Development

```bash
make test
make lint
```

Note: at the time of this documentation rewrite, tests pass and lint has existing pre-existing violations.

## Related docs

- [QUICKSTART.md](QUICKSTART.md)
- [API.md](API.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
