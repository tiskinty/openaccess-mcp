# OpenAccess MCP

OpenAccess MCP is a Python project for policy-checked remote-access operations (SSH, SFTP, rsync, tunnels, WireGuard toggles, and RDP broker helpers).

Current package version: `0.0.1` (alpha).

## Current state (important)

This repository currently provides two practical ways to use the project:

1. **As a Python library**, by creating `OpenAccessMCPServer` and calling its async handler methods (for example `ssh_exec`, `sftp_transfer`, `rsync_sync`, `tunnel_create`).
2. **As a CLI utility** for server bootstrap and audit tooling (`openaccess-mcp ...`, `openaccess-audit ...`).

### MCP integration status

The internal MCP server object is initialized, but `_register_tools()` is currently a no-op in `openaccess_mcp/server.py`. That means tool registration is not wired yet in this branch.

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

- `/tmp/workspace/tiskinty/openaccess-mcp/openaccess_mcp/server.py` – main orchestration class and async handlers
- `/tmp/workspace/tiskinty/openaccess-mcp/openaccess_mcp/providers/` – protocol providers
- `/tmp/workspace/tiskinty/openaccess-mcp/openaccess_mcp/policy/` – policy engine
- `/tmp/workspace/tiskinty/openaccess-mcp/openaccess_mcp/secrets/` – secret providers/store
- `/tmp/workspace/tiskinty/openaccess-mcp/openaccess_mcp/audit/` – audit logger and audit CLI
- `/tmp/workspace/tiskinty/openaccess-mcp/examples/` – sample profiles and sample file-based secrets

## Install

```bash
cd /tmp/workspace/tiskinty/openaccess-mcp
pip install -e ".[dev]"
```

## CLI usage

### Main CLI

```bash
openaccess-mcp --help
```

Commands currently available:

- `openaccess-mcp start`
- `openaccess-mcp profiles`
- `openaccess-mcp audit`
- `openaccess-mcp verify`
- `openaccess-mcp generate-keys`
- `openaccess-mcp version`

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

See `/tmp/workspace/tiskinty/openaccess-mcp/API.md` for handler signatures and response format.

## Development

```bash
make test
make lint
```

Note: at the time of this documentation rewrite, tests pass and lint has existing pre-existing violations.

## Related docs

- `/tmp/workspace/tiskinty/openaccess-mcp/QUICKSTART.md`
- `/tmp/workspace/tiskinty/openaccess-mcp/API.md`
- `/tmp/workspace/tiskinty/openaccess-mcp/DEPLOYMENT.md`
- `/tmp/workspace/tiskinty/openaccess-mcp/CONTRIBUTING.md`
