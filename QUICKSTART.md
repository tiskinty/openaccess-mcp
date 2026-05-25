# Quick Start

This quick start reflects the current behavior of the `0.0.1` repository.

## 1) Install

```bash
cd openaccess-mcp
pip install -e ".[dev]"
```

## 2) Inspect sample configuration

- Sample profiles: `examples/profiles/`
- Sample file-based secrets: `examples/secrets/`

List profiles with the CLI:

```bash
openaccess-mcp profiles --profiles ./examples/profiles
```

## 3) Start the CLI server process

```bash
openaccess-mcp start --profiles ./examples/profiles --secrets-dir ./examples/secrets
```

This initializes providers, secret store, and audit logging, then runs the MCP stdio server loop.

## 4) Call handlers directly from Python

```python
import asyncio
from pathlib import Path

from openaccess_mcp.server import OpenAccessMCPServer


async def quick_demo() -> None:
    server = OpenAccessMCPServer(
        profiles_dir=Path("./examples/profiles"),
        secrets_dir=Path("./examples/secrets"),
    )

    # SSH example
    ssh_result = await server.ssh_exec(
        profile_id="dev-test-01",
        command="pwd",
        caller="devuser",
    )
    print("ssh:", ssh_result)

    # SFTP example
    sftp_result = await server.sftp_transfer(
        profile_id="dev-test-01",
        direction="get",
        remote_path="/tmp/remote.txt",
        local_path="/tmp/local.txt",
        caller="devuser",
    )
    print("sftp:", sftp_result)

    await server.cleanup()


asyncio.run(quick_demo())
```

## 5) MCP endpoint setup and use (tools/list, tools/call)

Start the MCP stdio server:

```bash
openaccess-mcp start --profiles ./examples/profiles --secrets-dir ./examples/secrets
```

From an MCP client, call:

- `tools/list` to discover available tools
- `tools/call` with one of:
  - `ssh.exec`
  - `sftp.transfer`
  - `rsync.sync`
  - `tunnel.create`
  - `tunnel.close`
  - `vpn.wireguard.toggle`
  - `rdp.launch`

Example payload for `tools/call` (`ssh.exec`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ssh.exec",
    "arguments": {
      "profile_id": "dev-test-01",
      "command": "pwd",
      "caller": "devuser"
    }
  }
}
```

## 6) Audit tooling

Generate keys:

```bash
openaccess-audit generate-keys --output-dir ./keys
```

Inspect stats:

```bash
openaccess-audit stats ./audit/audit.log
```

Verify chain integrity:

```bash
openaccess-audit verify ./audit/audit.log
```

## 7) Validate your environment

```bash
make test
make lint
```

At rewrite time:

- `make test` passes.
- `make lint` reports existing issues in repository Python files.

## Current limitations

- The stdio MCP server is wired for tool registration/calls, but no separate HTTP API is implemented in this branch.
- Some deployment assets still assume commands/endpoints that do not exist in the current CLI implementation.
