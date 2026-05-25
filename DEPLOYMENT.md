# Deployment Notes (Current Repository State)

This file documents what is currently true in this repository, including known gaps.

## What works today

### Local Python execution

```bash
cd openaccess-mcp
pip install -e ".[dev]"
openaccess-mcp start --profiles ./examples/profiles --secrets-dir ./examples/secrets
```

### Programmatic usage

Use `OpenAccessMCPServer` directly from Python and call async handlers (`ssh_exec`, `sftp_transfer`, `rsync_sync`, etc.).

## Container and orchestration assets

The repository includes:

- `Dockerfile`
- `docker-compose.yml`
- `k8s/deployment.yaml`

These files are currently **not aligned** with the implemented CLI/server behavior.

### Known mismatches

- Docker `CMD` uses `openaccess-mcp serve --host --port`, but the CLI command currently implemented is `openaccess-mcp start` with different options.
- Compose/Kubernetes configs assume host/port/env-driven runtime and HTTP-style health semantics that are not represented by the current Typer CLI entrypoints.
- Deployment manifests should be treated as draft scaffolding until runtime interface alignment is completed.

## Recommendation for current users

- Use local Python installation for active development and testing.
- Treat Docker/Compose/Kubernetes artifacts as templates requiring updates before production use.
- Validate behavior with:

```bash
make test
make lint
```

## What needs to happen before production deployment

1. Align CLI/runtime contract used by Docker and Kubernetes with implemented commands.
2. Confirm intended transport/health model for the MCP server process.
3. Re-test and update manifests after runtime alignment.
