# Deployment Notes (Current Repository State)

This file documents what is currently true in this repository, including known gaps.

## What works today

### Local Python execution

```bash
cd openaccess-mcp
pip install -e ".[dev]"
openaccess-mcp serve --host 0.0.0.0 --port 8000 --profiles ./examples/profiles --secrets-dir ./examples/secrets
```

### Programmatic usage

Use `OpenAccessMCPServer` directly from Python and call async handlers (`ssh_exec`, `sftp_transfer`, `rsync_sync`, etc.).

### Web API endpoints

- `GET /health`
- `GET /api/v1/tools`
- `POST /api/v1/tools/call`
- `POST /api/v1/mcp`

## Container and orchestration assets

The repository includes:

- `Dockerfile`
- `docker-compose.yml`
- `k8s/deployment.yaml`

These files are currently **not aligned** with the implemented CLI/server behavior.

### Known mismatches

- `docker-compose.yml` and `k8s/deployment.yaml` still assume additional environment-driven wiring (for example secrets/audit paths and full health/metrics strategy) that is not fully represented in current runtime options.
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
