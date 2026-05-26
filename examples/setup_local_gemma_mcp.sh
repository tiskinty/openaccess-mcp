#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-8000}"
MCP_BASE_URL="http://${MCP_HOST}:${MCP_PORT}"
MCP_PROFILES_DIR="${MCP_PROFILES_DIR:-${ROOT_DIR}/examples/profiles}"
MCP_SECRETS_DIR="${MCP_SECRETS_DIR:-${ROOT_DIR}/examples/secrets}"
GEMMA_MODEL="${GEMMA_MODEL:-gemma2:2b}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
PID_FILE="${ROOT_DIR}/.gemma-mcp-server.pid"
LOG_DIR="${ROOT_DIR}/logs"
LOG_FILE="${LOG_DIR}/openaccess-mcp-serve.log"
RUN_MCP_BACKGROUND=0
INSTALL_STARTUP=0
STARTED_MCP=0

usage() {
  cat <<EOF
Usage: $0 [--background] [--install-startup]

Options:
  --background       Start OpenAccess MCP web API in the background when not running
  --install-startup  Install and enable a user-level systemd startup service (Linux)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --background)
      RUN_MCP_BACKGROUND=1
      ;;
    --install-startup)
      INSTALL_STARTUP=1
      RUN_MCP_BACKGROUND=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

start_mcp_background() {
  mkdir -p "${LOG_DIR}"
  openaccess-mcp serve \
    --host "${MCP_HOST}" \
    --port "${MCP_PORT}" \
    --profiles "${MCP_PROFILES_DIR}" \
    --secrets-dir "${MCP_SECRETS_DIR}" \
    >"${LOG_FILE}" 2>&1 &
  echo $! > "${PID_FILE}"
  STARTED_MCP=1
}

install_startup_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; skipping startup service installation."
    return
  fi

  local service_dir="${HOME}/.config/systemd/user"
  local service_file="${service_dir}/openaccess-mcp.service"
  local openaccess_mcp_bin
  openaccess_mcp_bin="$(command -v openaccess-mcp)"

  mkdir -p "${service_dir}"
  cat > "${service_file}" <<EOF
[Unit]
Description=OpenAccess MCP Web API
After=network-online.target

[Service]
Type=simple
ExecStart=${openaccess_mcp_bin} serve --host ${MCP_HOST} --port ${MCP_PORT} --profiles ${MCP_PROFILES_DIR} --secrets-dir ${MCP_SECRETS_DIR}
Restart=on-failure

[Install]
WantedBy=default.target
EOF

  if systemctl --user daemon-reload >/dev/null 2>&1 && systemctl --user enable --now openaccess-mcp.service >/dev/null 2>&1; then
    echo "Installed startup service: ${service_file}"
    echo "Manage it with: systemctl --user status openaccess-mcp.service"
  else
    echo "Unable to enable user startup service automatically."
    echo "Startup file written to: ${service_file}"
  fi
}

if ! command -v ollama >/dev/null 2>&1; then
  echo "ollama is required but not installed. Visit https://ollama.com for installation instructions."
  exit 1
fi

if ! command -v openaccess-mcp >/dev/null 2>&1; then
  echo "openaccess-mcp CLI is required. From the repository root, install with: pip install -e '.[dev]'"
  exit 1
fi

if [[ ! -d "${MCP_PROFILES_DIR}" ]]; then
  echo "profiles directory not found: ${MCP_PROFILES_DIR}"
  exit 1
fi

if [[ ! -d "${MCP_SECRETS_DIR}" ]]; then
  echo "secrets directory not found: ${MCP_SECRETS_DIR}"
  exit 1
fi

echo "Ensuring local Gemma model is available: ${GEMMA_MODEL}"
if ! ollama list | grep -Fq "${GEMMA_MODEL}"; then
  echo "Pulling ${GEMMA_MODEL} (this may take a while)..."
  ollama pull "${GEMMA_MODEL}"
fi

if ! curl -fsS "${MCP_BASE_URL}/health" >/dev/null 2>&1; then
  if [[ "${RUN_MCP_BACKGROUND}" -eq 1 ]]; then
    echo "Starting OpenAccess MCP web API on ${MCP_BASE_URL}"
    start_mcp_background
    sleep 2
  else
    echo "OpenAccess MCP web API is not running at ${MCP_BASE_URL}."
    echo "Start it first, or rerun this script with --background."
    exit 1
  fi
else
  echo "OpenAccess MCP web API is already running at ${MCP_BASE_URL}"
fi

if [[ "${INSTALL_STARTUP}" -eq 1 ]]; then
  install_startup_service
fi

mkdir -p "${ROOT_DIR}/examples/gemma"

export MCP_BASE_URL
export GEMMA_MODEL
export OLLAMA_BASE_URL
python - <<'PY'
import json
import os
import urllib.request
from pathlib import Path

mcp_base_url = os.environ["MCP_BASE_URL"]
gemma_model = os.environ["GEMMA_MODEL"]
ollama_base_url = os.environ["OLLAMA_BASE_URL"]

with urllib.request.urlopen(f"{mcp_base_url}/api/v1/tools") as response:
    tools_response = json.load(response)

tools = []
for tool in tools_response["tools"]:
    tools.append(
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["inputSchema"],
            },
        }
    )

output_dir = Path("examples/gemma")
output_dir.mkdir(parents=True, exist_ok=True)

request_payload = {
    "model": gemma_model,
    "stream": False,
    "messages": [
        {
            "role": "system",
            "content": (
                "You can use OpenAccess MCP tools. "
                "Pick an appropriate tool and return a tool call when needed."
            ),
        },
        {
            "role": "user",
            "content": "Run `uname -a` on profile dev-test-01 using the available tools.",
        },
    ],
    "tools": tools,
}

config_payload = {
    "mcpBaseUrl": mcp_base_url,
    "ollamaBaseUrl": ollama_base_url,
    "model": gemma_model,
    "toolCount": len(tools),
}

(output_dir / "gemma-mcp-config.json").write_text(json.dumps(config_payload, indent=2))
(output_dir / "ollama-tooling-request.json").write_text(json.dumps(request_payload, indent=2))
PY

echo
echo "Generated:"
echo "  examples/gemma/gemma-mcp-config.json"
echo "  examples/gemma/ollama-tooling-request.json"
echo
echo "Try a Gemma tool-selection request:"
echo "curl -sS ${OLLAMA_BASE_URL}/api/chat \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d @${ROOT_DIR}/examples/gemma/ollama-tooling-request.json"
echo
if [[ "${STARTED_MCP}" -eq 1 ]]; then
  echo "If this script started MCP web API, stop it with:"
  echo "  kill \$(cat ${PID_FILE}) && rm -f ${PID_FILE}"
fi
