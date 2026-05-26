"""CLI for OpenAccess MCP."""

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .server import OpenAccessMCPServer
from .audit import get_audit_logger, create_audit_signer
from .secrets import initialize_secret_store

app = typer.Typer(help="OpenAccess MCP - Secure remote access server")
console = Console()
MAX_HTTP_BODY_BYTES = 1024 * 1024
LOOP_THREAD_JOIN_TIMEOUT_SECONDS = 2


@app.command()
def start(
    profiles: Path = typer.Option(
        "./profiles",
        "--profiles",
        "-p",
        help="Directory containing profile JSON files"
    ),
    vault_addr: Optional[str] = typer.Option(
        None,
        "--vault-addr",
        help="HashiCorp Vault address"
    ),
    vault_token: Optional[str] = typer.Option(
        None,
        "--vault-token",
        help="HashiCorp Vault token"
    ),
    secrets_dir: Optional[Path] = typer.Option(
        None,
        "--secrets-dir",
        help="Directory for file-based secrets"
    ),
    audit_log: Optional[Path] = typer.Option(
        None,
        "--audit-log",
        help="Audit log file path"
    ),
    audit_key: Optional[Path] = typer.Option(
        None,
        "--audit-key",
        help="Audit signing key path"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
    )
):
    """Start the OpenAccess MCP server."""
    try:
        # Validate profiles directory
        if not profiles.exists():
            console.print(f"[red]Error: Profiles directory not found: {profiles}[/red]")
            sys.exit(1)
        
        # Initialize secret store
        if vault_addr and vault_token:
            initialize_secret_store(
                vault_addr=vault_addr,
                vault_token=vault_token,
                secrets_dir=secrets_dir
            )
            console.print(f"[green]✓[/green] Vault integration enabled")
        elif secrets_dir:
            initialize_secret_store(secrets_dir=secrets_dir)
            console.print(f"[green]✓[/green] File-based secrets enabled")
        else:
            console.print("[yellow]⚠[/yellow] No secret store configured, using defaults")
        
        # Initialize audit system
        if audit_key:
            signer = create_audit_signer(audit_key)
            console.print(f"[green]✓[/green] Audit signing enabled with key: {audit_key}")
        else:
            signer = create_audit_signer()
            console.print(f"[green]✓[/green] Audit signing enabled with generated key")
        
        if audit_log:
            audit_logger = get_audit_logger(audit_log)
            console.print(f"[green]✓[/green] Audit logging enabled: {audit_log}")
        
        # Display startup information
        console.print(Panel.fit(
            "[bold blue]OpenAccess MCP Server[/bold blue]\n"
            f"Profiles: {profiles.absolute()}\n"
            f"Audit: {'enabled' if audit_log else 'default'}\n"
            f"Secrets: {'vault' if vault_addr else 'file' if secrets_dir else 'default'}",
            title="Server Configuration"
        ))
        
        # Create and run server
        server = OpenAccessMCPServer(profiles)
        
        if verbose:
            console.print("[dim]Starting server in verbose mode...[/dim]")
        
        asyncio.run(server.run())
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@app.command()
def profiles(
    profiles_dir: Path = typer.Option(
        "./profiles",
        "--profiles",
        "-p",
        help="Directory containing profile JSON files"
    )
):
    """List available profiles."""
    try:
        if not profiles_dir.exists():
            console.print(f"[red]Error: Profiles directory not found: {profiles_dir}[/red]")
            sys.exit(1)
        
        profile_files = list(profiles_dir.glob("*.json"))
        
        if not profile_files:
            console.print(f"[yellow]No profile files found in {profiles_dir}[/yellow]")
            return
        
        table = Table(title=f"Profiles in {profiles_dir}")
        table.add_column("ID", style="cyan")
        table.add_column("Host", style="green")
        table.add_column("Port", style="blue")
        table.add_column("Protocols", style="yellow")
        table.add_column("Description", style="white")
        
        for profile_file in profile_files:
            try:
                import json
                with open(profile_file, "r") as f:
                    profile_data = json.load(f)
                
                table.add_row(
                    profile_data.get("id", "unknown"),
                    profile_data.get("host", "unknown"),
                    str(profile_data.get("port", 22)),
                    ", ".join(profile_data.get("protocols", [])),
                    profile_data.get("description", "")
                )
            except Exception as e:
                table.add_row(
                    profile_file.stem,
                    "[red]Error[/red]",
                    "",
                    "",
                    str(e)
                )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def audit(
    log_file: Path = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Audit log file path"
    )
):
    """Show audit log statistics."""
    try:
        audit_logger = get_audit_logger(log_file)
        stats = audit_logger.get_log_stats()
        
        if "error" in stats:
            console.print(f"[red]Error reading audit log: {stats['error']}[/red]")
            return
        
        table = Table(title="Audit Log Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Lines", str(stats["total_lines"]))
        table.add_row("File Size", f"{stats['file_size_bytes']} bytes")
        table.add_row("Last Modified", stats["last_modified"])
        
        console.print(table)
        
        # Show record counts by tool
        if stats["record_counts"]:
            tool_table = Table(title="Records by Tool")
            tool_table.add_column("Tool", style="cyan")
            tool_table.add_column("Result", style="yellow")
            tool_table.add_column("Count", style="green")
            
            for tool, results in stats["record_counts"].items():
                for result, count in results.items():
                    tool_table.add_row(tool, result, str(count))
            
            console.print(tool_table)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def verify(
    log_file: Path = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Audit log file path"
    )
):
    """Verify audit log integrity."""
    try:
        audit_logger = get_audit_logger(log_file)
        verification = audit_logger.verify_log_integrity()
        
        if "error" in verification:
            console.print(f"[red]Verification failed: {verification['error']}[/red]")
            return
        
        table = Table(title="Audit Log Verification")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Records", str(verification["total_records"]))
        table.add_row("Chain Valid", "✓" if verification["chain_valid"] else "✗")
        table.add_row("First Record", verification["first_record"] or "N/A")
        table.add_row("Last Record", verification["last_record"] or "N/A")
        
        console.print(table)
        
        if verification["chain_valid"]:
            console.print("[green]✓ Audit log integrity verified[/green]")
        else:
            console.print("[red]✗ Audit log integrity check failed[/red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def generate_keys(
    output_dir: Path = typer.Option(
        "./keys",
        "--output-dir",
        "-o",
        help="Output directory for generated keys"
    )
):
    """Generate new audit signing keys."""
    try:
        signer = create_audit_signer()
        private_key, public_key = signer.generate_keypair(output_dir)
        
        console.print(f"[green]✓[/green] Generated new audit keypair:")
        console.print(f"  Private key: {private_key}")
        console.print(f"  Public key: {public_key}")
        console.print(f"\n[yellow]Warning: Keep the private key secure![/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"[bold blue]OpenAccess MCP[/bold blue] version {__version__}")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host interface for the web API server"
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port for the web API server"
    ),
    profiles: Path = typer.Option(
        "./profiles",
        "--profiles",
        "-p",
        help="Directory containing profile JSON files"
    ),
    secrets_dir: Optional[Path] = typer.Option(
        None,
        "--secrets-dir",
        help="Directory for file-based secrets"
    ),
):
    """Serve MCP tools over HTTP endpoints."""
    if not profiles.exists():
        console.print(f"[red]Error: Profiles directory not found: {profiles}[/red]")
        raise typer.Exit(code=1)

    server = OpenAccessMCPServer(
        profiles_dir=profiles,
        secrets_dir=secrets_dir,
    )
    event_loop = asyncio.new_event_loop()
    loop_ready = threading.Event()

    def run_event_loop():
        asyncio.set_event_loop(event_loop)
        loop_ready.set()
        event_loop.run_forever()

    loop_thread = threading.Thread(target=run_event_loop, name="openaccess-mcp-event-loop", daemon=False)
    loop_thread.start()
    loop_ready.wait()

    def run_async(coro):
        future = asyncio.run_coroutine_threadsafe(coro, event_loop)
        return future.result()

    class OpenAccessHTTPRequestHandler(BaseHTTPRequestHandler):
        max_body_bytes = MAX_HTTP_BODY_BYTES

        def _write_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                return {}
            if content_length > self.max_body_bytes:
                raise ValueError(
                    f"Request body too large: {content_length} bytes exceeds limit "
                    f"of {self.max_body_bytes} bytes"
                )
            raw = self.rfile.read(content_length)
            return json.loads(raw.decode("utf-8"))

        def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
            if self.path == "/health":
                self._write_json(200, {"status": "ok"})
                return

            if self.path == "/api/v1/tools":
                try:
                    self._write_json(200, run_async(server.web_list_tools()))
                except Exception as error:
                    self._write_json(500, {"error": str(error)})
                return

            self._write_json(404, {"error": "Not found"})

        def do_POST(self):  # noqa: N802 - required by BaseHTTPRequestHandler
            try:
                payload = self._read_json()
            except (json.JSONDecodeError, ValueError) as error:
                self._write_json(400, {"error": str(error)})
                return

            if self.path == "/api/v1/tools/call":
                try:
                    response = run_async(
                        server.web_call_tool(
                            name=payload.get("name"),
                            arguments=payload.get("arguments"),
                        )
                    )
                except Exception as error:
                    self._write_json(500, {"error": str(error)})
                    return
                self._write_json(200, response)
                return

            if self.path == "/api/v1/mcp":
                try:
                    response = run_async(server.web_jsonrpc(payload))
                except Exception as error:
                    self._write_json(500, {"error": str(error)})
                    return
                if response is None:
                    self.send_response(204)
                    self.end_headers()
                    return
                self._write_json(200, response)
                return

            self._write_json(404, {"error": "Not found"})

        def log_message(self, message_format, *args):
            """Disable default HTTP request logging for cleaner CLI output."""
            pass

    httpd = ThreadingHTTPServer((host, port), OpenAccessHTTPRequestHandler)

    console.print(
        f"[green]✓[/green] Web API server listening on http://{host}:{port}\n"
        f"[dim]GET /health, GET /api/v1/tools, POST /api/v1/tools/call, POST /api/v1/mcp[/dim]"
    )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        try:
            run_async(server.cleanup())
        finally:
            event_loop.call_soon_threadsafe(event_loop.stop)
            loop_thread.join(timeout=LOOP_THREAD_JOIN_TIMEOUT_SECONDS)
            event_loop.close()


if __name__ == "__main__":
    app()
