"""Integration tests for OpenAccess MCP."""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, Mock
import json

from mcp import types as mcp_types
from openaccess_mcp.server import OpenAccessMCPServer
from openaccess_mcp.types import Profile, AuthRef, Policy
from openaccess_mcp.secrets.store import SecretStore
from openaccess_mcp.policy.engine import PolicyEngine
from unittest.mock import AsyncMock


class TestOpenAccessMCPServer:
    """Integration tests for the OpenAccess MCP server."""
    
    @pytest.fixture
    async def server(self):
        """Create a test server instance."""
        # Create temporary directories
        with tempfile.TemporaryDirectory() as temp_dir:
            profiles_dir = Path(temp_dir) / "profiles"
            secrets_dir = Path(temp_dir) / "secrets"
            audit_dir = Path(temp_dir) / "audit"
            
            profiles_dir.mkdir()
            secrets_dir.mkdir()
            audit_dir.mkdir()
            
            # Create test profile
            profile = Profile(
                id="test-server",
                host="127.0.0.1",
                port=22,
                protocols=["ssh", "sftp", "rsync", "tunnel", "vpn", "rdp"],
                auth=AuthRef(type="file_ref", ref="test-server"),
                policy=Policy(
                    roles=["admin"],
                    command_allowlist=["^echo\\b", "^ls\\b", "^cat\\b"],
                    deny_sudo=False,
                    max_session_seconds=900
                )
            )
            
            profile_file = profiles_dir / "test-server.json"
            profile_file.write_text(profile.model_dump_json())
            
            # Create test secret
            secret_data = {
                "username": "testuser",
                "password": "testpass"
            }
            
            secret_file = secrets_dir / "test-server.json"
            secret_file.write_text(json.dumps(secret_data))
            
            # Create server instance
            server = OpenAccessMCPServer(
                profiles_dir=profiles_dir,
                secrets_dir=secrets_dir,
                audit_log_path=audit_dir / "audit.log",
                audit_key_path=audit_dir / "audit.key"
            )
            
            # Create a mock audit logger to avoid signing key issues
            mock_audit_logger = Mock()
            mock_audit_logger.log_tool_call = AsyncMock(return_value=None)
            mock_audit_logger.log_record = AsyncMock(return_value=None)
            
            # Replace the audit logger with our mock
            server.audit_logger = mock_audit_logger
            
            yield server
            
            # Cleanup
            await server.cleanup()
    
    @pytest.mark.asyncio
    async def test_server_initialization(self, server):
        """Test server initialization."""
        assert server.profiles_dir is not None
        assert server.secret_store is not None
        assert server.audit_logger is not None
        assert server.ssh_provider is not None
        assert server.sftp_provider is not None
        assert server.rsync_provider is not None
        assert server.tunnel_provider is not None
        assert server.vpn_provider is not None
        assert server.rdp_provider is not None

    @pytest.mark.asyncio
    async def test_mcp_list_tools_registers_supported_tools(self, server):
        """Test MCP tool registration for all currently wired tools."""
        list_tools_handler = server.server.request_handlers[mcp_types.ListToolsRequest]

        result = await list_tools_handler(mcp_types.ListToolsRequest())

        assert isinstance(result.root, mcp_types.ListToolsResult)
        tool_names = {tool.name for tool in result.root.tools}
        assert "ssh.exec" in tool_names
        assert "sftp.transfer" in tool_names
        assert "rsync.sync" in tool_names
        assert "tunnel.create" in tool_names
        assert "tunnel.close" in tool_names
        assert "vpn.wireguard.toggle" in tool_names
        assert "rdp.launch" in tool_names

    @pytest.mark.asyncio
    async def test_mcp_call_tool_routes_to_supported_handlers(self, server):
        """Test MCP call routing for all currently wired tools."""
        call_tool_handler = server.server.request_handlers[mcp_types.CallToolRequest]

        with patch.object(server, "handle_ssh_exec", new=AsyncMock(return_value={"success": True, "data": {"stdout": "ok"}})) as mock_ssh:
            ssh_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="ssh.exec",
                        arguments={"profile_id": "test-server", "command": "echo ok"}
                    )
                )
            )

            assert isinstance(ssh_result.root, mcp_types.CallToolResult)
            assert ssh_result.root.isError is False
            assert ssh_result.root.structuredContent["success"] is True
            mock_ssh.assert_awaited_once_with(
                profile_id="test-server",
                command="echo ok",
                pty=False,
                sudo=False,
                timeout_seconds=60,
                dry_run=False,
                change_ticket=None,
                caller=None,
                token=None
            )

        with patch.object(server, "handle_sftp_transfer", new=AsyncMock(return_value={"success": True, "data": {"status": "completed"}})) as mock_sftp:
            sftp_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="sftp.transfer",
                        arguments={
                            "profile_id": "test-server",
                            "direction": "get",
                            "remote_path": "/remote/file.txt",
                            "local_path": "/tmp/file.txt"
                        }
                    )
                )
            )

            assert isinstance(sftp_result.root, mcp_types.CallToolResult)
            assert sftp_result.root.isError is False
            assert sftp_result.root.structuredContent["success"] is True
            mock_sftp.assert_awaited_once_with(
                profile_id="test-server",
                direction="get",
                remote_path="/remote/file.txt",
                local_path="/tmp/file.txt",
                checksum=None,
                create_dirs=True,
                mode=None,
                caller=None,
                token=None
            )

        with patch.object(server, "handle_rsync_sync", new=AsyncMock(return_value={"success": True, "data": {"status": "completed"}})) as mock_rsync:
            rsync_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="rsync.sync",
                        arguments={
                            "profile_id": "test-server",
                            "direction": "push",
                            "source": "/tmp/src",
                            "dest": "/tmp/dest",
                        },
                    )
                )
            )

            assert isinstance(rsync_result.root, mcp_types.CallToolResult)
            assert rsync_result.root.isError is False
            assert rsync_result.root.structuredContent["success"] is True
            mock_rsync.assert_awaited_once_with(
                profile_id="test-server",
                direction="push",
                source="/tmp/src",
                dest="/tmp/dest",
                delete_extras=False,
                dry_run=True,
                exclude=None,
                bandwidth_limit_kbps=None,
                change_ticket=None,
                caller=None,
                token=None,
            )

        with patch.object(server, "handle_tunnel_create", new=AsyncMock(return_value={"success": True, "data": {"tunnel_id": "t-1"}})) as mock_tunnel_create:
            tunnel_create_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="tunnel.create",
                        arguments={
                            "profile_id": "test-server",
                            "tunnel_type": "local",
                            "target_host": "127.0.0.1",
                            "target_port": 8080,
                        },
                    )
                )
            )

            assert isinstance(tunnel_create_result.root, mcp_types.CallToolResult)
            assert tunnel_create_result.root.isError is False
            assert tunnel_create_result.root.structuredContent["success"] is True
            mock_tunnel_create.assert_awaited_once_with(
                profile_id="test-server",
                tunnel_type="local",
                listen_host="127.0.0.1",
                listen_port=0,
                target_host="127.0.0.1",
                target_port=8080,
                ttl_seconds=3600,
                caller=None,
                token=None,
            )

        with patch.object(server, "handle_tunnel_close", new=AsyncMock(return_value={"success": True, "data": {"status": "closed"}})) as mock_tunnel_close:
            tunnel_close_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="tunnel.close",
                        arguments={"tunnel_id": "t-1"},
                    )
                )
            )

            assert isinstance(tunnel_close_result.root, mcp_types.CallToolResult)
            assert tunnel_close_result.root.isError is False
            assert tunnel_close_result.root.structuredContent["success"] is True
            mock_tunnel_close.assert_awaited_once_with(
                tunnel_id="t-1",
                caller=None,
                token=None,
            )

        with patch.object(server, "handle_vpn_wireguard_toggle", new=AsyncMock(return_value={"success": True, "data": {"status": "up"}})) as mock_vpn:
            vpn_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="vpn.wireguard.toggle",
                        arguments={
                            "profile_id": "test-server",
                            "peer_id": "peer-1",
                            "action": "up",
                        },
                    )
                )
            )

            assert isinstance(vpn_result.root, mcp_types.CallToolResult)
            assert vpn_result.root.isError is False
            assert vpn_result.root.structuredContent["success"] is True
            mock_vpn.assert_awaited_once_with(
                profile_id="test-server",
                peer_id="peer-1",
                action="up",
                config_path=None,
                interface_name=None,
                caller=None,
                token=None,
            )

        with patch.object(server, "handle_rdp_launch", new=AsyncMock(return_value={"success": True, "data": {"connection_id": "rdp-1"}})) as mock_rdp:
            rdp_result = await call_tool_handler(
                mcp_types.CallToolRequest(
                    params=mcp_types.CallToolRequestParams(
                        name="rdp.launch",
                        arguments={"profile_id": "test-server"},
                    )
                )
            )

            assert isinstance(rdp_result.root, mcp_types.CallToolResult)
            assert rdp_result.root.isError is False
            assert rdp_result.root.structuredContent["success"] is True
            mock_rdp.assert_awaited_once_with(
                profile_id="test-server",
                ttl_seconds=3600,
                domain=None,
                gateway=None,
                caller=None,
                token=None,
            )

    @pytest.mark.asyncio
    async def test_web_api_list_tools_returns_supported_tools(self, server):
        """Test web API tool listing."""
        result = await server.web_list_tools()

        tool_names = {tool["name"] for tool in result["tools"]}
        assert "ssh.exec" in tool_names
        assert "sftp.transfer" in tool_names
        assert "rsync.sync" in tool_names
        assert "tunnel.create" in tool_names
        assert "tunnel.close" in tool_names
        assert "vpn.wireguard.toggle" in tool_names
        assert "rdp.launch" in tool_names

    @pytest.mark.asyncio
    async def test_web_api_call_tool_routes_to_handlers(self, server):
        """Test web API tool call routing."""
        with patch.object(server, "handle_ssh_exec", new=AsyncMock(return_value={"success": True, "data": {"stdout": "ok"}})) as mock_ssh:
            result = await server.web_call_tool(
                name="ssh.exec",
                arguments={"profile_id": "test-server", "command": "echo ok"},
            )

            assert result["success"] is True
            mock_ssh.assert_awaited_once_with(
                profile_id="test-server",
                command="echo ok",
                pty=False,
                sudo=False,
                timeout_seconds=60,
                dry_run=False,
                change_ticket=None,
                caller=None,
                token=None,
            )

    @pytest.mark.asyncio
    async def test_web_api_call_tool_validates_required_arguments(self, server):
        """Test web API required-argument validation."""
        result = await server.web_call_tool(
            name="ssh.exec",
            arguments={"profile_id": "test-server"},
        )

        assert result["success"] is False
        assert "Missing required arguments" in result["error"]

    @pytest.mark.asyncio
    async def test_web_api_jsonrpc_tools_methods(self, server):
        """Test web API JSON-RPC dispatch."""
        list_result = await server.web_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
        )

        assert list_result["id"] == 1
        assert "tools" in list_result["result"]

        with patch.object(server, "handle_sftp_transfer", new=AsyncMock(return_value={"success": True, "data": {"status": "completed"}})) as mock_sftp:
            call_result = await server.web_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "sftp.transfer",
                        "arguments": {
                            "profile_id": "test-server",
                            "direction": "get",
                            "remote_path": "/remote/file.txt",
                            "local_path": "/tmp/file.txt",
                        },
                    },
                }
            )

            assert call_result["id"] == 2
            assert call_result["result"]["success"] is True
            mock_sftp.assert_awaited_once()

        unknown_result = await server.web_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "unknown/method",
            }
        )
        assert unknown_result["id"] == 3
        assert unknown_result["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_web_api_jsonrpc_notification_returns_no_response(self, server):
        """Test web API JSON-RPC notifications return no response."""
        with patch.object(server, "handle_ssh_exec", new=AsyncMock(return_value={"success": True, "data": {"stdout": "ok"}})) as mock_ssh:
            result = await server.web_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "ssh.exec",
                        "arguments": {
                            "profile_id": "test-server",
                            "command": "echo ok",
                        },
                    },
                }
            )

            assert result is None
            mock_ssh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_web_api_jsonrpc_invalid_request_returns_standard_error(self, server):
        """Test JSON-RPC invalid request handling."""
        result = await server.web_jsonrpc(
            {
                "id": 1,
                "method": "tools/list",
            }
        )

        assert result["id"] is None
        assert result["error"]["code"] == -32600
    
    @pytest.mark.asyncio
    async def test_profile_loading(self, server):
        """Test profile loading functionality."""
        profile = await server._load_profile("test-server")
        
        assert profile.id == "test-server"
        assert profile.host == "127.0.0.1"
        assert profile.port == 22
        assert "ssh" in profile.protocols
        assert "sftp" in profile.protocols
        assert "rsync" in profile.protocols
        assert "tunnel" in profile.protocols
    
    @pytest.mark.asyncio
    async def test_secret_resolution(self, server):
        """Test secret resolution."""
        profile = await server._load_profile("test-server")
        secret = await server.secret_store.resolve(profile.auth)
        
        assert secret.username == "testuser"
        assert secret.password == "testpass"
    
    @pytest.mark.asyncio
    async def test_policy_enforcement(self, server):
        """Test policy enforcement."""
        profile = await server._load_profile("test-server")
        
        # Test allowed command
        from openaccess_mcp.policy.engine import PolicyContext, enforce_policy
        
        context = PolicyContext(
            actor="testuser",
            actor_roles=["admin"],
            profile=profile,
            tool="ssh.exec",
            command="echo hello"
        )
        
        decision = enforce_policy(context)
        assert decision.allowed is True
        
        # Test denied command
        context.command = "rm -rf /"
        try:
            decision = enforce_policy(context)
            # If we get here, the command was allowed (which is wrong)
            assert False, "Dangerous command should have been blocked"
        except Exception as e:
            # This is expected - dangerous commands should be blocked
            assert "Command not allowed" in str(e)
            assert "rm -rf /" in str(e)
    
    @pytest.mark.asyncio
    async def test_ssh_exec_tool(self, server):
        """Test SSH exec tool."""
        with patch.object(server.ssh_provider, 'exec_command') as mock_exec, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful SSH command execution
            mock_result = Mock()
            mock_result.stdout = "hello world"
            mock_result.stderr = ""
            mock_result.exit_code = 0
            mock_result.session_id = "test-session-123"
            mock_exec.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Call the tool
            result = await server.ssh_exec(
                profile_id="test-server",
                command="echo hello world",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "stdout" in result["data"]
            assert result["data"]["stdout"] == "hello world"
            assert result["data"]["exit_code"] == 0
            assert result["data"]["session_id"] == "test-session-123"
    
    @pytest.mark.asyncio
    async def test_sftp_transfer_tool(self, server):
        """Test SFTP transfer tool."""
        with patch.object(server.sftp_provider, 'transfer_file') as mock_transfer, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful SFTP transfer
            mock_result = Mock()
            mock_result.success = True
            mock_result.bytes_transferred = 1024
            mock_result.checksum = "abc123"
            mock_transfer.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Create temporary file for testing
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(b"test content")
                temp_file_path = temp_file.name
            
            try:
                # Call the tool
                result = await server.sftp_transfer(
                    profile_id="test-server",
                    direction="get",
                    remote_path="/remote/file.txt",
                    local_path=temp_file_path,
                    caller="testuser"
                )
                
                assert result["success"] is True
                assert "bytes_transferred" in result["data"]
                assert result["data"]["bytes_transferred"] == 1024
                assert result["data"]["checksum"] == "abc123"
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_rsync_sync_tool(self, server):
        """Test rsync sync tool."""
        with patch.object(server.rsync_provider, 'sync') as mock_sync, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful rsync sync
            mock_result = Mock()
            mock_result.success = True
            mock_result.files_transferred = 5
            mock_result.bytes_transferred = 1024
            mock_result.dry_run = False
            mock_sync.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Call the tool
            result = await server.rsync_sync(
                profile_id="test-server",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "files_transferred" in result["data"]
            assert result["data"]["files_transferred"] == 5
            assert result["data"]["bytes_transferred"] == 1024
    
    @pytest.mark.asyncio
    async def test_tunnel_create_tool(self, server):
        """Test tunnel create tool."""
        with patch.object(server.tunnel_provider, 'create_tunnel') as mock_create, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful tunnel creation
            mock_result = Mock()
            mock_result.tunnel_id = "tunnel-123"
            mock_result.tunnel_type = "local"
            mock_result.listen_port = 8080
            mock_result.target_host = "internal.host"
            mock_result.target_port = 80
            mock_result.profile_id = "test-server"
            mock_create.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Call the tool
            result = await server.tunnel_create(
                profile_id="test-server",
                tunnel_type="local",
                target_host="internal.host",
                target_port=80,
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "tunnel_id" in result["data"]
            assert result["data"]["tunnel_type"] == "local"
            assert result["data"]["listen_port"] == 8080
    
    @pytest.mark.asyncio
    async def test_vpn_wireguard_tool(self, server):
        """Test WireGuard VPN tool."""
        with patch.object(server.vpn_provider, 'wireguard_toggle') as mock_toggle, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful VPN toggle
            mock_result = Mock()
            mock_result.status = "up"
            mock_result.interface = "wg-test-peer"
            mock_result.peer_id = "test-peer"
            mock_result.ip_address = "10.0.0.1"
            mock_result.error = None
            mock_toggle.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Call the tool
            result = await server.vpn_wireguard_toggle(
                profile_id="test-server",
                peer_id="test-peer",
                action="up",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "status" in result["data"]
            assert result["data"]["status"] == "up"
            assert result["data"]["interface"] == "wg-test-peer"
            assert result["data"]["peer_id"] == "test-peer"
            assert result["data"]["ip_address"] == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_rdp_launch_tool(self, server):
        """Test RDP launch tool."""
        with patch.object(server.rdp_provider, 'create_connection') as mock_create, \
             patch.object(server.rdp_provider, 'generate_rdp_file') as mock_rdp_file, \
             patch.object(server.rdp_provider, 'generate_connection_url') as mock_url, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful RDP connection creation
            mock_connection = Mock()
            mock_connection.connection_id = "rdp-123"
            mock_connection.host = "test-server"
            mock_connection.port = 3389
            mock_connection.username = "testuser"
            mock_create.return_value = mock_connection
            
            # Mock RDP file generation
            mock_rdp_file.return_value = "full address:s:test-server:3389\nusername:s:testuser"
            
            # Mock connection URL generation
            mock_url.return_value = "rdp://test-server:3389"
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Call the tool
            result = await server.rdp_launch(
                profile_id="test-server",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "connection_id" in result["data"]
            assert result["data"]["connection_id"] == "rdp-123"
            assert "rdp_file" in result["data"]
            assert "connection_url" in result["data"]
            assert result["data"]["connection_url"] == "rdp://test-server:3389"
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, server):
        """Test audit logging functionality."""
        # Perform an operation that should be logged
        with patch.object(server.ssh_provider, 'exec_command') as mock_exec, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful SSH command execution
            mock_result = Mock()
            mock_result.stdout = "test output"
            mock_result.stderr = ""
            mock_result.exit_code = 0
            mock_result.session_id = "test-session-456"
            mock_exec.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            await server.ssh_exec(
                profile_id="test-server",
                command="echo test",
                caller="testuser"
            )
            
            # Verify audit logger was called
            mock_audit.assert_called_once()
            call_args = mock_audit.call_args
            assert call_args[1]["tool"] == "ssh.exec"
            assert call_args[1]["profile_id"] == "test-server"
            assert call_args[1]["actor"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_error_handling(self, server):
        """Test error handling in tools."""
        # Test with non-existent profile
        result = await server.ssh_exec(
            profile_id="non-existent",
            command="echo test",
            caller="testuser"
        )
        
        assert result["success"] is False
        assert "error" in result
        assert "Profile not found" in result["error"]
        
        # Test with invalid command (policy violation)
        with patch.object(server.ssh_provider, 'exec_command') as mock_exec, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock audit logger
            mock_audit.return_value = None
            
            # The policy should block this command
            result = await server.ssh_exec(
                profile_id="test-server",
                command="rm -rf /",
                caller="testuser"
            )
            
            assert result["success"] is False
            assert "error" in result
            assert "Command not allowed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_server_cleanup(self, server):
        """Test server cleanup functionality."""
        # Test that cleanup doesn't crash
        await server.cleanup()
        
        # Verify cleanup completed without errors
        # (The actual tunnel cleanup is tested in the tunnel provider tests)
        assert True  # If we get here, cleanup didn't crash


class TestEndToEndWorkflows:
    """End-to-end workflow tests."""
    
    @pytest.fixture
    async def server(self):
        """Create a test server for workflow testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            profiles_dir = Path(temp_dir) / "profiles"
            secrets_dir = Path(temp_dir) / "secrets"
            audit_dir = Path(temp_dir) / "audit"
            
            profiles_dir.mkdir()
            secrets_dir.mkdir()
            audit_dir.mkdir()
            
            # Create test profile
            profile = Profile(
                id="workflow-test",
                host="127.0.0.1",
                port=22,
                protocols=["ssh", "sftp", "rsync", "tunnel", "vpn", "rdp"],
                auth=AuthRef(type="file_ref", ref="workflow-test"),
                policy=Policy(
                    roles=["admin"],
                    command_allowlist=["^echo\\b", "^ls\\b", "^cat\\b"],
                    deny_sudo=False,
                    max_session_seconds=900
                )
            )
            
            profile_file = profiles_dir / "workflow-test.json"
            profile_file.write_text(profile.model_dump_json())
            
            # Create test secret
            secret_data = {
                "username": "workflowuser",
                "password": "workflowpass"
            }
            
            secret_file = secrets_dir / "workflow-test.json"
            secret_file.write_text(json.dumps(secret_data))
            
            server = OpenAccessMCPServer(
                profiles_dir=profiles_dir,
                secrets_dir=secrets_dir,
                audit_log_path=audit_dir / "audit.log",
                audit_key_path=audit_dir / "audit.key"
            )
            
            # Create a mock audit logger to avoid signing key issues
            mock_audit_logger = Mock()
            mock_audit_logger.log_tool_call = AsyncMock(return_value=None)
            mock_audit_logger.log_record = AsyncMock(return_value=None)
            
            # Replace the audit logger with our mock
            server.audit_logger = mock_audit_logger
            
            yield server
            
            await server.cleanup()
    
    @pytest.mark.asyncio
    async def test_ssh_to_sftp_workflow(self, server):
        """Test SSH command execution followed by SFTP file transfer."""
        with patch.object(server.ssh_provider, 'exec_command') as mock_ssh, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful SSH command execution
            mock_result = Mock()
            mock_result.stdout = "file1.txt\nfile2.txt"
            mock_result.stderr = ""
            mock_result.exit_code = 0
            mock_result.session_id = "workflow-session-123"
            mock_ssh.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # List files via SSH
            ssh_result = await server.ssh_exec(
                profile_id="workflow-test",
                command="ls -1",
                caller="workflowuser"
            )
            
            assert ssh_result["success"] is True
        
        with patch.object(server.sftp_provider, 'transfer_file') as mock_sftp, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful SFTP transfer
            mock_result = Mock()
            mock_result.success = True
            mock_result.bytes_transferred = 512
            mock_result.checksum = "abc123"
            mock_sftp.return_value = mock_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Download a file via SFTP
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file_path = temp_file.name
            
            try:
                sftp_result = await server.sftp_transfer(
                    profile_id="workflow-test",
                    direction="get",
                    remote_path="/remote/file1.txt",
                    local_path=temp_file_path,
                    caller="workflowuser"
                )
                
                assert sftp_result["success"] is True
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_tunnel_to_rdp_workflow(self, server):
        """Test tunnel creation followed by RDP connection."""
        with patch.object(server.tunnel_provider, 'create_tunnel') as mock_tunnel_create, \
             patch.object(server.rdp_provider, 'create_connection') as mock_rdp_create, \
             patch.object(server.rdp_provider, 'generate_rdp_file') as mock_rdp_file, \
             patch.object(server.rdp_provider, 'generate_connection_url') as mock_url, \
             patch.object(server.tunnel_provider, 'close_tunnel') as mock_tunnel_close, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock successful tunnel creation
            mock_tunnel_result = Mock()
            mock_tunnel_result.tunnel_id = "workflow-tunnel-123"
            mock_tunnel_result.local_port = 8080
            mock_tunnel_create.return_value = mock_tunnel_result
            
            # Mock successful RDP connection creation
            mock_connection = Mock()
            mock_connection.connection_id = "workflow-rdp-123"
            mock_connection.host = "workflow-test"
            mock_connection.port = 3389
            mock_connection.username = "workflowuser"
            mock_rdp_create.return_value = mock_connection
            
            # Mock RDP file generation
            mock_rdp_file.return_value = "full address:s:workflow-test:3389\nusername:s:workflowuser"
            
            # Mock connection URL generation
            mock_url.return_value = "rdp://workflow-test:3389"
            
            # Mock successful tunnel close
            mock_close_result = Mock()
            mock_close_result.success = True
            mock_tunnel_close.return_value = mock_close_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Create tunnel
            tunnel_result = await server.tunnel_create(
                profile_id="workflow-test",
                tunnel_type="local",
                target_host="internal.rdp.host",
                target_port=3389,
                caller="workflowuser"
            )
            
            assert tunnel_result["success"] is True
            tunnel_id = tunnel_result["data"]["tunnel_id"]
        
            # Launch RDP connection
            rdp_result = await server.rdp_launch(
                profile_id="workflow-test",
                caller="workflowuser"
            )
            
            assert rdp_result["success"] is True
            
            # Close tunnel
            close_result = await server.tunnel_close(
                tunnel_id=tunnel_id,
                caller="workflowuser"
            )
            
            assert close_result["success"] is True
    
    @pytest.mark.asyncio
    async def test_rsync_dry_run_workflow(self, server):
        """Test rsync dry-run followed by actual sync."""
        with patch.object(server.rsync_provider, 'sync') as mock_sync, \
             patch.object(server.audit_logger, 'log_tool_call') as mock_audit:
            # Mock dry-run
            mock_dry_run_result = Mock()
            mock_dry_run_result.success = True
            mock_dry_run_result.files_transferred = 2
            mock_dry_run_result.bytes_transferred = 2048
            mock_dry_run_result.dry_run = True
            mock_sync.return_value = mock_dry_run_result
            
            # Mock audit logger
            mock_audit.return_value = None
            
            # Perform dry-run
            dry_run_result = await server.rsync_sync(
                profile_id="workflow-test",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                delete_extras=False,
                dry_run=True,
                caller="workflowuser"
            )
            
            assert dry_run_result["success"] is True
            assert dry_run_result["data"]["dry_run"] is True
            
            # Now perform actual sync
            mock_sync_result = Mock()
            mock_sync_result.success = True
            mock_sync_result.files_transferred = 2
            mock_sync_result.bytes_transferred = 2048
            mock_sync_result.dry_run = False
            mock_sync.return_value = mock_sync_result
            
            sync_result = await server.rsync_sync(
                profile_id="workflow-test",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                delete_extras=False,
                dry_run=False,
                caller="workflowuser"
            )
            
            assert sync_result["success"] is True
            assert sync_result["data"]["dry_run"] is False


if __name__ == "__main__":
    pytest.main([__file__])
