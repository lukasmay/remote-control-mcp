# Remote Control MCP

An MCP (Model Context Protocol) server that gives AI agents direct SSH access to remote VMs. It handles OS differences transparently — the AI interacts with remote hosts without needing to know the underlying infrastructure.

## What It Does

- **SSH into remote VMs** (Linux and Windows) and run commands
- **Read, write, and edit files** on remote hosts via SFTP
- **Search files** by name (`find`/`Get-ChildItem`) and content (`grep`/`Select-String`)
- **Transfer files** between your local machine and the sandbox
- **Multi-sandbox support** — switch between VMs with one command
- **Jump host / ProxyJump** — reach VMs behind bastion hosts
- **OS-transparent** — Windows PowerShell commands are auto-encoded, path handling works cross-platform
- **Audit logging** — every tool call is logged to `audit_logs/sandbox_audit.jsonl`

## Tools

| Tool | Description |
|------|-------------|
| `sandbox_list` | List all configured sandboxes and which is active |
| `sandbox_select` | Switch the active sandbox target |
| `sandbox_info` | Get structured system info (OS, hostname, IPs, arch, uptime) |
| `sandbox_exec` | Run a command on the remote host |
| `sandbox_ls` | List directory contents |
| `sandbox_read_file` | Read a file's contents |
| `sandbox_write_file` | Create or overwrite a file |
| `sandbox_edit_file` | Replace an exact string in a file |
| `sandbox_find` | Search for files by name/glob pattern |
| `sandbox_grep` | Search file contents for text |
| `sandbox_transfer` | Copy files between local and remote (`local:`/`remote:` prefix notation) |

## Prerequisites

- **Python 3.10+**
- **uv** (recommended) or pip for package management
- **SSH access** to at least one remote VM (key-based or password auth)
- **An MCP-compatible AI agent** (any agent that supports the Model Context Protocol)

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/lukasmay/remote-control-mcp.git
cd remote-control-mcp
```

### 2. Create virtual environment and install dependencies
If you are using `uv` run these commands
```bash
uv venv
uv pip install fastmcp paramiko pyyaml
```

Else use
```bash
python3 -m venv venv
source .venv/bin/activate
pip install fastmcp paramiko pyyaml
```

### 3. Configure your sandboxes

Copy the template config and edit it with your VM details:

```bash
cp sandbox_config.template.yaml sandbox_config.yaml
```

Edit `sandbox_config.yaml` — see [Configuration](#configuration) below.

### 4. Register the MCP server

Add this server to your AI agent's MCP configuration. The exact setup varies by agent — consult your agent's documentation for how to register MCP servers.

The server runs over **stdio** transport. Your agent needs two absolute paths:

- **Command**: `/absolute/path/to/remote-control-mcp/.venv/bin/python`
- **Argument**: `/absolute/path/to/remote-control-mcp/sandbox_server.py`

Example MCP configuration (format may vary by agent):

```json
{
  "mcpServers": {
    "sandbox": {
      "type": "stdio",
      "command": "/absolute/path/to/remote-control-mcp/.venv/bin/python",
      "args": [
        "/absolute/path/to/remote-control-mcp/sandbox_server.py"
      ]
    }
  }
}
```

**Both paths must be absolute.** The `command` points to the Python binary inside the venv, and the first arg is the server script.

### 5. Reload your agent's MCP servers

After saving the configuration, reload or restart your agent's MCP connection so it picks up the new server. You should see the sandbox tools become available.

## Configuration

### sandbox_config.yaml

```yaml
sandboxes:
  - id: "my-linux-vm"            # Unique identifier
    name: "Linux Analysis Box"    # Display name
    os: "linux"                   # "linux" or "windows"
    host: "192.168.1.100"         # IP or hostname
    port: 22
    username: "analyst"
    password: ""                  # Leave empty if using key auth
    key_path: "~/.ssh/id_ed25519" # Leave empty if using password auth
    working_dir: ""               # Default working directory (optional)
    connect_timeout: 10
    command_timeout: 60

  - id: "my-windows-vm"
    name: "Windows Sandbox"
    os: "windows"
    host: "192.168.1.101"
    port: 22
    username: "admin"
    password: "mypassword"
    key_path: ""
    working_dir: ""
    connect_timeout: 10
    command_timeout: 60

default_sandbox: "my-linux-vm"    # Which sandbox is active on startup
```

### Jump host (optional)

For VMs behind a bastion/jump host, add a `jump` block:

```yaml
  - id: "internal-vm"
    name: "Internal Network VM"
    os: "linux"
    host: "10.0.0.50"             # Internal IP (reachable from jump host)
    port: 22
    username: "analyst"
    key_path: "~/.ssh/my_key"
    working_dir: ""
    connect_timeout: 10
    command_timeout: 60
    jump:
      host: "bastion.example.com"  # Jump host (reachable from your machine)
      port: 22
      username: "jump_user"
      key_path: "~/.ssh/my_key"
```

### Windows SSH requirements

The Windows VM needs OpenSSH Server installed and running. PowerShell must be available. The server automatically wraps all commands in `powershell -EncodedCommand` to avoid variable-stripping issues with Windows OpenSSH.

## File Structure

```
remote-control-mcp/
├── sandbox_server.py              # The MCP server (this is the only code file)
├── sandbox_config.yaml            # Your sandbox configuration (git-ignored)
├── sandbox_config.template.yaml   # Template config for new setups
├── SETUP_PROMPT.md                # AI-assisted setup prompt
├── .gitignore
├── audit_logs/                    # Auto-created, stores JSONL audit logs
│   └── sandbox_audit.jsonl
└── .venv/                         # Python virtual environment
```

## Usage Examples

Once configured, the AI agent can use the sandbox tools naturally:

- "Connect to the Linux VM and check what's running"
- "Find all `.log` files on the Windows box and grep for errors"
- "Edit the config file on the remote host — change the port from 8080 to 9090"
- "Download the malware sample from the sandbox to my local machine"
- "Switch to the internal VM and check its network configuration"

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Tools don't appear | Reload your agent's MCP servers. Check paths in MCP config are absolute. |
| Connection timeout | Verify the VM is running and SSH is reachable: `ssh user@host` |
| Jump host timeout | Check VPN is connected and bastion host is reachable |
| Windows commands fail | Ensure OpenSSH Server is running and PowerShell is available |
| Permission denied | Check SSH key permissions (`chmod 600`) or verify password |
