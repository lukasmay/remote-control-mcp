# Setup Prompt

Copy and paste the prompt below into your MCP-compatible AI agent to have it configure the sandbox MCP server for your system. It will ask you for your VM details and generate the config files with the correct paths.

---

## Prompt

```
I need you to set up the Remote Control MCP server. Here's what to do:

1. First, find where the sandbox server lives on my system. Look for `sandbox_server.py` — it should be in the remote-control-mcp directory. Note the absolute path.

2. Check that the virtual environment exists at `.venv/` in that directory. If it doesn't:
   - Run: uv venv
   - Run: uv pip install fastmcp paramiko pyyaml

3. Create `sandbox_config.yaml` from the template. Ask me for:
   - How many VMs I want to connect to
   - For each VM: a short id, display name, OS (linux/windows), IP address, SSH port, username, and whether I use key auth or password auth
   - If key auth: the path to my SSH key
   - If password auth: the password
   - Whether any VMs require a jump host (and if so, the jump host details)
   - Which sandbox should be the default

4. Register this as an MCP server in my agent's configuration. The server uses stdio transport. Use the correct absolute paths for MY system:

   - Command: <absolute-path-to-remote-control-mcp>/.venv/bin/python
   - Argument: <absolute-path-to-remote-control-mcp>/sandbox_server.py

   IMPORTANT: Both paths must be absolute (starting with /).

5. After creating the config, tell me to reload my agent's MCP servers, then test the connection with sandbox_info.
```

---

## What this does

When you give this prompt to your AI agent, it will:

1. Locate `sandbox_server.py` on your filesystem
2. Ensure the Python venv and dependencies are set up
3. Walk you through configuring your VMs interactively
4. Generate `sandbox_config.yaml` with your details
5. Set up the MCP server registration with the correct absolute paths for your system
6. Test the connection

## Notes

- The MCP server registration goes in your **agent's MCP configuration**. If you want sandbox tools available in multiple projects or contexts, each needs its own registration pointing to the same server.
- `sandbox_config.yaml` is gitignored by default since it contains credentials. The template file (`sandbox_config.template.yaml`) is safe to commit.
- On macOS, the Python path will look like: `/Users/yourname/.../remote-control-mcp/.venv/bin/python`
- On Linux, it will look like: `/home/yourname/.../remote-control-mcp/.venv/bin/python`
