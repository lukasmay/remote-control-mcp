#!/usr/bin/env python
"""
Remote Sandbox Control MCP Server

FastMCP server with Paramiko SSH backend for controlling remote
sandbox VMs from Claude Code. Supports multiple sandboxes, connection
pooling, audit logging, jump hosts, and OS-transparent tooling.
"""

import base64
import datetime
import functools
import inspect
import json
import logging
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

import paramiko
import yaml
from fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_PATH = os.environ.get(
    "SANDBOX_CONFIG",
    os.path.join(os.path.dirname(__file__), "sandbox_config.yaml"),
)


def _load_raw_config() -> dict:
    """Load and normalize config, supporting both old and new formats."""
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f)

    if "sandboxes" in raw:
        return raw

    sandbox = raw["sandbox"]
    return {
        "sandboxes": [sandbox],
        "default_sandbox": sandbox.get("id", "default"),
    }


class SandboxManager:
    """Manages multiple sandbox configurations and tracks the active one."""

    def __init__(self):
        self._sandboxes: dict[str, dict] = {}
        self._active_id: str = ""
        self.reload()

    def reload(self):
        raw = _load_raw_config()
        self._sandboxes = {s["id"]: s for s in raw["sandboxes"]}
        default = raw.get("default_sandbox", "")
        if self._active_id not in self._sandboxes:
            self._active_id = default or next(iter(self._sandboxes))

    @property
    def active(self) -> dict:
        return self._sandboxes[self._active_id]

    @property
    def active_id(self) -> str:
        return self._active_id

    def select(self, sandbox_id: str):
        if sandbox_id not in self._sandboxes:
            raise KeyError(sandbox_id)
        old_id = self._active_id
        self._active_id = sandbox_id
        if old_id != sandbox_id and old_id in _pools:
            _pools[old_id].close()

    def list_sandboxes(self) -> list[dict]:
        return [
            {"id": s["id"], "name": s.get("name", ""), "os": s.get("os", "linux"), "host": s["host"]}
            for s in self._sandboxes.values()
        ]


_manager = SandboxManager()

# ---------------------------------------------------------------------------
# SSH Connection Pooling
# ---------------------------------------------------------------------------


class SSHPool:
    """Maintains a reusable SSH connection for a single sandbox."""

    def __init__(self):
        self._client: paramiko.SSHClient | None = None
        self._jump_client: paramiko.SSHClient | None = None
        self._lock = threading.Lock()

    def get_client(self, cfg: dict) -> paramiko.SSHClient:
        with self._lock:
            if self._client is not None:
                if self._is_alive():
                    return self._client
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None

            self._client = self._connect(cfg)
            return self._client

    def _is_alive(self) -> bool:
        try:
            if self._jump_client is not None:
                jt = self._jump_client.get_transport()
                if jt is None or not jt.is_active():
                    return False
            transport = self._client.get_transport()
            if transport is None or not transport.is_active():
                return False
            transport.send_ignore()
            return True
        except Exception:
            return False

    def _connect(self, cfg: dict) -> paramiko.SSHClient:
        jump_cfg = cfg.get("jump")
        sock = None

        if jump_cfg:
            self._jump_client = self._connect_host(jump_cfg)
            transport = self._jump_client.get_transport()
            sock = transport.open_channel(
                "direct-tcpip",
                (cfg["host"], cfg.get("port", 22)),
                ("127.0.0.1", 0),
            )

        return self._connect_host(cfg, sock=sock)

    def _connect_host(self, cfg: dict, sock=None) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": cfg["host"],
            "port": cfg.get("port", 22),
            "username": cfg["username"],
            "timeout": cfg.get("connect_timeout", 10),
        }

        key_path = cfg.get("key_path", "")
        password = cfg.get("password", "")

        if key_path:
            connect_kwargs["key_filename"] = os.path.expanduser(key_path)
        if password:
            connect_kwargs["password"] = password
        if not key_path and not password:
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

        if sock:
            connect_kwargs["sock"] = sock

        client.connect(**connect_kwargs)
        return client

    def get_sftp(self, cfg: dict) -> paramiko.SFTPClient:
        try:
            return self.get_client(cfg).open_sftp()
        except Exception:
            self.close()
            return self.get_client(cfg).open_sftp()

    def close(self):
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            if self._jump_client is not None:
                try:
                    self._jump_client.close()
                except Exception:
                    pass
                self._jump_client = None


_pools: dict[str, SSHPool] = {}


def _get_pool() -> SSHPool:
    sid = _manager.active_id
    if sid not in _pools:
        _pools[sid] = SSHPool()
    return _pools[sid]


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------


def _get_ssh_client() -> paramiko.SSHClient:
    return _get_pool().get_client(_manager.active)


def _resolve_path(path: str) -> str:
    """Resolve a relative path against the configured working_dir."""
    working_dir = _manager.active.get("working_dir", "")
    if not working_dir or not path:
        return path
    if path.startswith("/") or path.startswith("\\") or (len(path) >= 2 and path[1] == ":"):
        return path
    return f"{working_dir.rstrip('/').rstrip(chr(92))}/{path}"


def _parent_dir(path: str) -> str:
    """Extract parent directory, handling both / and \\ separators."""
    last_sep = max(path.rfind("/"), path.rfind("\\"))
    return path[:last_sep] if last_sep > 0 else ""


def _is_windows() -> bool:
    return _manager.active.get("os", "linux").lower() == "windows"


def _ps_encoded(script: str) -> str:
    """Encode a PowerShell script as base64 -EncodedCommand to avoid SSH shell escaping."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -EncodedCommand {encoded}"


def _exec(command: str, timeout: int | None = None) -> tuple[str, str, int]:
    """Execute a command over SSH. Returns (stdout, stderr, exit_code)."""
    cfg = _manager.active
    if timeout is None:
        timeout = cfg.get("command_timeout", 60)
    working_dir = cfg.get("working_dir", "")
    if working_dir:
        if _is_windows():
            command = f"Set-Location '{working_dir}'; {command}"
        else:
            command = f"cd '{working_dir}'; {command}"
    pool = _get_pool()
    try:
        client = pool.get_client(cfg)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
    except Exception:
        pool.close()
        client = pool.get_client(cfg)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"), exit_code


def _get_sftp() -> paramiko.SFTPClient:
    return _get_pool().get_sftp(_manager.active)


def _read_remote_file(path: str) -> tuple[str, bytes]:
    """Read a remote file via SFTP. Returns (decoded_text, raw_bytes)."""
    sftp = _get_sftp()
    try:
        with sftp.open(path, "r") as f:
            raw = f.read()
    finally:
        sftp.close()
    try:
        return raw.decode("utf-8"), raw
    except UnicodeDecodeError:
        return raw.decode("latin-1"), raw


def _write_remote_file(path: str, content: bytes):
    """Write bytes to a remote file via SFTP."""
    sftp = _get_sftp()
    try:
        with sftp.open(path, "w") as f:
            f.write(content)
    finally:
        sftp.close()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------


class AuditLogger:
    def __init__(self):
        self._session_id = str(uuid.uuid4())[:8]
        log_dir = os.path.join(os.path.dirname(__file__), "audit_logs")
        os.makedirs(log_dir, exist_ok=True)
        self._log_path = os.path.join(log_dir, "sandbox_audit.jsonl")

    def log(self, tool_name: str, params: dict, result: dict, duration_ms: float):
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session_id": self._session_id,
            "tool": tool_name,
            "params": params,
            "result_summary": self._summarize(result),
            "duration_ms": round(duration_ms, 1),
        }
        with open(self._log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def _summarize(self, result: dict) -> dict:
        summary = {}
        for k, v in result.items():
            if k == "content" and isinstance(v, str) and len(v) > 100:
                summary[k] = v[:100] + "..."
            elif k in ("processes", "connections", "entries", "matches") and isinstance(v, list):
                summary[k + "_count"] = len(v)
            elif k == "stdout" and isinstance(v, str) and len(v) > 200:
                summary[k] = v[:200] + "..."
            else:
                summary[k] = v
        return summary


_audit = AuditLogger()


def audited(fn):
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        params = dict(bound.arguments)
        start = time.monotonic()
        result = fn(*args, **kwargs)
        duration_ms = (time.monotonic() - start) * 1000
        try:
            _audit.log(fn.__name__, params, result, duration_ms)
        except Exception as e:
            logger.warning("Audit log failed: %s", e)
        return result

    return wrapper


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Sandbox Control",
    instructions=(
        "Tools for working on a remote sandbox VM. "
        "Use these to execute commands, read/edit/write files, search, "
        "and transfer files on the sandbox. Use sandbox_info to learn "
        "about the connected system before running commands."
    ),
)


# == Sandbox Management =====================================================


@mcp.tool
@audited
def sandbox_list() -> dict:
    """List all configured sandboxes and show which is active.

    Returns:
        dict with active sandbox id and list of available sandboxes.
    """
    _manager.reload()
    return {"active": _manager.active_id, "sandboxes": _manager.list_sandboxes()}


@mcp.tool
@audited
def sandbox_select(sandbox_id: str) -> dict:
    """Switch the active sandbox target.

    Args:
        sandbox_id: The id of the sandbox to switch to.

    Returns:
        dict with status and active sandbox info.
    """
    try:
        _manager.select(sandbox_id)
        return {"status": "ok", "active_sandbox": sandbox_id, "name": _manager.active.get("name", "")}
    except KeyError:
        return {"error": f"Unknown sandbox: {sandbox_id}", "available": list(s["id"] for s in _manager.list_sandboxes())}


@mcp.tool
@audited
def sandbox_info() -> dict:
    """Get structured system information about the active sandbox.

    Call this first when connecting to a new sandbox to learn what OS,
    architecture, and environment you're working with.

    Returns:
        dict with hostname, os, os_name, kernel, arch, ip_addresses,
        uptime_seconds, and working_dir.
    """
    logger.info("info check")
    cfg = _manager.active

    try:
        _get_ssh_client()
    except Exception as e:
        return {
            "sandbox_id": cfg.get("id", "unknown"),
            "name": cfg.get("name", "unknown"),
            "connected": False,
            "error": str(e),
        }

    if _is_windows():
        return _info_windows(cfg)
    else:
        return _info_linux(cfg)


def _info_windows(cfg: dict) -> dict:
    ps_script = (
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "$cs = Get-CimInstance Win32_ComputerSystem; "
        "$uptime = (Get-Date) - $os.LastBootUpTime; "
        "$ips = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast | "
        "Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ','; "
        "[PSCustomObject]@{ "
        "hostname = $env:COMPUTERNAME; "
        "os_name = $os.Caption; "
        "os_version = $os.Version; "
        "kernel = $os.BuildNumber; "
        "arch = $os.OSArchitecture; "
        "uptime_seconds = [int]$uptime.TotalSeconds; "
        "ip_addresses = $ips "
        "} | ConvertTo-Json -Compress"
    )
    stdout, stderr, exit_code = _exec(_ps_encoded(ps_script))

    result = {
        "sandbox_id": cfg.get("id", "unknown"),
        "name": cfg.get("name", "unknown"),
        "connected": True,
        "os": "windows",
        "working_dir": cfg.get("working_dir", ""),
    }

    if exit_code == 0 and stdout.strip():
        try:
            info = json.loads(stdout.strip())
            result["hostname"] = info.get("hostname", "")
            result["os_name"] = info.get("os_name", "").strip()
            result["os_version"] = info.get("os_version", "")
            result["kernel"] = info.get("kernel", "")
            result["arch"] = info.get("arch", "")
            result["uptime_seconds"] = info.get("uptime_seconds", 0)
            ips = info.get("ip_addresses", "")
            result["ip_addresses"] = [ip.strip() for ip in ips.split(",") if ip.strip()] if isinstance(ips, str) else [ips] if ips else []
        except (json.JSONDecodeError, AttributeError):
            result["raw_info"] = stdout.strip()
    else:
        result["raw_info"] = stdout.strip()

    return result


def _info_linux(cfg: dict) -> dict:
    cmd = (
        'echo "HOSTNAME=$(hostname)";'
        'echo "KERNEL=$(uname -r)";'
        'echo "ARCH=$(uname -m)";'
        'echo "UPTIME_S=$(awk \'{printf "%d", $1}\' /proc/uptime 2>/dev/null || echo 0)";'
        'echo "IPS=$(hostname -I 2>/dev/null || echo unknown)";'
        'grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null || echo "PRETTY_NAME=Linux";'
        'grep "^VERSION_ID=" /etc/os-release 2>/dev/null || echo "VERSION_ID=unknown"'
    )
    stdout, stderr, exit_code = _exec(cmd)

    parsed = {}
    for line in stdout.strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip().strip('"')

    ips_raw = parsed.get("IPS", "")
    ip_list = [ip for ip in ips_raw.split() if ip and ip != "unknown"]

    return {
        "sandbox_id": cfg.get("id", "unknown"),
        "name": cfg.get("name", "unknown"),
        "connected": True,
        "os": "linux",
        "hostname": parsed.get("HOSTNAME", ""),
        "os_name": parsed.get("PRETTY_NAME", "Linux"),
        "os_version": parsed.get("VERSION_ID", ""),
        "kernel": parsed.get("KERNEL", ""),
        "arch": parsed.get("ARCH", ""),
        "uptime_seconds": int(parsed.get("UPTIME_S", "0") or "0"),
        "ip_addresses": ip_list,
        "working_dir": cfg.get("working_dir", ""),
    }


# == Command Execution ======================================================


@mcp.tool
@audited
def sandbox_exec(command: str, working_dir: str = "", timeout: int = 60, auto_encode: bool = True) -> dict:
    """Execute a command on the remote sandbox.

    On Windows sandboxes, commands are automatically wrapped in PowerShell
    (EncodedCommand) unless they already start with 'powershell', 'pwsh',
    or 'cmd'. Set auto_encode=False to send raw commands.

    On Linux, commands run in the default shell (usually bash).

    Args:
        command: Shell command to run.
        working_dir: Optional override working directory.
        timeout: Command timeout in seconds (default 60).
        auto_encode: Auto-wrap PowerShell on Windows (default True).

    Returns:
        dict with os, stdout, stderr, and exit_code.
    """
    if working_dir:
        if _is_windows():
            command = f"Set-Location '{working_dir}'; {command}"
        else:
            command = f"cd '{working_dir}'; {command}"

    if auto_encode and _is_windows():
        cmd_lower = command.strip().lower()
        if not (cmd_lower.startswith("powershell") or cmd_lower.startswith("pwsh") or cmd_lower.startswith("cmd")):
            command = _ps_encoded(command)

    logger.info("exec: %s", command[:200])
    stdout, stderr, exit_code = _exec(command, timeout=timeout)
    return {"os": _manager.active.get("os", "linux"), "stdout": stdout, "stderr": stderr, "exit_code": exit_code}


# == File Operations ========================================================


@mcp.tool
@audited
def sandbox_ls(path: str = ".", show_hidden: bool = False) -> dict:
    """List directory contents on the sandbox.

    Args:
        path: Directory path to list (default: working directory).
        show_hidden: Include hidden files/directories.

    Returns:
        dict with list of entries (name, size, is_dir, permissions).
    """
    path = _resolve_path(path)
    logger.info("ls: %s", path)

    sftp = _get_sftp()
    try:
        entries = []
        for attr in sftp.listdir_attr(path):
            if not show_hidden and attr.filename.startswith("."):
                continue
            entries.append({
                "name": attr.filename,
                "size": attr.st_size,
                "is_dir": stat.S_ISDIR(attr.st_mode) if attr.st_mode else False,
                "permissions": stat.filemode(attr.st_mode) if attr.st_mode else "?",
                "modified": attr.st_mtime,
            })
        return {"path": path, "count": len(entries), "entries": entries}
    finally:
        sftp.close()


@mcp.tool
@audited
def sandbox_read_file(path: str, offset: int = 0, limit: int = 2000) -> dict:
    """Read the contents of a file on the sandbox.

    Args:
        path: Path to the file on the sandbox.
        offset: Line number to start reading from (0-based).
        limit: Maximum number of lines to return.

    Returns:
        dict with file contents and metadata.
    """
    path = _resolve_path(path)
    logger.info("read_file: %s (offset=%d, limit=%d)", path, offset, limit)

    sftp = _get_sftp()
    try:
        with sftp.open(path, "r") as f:
            raw = f.read()

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except UnicodeDecodeError:
                return {
                    "path": path,
                    "binary": True,
                    "size": len(raw),
                    "preview_base64": base64.b64encode(raw[:4096]).decode(),
                }

        lines = text.splitlines()
        total_lines = len(lines)
        selected = lines[offset : offset + limit]

        return {
            "path": path,
            "total_lines": total_lines,
            "offset": offset,
            "lines_returned": len(selected),
            "content": "\n".join(selected),
        }
    finally:
        sftp.close()


@mcp.tool
@audited
def sandbox_write_file(path: str, content: str) -> dict:
    """Write text content to a file on the sandbox.

    Creates parent directories automatically if they don't exist.
    Use this for creating new files. For editing existing files,
    use sandbox_edit_file instead.

    Args:
        path: Destination path on the sandbox.
        content: Text content to write.

    Returns:
        dict with status, path, and bytes written.
    """
    resolved = _resolve_path(path)
    logger.info("write_file: %s", resolved)

    parent = _parent_dir(resolved)
    if parent:
        if _is_windows():
            _exec(_ps_encoded(f"New-Item -ItemType Directory -Force -Path '{parent}'"))
        else:
            _exec(f"mkdir -p '{parent}'")

    encoded = content.encode("utf-8")
    _write_remote_file(resolved, encoded)
    return {"status": "ok", "path": resolved, "bytes_written": len(encoded)}


@mcp.tool
@audited
def sandbox_edit_file(path: str, old_string: str, new_string: str) -> dict:
    """Edit a file on the sandbox by replacing an exact string match.

    Mirrors the behavior of Claude's Edit tool: finds exactly one
    occurrence of old_string and replaces it with new_string. Fails
    if old_string matches zero times or more than once.

    Args:
        path: Path to the file on the sandbox.
        old_string: Exact text to find (must match exactly once).
        new_string: Replacement text.

    Returns:
        dict with status and path, or error if match count != 1.
    """
    resolved = _resolve_path(path)
    logger.info("edit_file: %s", resolved)

    text, _ = _read_remote_file(resolved)

    count = text.count(old_string)
    if count == 0:
        return {"error": "No match found for old_string", "path": resolved}
    if count > 1:
        return {"error": f"Found {count} matches — provide more context to make old_string unique", "path": resolved}

    new_text = text.replace(old_string, new_string, 1)
    _write_remote_file(resolved, new_text.encode("utf-8"))
    return {"status": "ok", "path": resolved, "replacements": 1}


# == Search Tools ===========================================================


@mcp.tool
@audited
def sandbox_find(path: str = ".", pattern: str = "*", max_depth: int = 0, max_results: int = 100) -> dict:
    """Search for files on the sandbox by name pattern.

    Args:
        path: Directory to search in (default: working directory).
        pattern: Glob pattern to match (e.g., "*.exe", "*.log", "config*").
        max_depth: Maximum directory depth (0 = unlimited).
        max_results: Limit number of results (default 100).

    Returns:
        dict with matched file paths and count.
    """
    path = _resolve_path(path)
    logger.info("find: %s pattern=%s", path, pattern)

    if _is_windows():
        depth_clause = f"-Depth {max_depth}" if max_depth > 0 else ""
        ps_script = (
            f"Get-ChildItem -Path '{path}' -Recurse {depth_clause} "
            f"-Filter '{pattern}' -ErrorAction SilentlyContinue | "
            f"Select-Object -First {max_results} | "
            f"ForEach-Object {{ $_.FullName }}"
        )
        stdout, stderr, exit_code = _exec(_ps_encoded(ps_script))
    else:
        depth_clause = f"-maxdepth {max_depth}" if max_depth > 0 else ""
        cmd = f"find '{path}' {depth_clause} -name '{pattern}' 2>/dev/null | head -n {max_results}"
        stdout, stderr, exit_code = _exec(cmd)

    matches = [line.strip() for line in stdout.strip().splitlines() if line.strip()]
    return {"path": path, "pattern": pattern, "count": len(matches), "matches": matches}


@mcp.tool
@audited
def sandbox_grep(pattern: str, path: str = ".", file_pattern: str = "", max_results: int = 50, ignore_case: bool = False) -> dict:
    """Search file contents for a text pattern on the sandbox.

    Args:
        pattern: Text pattern to search for.
        path: File or directory to search in.
        file_pattern: Only search files matching this glob (e.g., "*.log").
        max_results: Maximum number of matching lines to return.
        ignore_case: Case-insensitive search.

    Returns:
        dict with matching lines, file paths, and line numbers.
    """
    path = _resolve_path(path)
    logger.info("grep: %s in %s", pattern, path)

    if _is_windows():
        return _grep_windows(pattern, path, file_pattern, max_results, ignore_case)
    else:
        return _grep_linux(pattern, path, file_pattern, max_results, ignore_case)


def _grep_linux(pattern: str, path: str, file_pattern: str, max_results: int, ignore_case: bool) -> dict:
    flags = "-rn"
    if ignore_case:
        flags += "i"
    include = f"--include='{file_pattern}'" if file_pattern else ""
    cmd = f"grep {flags} {include} '{pattern}' '{path}' 2>/dev/null | head -n {max_results}"
    stdout, stderr, exit_code = _exec(cmd)

    matches = []
    for line in stdout.strip().splitlines():
        # Format: file:line_number:text  OR  line_number:text (single file)
        parts = line.split(":", 2)
        if len(parts) >= 3 and not parts[0].isdigit():
            # Multi-file: file:line:text
            matches.append({"file": parts[0], "line": int(parts[1]) if parts[1].isdigit() else 0, "text": parts[2]})
        elif len(parts) >= 2 and parts[0].isdigit():
            # Single file: line:text (rejoin remaining parts)
            matches.append({"file": path, "line": int(parts[0]), "text": ":".join(parts[1:])})
        else:
            matches.append({"file": path, "line": 0, "text": line})

    return {"pattern": pattern, "count": len(matches), "matches": matches}


def _grep_windows(pattern: str, path: str, file_pattern: str, max_results: int, ignore_case: bool) -> dict:
    case_flag = "" if ignore_case else "-CaseSensitive"
    if file_pattern:
        ps_script = (
            f"Get-ChildItem -Path '{path}' -Recurse -Filter '{file_pattern}' -ErrorAction SilentlyContinue | "
            f"Select-String -Pattern '{pattern}' {case_flag} -ErrorAction SilentlyContinue | "
            f"Select-Object -First {max_results} | "
            f"ForEach-Object {{ \"$($_.Path):$($_.LineNumber):$($_.Line)\" }}"
        )
    else:
        ps_script = (
            f"Select-String -Path '{path}' -Pattern '{pattern}' {case_flag} -ErrorAction SilentlyContinue | "
            f"Select-Object -First {max_results} | "
            f"ForEach-Object {{ \"$($_.Path):$($_.LineNumber):$($_.Line)\" }}"
        )
    stdout, stderr, exit_code = _exec(_ps_encoded(ps_script))

    matches = []
    for line in stdout.strip().splitlines():
        # Windows paths start with drive letter (e.g. C:\...:line:text)
        # Detect drive letter prefix and rejoin before parsing
        if len(line) >= 2 and line[1] == ":":
            # Drive letter — rejoin: "C" + ":" + rest, then split from position 2
            rest = line[2:]  # everything after "C:"
            rest_parts = rest.split(":", 2)
            if len(rest_parts) >= 3:
                # \path:line:text
                matches.append({"file": line[:2] + rest_parts[0], "line": int(rest_parts[1]) if rest_parts[1].isdigit() else 0, "text": rest_parts[2]})
            else:
                matches.append({"file": path, "line": 0, "text": line})
        else:
            parts = line.split(":", 2)
            if len(parts) >= 3:
                matches.append({"file": parts[0], "line": int(parts[1]) if parts[1].isdigit() else 0, "text": parts[2]})
            elif line.strip():
                matches.append({"file": path, "line": 0, "text": line})

    return {"pattern": pattern, "count": len(matches), "matches": matches}


# == File Transfer ==========================================================


@mcp.tool
@audited
def sandbox_transfer(source: str, dest: str) -> dict:
    """Copy a file between the local machine and the sandbox.

    Use 'local:' and 'remote:' prefixes to specify source and destination.
    Remote paths are resolved against the sandbox working directory.

    Examples:
        sandbox_transfer("local:~/sample.exe", "remote:/tmp/sample.exe")
        sandbox_transfer("remote:data/results.csv", "local:~/evidence/results.csv")

    Args:
        source: Source path with prefix (local: or remote:).
        dest: Destination path with prefix (local: or remote:).

    Returns:
        dict with status, direction, and bytes transferred.
    """
    logger.info("transfer: %s -> %s", source, dest)

    src_local = source.startswith("local:")
    src_remote = source.startswith("remote:")
    dst_local = dest.startswith("local:")
    dst_remote = dest.startswith("remote:")

    if not (src_local or src_remote):
        return {"error": f"Source must start with 'local:' or 'remote:' — got '{source}'"}
    if not (dst_local or dst_remote):
        return {"error": f"Dest must start with 'local:' or 'remote:' — got '{dest}'"}
    if src_local == dst_local:
        direction = "local→local" if src_local else "remote→remote"
        return {"error": f"Cannot copy {direction}. One must be 'local:' and the other 'remote:'."}

    src_path = source.split(":", 1)[1]
    dst_path = dest.split(":", 1)[1]

    if src_local and dst_remote:
        # Upload
        local_path = os.path.expanduser(src_path)
        if not os.path.isfile(local_path):
            return {"error": f"Local file not found: {local_path}"}
        remote_path = _resolve_path(dst_path)
        file_size = os.path.getsize(local_path)

        sftp = _get_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

        return {"status": "ok", "direction": "upload", "bytes": file_size, "source": source, "dest": dest}

    else:
        # Download
        remote_path = _resolve_path(src_path)
        local_path = os.path.expanduser(dst_path)
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        sftp = _get_sftp()
        try:
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()

        file_size = os.path.getsize(local_path)
        return {"status": "ok", "direction": "download", "bytes": file_size, "source": source, "dest": dest}


# ===========================================================================
# Unregistered tools — available for project-specific re-enablement
# Add @mcp.tool and @audited decorators to activate.
# ===========================================================================


def sandbox_status() -> dict:
    """Legacy status check — replaced by sandbox_info."""
    logger.info("status check")
    cfg = _manager.active
    try:
        _get_ssh_client()
    except Exception as e:
        return {"sandbox_id": cfg.get("id", "unknown"), "name": cfg.get("name", "unknown"), "connected": False, "error": str(e)}
    if _is_windows():
        info_cmd = _ps_encoded("[System.Environment]::OSVersion.VersionString; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
    else:
        info_cmd = "uname -a && uptime"
    stdout, stderr, exit_code = _exec(info_cmd)
    return {"sandbox_id": cfg.get("id", "unknown"), "name": cfg.get("name", "unknown"), "host": cfg["host"], "os": cfg.get("os", "linux"), "connected": True, "info": stdout.strip(), "exit_code": exit_code}


def sandbox_upload(local_path: str, remote_path: str) -> dict:
    """Legacy upload — replaced by sandbox_transfer."""
    local_path = os.path.expanduser(local_path)
    if not os.path.isfile(local_path):
        return {"error": f"Local file not found: {local_path}"}
    file_size = os.path.getsize(local_path)
    remote_path = _resolve_path(remote_path)
    sftp = _get_sftp()
    try:
        sftp.put(local_path, remote_path)
        return {"status": "ok", "bytes": file_size, "remote_path": remote_path}
    finally:
        sftp.close()


def sandbox_download(remote_path: str, local_path: str) -> dict:
    """Legacy download — replaced by sandbox_transfer."""
    local_path = os.path.expanduser(local_path)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    remote_path = _resolve_path(remote_path)
    sftp = _get_sftp()
    try:
        sftp.get(remote_path, local_path)
        file_size = os.path.getsize(local_path)
        return {"status": "ok", "bytes": file_size, "local_path": local_path}
    finally:
        sftp.close()


def sandbox_ps() -> dict:
    """List running processes — available for re-enablement."""
    logger.info("ps")
    if _is_windows():
        ps_script = "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet64 | ConvertTo-Csv -NoTypeInformation"
        stdout, stderr, exit_code = _exec(_ps_encoded(ps_script))
        if exit_code != 0:
            return {"error": stderr, "exit_code": exit_code}
        processes = []
        lines = stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.strip('"').split('","')
            if len(parts) >= 4:
                processes.append({"pid": parts[0], "name": parts[1], "cpu": parts[2], "memory_bytes": parts[3]})
        return {"count": len(processes), "processes": processes}
    else:
        stdout, stderr, exit_code = _exec("ps aux --no-headers")
        if exit_code != 0:
            return {"error": stderr, "exit_code": exit_code}
        processes = []
        for line in stdout.strip().splitlines():
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({"pid": parts[1], "name": parts[10], "cpu": parts[2], "memory": parts[3]})
        return {"count": len(processes), "processes": processes}


def sandbox_kill(pid: int, force: bool = False) -> dict:
    """Kill a process by PID — available for re-enablement."""
    logger.info("kill: pid=%d force=%s", pid, force)
    if _is_windows():
        ps_script = (
            f"Stop-Process -Id {pid} -Force -ErrorAction Stop; "
            f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) "
            f"{{ 'STILL_RUNNING' }} else {{ 'KILLED' }}"
        )
        cmd = _ps_encoded(ps_script)
    else:
        sig = "-9" if force else "-15"
        cmd = f"kill {sig} {pid}; sleep 0.5; kill -0 {pid} 2>/dev/null && echo STILL_RUNNING || echo KILLED"
    stdout, stderr, exit_code = _exec(cmd)
    result_text = stdout.strip()
    if "KILLED" in result_text:
        return {"pid": pid, "status": "killed"}
    elif "STILL_RUNNING" in result_text:
        return {"pid": pid, "status": "failed", "detail": "Process still running after signal"}
    else:
        return {"pid": pid, "status": "failed", "detail": stderr.strip() or result_text}


def sandbox_netstat(state_filter: str = "") -> dict:
    """List network connections — available for re-enablement."""
    logger.info("netstat: filter=%s", state_filter or "default")
    if _is_windows():
        return _netstat_windows(state_filter)
    else:
        return _netstat_linux(state_filter)


def _netstat_windows(state_filter: str) -> dict:
    ps_script = (
        "$conns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess; "
        "$procs = Get-Process | Select-Object Id, ProcessName; "
        "$lookup = @{}; $procs | ForEach-Object { $lookup[$_.Id] = $_.ProcessName }; "
        "$conns | ForEach-Object { $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $lookup[[int]$_.OwningProcess] -PassThru } | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    stdout, stderr, exit_code = _exec(_ps_encoded(ps_script))
    if exit_code != 0:
        return {"error": stderr, "exit_code": exit_code}
    noise_states = {"TimeWait", "CloseWait"}
    connections = []
    lines = stdout.strip().splitlines()
    for line in lines[1:]:
        parts = line.strip('"').split('","')
        if len(parts) >= 7:
            conn_state = parts[4]
            if state_filter and conn_state.lower() != state_filter.lower():
                continue
            if not state_filter and conn_state in noise_states:
                continue
            connections.append({"local_addr": parts[0], "local_port": int(parts[1]) if parts[1].isdigit() else parts[1], "remote_addr": parts[2], "remote_port": int(parts[3]) if parts[3].isdigit() else parts[3], "state": conn_state, "pid": parts[5], "process": parts[6]})
    return {"count": len(connections), "connections": connections}


def _netstat_linux(state_filter: str) -> dict:
    stdout, stderr, exit_code = _exec("ss -tunap --no-header")
    if exit_code != 0:
        return {"error": stderr, "exit_code": exit_code}
    noise_states = {"TIME-WAIT", "CLOSE-WAIT"}
    pid_re = re.compile(r'pid=(\d+)')
    name_re = re.compile(r'users:\(\("([^"]+)"')
    connections = []
    for line in stdout.strip().splitlines():
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        conn_state = parts[1]
        local_full = parts[4]
        remote_full = parts[5]
        process_info = parts[6] if len(parts) > 6 else ""
        if state_filter and conn_state.lower() != state_filter.lower():
            continue
        if not state_filter and conn_state in noise_states:
            continue
        local_addr, local_port = _split_addr_port(local_full)
        remote_addr, remote_port = _split_addr_port(remote_full)
        pid_match = pid_re.search(process_info)
        name_match = name_re.search(process_info)
        connections.append({"local_addr": local_addr, "local_port": local_port, "remote_addr": remote_addr, "remote_port": remote_port, "state": conn_state, "pid": pid_match.group(1) if pid_match else "", "process": name_match.group(1) if name_match else ""})
    return {"count": len(connections), "connections": connections}


def _split_addr_port(addr_str: str) -> tuple[str, int | str]:
    if addr_str.startswith("["):
        bracket_end = addr_str.rfind("]")
        addr = addr_str[1:bracket_end]
        port_str = addr_str[bracket_end + 2:]
    else:
        idx = addr_str.rfind(":")
        addr = addr_str[:idx]
        port_str = addr_str[idx + 1:]
    return addr, int(port_str) if port_str.isdigit() else port_str


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
