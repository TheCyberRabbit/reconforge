#!/usr/bin/env python3
"""
ReconForge — modular reconnaissance toolkit for AUTHORIZED security testing.

    ┌──────────────────────────────────────────────────────────────────────┐
    │  AUTHORIZED USE ONLY: penetration tests with signed scope, bug       │
    │  bounty programs, CTFs, labs, and systems you own. You are solely    │
    │  responsible for complying with the law in your jurisdiction.        │
    └──────────────────────────────────────────────────────────────────────┘

Requirements:
    Python >= 3.10
    pip install rich

Run:
    python reconforg.py                                  # interactive shell
    python reconforg.py --list-plugins
    python reconforg.py --list-tools
    python reconforg.py -t scanme.nmap.org -p nmap -o scan_type=vuln
    python reconforg.py -T targets.txt -p subfinder -o scan_type=all -e md
    python reconforg.py -p hashcat -o scan_type=dictionary -o hash_file=h.txt -o mode=0

Interactive quickstart:
    add scanme.nmap.org, example.com    # multiple targets (or: load targets.txt)
    plugins                             # list plugins (with preset counts)
    use nmap                            # select a plugin
    scans                               # show available scan types
    set scan_type aggressive            # pick a scan type
    options                             # review all options
    run                                 # run against ALL targets
    results                             # summary of finished scans
    export md                           # export report (json | md | txt)
    tools / tool hashcat                # tool status, install & troubleshooting
    help                                # full command list

Extending ReconForge:
    Subclass BasePlugin, decorate it with @plugin, and implement
    build_command(). Optionally define `scan_types` presets. The plugin is
    discovered automatically at startup.
"""

from __future__ import annotations

import argparse
import atexit
import copy
import getpass
import json
import logging
import platform
import re
import shlex
import shutil
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

APP_NAME = "ReconForge"
__version__ = "2.0.0"

CONFIG_PATH = Path("~/.reconforg/config.json").expanduser()
HISTORY_PATH = Path("~/.reconforg/history.txt").expanduser()
READLINE_PATH = Path("~/.reconforg/readline_history").expanduser()

DEFAULT_RULES_PATH = "/usr/share/hashcat/rules/best64.rule"


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ReconForgeError(Exception):
    """Base class for all expected ReconForge errors."""


class ConfigError(ReconForgeError):
    """Raised when configuration is missing or invalid."""


class TargetError(ReconForgeError):
    """Raised for target list problems (missing file, empty list, ...)."""


class PluginError(ReconForgeError):
    """Raised when a plugin is misconfigured or fails to run."""


class ToolNotFoundError(ReconForgeError):
    """Raised when a required external tool cannot be located."""

    def __init__(self, tool: str, hint: str = "") -> None:
        self.tool = tool
        self.hint = hint
        message = f"Required tool not found: {tool}"
        if hint:
            message += f" ({hint})"
        super().__init__(message)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ScanStatus(str, Enum):
    """Outcome classification for a single scan."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"

    @property
    def styled(self) -> str:
        """Rich markup representation for tables."""
        styles = {
            ScanStatus.SUCCESS: "bold green",
            ScanStatus.FAILED: "bold red",
            ScanStatus.TIMEOUT: "bold yellow",
            ScanStatus.SKIPPED: "dim",
        }
        return f"[{styles[self]}]{self.value.upper()}[/]"


@dataclass
class CommandOutcome:
    """Raw result of executing one external command."""

    command: list[str]
    exit_code: int | None = None
    stdout: str = ""
    timed_out: bool = False
    error: str | None = None
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        """True when the command ran to completion with exit code 0."""
        return self.exit_code == 0 and not self.timed_out and self.error is None


@dataclass
class ScanResult:
    """A single, reportable unit of work (one tool run against one target)."""

    plugin_id: str
    plugin_name: str
    target: str
    command: list[str]
    status: ScanStatus
    exit_code: int | None
    started_at: str
    duration: float
    stdout: str
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    output_file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for reports (enums become plain strings)."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "legal": {"accepted": False},
    "paths": {
        "output": "~/.reconforg/output",
        "reports": "~/.reconforg/reports",
        "logs": "~/.reconforg/logs",
    },
    "runner": {
        "timeout": 1800,
        "max_output_chars": 400_000,
    },
    "wordlists": {
        "directory": "/usr/share/wordlists/dirb/common.txt",
        "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "passwords": "/usr/share/wordlists/rockyou.txt",
    },
    "plugins": {},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class Config:
    """JSON-backed configuration store with dotted-key access."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)

    @classmethod
    def load(cls, path: Path) -> "Config":
        """Load config from disk, creating it with defaults on first run."""
        cfg = cls(path)
        if path.exists():
            try:
                stored = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigError(f"Could not read config file {path}: {exc}") from exc
            cfg.data = _deep_merge(DEFAULT_CONFIG, stored)
        else:
            cfg.save()
        return cfg

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Read a value using dotted notation, e.g. ``runner.timeout``."""
        node: Any = self.data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted_key: str, value: Any) -> None:
        """Write (and persist) a value using dotted notation."""
        parts = dotted_key.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ConfigError(f"Cannot set '{dotted_key}': '{part}' is not a section")
        node[parts[-1]] = value
        self.save()

    def expanded_path(self, dotted_key: str) -> Path:
        """Return a config path value expanded and absolute."""
        raw = self.get(dotted_key)
        if not raw:
            raise ConfigError(f"Missing config key: {dotted_key}")
        return Path(str(raw)).expanduser().resolve()


def build_logger(log_dir: Path) -> logging.Logger:
    """Create (or return) the application logger writing into *log_dir*."""
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("reconforg")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    handler = RotatingFileHandler(
        log_dir / "reconforg.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# Tool knowledge base: detection, install hints, troubleshooting
# ─────────────────────────────────────────────────────────────────────────────

GENERIC_TROUBLESHOOT: list[str] = [
    "Confirm the tool is installed and on your PATH (`which <tool>` / `where <tool>`).",
    "Run the exact command shown below in a normal terminal to see unfiltered errors.",
    "Update the tool to the latest release; CLI flags change between versions.",
    "Check file permissions on wordlists, hash files and output directories.",
    "If you just installed the tool, open a new shell so PATH changes apply.",
]

TOOLS: dict[str, dict[str, Any]] = {
    "nmap": {
        "description": "Network scanner and port-auditing workhorse.",
        "docs": "https://nmap.org/book/",
        "install": {
            "Debian/Ubuntu/Kali": "sudo apt install nmap",
            "Fedora/RHEL": "sudo dnf install nmap",
            "Arch": "sudo pacman -S nmap",
            "macOS": "brew install nmap",
            "Windows": "choco install nmap (or installer from nmap.org)",
        },
        "troubleshoot": [
            "Privileged presets (syn, udp, udp_full, os, aggressive, vuln) usually need root — run ReconForge via sudo or pick a connect-based preset (quick, top100, top1000, version).",
            "'Operation not permitted' on SYN scans: run with sudo, or use scan_type `version`.",
            "Scans very slow: reduce scope with scan_type `top100` or a specific `ports` list.",
            "All hosts come back filtered: a firewall may drop probes; try `-Pn` via `extra_args`.",
            "Empty service versions: raise intensity with `extra_args`: `-sV --version-intensity 5`.",
        ],
    },
    "gobuster": {
        "description": "Fast directory/DNS/vhost/fuzz brute-forcer.",
        "docs": "https://github.com/OJ/gobuster",
        "install": {
            "Debian/Ubuntu/Kali": "sudo apt install gobuster",
            "macOS": "brew install gobuster",
            "Go": "go install github.com/OJ/gobuster/v3@latest",
        },
        "troubleshoot": [
            "The dns, vhost and fuzz scan types require gobuster v3.1+; check `gobuster --help` and upgrade if needed.",
            "Wordlist errors are almost always a bad path — verify with `ls`, then fix the `wordlist` option or the matching config key.",
            "Only 403s? Adjust `status_codes` or switch wordlists/extensions.",
            "TLS certificate errors: add `-k` via `extra_args` (authorized tests only).",
            "Rate limiting / WAF blocks: lower `threads` (e.g. `set threads 5`).",
        ],
    },
    "ffuf": {
        "description": "Fast web fuzzer written in Go.",
        "docs": "https://github.com/ffuf/ffuf",
        "install": {
            "Debian/Kali": "sudo apt install ffuf",
            "macOS": "brew install ffuf",
            "Go": "go install github.com/ffuf/ffuf/v2@latest",
        },
        "troubleshoot": [
            "Fuzz URLs must contain the FUZZ keyword; ReconForge builds it from `fuzz_path` and the scan type.",
            "Everything filtered? Adjust `match_codes` or set `filter_codes`; use `-fs/-fw` via `extra_args` for size/word filters.",
            "vhost scans often need a filter (e.g. `set extra_args -fc 400`) to drop the default-host noise.",
            "Wordlist encoding issues: convert to UTF-8 and Unix line endings (`dos2unix`).",
            "TLS errors: add `-k` via `extra_args`. HTTP 429 responses: lower `threads`.",
        ],
    },
    "dirsearch": {
        "description": "Python-based web path scanner.",
        "docs": "https://github.com/maurosoria/dirsearch",
        "install": {
            "pip": "pip install dirsearch",
            "Debian/Ubuntu": "sudo apt install dirsearch",
            "git": "git clone https://github.com/maurosoria/dirsearch && cd dirsearch && pip install .",
        },
        "troubleshoot": [
            "Installed from git? Ensure `dirsearch` or `dirsearch.py` is on PATH (symlink or alias it).",
            "Requires Python 3.7+; try running `python3 dirsearch.py` directly.",
            "Permission denied writing reports: check ownership of the output directory.",
            "Noisy 403/429 results: populate `exclude_status` (e.g. `set exclude_status 403,429`).",
        ],
    },
    "subfinder": {
        "description": "Fast passive subdomain enumeration (ProjectDiscovery).",
        "docs": "https://github.com/projectdiscovery/subfinder",
        "install": {
            "Go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "macOS": "brew install subfinder",
            "Debian/Kali": "sudo apt install subfinder",
        },
        "troubleshoot": [
            "No results: the domain may have few records; try scan_type `all` or pair with amass.",
            "Some passive sources work best with free API keys configured in ~/.config/subfinder/provider-config.yaml.",
            "Rate limited by a source? Try scan_type `stealth` or lower `rate_limit`.",
            "Targets must be bare domains — ReconForge strips schemes automatically.",
        ],
    },
    "assetfinder": {
        "description": "Find domains and subdomains potentially related to a given domain.",
        "docs": "https://github.com/tomnomnom/assetfinder",
        "install": {
            "Go": "go install github.com/tomnomnom/assetfinder@latest",
            "macOS": "brew install assetfinder",
        },
        "troubleshoot": [
            "Requires a domain argument; ReconForge passes each target as a bare domain.",
            "`related` returns everything assetfinder can link — expect noise; `subs` is subdomains only.",
            "Pair with crt.sh / Amass for wider coverage.",
        ],
    },
    "amass": {
        "description": "OWASP Amass: in-depth attack surface mapping.",
        "docs": "https://github.com/owasp-amass/amass",
        "install": {
            "Go": "go install -v github.com/owasp-amass/amass/v4/...@master",
            "Debian/Kali": "sudo apt install amass",
            "macOS": "brew install amass",
        },
        "troubleshoot": [
            "Amass is thorough but slow/memory hungry; prefer scan_type `passive` first.",
            "Active presets (active, brute, alterations) generate real traffic — only with written authorization.",
            "Brute presets need a subdomain wordlist; set `wordlist` or `wordlists.subdomains` in config.",
            "API keys (SecurityTrails, VirusTotal, ...) improve coverage; configure them in the Amass config file.",
            "If it looks stuck it may be enumerating a huge zone; raise the `timeout` option.",
        ],
    },
    "dig": {
        "description": "Flexible DNS lookup utility (BIND).",
        "docs": "https://bind9.readthedocs.io/",
        "install": {
            "Debian/Ubuntu": "sudo apt install dnsutils",
            "Fedora/RHEL": "sudo dnf install bind-utils",
            "Arch": "sudo pacman -S bind",
            "macOS": "brew install bind",
        },
        "troubleshoot": [
            "On Debian/Ubuntu dig ships in the `dnsutils` package; on Fedora/RHEL it is `bind-utils`.",
            "Empty ANSWER section may simply mean the record does not exist — try record_type A or NS.",
            "Query a specific resolver with `set server 8.8.8.8`.",
            "axfr rarely succeeds — most servers refuse transfers; a REFUSED/SERVFAIL answer is itself useful recon.",
            "reverse scans expect an IP address as the target, not a hostname.",
        ],
    },
    "nslookup": {
        "description": "Classic DNS query tool.",
        "docs": "https://en.wikipedia.org/wiki/Nslookup",
        "install": {
            "Debian/Ubuntu": "sudo apt install dnsutils",
            "Fedora/RHEL": "sudo dnf install bind-utils",
            "Windows": "built into Windows",
        },
        "troubleshoot": [
            "On Linux, nslookup comes from the same dnsutils/bind-utils packages as dig.",
            "trace/axfr/reverse scan types need dig — run `set tool dig`.",
            "Some resolvers block or rate-limit queries; test with a public resolver.",
        ],
    },
    "whois": {
        "description": "Registration data lookups for domains and IPs.",
        "docs": "https://www.linux.com/topic/networking/whois-command/",
        "install": {
            "Debian/Ubuntu/Kali": "sudo apt install whois",
            "Fedora/RHEL": "sudo dnf install whois",
            "macOS": "brew install whois",
        },
        "troubleshoot": [
            "whois servers rate-limit aggressively; wait and retry.",
            "Some TLDs and privacy-protected domains return minimal data.",
            "Use scan_type `ip` for IP/netblock lookups; use `server` to pin a specific whois server.",
        ],
    },
    "hashcat": {
        "description": "Advanced password/hash recovery (CPU & GPU).",
        "docs": "https://hashcat.net/hashcat/",
        "install": {
            "Debian/Ubuntu/Kali": "sudo apt install hashcat",
            "Fedora": "sudo dnf install hashcat",
            "Arch": "sudo pacman -S hashcat",
            "macOS": "brew install hashcat",
        },
        "troubleshoot": [
            "'No devices found': check GPU drivers (CUDA/ROCm) or force CPU with `set device_type 1`.",
            "Run `hashcat -I` in a terminal to list detected compute backends, or scan_type `benchmark` inside ReconForge.",
            "Exit code 1 means 'Exhausted' — nothing matched; verify `mode` matches your hash type.",
            "'Hash-file exception': check formatting — one hash per line, no stray whitespace.",
            "Previously cracked hashes live in the potfile; use scan_type `show` to print them.",
            "Rules attacks need a rules file (Kali: /usr/share/hashcat/rules/best64.rule).",
            "Headless systems: try `set force true` together with `set device_type 1`.",
        ],
    },
}


class ToolRegistry:
    """Locates external binaries on PATH and caches the results."""

    def __init__(self) -> None:
        self._cache: dict[str, str | None] = {}

    def which(self, name: str) -> str | None:
        if name not in self._cache:
            self._cache[name] = shutil.which(name)
        return self._cache[name]

    def which_any(self, names: Iterable[str]) -> str | None:
        for name in names:
            path = self.which(name)
            if path:
                return path
        return None

    def is_available(self, name: str) -> bool:
        return self.which(name) is not None

    def missing(self, names: Iterable[str]) -> list[str]:
        return [name for name in names if not self.is_available(name)]

    def refresh(self) -> None:
        """Drop the cache (use after installing new tools)."""
        self._cache.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Command execution
# ─────────────────────────────────────────────────────────────────────────────

console = Console()


class CommandRunner:
    """Executes external security tools, streaming output while capturing it."""

    def __init__(
        self,
        logger: logging.Logger,
        default_timeout: int = 1800,
        max_output: int = 400_000,
    ) -> None:
        self.logger = logger
        self.default_timeout = default_timeout
        self.max_output = max_output

    def run(
        self,
        command: list[str],
        *,
        timeout: int | None = None,
        cwd: str | None = None,
    ) -> CommandOutcome:
        """Run *command*; never raises for tool-level problems."""
        timeout = timeout or self.default_timeout
        printable = shlex.join(command)
        self.logger.info("exec: %s", printable)
        console.print(Text(f"$ {printable}", style="bold magenta"))

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                cwd=cwd,
            )
        except FileNotFoundError:
            return CommandOutcome(command=command, error=f"Executable not found: {command[0]}")
        except PermissionError:
            return CommandOutcome(command=command, error=f"Permission denied launching: {command[0]}")
        except OSError as exc:
            return CommandOutcome(command=command, error=f"Could not start process: {exc}")

        state = {"timed_out": False}

        def _kill() -> None:
            state["timed_out"] = True
            self.logger.warning("timeout reached, killing: %s", printable)
            try:
                proc.kill()
            except OSError:
                pass

        timer = threading.Timer(timeout, _kill)
        timer.daemon = True
        timer.start()

        chunks: list[str] = []
        captured = 0
        truncated = False
        start = time.monotonic()
        assert proc.stdout is not None
        try:
            for raw_line in proc.stdout:
                self._echo(raw_line.rstrip("\n"))
                if captured < self.max_output:
                    chunks.append(raw_line)
                    captured += len(raw_line)
                else:
                    truncated = True
            proc.wait()
        except KeyboardInterrupt:
            proc.kill()
            proc.wait()
            raise
        finally:
            timer.cancel()

        duration = time.monotonic() - start
        stdout = "".join(chunks)
        if truncated:
            stdout += f"\n[... output truncated at {self.max_output} characters ...]"
        error = f"Command timed out after {timeout}s and was killed" if state["timed_out"] else None
        self.logger.info(
            "done: exit=%s timed_out=%s duration=%.1fs cmd=%s",
            proc.returncode, state["timed_out"], duration, printable,
        )
        return CommandOutcome(
            command=command,
            exit_code=proc.returncode,
            stdout=stdout,
            timed_out=state["timed_out"],
            error=error,
            duration=duration,
        )

    def _echo(self, line: str) -> None:
        line = line.replace("\r", "")
        if len(line) > 300:
            line = line[:300] + " …"
        console.print(Text(line, style="dim"))


# ─────────────────────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────────────────────

class TargetManager:
    """An ordered, de-duplicated collection of targets (hosts, domains, URLs)."""

    def __init__(self) -> None:
        self._targets: list[str] = []

    def add(self, raw: str) -> list[str]:
        """Add one or more targets from a raw string (comma/space separated)."""
        added: list[str] = []
        for piece in re.split(r"[,\s]+", raw.strip()):
            target = piece.strip()
            if not target or target.startswith("#"):
                continue
            if target not in self._targets:
                self._targets.append(target)
                added.append(target)
        return added

    def add_many(self, items) -> list[str]:
        added: list[str] = []
        for item in items:
            added.extend(self.add(item))
        return added

    def remove(self, target: str) -> bool:
        if target in self._targets:
            self._targets.remove(target)
            return True
        return False

    def clear(self) -> None:
        self._targets.clear()

    def load_file(self, path: Path) -> tuple[int, int]:
        """Load targets from a file (one per line, ``#`` comments ignored)."""
        if not path.exists():
            raise TargetError(f"Targets file not found: {path}")
        added = skipped = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            new = self.add(line)
            added += len(new)
            if not new:
                skipped += 1
        return added, skipped

    def all(self) -> list[str]:
        return list(self._targets)

    def __len__(self) -> int:
        return len(self._targets)

    @property
    def has_targets(self) -> bool:
        return bool(self._targets)

    def write_list_file(self, path: Path) -> Path:
        """Write all targets to *path* (one per line) for tools taking -dL/-iL."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self._targets) + "\n", encoding="utf-8")
        return path


# ─────────────────────────────────────────────────────────────────────────────
# History
# ─────────────────────────────────────────────────────────────────────────────

class HistoryStore:
    """Append-only, timestamped history of REPL and tool commands."""

    def __init__(self, path: Path, limit: int = 2000) -> None:
        self.path = path
        self.limit = limit
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, entry: str) -> None:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(f"{stamp} | {entry}\n")
        self._trim()

    def recent(self, count: int = 20) -> list[str]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-count:]

    def _trim(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) > self.limit:
                self.path.write_text("\n".join(lines[-self.limit:]) + "\n", encoding="utf-8")
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

class ReportExporter:
    """Serialises collected scan results to shareable report files."""

    FORMATS = {"json": "json", "md": "md", "markdown": "md", "txt": "txt", "text": "txt"}

    def __init__(self, reports_dir: Path, logger: logging.Logger) -> None:
        self.reports_dir = reports_dir
        self.logger = logger
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        results: list[ScanResult],
        targets: list[str],
        fmt: str,
        dest: str | None = None,
    ) -> Path:
        fmt_key = self.FORMATS.get(fmt.lower())
        if not fmt_key:
            raise ConfigError(f"Unknown report format '{fmt}'. Use json, md or txt.")
        session = self._session(results, targets)
        if fmt_key == "json":
            body = json.dumps(session, indent=2, ensure_ascii=False)
        elif fmt_key == "md":
            body = self._markdown(session)
        else:
            body = self._text(session)

        if dest:
            path = Path(dest).expanduser().resolve()
        else:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = self.reports_dir / f"reconforg_report_{stamp}.{fmt_key}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        self.logger.info("report exported: %s", path)
        return path

    def _session(self, results: list[ScanResult], targets: list[str]) -> dict:
        return {
            "application": APP_NAME,
            "version": __version__,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "operator": getpass.getuser(),
            "host": platform.node(),
            "targets": list(targets),
            "result_count": len(results),
            "results": [r.to_dict() for r in results],
        }

    def _markdown(self, s: dict) -> str:
        lines = [
            f"# {APP_NAME} Security Assessment Report",
            "",
            f"- **Generated:** {s['generated_at']}",
            f"- **Operator:** {s['operator']} @ {s['host']}",
            f"- **Version:** {s['version']}",
            f"- **Targets:** {', '.join(s['targets']) if s['targets'] else '(none)'}",
            f"- **Total results:** {s['result_count']}",
            "",
            "> Scope reminder: this report must only contain data from systems you are "
            "explicitly authorized to test.",
            "",
            "## Summary",
            "",
            "| # | Plugin | Target | Status | Exit | Duration (s) |",
            "|---|--------|--------|--------|------|--------------|",
        ]
        for i, r in enumerate(s["results"], 1):
            lines.append(
                f"| {i} | {r['plugin_id']} | {r['target']} | {r['status']} "
                f"| {r['exit_code']} | {r['duration']:.1f} |"
            )
        lines.append("")
        for i, r in enumerate(s["results"], 1):
            lines += [
                f"## Result {i}: {r['plugin_name']} → {r['target']}",
                "",
                f"- **Status:** {r['status']} | **Exit code:** {r['exit_code']} "
                f"| **Duration:** {r['duration']:.1f}s",
                f"- **Started:** {r['started_at']}",
                f"- **Command:** `{shlex.join(r['command'])}`",
            ]
            if r.get("error"):
                lines.append(f"- **Error:** {r['error']}")
            if r.get("output_file"):
                lines.append(f"- **Output file:** `{r['output_file']}`")
            out = (r["stdout"] or "(no output)").replace("```", "'''")
            if len(out) > 50_000:
                out = out[:50_000] + "\n[truncated]"
            lines += ["", "```text", out, "```", ""]
        return "\n".join(lines)

    def _text(self, s: dict) -> str:
        bar = "=" * 78
        thin = "-" * 78
        lines = [
            bar,
            f"{APP_NAME.upper()} SECURITY ASSESSMENT REPORT".center(78),
            bar,
            f"Generated : {s['generated_at']}",
            f"Operator  : {s['operator']} @ {s['host']}",
            f"Version   : {s['version']}",
            f"Targets   : {', '.join(s['targets']) if s['targets'] else '(none)'}",
            f"Results   : {s['result_count']}",
            bar,
            "",
            "AUTHORIZED USE ONLY — confirm scope before distribution.",
            "",
        ]
        for i, r in enumerate(s["results"], 1):
            lines += [
                thin,
                f"RESULT {i}: {r['plugin_name']} -> {r['target']}",
                thin,
                f"Status   : {r['status']} (exit {r['exit_code']}) duration {r['duration']:.1f}s",
                f"Started  : {r['started_at']}",
                f"Command  : {shlex.join(r['command'])}",
            ]
            if r.get("error"):
                lines.append(f"Error    : {r['error']}")
            if r.get("output_file"):
                lines.append(f"File     : {r['output_file']}")
            lines += ["", "OUTPUT:", r["stdout"].strip() or "(no output)", ""]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers (Rich)
# ─────────────────────────────────────────────────────────────────────────────

BANNER = (
    "╦═╗ ╔═╗ ╔═╗ ╔═╗ ╔╗╔ ╔═╗ ╔═╗ ╦═╗ ╔═╗ ╔═╗\n"
    "╠╦╝ ║╣  ║   ║ ║ ║║║ ╠╣  ║ ║ ║ ║ ╠╦╝ ║╣ \n"
    "╩╚═ ╚═╝ ╚═╝ ╚═╝ ╝╚╝ ╚   ╚═╝ ╩╚═ ╩╚═ ╚═╝"
)

TAGLINE = "Modular reconnaissance & assessment toolkit"

LEGAL_TEXT = (
    f"{APP_NAME} orchestrates offensive security tooling and must only be used\n"
    "against systems you are explicitly authorized to test:\n\n"
    "  • Penetration tests under a signed scope / rules of engagement\n"
    "  • Bug bounty programs (within their published policy)\n"
    "  • CTF challenges and isolated lab environments\n"
    "  • Assessments of infrastructure you own\n\n"
    "Unauthorized access to computer systems violates laws such as the CFAA\n"
    "(US), Computer Misuse Act (UK) and equivalents worldwide. The authors\n"
    "accept no liability for misuse. You are solely responsible for your actions."
)


def banner(version: str) -> None:
    console.print(
        Panel(
            Text(BANNER, style="bold cyan"),
            border_style="cyan",
            title=f"[bold]{APP_NAME}[/bold] — {TAGLINE}",
            subtitle=f"[dim]v{version} • authorized security testing only[/dim]",
            padding=(0, 2),
        )
    )


def info(message: str) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {message}")


def success(message: str) -> None:
    console.print(f"[bold green][+][/bold green] {message}")


def warning(message: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def error(message: str) -> None:
    console.print(f"[bold red][x][/bold red] {message}")


def legal_panel() -> None:
    console.print(
        Panel(LEGAL_TEXT, title="[bold red]Authorized Use Required[/bold red]", border_style="red")
    )


def progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def plugin_table(plugins: dict, registry: ToolRegistry, active_id: str | None = None) -> Table:
    table = Table(title=f"{APP_NAME} Plugins", title_style="bold magenta", header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Tools")
    table.add_column("Scan types", justify="right")
    table.add_column("Ready")
    for pid, plugin in plugins.items():
        missing = plugin.missing_tools(registry)
        ready = (
            "[green]yes[/green]"
            if not missing
            else f"[red]missing: {', '.join(missing)}[/red]"
        )
        label = f"[bold green]➤ {pid}[/bold green]" if pid == active_id else pid
        presets = str(len(plugin.scan_types)) if plugin.scan_types else "-"
        table.add_row(label, escape(plugin.name), plugin.category,
                      ", ".join(plugin.required_tools) or "-", presets, ready)
    return table


def options_table(plugin) -> Table:
    table = Table(title=f"Options — {plugin.name}", title_style="bold magenta", header_style="bold")
    table.add_column("Option", style="cyan")
    table.add_column("Value")
    table.add_column("Default", style="dim")
    for key in sorted(plugin.options):
        table.add_row(key, escape(str(plugin.options[key])),
                      escape(str(plugin.default_options.get(key, ""))))
    return table


def scan_types_table(plugin) -> Table:
    table = Table(title=f"Scan types — {plugin.name}", title_style="bold magenta", header_style="bold")
    table.add_column("Scan type", style="cyan")
    table.add_column("Description")
    current = plugin.scan_type_value()
    for name, desc in plugin.scan_types.items():
        label = f"[bold green]➤ {name}[/bold green]" if name == current else name
        table.add_row(label, escape(desc))
    return table


def targets_table(manager: TargetManager) -> Table:
    table = Table(title=f"Targets ({len(manager)})", title_style="bold magenta", header_style="bold")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Target", style="cyan")
    for i, target in enumerate(manager.all(), 1):
        table.add_row(str(i), escape(target))
    return table


def results_table(results: list[ScanResult]) -> Table:
    table = Table(title=f"Scan Results ({len(results)})", title_style="bold magenta", header_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Time", style="dim")
    table.add_column("Plugin", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Exit", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Output file", style="dim")
    for i, r in enumerate(results, 1):
        when = r.started_at.split("T")[1][:8] if "T" in r.started_at else r.started_at
        table.add_row(
            str(i), when, r.plugin_id, escape(r.target), r.status.styled,
            escape(str(r.exit_code)), f"{r.duration:.1f}s", escape(r.output_file or "-"),
        )
    return table


def show_result(result: ScanResult, index: int | None = None) -> None:
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold cyan", justify="right")
    meta.add_column()
    meta.add_row("Plugin", f"{escape(result.plugin_name)} ({escape(result.plugin_id)})")
    meta.add_row("Target", escape(result.target))
    meta.add_row("Status", result.status.styled)
    meta.add_row("Exit code", escape(str(result.exit_code)))
    meta.add_row("Started", escape(result.started_at))
    meta.add_row("Duration", f"{result.duration:.1f}s")
    meta.add_row("Command", escape(shlex.join(result.command)))
    if result.output_file:
        meta.add_row("Output file", escape(result.output_file))
    if result.error:
        meta.add_row("Error", f"[yellow]{escape(result.error)}[/yellow]")
    title = f"[bold]Result {index}[/bold]" if index else "[bold]Result[/bold]"
    console.print(Panel(meta, title=title, border_style="blue"))
    body = result.stdout.strip() or "(no captured output)"
    if len(body) > 50_000:
        body = body[:50_000] + "\n[... truncated ...]"
    console.print(Panel(Text(body), title="Captured output", border_style="dim"))


def tool_status_table(registry: ToolRegistry) -> Table:
    table = Table(title="External Tool Status", title_style="bold magenta", header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Location / Install")
    table.add_column("Docs", style="dim")
    for name in sorted(TOOLS):
        info_ = TOOLS[name]
        path = registry.which(name)
        if path:
            status, location = "[green]✔ installed[/green]", path
        else:
            status = "[red]✘ missing[/red]"
            location = next(iter(info_.get("install", {}).values()), f"see `tool {name}`")
        table.add_row(name, status, escape(location), info_.get("docs", ""))
    return table


def tool_detail_panel(name: str, registry: ToolRegistry) -> None:
    info_ = TOOLS.get(name)
    if not info_:
        warning(f"Unknown tool '{name}'. Known tools: {', '.join(sorted(TOOLS))}")
        return
    lines = [info_["description"], ""]
    path = registry.which(name)
    if path:
        lines.append(f"Status: [green]installed[/green] ({escape(path)})")
    else:
        lines.append("Status: [red]not found on PATH[/red]")
    if info_.get("install"):
        lines.append("\n[bold]Install:[/bold]")
        lines += [f"  • {escape(k)}: {escape(v)}" for k, v in info_["install"].items()]
    if info_.get("troubleshoot"):
        lines.append("\n[bold]Troubleshooting:[/bold]")
        lines += [f"  • {escape(t)}" for t in info_["troubleshoot"]]
    if info_.get("docs"):
        lines.append(f"\nDocs: {info_['docs']}")
    console.print(Panel("\n".join(lines), title=f"[bold]{escape(name)}[/bold]", border_style="blue"))


def missing_tools_panel(missing: Iterable[str]) -> None:
    lines: list[str] = []
    for tool in missing:
        info_ = TOOLS.get(tool, {})
        lines.append(f"[bold red]{escape(tool)}[/bold red] is not installed or not on PATH.")
        installs = info_.get("install", {})
        if installs:
            lines.append("  Install it with:")
            for os_name, cmd in installs.items():
                lines.append(f"    • [cyan]{escape(os_name)}:[/cyan] {escape(cmd)}")
        if info_.get("docs"):
            lines.append(f"  Docs: {info_['docs']}")
        lines.append("")
    console.print(Panel("\n".join(lines), title="[bold red]Missing tools[/bold red]", border_style="red"))


def show_troubleshooting(tool: str, outcome: CommandOutcome) -> None:
    """Rendered whenever a wrapped tool fails, times out, or cannot start."""
    lines: list[str] = []
    if outcome.timed_out:
        lines.append(
            "• The command was killed after exceeding the timeout. Raise it with "
            "[cyan]set timeout 3600[/cyan] or [cyan]config set runner.timeout 3600[/cyan]."
        )
    if outcome.error:
        lines.append(f"• Error: [yellow]{escape(outcome.error)}[/yellow]")
    if outcome.exit_code not in (None, 0):
        lines.append(f"• [bold]{escape(tool)}[/bold] exited with code [red]{outcome.exit_code}[/red].")
    tips = TOOLS.get(tool, {}).get("troubleshoot") or GENERIC_TROUBLESHOOT
    lines.append("\n[bold]Troubleshooting checklist:[/bold]")
    lines += [f"• {escape(tip)}" for tip in tips]
    lines.append(
        "\nRe-run the command manually to inspect raw errors:\n"
        f"  [cyan]{escape(shlex.join(outcome.command))}[/cyan]"
    )
    docs = TOOLS.get(tool, {}).get("docs")
    if docs:
        lines.append(f"Documentation: {docs}")
    console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold yellow]Troubleshooting {escape(tool)}[/bold yellow]",
            border_style="yellow",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Execution context shared with plugins
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReconContext:
    """Everything a plugin needs to do its job, in one place."""

    config: Config
    logger: logging.Logger
    tools: ToolRegistry
    runner: CommandRunner
    targets: TargetManager
    history: HistoryStore
    results: list[ScanResult] = field(default_factory=list)

    def record_result(self, result: ScanResult) -> None:
        """Store a finished scan result and log it."""
        self.results.append(result)
        self.logger.info(
            "result: plugin=%s target=%s status=%s exit=%s duration=%.1fs",
            result.plugin_id, result.target, result.status.value,
            result.exit_code, result.duration,
        )

    def output_path(self, plugin_id: str, label: str, extension: str = "txt") -> Path:
        """Build a unique, timestamped output file path inside the output dir."""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", label)[:60].strip("_") or "scan"
        directory = self.config.expanded_path("paths.output")
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{plugin_id}_{safe}_{stamp}.{extension}"

    def temp_target_file(self, plugin_id: str) -> Path:
        """Write the current target list to disk for tools accepting -dL style files."""
        directory = self.config.expanded_path("paths.output")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{plugin_id}_targets_{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        return self.targets.write_list_file(path)


# ─────────────────────────────────────────────────────────────────────────────
# Plugin framework
# ─────────────────────────────────────────────────────────────────────────────

class BasePlugin(ABC):
    """Base class every ReconForge plugin inherits from.

    To add a new tool, subclass this, decorate with ``@plugin`` and implement
    :meth:`build_command`. Optionally define :attr:`scan_types` presets and
    override :meth:`run`, :meth:`validate` or :meth:`save_output`.
    """

    #: Unique identifier used with `use <id>` and in reports.
    id: str = ""
    #: Human friendly name shown in menus and reports.
    name: str = ""
    #: One-line description.
    description: str = ""
    #: Menu grouping (e.g. "Content Discovery").
    category: str = "General"
    #: External binaries the plugin needs on PATH.
    required_tools: tuple[str, ...] = ()
    #: Alternate binary names to try, per required tool.
    tool_aliases: dict[str, tuple[str, ...]] = {}
    #: Whether the plugin needs entries in the target list.
    requires_targets: bool = True
    #: Default option values; users override them with `set key value`.
    default_options: dict[str, Any] = {}
    #: Available scan presets: name -> human description (empty = no presets).
    scan_types: dict[str, str] = {}

    def __init__(self) -> None:
        self.options: dict[str, Any] = dict(self.default_options)
        self._last_output: Path | None = None

    # -- options -----------------------------------------------------------
    def option(self, key: str, default: Any = None) -> Any:
        value = self.options.get(key)
        return default if value in (None, "") else value

    def set_option(self, key: str, value: str) -> None:
        self.options[key] = value

    def unset_option(self, key: str) -> bool:
        if key in self.options:
            self.options[key] = self.default_options.get(key, "")
            return True
        return False

    def scan_type_value(self) -> str:
        """Current scan_type option, lower-cased."""
        return str(self.option("scan_type", "")).lower()

    def effective_timeout(self, ctx: ReconContext) -> int:
        try:
            return int(self.option("timeout", 0)) or int(ctx.config.get("runner.timeout", 1800))
        except (TypeError, ValueError):
            return int(ctx.config.get("runner.timeout", 1800))

    # -- tooling -------------------------------------------------------------
    @property
    def primary_tool(self) -> str:
        """Tool whose troubleshooting advice is shown on failure."""
        return self.required_tools[0] if self.required_tools else self.id

    def missing_tools(self, registry: ToolRegistry) -> list[str]:
        missing = []
        for tool in self.required_tools:
            candidates = self.tool_aliases.get(tool, (tool,))
            if not registry.which_any(candidates):
                missing.append(tool)
        return missing

    def resolve_tool(self, registry: ToolRegistry, name: str) -> str:
        """Return the first available binary name for *name*."""
        candidates = self.tool_aliases.get(name, (name,))
        return registry.which_any(candidates) or candidates[0]

    # -- validation ------------------------------------------------------------
    def check_scan_type(self) -> str | None:
        """Generic validation of the scan_type option against declared presets."""
        if not self.scan_types:
            return None
        chosen = self.scan_type_value()
        if chosen not in self.scan_types:
            valid = ", ".join(sorted(self.scan_types))
            return (f"Unknown scan_type '{chosen or '(none)'}'. "
                    f"Valid scan types: {valid}. Use `scans` for descriptions.")
        return None

    def validate(self, ctx: ReconContext) -> str | None:
        """Subclass hook: return an error message to block the run, else None."""
        return None

    def preflight(self, ctx: ReconContext) -> bool:
        """Check tools, targets and plugin-specific rules. Displays problems."""
        missing = self.missing_tools(ctx.tools)
        if missing:
            missing_tools_panel(missing)
            return False
        if self.requires_targets and not ctx.targets.has_targets:
            warning("No targets set. Use [bold]add <target>[/bold] or [bold]load <file>[/bold] first.")
            return False
        problem = self.check_scan_type() or self.validate(ctx)
        if problem:
            warning(problem)
            return False
        return True

    # -- helpers -----------------------------------------------------------------
    @staticmethod
    def ensure_scheme(target: str, default: str = "http://") -> str:
        """Prefix http:// when a URL target has no scheme."""
        return target if target.startswith(("http://", "https://")) else default + target

    @staticmethod
    def strip_scheme(target: str) -> str:
        """Reduce a URL/host to a bare domain for DNS-style tools."""
        target = target.split("://", 1)[-1]
        return target.split("/", 1)[0].split(":", 1)[0]

    @staticmethod
    def is_truthy(value: Any) -> bool:
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    # -- execution -----------------------------------------------------------------
    @abstractmethod
    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        """Compose the CLI invocation for one target (or None if targetless)."""

    def save_output(self, ctx: ReconContext, target_label: str, output: str) -> str | None:
        """Hook: return the path of a produced output file, if any."""
        return None

    def save_captured_output(self, ctx: ReconContext, label: str, output: str) -> str | None:
        """Write captured stdout to a timestamped file (for tools without -o)."""
        if not output.strip():
            return None
        path = ctx.output_path(self.id, label)
        path.write_text(output, encoding="utf-8")
        return str(path)

    def execute(self, ctx: ReconContext, command: list[str], target_label: str) -> ScanResult:
        """Run one command through the shared runner and record the result."""
        console.rule(f"[bold blue]{self.id}[/bold blue] :: [green]{escape(target_label)}[/green]")
        started = utc_now_iso()
        outcome = ctx.runner.run(command, timeout=self.effective_timeout(ctx))

        if outcome.timed_out:
            status = ScanStatus.TIMEOUT
        elif outcome.exit_code == 0:
            status = ScanStatus.SUCCESS
        else:
            status = ScanStatus.FAILED

        result = ScanResult(
            plugin_id=self.id,
            plugin_name=self.name,
            target=target_label,
            command=command,
            status=status,
            exit_code=outcome.exit_code,
            started_at=started,
            duration=outcome.duration,
            stdout=outcome.stdout,
            error=outcome.error,
        )
        result.output_file = self.save_output(ctx, target_label, outcome.stdout)
        ctx.record_result(result)
        ctx.history.add(f"tool:{shlex.join(command)}")

        if not outcome.ok:
            show_troubleshooting(self.primary_tool, outcome)
        else:
            success(
                f"[green]{self.id}[/green] finished against "
                f"[bold]{escape(target_label)}[/bold] in {outcome.duration:.1f}s"
            )
        return result

    def run(self, ctx: ReconContext) -> list[ScanResult]:
        """Default execution flow: preflight, then one command per target."""
        if not self.preflight(ctx):
            return []
        return self.run_targets(ctx)

    def run_targets(self, ctx: ReconContext) -> list[ScanResult]:
        """One command per target (no preflight — call from run())."""
        targets: list[str | None] = ctx.targets.all() if self.requires_targets else [None]
        results: list[ScanResult] = []
        if len(targets) > 1:
            with progress() as bar:
                task = bar.add_task(self.id, total=len(targets))
                for target in targets:
                    results.append(self._run_one(ctx, target))
                    bar.advance(task)
        else:
            for target in targets:
                results.append(self._run_one(ctx, target))
        return results

    def _run_one(self, ctx: ReconContext, target: str | None) -> ScanResult:
        command = self.build_command(ctx, target)
        return self.execute(ctx, command, target or self.name)


# Plugin registry ----------------------------------------------------------------

PLUGIN_CLASSES: list[type[BasePlugin]] = []


def plugin(cls: type[BasePlugin]) -> type[BasePlugin]:
    """Class decorator registering a plugin for auto-discovery."""
    PLUGIN_CLASSES.append(cls)
    return cls


def discover_plugins() -> dict[str, BasePlugin]:
    """Instantiate every registered plugin, keyed by id."""
    plugins: dict[str, BasePlugin] = {}
    for cls in PLUGIN_CLASSES:
        instance = cls()
        if instance.id:
            plugins.setdefault(instance.id, instance)
    return dict(sorted(plugins.items()))


# ─────────────────────────────────────────────────────────────────────────────
# Bundled plugins
# ─────────────────────────────────────────────────────────────────────────────

@plugin
class NmapPlugin(BasePlugin):
    """Run Nmap against all configured targets in a single invocation."""

    id = "nmap"
    name = "Nmap Port Scanner"
    description = "Port scanning, service detection and host discovery with Nmap."
    category = "Port Scanning"
    required_tools = ("nmap",)

    scan_types = {
        "quick": "Fast scan of the 100 most common ports (-F).",
        "top100": "TCP connect scan of the top 100 ports.",
        "top1000": "TCP connect scan of the top 1000 ports (default Nmap coverage).",
        "full": "All 65535 TCP ports (-p-) — slow but thorough.",
        "version": "Service version detection + default scripts (-sV -sC) on top 1000.",
        "syn": "Stealth SYN scan (-sS) on top 1000 — requires root.",
        "udp": "Top 25 UDP ports (-sU) — requires root.",
        "udp_full": "All UDP ports (-sU -p-) — very slow, requires root.",
        "aggressive": "OS + version + scripts + traceroute (-A) — loud, requires root.",
        "os": "OS detection only (-O) on top 1000 — requires root.",
        "vuln": "NSE vulnerability scripts (--script vuln) with version detection.",
        "ping": "Host discovery only (-sn), no port scan.",
        "slow": "Slow & thorough: -T2 -sV -sC -p- (IDS evasion timing).",
        "custom": "You choose: set `ports` and/or `extra_args`.",
    }

    PRESET_FLAGS = {
        "quick": ["-F"],
        "top100": ["--top-ports", "100"],
        "top1000": ["--top-ports", "1000"],
        "full": ["-p-"],
        "version": ["-sV", "-sC", "--top-ports", "1000"],
        "syn": ["-sS", "--top-ports", "1000"],
        "udp": ["-sU", "--top-ports", "25"],
        "udp_full": ["-sU", "-p-"],
        "aggressive": ["-A"],
        "os": ["-O", "--top-ports", "1000"],
        "vuln": ["-sV", "--script", "vuln", "--top-ports", "1000"],
        "ping": ["-sn"],
        "slow": ["-T2", "-sV", "-sC", "-p-"],
        "custom": [],
    }

    default_options = {
        "scan_type": "quick",
        "ports": "",
        "extra_args": "",
        "timeout": "1800",
    }

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "quick"
        command = [self.resolve_tool(ctx.tools, "nmap"), *self.PRESET_FLAGS[scan]]
        if self.option("ports"):
            command += ["-p", str(self.option("ports"))]
        self._last_output = ctx.output_path(self.id, "scan")
        command += ["--reason", "-oN", str(self._last_output)]
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        command += [self.strip_scheme(t) for t in ctx.targets.all()]
        return command

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None

    def run(self, ctx: ReconContext) -> list[ScanResult]:
        """Nmap accepts many targets at once, so run a single combined scan."""
        if not self.preflight(ctx):
            return []
        command = self.build_command(ctx, None)
        label = ", ".join(self.strip_scheme(t) for t in ctx.targets.all())
        return [self.execute(ctx, command, label)]


@plugin
class GobusterPlugin(BasePlugin):
    """Directory / DNS / vhost / fuzz brute-forcing with Gobuster."""

    id = "gobuster"
    name = "Gobuster Bruteforce"
    description = "Directory, DNS, vhost and FUZZ brute-forcing with Gobuster."
    category = "Content Discovery"
    required_tools = ("gobuster",)

    scan_types = {
        "dir": "Standard directory/file brute force with `extensions`.",
        "dir_big": "Directories with a large extension set (backups, archives, logs…).",
        "dir_api": "API-focused extensions (json, xml, yaml, conf…).",
        "dns": "Subdomain brute force via DNS (uses the subdomain wordlist).",
        "vhost": "Virtual host discovery against the target.",
        "fuzz": "Generic FUZZ keyword fuzzing (set `fuzz_path`, default /FUZZ).",
    }

    default_options = {
        "scan_type": "dir",
        "wordlist": "",
        "extensions": "php,html,txt",
        "threads": "20",
        "status_codes": "",
        "domain": "",
        "user_agent": "",
        "cookies": "",
        "fuzz_path": "/FUZZ",
        "extra_args": "",
        "timeout": "1800",
    }

    def _wordlist_for(self, ctx: ReconContext, scan: str) -> str:
        if scan in ("dns", "vhost"):
            return str(self.option("wordlist", "") or ctx.config.get("wordlists.subdomains", ""))
        return str(self.option("wordlist", "") or ctx.config.get("wordlists.directory", ""))

    def validate(self, ctx: ReconContext) -> str | None:
        scan = self.scan_type_value() or "dir"
        wordlist = self._wordlist_for(ctx, scan)
        if not wordlist:
            key = "wordlists.subdomains" if scan in ("dns", "vhost") else "wordlists.directory"
            return f"No wordlist configured. Set `wordlist` or `config set {key} <path>`."
        if not Path(wordlist).expanduser().is_file():
            return (f"Wordlist not found: {wordlist}. Install SecLists "
                    "(https://github.com/danielmiessler/SecLists) or fix the configured path.")
        if scan == "fuzz" and "FUZZ" not in str(self.option("fuzz_path", "/FUZZ")):
            return "`fuzz_path` must contain the FUZZ keyword."
        return None

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "dir"
        tool = self.resolve_tool(ctx.tools, "gobuster")
        domain = str(self.option("domain", "")) or self.strip_scheme(target or "")
        self._last_output = ctx.output_path(self.id, self.strip_scheme(target or "scan"))
        threads = str(self.option("threads", "20"))
        wordlist = str(Path(self._wordlist_for(ctx, scan)).expanduser())

        if scan == "dns":
            command = [tool, "dns", "-d", domain, "-w", wordlist,
                       "-t", threads, "-o", str(self._last_output)]
        elif scan == "vhost":
            command = [tool, "vhost", "-u", self.ensure_scheme(target or ""),
                       "--domain", domain, "-w", wordlist,
                       "-t", threads, "-o", str(self._last_output)]
        elif scan == "fuzz":
            url = self.ensure_scheme(target or "") + str(self.option("fuzz_path", "/FUZZ"))
            command = [tool, "fuzz", "-u", url, "-w", wordlist,
                       "-t", threads, "-o", str(self._last_output)]
        else:  # dir / dir_big / dir_api
            extensions = {
                "dir": str(self.option("extensions", "php,html,txt")),
                "dir_big": "php,html,htm,asp,aspx,js,css,txt,json,xml,bak,old,zip,log,sql",
                "dir_api": "json,xml,yaml,yml,conf,ini,log,txt",
            }[scan]
            command = [tool, "dir", "-u", self.ensure_scheme(target or ""),
                       "-w", wordlist, "-t", threads, "-x", extensions,
                       "-o", str(self._last_output)]

        if self.option("status_codes"):
            command += ["-s", str(self.option("status_codes"))]
        if self.option("user_agent"):
            command += ["-a", str(self.option("user_agent"))]
        if self.option("cookies"):
            command += ["-c", str(self.option("cookies"))]
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None


@plugin
class FfufPlugin(BasePlugin):
    """Web fuzzing with FFUF across many scan profiles."""

    id = "ffuf"
    name = "FFUF Web Fuzzer"
    description = "High-speed web fuzzing with ffuf (FUZZ keyword driven)."
    category = "Content Discovery"
    required_tools = ("ffuf",)

    scan_types = {
        "dirs": "Path/directory fuzzing at `fuzz_path` (default /FUZZ).",
        "files": "File fuzzing with common extensions.",
        "recursive": "Recursive directory fuzzing (`recursion_depth`).",
        "vhost": "Virtual-host fuzzing via Host: FUZZ.<domain> header.",
        "params": "GET parameter name discovery (?FUZZ=1).",
        "param_value": "Fuzz the value of `param` (?param=FUZZ).",
        "api": "API endpoint fuzzing with json/xml/yaml extensions.",
        "post": "POST body fuzzing (FUZZ=reconforg).",
    }

    default_options = {
        "scan_type": "dirs",
        "wordlist": "",
        "fuzz_path": "/FUZZ",
        "param": "id",
        "extensions": "php,html,txt",
        "match_codes": "200,204,301,302,307,401,403,500",
        "filter_codes": "",
        "recursion_depth": "2",
        "threads": "40",
        "extra_args": "",
        "timeout": "1800",
    }

    def _wordlist(self, ctx: ReconContext) -> str:
        return str(self.option("wordlist", "") or ctx.config.get("wordlists.directory", ""))

    def validate(self, ctx: ReconContext) -> str | None:
        scan = self.scan_type_value() or "dirs"
        raw = self._wordlist(ctx)
        if not raw:
            return ("No wordlist configured. Set the `wordlist` option or run "
                    "`config set wordlists.directory <path>`.")
        if not Path(raw).expanduser().is_file():
            return f"Wordlist not found: {raw}. Fix the path or install SecLists."
        if scan == "param_value" and not self.option("param"):
            return "scan_type `param_value` needs the `param` option (e.g. `set param id`)."
        if scan in ("dirs", "files", "recursive", "api", "post") and \
                "FUZZ" not in str(self.option("fuzz_path", "/FUZZ")):
            return "`fuzz_path` must contain the FUZZ keyword, e.g. `/FUZZ`."
        return None

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "dirs"
        tool = self.resolve_tool(ctx.tools, "ffuf")
        domain = self.strip_scheme(target or "")
        base = self.ensure_scheme(target or "")
        fuzz_path = str(self.option("fuzz_path", "/FUZZ"))
        wordlist = str(Path(self._wordlist(ctx)).expanduser())
        self._last_output = ctx.output_path(self.id, domain or "scan", "json")

        command = [tool, "-noninteractive"]
        if scan == "vhost":
            command += ["-u", base, "-H", f"Host: FUZZ.{domain}", "-w", wordlist]
        elif scan == "params":
            command += ["-u", f"{base}/?FUZZ=1", "-w", wordlist]
        elif scan == "param_value":
            param = str(self.option("param", "id"))
            command += ["-u", f"{base}/?{param}=FUZZ", "-w", wordlist]
        elif scan == "post":
            command += ["-u", base + fuzz_path, "-w", wordlist,
                        "-X", "POST", "-d", "FUZZ=reconforg"]
        else:
            command += ["-u", base + fuzz_path, "-w", wordlist]

        if scan == "files":
            command += ["-e", str(self.option("extensions", "php,html,txt"))]
        elif scan == "api":
            command += ["-e", "json,xml,yaml,yml,txt"]
        elif scan == "recursive":
            command += ["-recursion", "-recursion-depth",
                        str(self.option("recursion_depth", "2"))]

        command += [
            "-mc", str(self.option("match_codes")),
            "-t", str(self.option("threads", "40")),
            "-o", str(self._last_output), "-of", "json",
        ]
        if self.option("filter_codes"):
            command += ["-fc", str(self.option("filter_codes"))]
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None


@plugin
class DirsearchPlugin(BasePlugin):
    """Web path scanning with dirsearch profiles."""

    id = "dirsearch"
    name = "Dirsearch Web Path Scanner"
    description = "Classic web path scanning with dirsearch."
    category = "Content Discovery"
    required_tools = ("dirsearch",)
    tool_aliases = {"dirsearch": ("dirsearch", "dirsearch.py")}

    scan_types = {
        "standard": "Default extension set (php, html, txt).",
        "full": "Wide extension set covering backups, configs and archives.",
        "api": "API extensions (json, xml, yaml, asmx, wsdl…).",
        "backup": "Backup/archive extensions only.",
        "recursive": "Standard set with recursion (-R).",
        "custom": "Your own `wordlist` (required) and extensions.",
    }

    EXTENSION_PROFILES = {
        "standard": "php,html,txt",
        "full": "php,html,htm,asp,aspx,js,css,txt,json,xml,yml,bak,old,zip,tar.gz,log,sql,inc",
        "api": "json,xml,yaml,yml,asmx,svc,wsdl,txt",
        "backup": "bak,old,zip,tar,tar.gz,sql,7z,rar",
        "recursive": "php,html,txt",
    }

    default_options = {
        "scan_type": "standard",
        "extensions": "",
        "wordlist": "",
        "exclude_status": "",
        "threads": "25",
        "extra_args": "",
        "timeout": "1800",
    }

    def validate(self, ctx: ReconContext) -> str | None:
        scan = self.scan_type_value() or "standard"
        if scan == "custom":
            raw = str(self.option("wordlist", ""))
            if not raw:
                return "scan_type `custom` requires the `wordlist` option."
            if not Path(raw).expanduser().is_file():
                return f"Wordlist not found: {raw}."
        return None

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "standard"
        tool = self.resolve_tool(ctx.tools, "dirsearch")
        self._last_output = ctx.output_path(self.id, self.strip_scheme(target or "scan"))
        extensions = str(self.option("extensions", "")) or self.EXTENSION_PROFILES.get(scan, "")

        command = [
            tool,
            "-u", self.ensure_scheme(target or ""),
            "-t", str(self.option("threads", "25")),
            "-o", str(self._last_output),
            "--format", "plain",
        ]
        if extensions:
            command += ["-e", extensions]
        if scan == "recursive":
            command.append("-R")
        if self.option("wordlist"):
            command += ["-w", str(Path(str(self.option("wordlist"))).expanduser())]
        if self.option("exclude_status"):
            command += ["-x", str(self.option("exclude_status"))]
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None


@plugin
class SubfinderPlugin(BasePlugin):
    """Passive subdomain enumeration; batches many domains via -dL."""

    id = "subfinder"
    name = "Subfinder Subdomain Enumeration"
    description = "Fast passive subdomain enumeration; supports batch domain lists."
    category = "Subdomain Enumeration"
    required_tools = ("subfinder",)

    scan_types = {
        "quick": "Fast passive run with default sources.",
        "all": "Include all subdomains (-all), including wildcard results.",
        "sources": "Only the sources listed in `sources` (comma separated).",
        "stealth": "Rate-limited run (`rate_limit`, default 2 req/s) for noisy targets.",
        "custom": "Plain run — shape it entirely with `extra_args`.",
    }

    default_options = {
        "scan_type": "quick",
        "sources": "",
        "threads": "",
        "rate_limit": "2",
        "extra_args": "",
        "timeout": "900",
    }

    def validate(self, ctx: ReconContext) -> str | None:
        if self.scan_type_value() == "sources" and not self.option("sources"):
            return ("scan_type `sources` requires the `sources` option "
                    "(e.g. `set sources crtsh,hackertarget`).")
        return None

    def _type_flags(self, ctx: ReconContext) -> list[str]:
        scan = self.scan_type_value() or "quick"
        flags: list[str] = []
        if scan == "all":
            flags.append("-all")
        elif scan == "sources":
            flags += ["-s", str(self.option("sources"))]
        elif scan == "stealth":
            flags += ["-rl", str(self.option("rate_limit", "2"))]
        if self.option("threads"):
            flags += ["-t", str(self.option("threads"))]
        elif scan == "quick":
            flags += ["-t", "25"]
        return flags

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        """Single-domain invocation (satisfies the abstract contract)."""
        self._last_output = ctx.output_path(self.id, self.strip_scheme(target or "subdomains"))
        command = [
            self.resolve_tool(ctx.tools, "subfinder"),
            "-d", self.strip_scheme(target or ""),
            "-silent",
            "-o", str(self._last_output),
        ]
        return command + self._type_flags(ctx)

    def run(self, ctx: ReconContext) -> list[ScanResult]:
        """One domain → plain run; many domains → batched via a -dL list file."""
        if not self.preflight(ctx):
            return []
        targets = ctx.targets.all()
        if len(targets) == 1:
            return [self._run_one(ctx, targets[0])]
        self._last_output = ctx.output_path(self.id, "subdomains")
        list_file = ctx.temp_target_file(self.id)
        command = [
            self.resolve_tool(ctx.tools, "subfinder"),
            "-dL", str(list_file),
            "-silent",
            "-o", str(self._last_output),
        ]
        command += self._type_flags(ctx)
        return [self.execute(ctx, command, f"{len(targets)} domains (batch)")]

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None


@plugin
class AssetfinderPlugin(BasePlugin):
    """Subdomain discovery with assetfinder."""

    id = "assetfinder"
    name = "Assetfinder Subdomain Discovery"
    description = "Find related domains and subdomains with assetfinder."
    category = "Subdomain Enumeration"
    required_tools = ("assetfinder",)

    scan_types = {
        "subs": "Subdomains only (--subs-only) — the usual recon choice.",
        "related": "All related domains assetfinder can find (noisier).",
    }

    default_options = {
        "scan_type": "subs",
        "extra_args": "",
        "timeout": "600",
    }

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        command = [self.resolve_tool(ctx.tools, "assetfinder")]
        if (self.scan_type_value() or "subs") == "subs":
            command.append("--subs-only")
        command.append(self.strip_scheme(target or ""))
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return self.save_captured_output(ctx, target_label, output)


@plugin
class AmassPlugin(BasePlugin):
    """Attack surface mapping with OWASP Amass."""

    id = "amass"
    name = "OWASP Amass Enumeration"
    description = "In-depth attack surface mapping and subdomain enumeration."
    category = "Subdomain Enumeration"
    required_tools = ("amass",)

    scan_types = {
        "passive": "Passive collection only (no direct traffic to the target).",
        "active": "Active collection: DNS brute via resolvers, scraping, certs.",
        "brute": "Active brute force with a subdomain wordlist.",
        "brute_passive": "Brute force layered on passive results (quieter).",
        "alterations": "Discover altered subdomains of existing findings.",
    }

    default_options = {
        "scan_type": "passive",
        "wordlist": "",
        "max_dns_queries": "",
        "extra_args": "",
        "timeout": "3600",
    }

    def _brute_wordlist(self, ctx: ReconContext) -> str:
        return str(self.option("wordlist", "") or ctx.config.get("wordlists.subdomains", ""))

    def validate(self, ctx: ReconContext) -> str | None:
        scan = self.scan_type_value() or "passive"
        if scan in ("brute", "brute_passive"):
            wl = self._brute_wordlist(ctx)
            if not wl:
                return ("Brute presets need a wordlist: set `wordlist` or "
                        "`config set wordlists.subdomains <path>`.")
            if not Path(wl).expanduser().is_file():
                return f"Wordlist not found: {wl}."
        return None

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "passive"
        domain = self.strip_scheme(target or "")
        self._last_output = ctx.output_path(self.id, domain)
        command = [self.resolve_tool(ctx.tools, "amass"), "enum"]
        if scan in ("passive", "brute_passive"):
            command.append("-passive")
        if scan in ("brute", "brute_passive"):
            command.append("-brute")
            command += ["-w", str(Path(self._brute_wordlist(ctx)).expanduser())]
        if scan == "alterations":
            command.append("-alterations")
        if self.option("max_dns_queries"):
            command += ["-max-dns-queries", str(self.option("max_dns_queries"))]
        command += ["-d", domain, "-o", str(self._last_output)]
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return str(self._last_output) if self._last_output else None


@plugin
class DnsLookupPlugin(BasePlugin):
    """DNS record lookups via dig or nslookup, with multi-record passes."""

    id = "dns"
    name = "DNS Lookup (dig / nslookup)"
    description = "Query DNS records with dig or nslookup."
    category = "DNS"
    required_tools = ("dig", "nslookup")  # informational; only the selected one is enforced
    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "CAA", "ANY")
    COMMON_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

    scan_types = {
        "single": "Query the chosen `record_type`.",
        "common": "Query A, AAAA, CNAME, MX, NS, TXT, SOA, CAA in one pass.",
        "trace": "Full delegation trace (dig +trace).",
        "axfr": "Attempt a zone transfer (authorized scope only).",
        "reverse": "Reverse PTR lookup (pass an IP as the target).",
    }

    default_options = {
        "scan_type": "single",
        "tool": "dig",
        "record_type": "A",
        "server": "",
        "extra_args": "",
        "timeout": "120",
    }

    @property
    def primary_tool(self) -> str:
        return str(self.option("tool", "dig"))

    def missing_tools(self, registry: ToolRegistry) -> list[str]:
        chosen = str(self.option("tool", "dig"))
        return [] if registry.which_any((chosen,)) else [chosen]

    def validate(self, ctx: ReconContext) -> str | None:
        tool = str(self.option("tool", "dig")).lower()
        if tool not in ("dig", "nslookup"):
            return "`tool` must be either 'dig' or 'nslookup'."
        scan = self.scan_type_value() or "single"
        if tool == "nslookup" and scan in ("trace", "axfr", "reverse"):
            return f"scan_type '{scan}' requires `set tool dig`."
        rtype = str(self.option("record_type", "A")).upper()
        if rtype not in self.RECORD_TYPES:
            return f"Unknown record_type '{rtype}'. Valid: {', '.join(self.RECORD_TYPES)}"
        return None

    def _record_command(self, ctx: ReconContext, target: str | None, rtype: str) -> list[str]:
        tool = str(self.option("tool", "dig")).lower()
        domain = self.strip_scheme(target or "")
        server = str(self.option("server", ""))
        scan = self.scan_type_value() or "single"

        if tool == "nslookup":
            command = [self.resolve_tool(ctx.tools, "nslookup"), f"-type={rtype}", domain]
            if server:
                command.append(server)
            return command

        dig = self.resolve_tool(ctx.tools, "dig")
        if scan == "reverse":
            command = [dig, "-x", domain, "+time=3", "+tries=1"]
        elif scan == "axfr":
            command = [dig, "AXFR", domain, "+time=5", "+tries=1"]
        elif scan == "trace":
            command = [dig, "+trace", "+time=3", "+tries=1", domain, rtype]
        else:
            command = [dig, "+noall", "+answer", "+time=3", "+tries=1", domain, rtype]
        if server:
            command.insert(1, f"@{server}")
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        return self._record_command(ctx, target, str(self.option("record_type", "A")).upper())

    def run(self, ctx: ReconContext) -> list[ScanResult]:
        if not self.preflight(ctx):
            return []
        if self.scan_type_value() == "common":
            results: list[ScanResult] = []
            pairs = [(t, rt) for t in ctx.targets.all() for rt in self.COMMON_TYPES]
            with progress() as bar:
                task = bar.add_task("dns common", total=len(pairs))
                for target, rtype in pairs:
                    label = f"{self.strip_scheme(target)} [{rtype}]"
                    results.append(self.execute(ctx, self._record_command(ctx, target, rtype), label))
                    bar.advance(task)
            return results
        return self.run_targets(ctx)

    def save_output(self, ctx, target_label, output):
        return self.save_captured_output(ctx, target_label, output)


@plugin
class WhoisPlugin(BasePlugin):
    """WHOIS registration lookups."""

    id = "whois"
    name = "WHOIS Lookup"
    description = "Registration data lookups for domains and IPs."
    category = "DNS"
    required_tools = ("whois",)

    scan_types = {
        "standard": "Domain lookup (schemes/paths stripped).",
        "ip": "IP/netblock lookup (target passed as-is).",
    }

    default_options = {
        "scan_type": "standard",
        "server": "",
        "extra_args": "",
        "timeout": "120",
    }

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "standard"
        query = (target or "") if scan == "ip" else self.strip_scheme(target or "")
        command = [self.resolve_tool(ctx.tools, "whois")]
        if self.option("server"):
            command += ["-h", str(self.option("server"))]
        command.append(query)
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        return self.save_captured_output(ctx, target_label, output)


@plugin
class HashcatPlugin(BasePlugin):
    """Hash/password cracking with hashcat (does not require targets)."""

    id = "hashcat"
    name = "Hashcat Password Recovery"
    description = ("Crack captured hashes with hashcat. Common modes: 0=MD5, 100=SHA1, "
                   "500=MD5crypt, 1000=NTLM, 1800=sha512crypt, 22000=WPA-PBKDF2.")
    category = "Password Cracking"
    required_tools = ("hashcat",)
    requires_targets = False

    scan_types = {
        "dictionary": "Straight dictionary attack (-a 0).",
        "dictionary_rules": "Dictionary + rules file (`rules_file`).",
        "bruteforce": "Mask brute force (-a 3) using `mask`.",
        "combinator": "Combine two wordlists (-a 1, needs `wordlist2`).",
        "hybrid_append": "Wordlist + mask appended (-a 6).",
        "hybrid_prepend": "Mask + wordlist prepended (-a 7).",
        "benchmark": "Benchmark the selected `mode` (no hashes needed).",
        "show": "Print already-cracked hashes from the potfile.",
    }

    ATTACK_MODES = {
        "dictionary": "0",
        "dictionary_rules": "0",
        "bruteforce": "3",
        "combinator": "1",
        "hybrid_append": "6",
        "hybrid_prepend": "7",
    }

    default_options = {
        "scan_type": "dictionary",
        "hash_file": "",
        "wordlist": "",
        "wordlist2": "",
        "rules_file": DEFAULT_RULES_PATH,
        "mask": "?a?a?a?a?a?a?a?a",
        "mode": "0",
        "device_type": "",
        "force": "false",
        "extra_args": "",
        "timeout": "3600",
    }

    def _hash_path(self) -> Path:
        return Path(str(self.option("hash_file"))).expanduser()

    def _wordlist_path(self, ctx: ReconContext) -> Path:
        raw = str(self.option("wordlist", "") or ctx.config.get("wordlists.passwords", ""))
        return Path(raw).expanduser()

    def validate(self, ctx: ReconContext) -> str | None:
        scan = self.scan_type_value() or "dictionary"
        if scan == "benchmark":
            return None
        if not self.option("hash_file"):
            return "Set `hash_file` to a file containing hashes, e.g. `set hash_file ./hashes.txt`."
        if not self._hash_path().is_file():
            return f"Hash file not found: {self.option('hash_file')}"
        if scan in ("dictionary", "dictionary_rules", "combinator",
                    "hybrid_append", "hybrid_prepend"):
            wl = self._wordlist_path(ctx)
            if str(wl) in (".", ""):
                return "Set `wordlist` or `config set wordlists.passwords <path>` (e.g. rockyou.txt)."
            if not wl.is_file():
                return (f"Wordlist not found: {wl}. On Kali: "
                        "`sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`.")
        if scan == "combinator":
            wl2 = str(self.option("wordlist2", ""))
            if not wl2:
                return "Combinator attack needs a second wordlist: set `wordlist2`."
            if not Path(wl2).expanduser().is_file():
                return f"wordlist2 not found: {wl2}"
        if scan == "dictionary_rules":
            rules = str(self.option("rules_file", DEFAULT_RULES_PATH))
            if not Path(rules).expanduser().is_file():
                return (f"Rules file not found: {rules}. Try {DEFAULT_RULES_PATH} "
                        "or set `rules_file`.")
        return None

    def build_command(self, ctx: ReconContext, target: str | None) -> list[str]:
        scan = self.scan_type_value() or "dictionary"
        tool = self.resolve_tool(ctx.tools, "hashcat")
        mode = str(self.option("mode", "0"))

        if scan == "benchmark":
            self._last_output = None
            command = [tool, "-b", "-m", mode]
        elif scan == "show":
            self._last_output = None
            command = [tool, "--show", "-m", mode, str(self._hash_path())]
        else:
            self._last_output = ctx.output_path(self.id, "cracked")
            command = [
                tool,
                "-m", mode,
                "-a", self.ATTACK_MODES[scan],
                "--session", "reconforg",
                "--quiet",
            ]
            if scan == "dictionary_rules":
                command += ["-r", str(Path(str(self.option("rules_file"))).expanduser())]
            command += ["-o", str(self._last_output), str(self._hash_path())]

            mask = str(self.option("mask", "?a?a?a?a?a?a?a?a"))
            wl = str(self._wordlist_path(ctx))
            if scan in ("dictionary", "dictionary_rules"):
                command.append(wl)
            elif scan == "combinator":
                command += [wl, str(Path(str(self.option("wordlist2"))).expanduser())]
            elif scan == "bruteforce":
                command.append(mask)
            elif scan == "hybrid_append":
                command += [wl, mask]
            elif scan == "hybrid_prepend":
                command += [mask, wl]

        if self.option("device_type"):
            command += ["-D", str(self.option("device_type"))]
        if self.is_truthy(self.option("force", "false")):
            command.append("--force")
        if self.option("extra_args"):
            command += shlex.split(str(self.option("extra_args")))
        return command

    def save_output(self, ctx, target_label, output):
        if self._last_output:
            return str(self._last_output)
        return self.save_captured_output(ctx, target_label, output)


# ─────────────────────────────────────────────────────────────────────────────
# Application shell
# ─────────────────────────────────────────────────────────────────────────────

HELP_COMMANDS: list[tuple[str, str]] = [
    ("help", "Show this help"),
    ("banner", "Re-display the startup banner"),
    ("plugins", "List all plugins, tool readiness and preset counts"),
    ("use <plugin>", "Select the active plugin"),
    ("options", "Show options for the active plugin"),
    ("scans", "Show scan types/presets for the active plugin"),
    ("set <key> <value>", "Set an option on the active plugin"),
    ("unset <key>", "Reset an option to its default"),
    ("run [plugin]", "Run the active (or named) plugin against all targets"),
    ("targets", "List current targets"),
    ("add <t1,t2,…>", "Add targets (comma or space separated)"),
    ("remove <target>", "Remove a target"),
    ("load <file>", "Load targets from a file (one per line, # comments)"),
    ("clear-targets", "Remove every target"),
    ("tools", "Show external tool availability and install hints"),
    ("tool <name>", "Deep-dive: install commands + troubleshooting for a tool"),
    ("results", "Summarise completed scans"),
    ("view <#>", "Display the full output of a result"),
    ("export <json|md|txt> [path]", "Export the session report"),
    ("history [n]", "Show recent command history"),
    ("config", "Show current configuration"),
    ("config set <key> <value>", "Persist a configuration value"),
    ("refresh", "Re-scan PATH for external tools"),
    ("clear", "Clear the screen"),
    ("exit / quit", "Leave ReconForge"),
]


def _help_table() -> Table:
    table = Table(title=f"{APP_NAME} Commands", title_style="bold magenta", header_style="bold")
    table.add_column("Command", style="cyan", no_wrap=True)
    table.add_column("Description")
    for cmd, desc in HELP_COMMANDS:
        table.add_row(cmd, desc)
    return table


class ReconForgeApp:
    """Interactive shell coordinating plugins, targets and reporting."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.config = Config.load(CONFIG_PATH)
        self.logger = build_logger(self.config.expanded_path("paths.logs"))
        self.registry = ToolRegistry()
        self.runner = CommandRunner(
            self.logger,
            default_timeout=int(self.config.get("runner.timeout", 1800)),
            max_output=int(self.config.get("runner.max_output_chars", 400_000)),
        )
        self.targets = TargetManager()
        self.history = HistoryStore(HISTORY_PATH)
        self.exporter = ReportExporter(self.config.expanded_path("paths.reports"), self.logger)
        self.ctx = ReconContext(
            config=self.config,
            logger=self.logger,
            tools=self.registry,
            runner=self.runner,
            targets=self.targets,
            history=self.history,
        )
        self.plugins = discover_plugins()
        self.active: BasePlugin | None = None
        self._configure_readline()

    # -- lifecycle -----------------------------------------------------------
    def _configure_readline(self) -> None:
        try:
            import readline
        except ImportError:
            return
        try:
            readline.read_history_file(READLINE_PATH)
        except (FileNotFoundError, OSError):
            pass
        readline.set_history_length(500)

        def _save() -> None:
            try:
                readline.write_history_file(READLINE_PATH)
            except OSError:
                pass

        atexit.register(_save)

    def startup(self) -> None:
        banner(__version__)
        if not self.ensure_legal_agreement():
            error("Agreement not accepted — nothing was scanned. Exiting.")
            raise SystemExit(2)
        self.logger.info("%s v%s session started", APP_NAME, __version__)
        ready = sum(1 for p in self.plugins.values() if not p.missing_tools(self.registry))
        info(
            f"Loaded [bold]{len(self.plugins)}[/bold] plugins "
            f"([green]{ready}[/green] fully ready). Type [bold cyan]help[/bold cyan] for commands."
        )

    def ensure_legal_agreement(self) -> bool:
        if self.config.get("legal.accepted"):
            return True
        legal_panel()
        try:
            answer = console.input("[bold]Type [red]I AGREE[/red] to continue: [/bold]")
        except (EOFError, KeyboardInterrupt):
            return False
        if answer.strip().upper() == "I AGREE":
            self.config.set("legal.accepted", True)
            self.logger.info("legal agreement accepted")
            return True
        return False

    def apply_cli_targets(self) -> None:
        added = self.targets.add_many(self.args.target or [])
        if self.args.targets_file:
            loaded, skipped = self.targets.load_file(Path(self.args.targets_file).expanduser())
            info(f"Loaded {loaded} target(s) from {self.args.targets_file} ({skipped} duplicates skipped).")
        if added:
            info(f"Added {len(added)} target(s) from the command line.")

    def repl(self) -> int:
        while True:
            try:
                line = console.input("[bold cyan]ReconForge[/bold cyan][dim] ❯ [/dim]").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                self.cmd_exit("", [])
                return 0
            if not line:
                continue
            self.history.add(line)
            try:
                if self.dispatch(line) is False:
                    return 0
            except ReconForgeError as exc:
                error(str(exc))
                self.logger.error("command failed: %s (%s)", line, exc)
            except KeyboardInterrupt:
                warning("Interrupted.")
            except Exception as exc:  # last-resort guard: log and keep the shell alive
                self.logger.exception("unexpected error")
                error(f"Unexpected error: {exc} (details in the log file)")

    def dispatch(self, line: str):
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            error(f"Could not parse command: {exc}")
            return None
        command, *rest = tokens
        handler = getattr(self, f"cmd_{command.replace('-', '_')}", None)
        if handler is None:
            warning(f"Unknown command: [bold]{escape(command)}[/bold]. Type [bold cyan]help[/bold cyan].")
            return None
        return handler(" ".join(rest), rest)

    # -- commands ---------------------------------------------------------------
    def cmd_help(self, args: str, tokens: list[str]) -> None:
        console.print(_help_table())

    def cmd_banner(self, args: str, tokens: list[str]) -> None:
        banner(__version__)

    def cmd_plugins(self, args: str, tokens: list[str]) -> None:
        console.print(plugin_table(self.plugins, self.registry,
                                   self.active.id if self.active else None))

    def cmd_use(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: use <plugin-id>. See `plugins`.")
            return
        plugin = self.plugins.get(tokens[0].lower())
        if plugin is None:
            error(f"No plugin named '{tokens[0]}'.")
            console.print(plugin_table(self.plugins, self.registry))
            return
        self.active = plugin
        success(f"Active plugin: [bold]{plugin.id}[/bold] — {escape(plugin.description)}")
        missing = plugin.missing_tools(self.registry)
        if missing:
            missing_tools_panel(missing)
        console.print(options_table(plugin))
        if plugin.scan_types:
            info(f"[bold]{len(plugin.scan_types)}[/bold] scan types available — "
                 f"type [bold cyan]scans[/bold cyan] to list them.")

    def cmd_options(self, args: str, tokens: list[str]) -> None:
        if self.active is None:
            warning("Select a plugin first with `use <plugin-id>`.")
            return
        console.print(options_table(self.active))

    def cmd_scans(self, args: str, tokens: list[str]) -> None:
        if self.active is None:
            warning("Select a plugin first with `use <plugin-id>`.")
            return
        if not self.active.scan_types:
            warning(f"Plugin [bold]{self.active.id}[/bold] has no scan type presets.")
            return
        console.print(scan_types_table(self.active))
        info("Switch with: [bold cyan]set scan_type <name>[/bold cyan]")

    def cmd_set(self, args: str, tokens: list[str]) -> None:
        if self.active is None:
            warning("Select a plugin first with `use <plugin-id>`.")
            return
        if len(tokens) < 2:
            warning("Usage: set <key> <value>")
            return
        key, value = tokens[0], " ".join(tokens[1:])
        # Instant validation for scan types with a friendly list of choices.
        if key.lower() == "scan_type" and self.active.scan_types:
            if value.lower() not in self.active.scan_types:
                error(f"Unknown scan type '{escape(value)}'. "
                      f"Options: {', '.join(sorted(self.active.scan_types))}")
                return
            value = value.lower()
        self.active.set_option(key, value)
        success(f"{escape(key)} = {escape(value)}")
        if key not in self.active.default_options:
            info(f"Note: '{escape(key)}' is not a default option for this plugin (stored anyway).")

    def cmd_unset(self, args: str, tokens: list[str]) -> None:
        if self.active is None:
            warning("Select a plugin first with `use <plugin-id>`.")
            return
        if not tokens:
            warning("Usage: unset <key>")
            return
        if self.active.unset_option(tokens[0]):
            success(f"{escape(tokens[0])} reset to default.")
        else:
            warning(f"No such option: {escape(tokens[0])}")

    def cmd_run(self, args: str, tokens: list[str]) -> None:
        plugin = None
        if tokens:
            plugin = self.plugins.get(tokens[0].lower())
            if plugin is None:
                error(f"No plugin named '{tokens[0]}'.")
                return
        else:
            plugin = self.active
        if plugin is None:
            warning("No plugin selected. Use `use <plugin-id>` first.")
            return
        results = plugin.run(self.ctx)
        if results:
            console.print(results_table(results))
        else:
            warning("No results were produced.")

    def cmd_targets(self, args: str, tokens: list[str]) -> None:
        if not self.targets.has_targets:
            warning("No targets set. Use `add <target>` or `load <file>`.")
            return
        console.print(targets_table(self.targets))

    def cmd_add(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: add <target[,target…]>")
            return
        added = self.targets.add_many(tokens)
        success(f"Added {len(added)} target(s). Total: {len(self.targets)}.")
        for t in added:
            console.print(f"  [cyan]{escape(t)}[/cyan]")

    def cmd_remove(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: remove <target>")
            return
        if self.targets.remove(tokens[0]):
            success(f"Removed {escape(tokens[0])}.")
        else:
            warning(f"No such target: {escape(tokens[0])}")

    def cmd_load(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: load <targets-file>")
            return
        path = Path(tokens[0]).expanduser()
        added, skipped = self.targets.load_file(path)
        success(f"Loaded {added} target(s) from {path} ({skipped} duplicates skipped). "
                f"Total: {len(self.targets)}.")

    def cmd_clear_targets(self, args: str, tokens: list[str]) -> None:
        self.targets.clear()
        success("All targets cleared.")

    def cmd_tools(self, args: str, tokens: list[str]) -> None:
        console.print(tool_status_table(self.registry))

    def cmd_tool(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: tool <name>. See `tools` for the list.")
            return
        tool_detail_panel(tokens[0], self.registry)

    def cmd_refresh(self, args: str, tokens: list[str]) -> None:
        self.registry.refresh()
        success("Tool cache refreshed (re-scanned PATH).")

    def cmd_results(self, args: str, tokens: list[str]) -> None:
        if not self.ctx.results:
            warning("No results yet — run a plugin first.")
            return
        console.print(results_table(self.ctx.results))

    def cmd_view(self, args: str, tokens: list[str]) -> None:
        if not self.ctx.results:
            warning("No results yet — run a plugin first.")
            return
        if not tokens:
            warning("Usage: view <result-number> (see `results`)")
            return
        try:
            index = int(tokens[0])
        except ValueError:
            error("Result number must be an integer.")
            return
        if not 1 <= index <= len(self.ctx.results):
            error(f"Choose a result between 1 and {len(self.ctx.results)}.")
            return
        show_result(self.ctx.results[index - 1], index)

    def cmd_export(self, args: str, tokens: list[str]) -> None:
        if not tokens:
            warning("Usage: export <json|md|txt> [path]")
            return
        dest = tokens[1] if len(tokens) > 1 else None
        if not self.ctx.results:
            warning("No results collected yet — the report will only contain session metadata.")
        path = self.exporter.export(self.ctx.results, self.targets.all(), tokens[0], dest)
        success(f"Report exported: [bold]{escape(str(path))}[/bold]")

    def cmd_history(self, args: str, tokens: list[str]) -> None:
        count = int(tokens[0]) if tokens and tokens[0].isdigit() else 20
        for line in self.history.recent(count):
            console.print(f"[dim]{escape(line)}[/dim]")

    def cmd_config(self, args: str, tokens: list[str]) -> None:
        if tokens and tokens[0] == "set":
            if len(tokens) < 3:
                warning("Usage: config set <dotted.key> <value>")
                return
            key, value = tokens[1], " ".join(tokens[2:])
            coerced: Any = value
            if value.lower() in ("true", "false"):
                coerced = value.lower() == "true"
            else:
                try:
                    coerced = int(value)
                except ValueError:
                    try:
                        coerced = float(value)
                    except ValueError:
                        pass
            self.config.set(key, coerced)
            success(f"config: {escape(key)} = {escape(str(coerced))}")
            return
        console.print_json(json.dumps(self.config.data))

    def cmd_clear(self, args: str, tokens: list[str]) -> None:
        console.clear()

    def cmd_exit(self, args: str, tokens: list[str]) -> bool:
        self.logger.info("session ended")
        info("Happy hacking — stay legal. [dim](ReconForge, out.)[/dim]")
        return False

    cmd_quit = cmd_exit

    # -- non-interactive batch mode ------------------------------------------------
    def run_batch(self) -> int:
        args = self.args
        banner(__version__)
        if not self.ensure_legal_agreement():
            error("Agreement not accepted — nothing was scanned.")
            return 2
        self.apply_cli_targets()
        if not args.plugin:
            error("Batch mode requires --plugin.")
            return 1
        plugin = self.plugins.get(args.plugin)
        if plugin is None:
            error(f"Unknown plugin '{args.plugin}'. Available: {', '.join(self.plugins)}.")
            return 1
        if plugin.requires_targets and not self.targets.has_targets:
            error("This plugin requires targets. Pass --target or --targets-file.")
            return 1
        for pair in args.option or []:
            if "=" not in pair:
                error(f"Invalid --option '{pair}' (expected key=value).")
                return 1
            key, value = pair.split("=", 1)
            plugin.set_option(key.strip(), value.strip())
        self.active = plugin
        info(f"Running [bold]{plugin.id}[/bold] → {len(self.targets)} target(s)")
        try:
            plugin.run(self.ctx)
        except ReconForgeError as exc:
            error(str(exc))
            return 1
        if self.ctx.results:
            console.print(results_table(self.ctx.results))
        if args.export:
            path = self.exporter.export(self.ctx.results, self.targets.all(), args.export, args.output)
            success(f"Report written to [bold]{escape(str(path))}[/bold]")
        failed = [r for r in self.ctx.results if r.status is not ScanStatus.SUCCESS]
        return 1 if failed else 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforg",
        description=f"{APP_NAME} v{__version__} — modular recon toolkit for authorized testing.",
        epilog=(
            "examples:\n"
            "  reconforg                                   # interactive shell\n"
            "  reconforg -t scanme.nmap.org -p nmap -o scan_type=vuln\n"
            "  reconforg -T targets.txt -p subfinder -o scan_type=all -e md\n"
            "  reconforg -t example.com -p ffuf -o scan_type=vhost -o filter_codes=400\n"
            "  reconforg -p hashcat -o scan_type=dictionary_rules -o hash_file=h.txt -o mode=1000\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("-t", "--target", action="append", help="Add a target (repeatable)")
    parser.add_argument("-T", "--targets-file", help="File with targets, one per line")
    parser.add_argument("-p", "--plugin", help="Run this plugin non-interactively")
    parser.add_argument("-o", "--option", action="append", help="Plugin option key=value (repeatable)")
    parser.add_argument("-e", "--export", choices=["json", "md", "txt"],
                        help="Export report after the run")
    parser.add_argument("--output", help="Report output path (with --export)")
    parser.add_argument("--list-plugins", action="store_true", help="List plugins and exit")
    parser.add_argument("--list-tools", action="store_true", help="List tool status and exit")
    return parser


def cli(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    app = ReconForgeApp(args)
    if args.list_plugins:
        console.print(plugin_table(app.plugins, app.registry))
        return 0
    if args.list_tools:
        console.print(tool_status_table(app.registry))
        return 0
    if args.plugin:
        return app.run_batch()
    app.startup()
    app.apply_cli_targets()
    return app.repl()


if __name__ == "__main__":
    raise SystemExit(cli())
