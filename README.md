<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/TUI-Rich-8A2BE2" alt="Rich TUI">
  <img src="https://img.shields.io/badge/Release-v2.0.0-orange" alt="Release">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Authorized_Use_Only-red?style=flat" alt="Authorized use only">
</p>

<h1 align="center">⚒️ ReconForge</h1>

<p align="center">
  A modular, Rich-powered terminal toolkit that orchestrates your favourite recon & security tools<br/>
  for <b>authorized</b> penetration tests, bug bounty hunting, CTFs and security assessments.
</p>

<p align="center">
  <b>One script. Ten tools. 50+ scan presets. JSON / Markdown / TXT reports.</b>
</p>

---

> ⚠️ **LEGAL — READ FIRST**
>
> ReconForge is intended **strictly for authorized security testing**: engagements with signed scope, bug bounty programs, CTF challenges, labs, and systems you own. Unauthorized access to computer systems is illegal (CFAA, Computer Misuse Act, and equivalents worldwide). The authors accept no liability for misuse. **You are solely responsible for your actions.**

---

## 📖 Table of Contents

- [What is ReconForge?](#-what-is-reconforg)
- [Features](#-features)
- [Preview](#-preview)
- [Supported Tools & Scan Types](#-supported-tools--scan-types)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Non-Interactive / Scripting](#-non-interactive--scripting)
- [Command Reference](#-command-reference)
- [Configuration](#-configuration)
- [Reports](#-reports)
- [Logging, History & Data Locations](#-logging-history--data-locations)
- [Troubleshooting & Tool Detection](#-troubleshooting--tool-detection)
- [Extending ReconForge](#-extending-reconforg)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ What is ReconForge?

ReconForge is a **single-file Python application** that gives you a clean, modern terminal interface (built with [Rich](https://github.com/Textualize/rich)) on top of the classic offensive-security toolchain.

Instead of memorizing flags and copy-pasting one-liners, you:

1. **Add targets** — one at a time, comma-separated, or from a file (hundreds at once).
2. **Pick a plugin** — Nmap, Gobuster, FFUF, Subfinder, Amass, hashcat, and more.
3. **Choose a scan type** — every plugin ships multiple curated presets (`vuln`, `vhost`, `brute`, `axfr`…).
4. **Run everything** — output streams live into the TUI with progress bars.
5. **Export** — produce a shareable JSON / Markdown / TXT report in one command.

The plugin system is dead simple: a new tool is **one class + one decorator**.

## 🔥 Features

- 🎨 **Modern Rich TUI** — colors, tables, panels, progress bars, banner, menus
- 🧩 **Plugin architecture** — auto-registered plugins, trivially extensible
- 🎯 **Multi-target workflows** — inline targets, comma lists, or target files (`load targets.txt`)
- 🧪 **50+ scan-type presets** — `scan_type` option per plugin with a `scans` browser
- 🔍 **Automatic tool detection** — missing binaries show per-OS install commands
- 🛠 **Built-in troubleshooting** — every failed run displays a checklist, repro command and docs link
- 📦 **Report export** — JSON, Markdown and TXT with full command/output capture
- 📜 **Command history** — persistent, timestamped (`history` command)
- ⚙️ **Persistent config** — `~/.reconforg/config.json` with dotted keys
- 📝 **Rotating log files** — every command and result is auditable
- ⏱ **Timeouts & output caps** — runaway tools get killed safely
- ⚖️ **Legal gate** — first-run authorization agreement

## 🖼 Preview

```text
╦═╗ ╔═╗ ╔═╗ ╔═╗ ╔╗╔ ╔═╗ ╔═╗ ╦═╗ ╔═╗ ╔═╗
╠╦╝ ║╣  ║   ║ ║ ║║║ ╠╣  ║ ║ ║ ║ ╠╦╝ ║╣        v2.0.0 • authorized testing only
╩╚═ ╚═╝ ╚═╝ ╚═╝ ╝╚╝ ╚   ╚═╝ ╩╚═ ╩╚═ ╚═╝

ReconForge ❯ use nmap
[+] Active plugin: nmap — Port scanning, service detection and host discovery.
[*] 14 scan types available — type scans to list them.

ReconForge ❯ scans
        Scan types — Nmap Port Scanner
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Scan type        ┃ Description                                  ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ quick            │ Fast scan of the 100 most common ports (-F). │
│ version          │ Service version detection + scripts (-sV)…   │
│ ➜ vuln           │ NSE vulnerability scripts (--script vuln)…   │
│ ping             │ Host discovery only (-sn), no port scan.     │
└──────────────────┴──────────────────────────────────────────────┘

ReconForge ❯ run
$ nmap -sV --script vuln --top-ports 1000 --reason -oN … scanme.nmap.org
…live streamed output…
[+] nmap finished against scanme.nmap.org in 41.7s
```

## 🔧 Supported Tools & Scan Types

| Plugin | Tool | Category | Scan types |
|---|---|---|---|
| `nmap` | [Nmap](https://nmap.org) | Port Scanning | `quick` `top100` `top1000` `full` `version` `syn` `udp` `udp_full` `aggressive` `os` `vuln` `ping` `slow` `custom` |
| `gobuster` | [Gobuster](https://github.com/OJ/gobuster) | Content Discovery | `dir` `dir_big` `dir_api` `dns` `vhost` `fuzz` |
| `ffuf` | [FFUF](https://github.com/ffuf/ffuf) | Content Discovery | `dirs` `files` `recursive` `vhost` `params` `param_value` `api` `post` |
| `dirsearch` | [dirsearch](https://github.com/maurosoria/dirsearch) | Content Discovery | `standard` `full` `api` `backup` `recursive` `custom` |
| `subfinder` | [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain Enum | `quick` `all` `sources` `stealth` `custom` |
| `assetfinder` | [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain Enum | `subs` `related` |
| `amass` | [OWASP Amass](https://github.com/owasp-amass/amass) | Subdomain Enum | `passive` `active` `brute` `brute_passive` `alterations` |
| `dns` | dig / nslookup | DNS | `single` `common` `trace` `axfr` `reverse` |
| `whois` | whois | DNS | `standard` `ip` |
| `hashcat` | [hashcat](https://hashcat.net/hashcat/) | Password Cracking | `dictionary` `dictionary_rules` `bruteforce` `combinator` `hybrid_append` `hybrid_prepend` `benchmark` `show` |

Run `plugins` inside the shell (or `--list-plugins`) to see live readiness per tool.

## 📦 Installation

**Requirements**

| Dependency | Version |
|---|---|
| Python | ≥ 3.10 |
| [Rich](https://github.com/Textualize/rich) | ≥ 13.7 |
| External tools | whichever plugins you plan to use |

```bash
# 1. Grab the script
git clone https://github.com/<your-username>/reconforg.git
cd reconforg

# 2. Install the only Python dependency
pip install rich          # or: pipx install rich

# 3. Run
python3 reconforg.py
```

> 💡 **Tip:** external tools are optional per plugin. Run `python3 reconforg.py --list-tools` to see exactly what is missing and the install command for your OS.

## 🚀 Quick Start

```text
$ python3 reconforg.py

Type I AGREE to continue: I AGREE

ReconForge ❯ help                              # full command list
ReconForge ❯ tools                             # what's installed / missing
ReconForge ❯ add scanme.nmap.org, example.com  # multiple targets at once
ReconForge ❯ load targets.txt                  # ...or from a file (one per line)
ReconForge ❯ plugins                           # browse plugins
ReconForge ❯ use nmap
ReconForge ❯ scans                             # list scan types
ReconForge ❯ set scan_type vuln
ReconForge ❯ run                               # runs against ALL targets
ReconForge ❯ results                           # summary table
ReconForge ❯ view 1                            # full output of result #1
ReconForge ❯ export md                         # json | md | txt
ReconForge ❯ exit
```

**Targets** can be added three ways:

```text
add 10.10.10.10                       # single target
add site1.com, site2.com, 10.0.0.0/24 # comma/space separated list
load targets.txt                      # file: one target per line, # comments OK
```

Plugins that accept bulk input (Nmap combines targets; Subfinder uses `-dL`) automatically batch multi-target runs.

## 🖥 Non-Interactive / Scripting

Everything works headlessly for pipelines, cron jobs and CI-style automation:

```bash
# Interactive list views
python3 reconforg.py --list-plugins
python3 reconforg.py --list-tools

# Single run with options (-o key=value, repeatable)
python3 reconforg.py -t scanme.nmap.org -p nmap -o scan_type=version

# Multiple targets from a file + auto-export a Markdown report
python3 reconforg.py -T targets.txt -p subfinder -o scan_type=all -e md

# FFUF vhost fuzzing with filters
python3 reconforg.py -t example.com -p ffuf -o scan_type=vhost -o filter_codes=400

# Hashcat without targets
python3 reconforg.py -p hashcat -o scan_type=dictionary_rules \
    -o hash_file=hashes.txt -o mode=1000 -o wordlist=rockyou.txt
```

| Flag | Purpose |
|---|---|
| `-t, --target` | Add a target (repeatable) |
| `-T, --targets-file` | Load targets from a file |
| `-p, --plugin` | Run this plugin non-interactively |
| `-o, --option key=value` | Set plugin option(s) (repeatable) |
| `-e, --export json\|md\|txt` | Export a report after the run |
| `--output` | Custom report path |
| `--list-plugins` / `--list-tools` | Informational listing |

> The legal agreement is accepted once interactively and remembered in the config file.

## ⌨️ Command Reference

| Command | Description |
|---|---|
| `help` | Show all commands |
| `banner` | Re-display the startup banner |
| `plugins` | List plugins, tool readiness and preset counts |
| `use <plugin>` | Select the active plugin |
| `options` | Show options for the active plugin |
| `scans` | Show scan types/presets for the active plugin |
| `set <key> <value>` | Set an option (validates `scan_type` instantly) |
| `unset <key>` | Reset an option to its default |
| `run [plugin]` | Run the active (or named) plugin against all targets |
| `targets` | List current targets |
| `add <t1,t2,…>` | Add targets (comma/space separated) |
| `remove <target>` | Remove a target |
| `load <file>` | Load targets from a file |
| `clear-targets` | Remove every target |
| `tools` | Tool availability + install hints |
| `tool <name>` | Deep-dive install & troubleshooting panel |
| `results` | Summarise completed scans |
| `view <#>` | Full output of a result |
| `export <json\|md\|txt> [path]` | Export the session report |
| `history [n]` | Recent command history |
| `config` / `config set <k> <v>` | View / persist configuration |
| `refresh` | Re-scan PATH for newly installed tools |
| `clear` | Clear the screen |
| `exit` / `quit` | Leave ReconForge |

## ⚙️ Configuration

Stored at `~/.reconforg/config.json` (created with sane defaults on first run).

| Key | Default | Purpose |
|---|---|---|
| `legal.accepted` | `false` | Authorization agreement flag |
| `paths.output` | `~/.reconforg/output` | Tool output files |
| `paths.reports` | `~/.reconforg/reports` | Exported reports |
| `paths.logs` | `~/.reconforg/logs` | Application logs |
| `runner.timeout` | `1800` | Default per-command timeout (seconds) |
| `runner.max_output_chars` | `400000` | Capture cap per command |
| `wordlists.directory` | dirb common.txt | Default for dir/vhost fuzzing |
| `wordlists.subdomains` | SecLists top-1M | Default for DNS/subdomain brute |
| `wordlists.passwords` | rockyou.txt | Default for hashcat |

```text
ReconForge ❯ config set wordlists.directory /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
ReconForge ❯ config set runner.timeout 3600
ReconForge ❯ config        # pretty-print current config
```

Every plugin option can also be inspected with `options` and changed with `set`.

## 📤 Reports

```text
ReconForge ❯ export json           # machine-readable
ReconForge ❯ export md             # Markdown — great for engagement notes
ReconForge ❯ export txt ~/report   # plain text, custom path
```

Each report includes: session metadata (operator, host, time, version), targets, a summary table, and for every result — the exact command, status, exit code, duration, output file path and full captured output.

## 🗂 Logging, History & Data Locations

| Path | Contents |
|---|---|
| `~/.reconforg/config.json` | Configuration |
| `~/.reconforg/logs/reconforg.log` | Rotating log (every command & result) |
| `~/.reconforg/history.txt` | Timestamped command history |
| `~/.reconforg/readline_history` | Arrow-key recall in the shell |
| `~/.reconforg/output/` | Per-tool output files (timestamped) |
| `~/.reconforg/reports/` | Exported reports |

## 🛠 Troubleshooting & Tool Detection

ReconForge never leaves you guessing:

- **Before every run** — missing binaries trigger a red panel with per-OS install commands.
- **After every failure** — a yellow panel shows the exit code/timeout, a tool-specific checklist, the exact command to reproduce manually, and docs links.
- `tools` — full status table for all known tools.
- `tool <name>` — deep-dive install + troubleshooting for one tool (e.g. `tool hashcat` covers OpenCL/driver issues, exit codes, potfile usage).
- `refresh` — re-scans PATH after installing a new tool mid-session.

Common quick fixes:

| Symptom | Fix |
|---|---|
| `Wordlist not found` | `config set wordlists.directory <path>` or install [SecLists](https://github.com/danielmiessler/SecLists) |
| Nmap `Operation not permitted` | Use sudo, or a connect-based preset (`version`, `top1000`) |
| hashcat `No devices found` | `set device_type 1` (CPU) or fix GPU drivers |
| Command timed out | `set timeout 7200` or `config set runner.timeout 7200` |
| rockyou.txt missing | `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz` |

## 🔌 Extending ReconForge

A new tool = one class. Drop this anywhere below the existing plugins in `reconforg.py`:

```python
@plugin
class HttpxPlugin(BasePlugin):
    id = "httpx"
    name = "HTTPX Probe"
    description = "Probe targets for live HTTP services."
    category = "Recon"
    required_tools = ("httpx",)

    scan_types = {
        "quick": "Status codes and titles only.",
        "full": "Titles, tech detection, status codes and content length.",
    }

    default_options = {"scan_type": "quick", "timeout": "600"}

    def build_command(self, ctx, target):
        command = ["httpx", "-u", self.ensure_scheme(target), "-silent"]
        if self.scan_type_value() == "full":
            command += ["-title", "-tech-detect", "-status-code", "-content-length"]
        return command

    def save_output(self, ctx, label, output):
        return self.save_captured_output(ctx, label, output)
```

That's it — it appears in `plugins`, gets `scans` support, validation, streaming output, progress bars, history, logging, reports and troubleshooting automatically.

**Override points:** `build_command()` (required) · `validate()` · `run()` · `save_output()` · `scan_types` · `default_options` · `tool_aliases`.

## 🗺 Roadmap

- [ ] Additional plugins: `httpx`, `dnsx`, `naabu`, `katana`, `nuclei`, `crt.sh`, `waybackurls`
- [ ] Workflow automation: chained pipelines (`subfinder → httpx → ffuf`)
- [ ] Parsed findings per plugin (open ports, live hosts, cracked hashes) with tables
- [ ] SQLite session storage & resume
- [ ] Per-engagement workspaces
- [ ] HTML report export

See the [issue tracker](../../issues) to request tools or vote on features.

## 🤝 Contributing

Contributions are welcome — especially new plugins and better troubleshooting entries.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/httpx-plugin`)
3. Commit your changes (`git commit -m "Add httpx plugin"`)
4. Push and open a Pull Request

Please keep the code OOP, documented, and consistent with the existing plugin style.

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for security professionals. Stay curious — and stay legal. ⚖️</sub>
</p>
