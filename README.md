<div align="center">
  <img src="./logo.svg" width="560" alt="keXDR logo">

  <p>
    <img alt="License" src="https://img.shields.io/badge/license-Research--Only-critical?style=flat-square">
    <img alt="Python" src="https://img.shields.io/badge/python-3.x-blue?style=flat-square">
    <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20eBPF-informational?style=flat-square">
    <img alt="LLM" src="https://img.shields.io/badge/interface-MCP%20server-8b5cf6?style=flat-square">
    <img alt="Status" src="https://img.shields.io/badge/status-research%20prototype-yellow?style=flat-square">
  </p>
</div>

---

## Overview

**keXDR** is a kernel-native host–network collaborative attack provenance system. It fuses full-kernelspace eBPF telemetry with an egress-centric, LLM-driven forensics loop: instead of starting from a historical entry point, keXDR starts from *active outbound network activity* — the traffic most likely to represent a live C2 channel — and reconstructs the full attack chain backward to its root cause using a persistent time-stitching memory engine.

The system is exposed as an **MCP server** (`KeXDR-Server`), so any MCP-compatible LLM client (Claude, Gemini CLI, etc.) can drive the investigation end-to-end: ingest logs, cluster network communities, walk each community's causal history, assign a verdict, and emit a shareable HTML report — with no manual graph wrangling required.

<p align="center">
  <em>Kernel sensor → Provenance graph → Egress-first LLM forensics loop → HTML incident report</em>
</p>

## Key Features

**Kernel-space audit sensor** (`ebpf_probe.py`)
- 🐳 Container-aware: tracks cgroup ID to distinguish host vs. Docker-originated activity, with automatic veth/docker0 interface discovery
- 🚀 Process execution capture (`execve`, full command + arguments)
- 📁 File monitoring (`openat`, read/write activity)
- 🔌 Network auditing across L3/L4 headers with L7 payload parsing (HTTP, DNS, MySQL, etc.)
- 👻 Fileless-malware detection via `memfd_create`
- 💉 Code-injection detection via `ptrace`
- 🗑️ Anti-forensics detection via `unlinkat` (deletion attempts)
- ⚠️ Privilege-escalation alerts on UID changes / `setuid`
- 💾 Automatic log rotation into `YYYY-MM-DD/audit_HH.json` shards

**Provenance & forensics engine** (`kexdr_mcp.py`)
- **Hippocampus time-stitching memory**: a persistent SQLite-backed store that links artifacts across log rotations by shared identity keys (PID, socket, file path), so process lineage and "Ghost" nodes (implants planted before the current logging window) can be recovered even when the planting event itself has aged out of the active window.
- **Egress-first community detection**: Leiden clustering over the provenance graph isolates distinct outbound network "communities," letting an analyst (human or LLM) triage active C2 candidates before doing any deep-dive tracing.
- **MITRE ATT&CK technique mapping**: a rule engine tags observed command lines and process behavior against ATT&CK techniques across the full kill chain, from Reconnaissance (T1595.x) through execution and persistence.
- **MCP tool surface**: the entire workflow — workspace setup, log ingestion, community listing, per-community topology retrieval, AI-verdict persistence, and final report generation — is exposed as MCP tools, so an LLM client can run the full "Deep Forensics Loop" autonomously.
- **Interactive HTML dashboard**: a self-contained multi-view report (`dashboard.html`) for exploring reconstructed communities, Ghost-node context, and time-stitched links.

## Architecture

```
┌──────────────────┐     ┌────────────────────┐     ┌───────────────────────────┐     ┌────────────────────┐
│   ebpf_probe.py   │ --> │   audit_HH.json     │ --> │   kexdr_mcp.py             │ --> │   HTML incident      │
│  (kernel sensor)  │     │  (rotating logs)    │     │   MCP server:               │     │   report /            │
│                   │     │                     │     │   Hippocampus + Leiden +    │     │   dashboard.html      │
│                   │     │                     │     │   ATT&CK mapping            │     │                     │
└──────────────────┘     └────────────────────┘     └──────────────┬──────────────┘     └────────────────────┘
                                                                     │
                                                          ┌──────────▼──────────┐
                                                          │  MCP client (LLM)    │
                                                          │  drives the egress-  │
                                                          │  first forensics loop│
                                                          └──────────────────────┘
```

## Repository Structure

| File | Description |
|---|---|
| `ebpf_probe.py` | Full-kernelspace eBPF sensor built on BCC; captures process, file, and network events into rotating JSON logs |
| `kexdr_mcp.py` | MCP server (`KeXDR-Server`): Hippocampus time-stitching memory, Leiden community detection, ATT&CK mapping, and HTML report generation |
| `dashboard.html` | Self-contained interactive report template rendered by the MCP server |
| `prompt` | Reference operator prompt for driving the "Egress-Centric Provenance Analysis" workflow via an MCP-compatible LLM client |
| `CAMPAIGN_DOSSIER.md` | Ground-truth cross-reference for 15 validated real-world attack campaigns (A1–A15), mapping each to its raw audit log, paper results, and public CVE/threat-intel references |
| `attack scenario.pdf` | attack evidence screenshots |
| `logo.svg` | Project logo |
| `LICENSE` | Research-only, non-commercial license terms |

## Requirements

- Linux with kernel support for eBPF/BCC
- Python 3
- [`bcc`](https://github.com/iovisor/bcc) Python bindings
- `python-igraph` and `leidenalg` (community detection; the server degrades gracefully with a warning if unavailable)
- `mcp` (Python MCP SDK, for `mcp.server.fastmcp.FastMCP`)
- An MCP-compatible LLM client (e.g. Claude, Gemini CLI) to drive the forensics loop

```bash
pip install python-igraph leidenalg mcp
sudo apt install bpfcc-tools python3-bpfcc
```

## Usage

**1. Capture kernel telemetry** (requires root):

```bash
sudo python3 ebpf_probe.py -i <interface> -o ./logs
```

**2. Start the MCP server:**

```bash
python3 kexdr_mcp.py
```

**3. Drive the investigation from an MCP-compatible LLM client**, using the operator prompt in [`prompt`](./prompt) as a template. The workflow follows a fixed sequence of MCP tool calls:

| Tool | Purpose |
|---|---|
| `setup_workspace(host_ip, output_path)` | Initialize the analysis workspace and report output path |
| `ingest_logs(pattern)` | Load a glob of rotated audit logs into the provenance graph |
| `list_communities(only_outbound)` | Return Leiden-clustered network communities, optionally filtered to active egress only |
| `get_community_topology(community_id)` | Retrieve the full causal subgraph for one community, including any recovered Ghost node |
| `save_ai_analysis(community_id, markdown)` | Persist the analyst's (LLM's) verdict and narrative for a community |
| `write_html_report()` | Render the final interactive HTML report |

The reference prompt instructs the client to triage outbound-only communities first, trace each one backward through the time-stitched lineage to its root cause, assign a verdict, and compile everything into a single HTML report.

## Ground-Truth Validation

keXDR's detection results have been cross-validated against **15 confirmed real-world attack campaigns (A1–A15)**, each traced to a specific raw audit log and independently corroborated against public CVE records and vendor threat-intel reporting (Log4j, Docker API abuse, ActiveMQ RCE, Condi/Orbit botnet, telnetd RCE, and more).

See [`CAMPAIGN_DOSSIER.md`](./CAMPAIGN_DOSSIER.md) for the full per-campaign breakdown, evidence mapping, and reference citations.

## Dataset

keXDR shares its evaluation telemetry with the [TR-PCI](https://github.com/Pikachu707/TR-PCI) project — both are released from the same **Zenodo** dataset (~70 GB uncompressed), covering raw eBPF audit logs and reconstructed provenance graphs for all campaigns referenced above.

| | |
|---|---|
| **Size** | ~70 GB (decompressed) |
| **Contents** | Raw audit logs, rotated JSON shards, reconstructed graph snapshots |
| **Access** | [Zenodo record link — *add DOI/link here*] |


<img width="861" height="520" alt="截屏2026-07-30 21 38 08" src="https://github.com/user-attachments/assets/591dccc5-0ada-41d6-a3e4-4320b68ecff3" />


> Released under the same research-only terms as this repository — see [License](#license).

## Citation

If you use this code or dataset in your research, please cite the associated paper. A full citation entry will be added here upon publication.

## License

This project is released under a **Research Use Only** license — see [`LICENSE`](./LICENSE) for full terms.

In short:
- ✅ Free to use, modify, and redistribute for **academic and non-commercial research purposes**.
- ❌ **Commercial use is not permitted** without prior written permission from the authors.

## Disclaimer

This project is a research prototype released in support of academic work on provenance-based intrusion detection. It is intended for use in controlled, authorized environments (e.g., testbeds, sandboxed VMs) and has not been hardened for production deployment.
