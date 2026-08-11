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

**keXDR** is a kernel-native host–network attack provenance system. A single in-kernel
observation point collects process, file and network events together, so a packet and
the syscall that produced it are recorded against the same kernel object rather than
reconciled afterwards from addresses and timestamps. The resulting provenance graph is
exposed to an LLM through an MCP server, which triages it under a bounded context budget
and a read-only tool surface.

The system has two components:

| | |
|---|---|
| `ebpf_probe.py` | Kernel-side collector. Writes rotating JSON logs. |
| `kexdr_mcp.py` | Orchestrator and MCP server. Builds the graph, clusters it, scores it, serves it to an agent. |

*Kernel sensor → provenance graph → budgeted LLM triage → HTML incident report*

---

## Versions


1.（**v1**） is a simplified, stable build. Use it to reproduce results over the processed
datasets: it is frozen, has no moving parts, and its behaviour on the released logs does
not change.

2.（**latest**） is the build that runs in production as our paper described. It is the one under active development.

Their log formats are not interchangeable, but both of them can run on the release dataset. 

---

## Architecture

```
┌──────────────────┐    ┌──────────────────┐    ┌───────────────────────────┐    ┌──────────────────┐
│  ebpf_probe.py   │───▶│  audit_HH.json   │───▶│  kexdr_mcp.py             │───▶│  HTML incident   │
│  kernel sensor   │    │  rotating logs   │    │  MCP server:              │    │  report          │
│                  │    │                  │    │  stitching + Leiden +     │    │  dashboard.html  │
│  sk_storage      │    │                  │    │  ATT&CK + budgeting       │    │                  │
└──────────────────┘    └──────────────────┘    └─────────────┬─────────────┘    └──────────────────┘
                                                              │
                                                  ┌───────────▼───────────┐
                                                  │  MCP client (LLM)     │
                                                  │  reads, submits a     │
                                                  │  verdict, acts never  │
                                                  └───────────────────────┘
```

---

## Requirements

- Linux 5.8–6.8 with BTF and cgroup v2
- Root, and `bcc` Python bindings
- `python-igraph` + `leidenalg` (clustering; the server runs without them but treats the
  graph as one community)
- `mcp` (Python SDK, for `mcp.server.fastmcp`)
- An MCP-compatible LLM client

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
pip install python-igraph leidenalg mcp
```

Helper availability differs by BPF program type across kernels. The loader attaches what
it can, reports what it could not, and degrades the affected records explicitly — it never
reports an attribution it did not establish. Check the startup banner:

```
Monitoring active. Attribution mode: EXACT (kappa)
```

`PARTIAL` means active opens bind but passive opens and connected UDP do not.
`DEGRADED` means the socket key is unavailable entirely and every network record will be
tagged `degraded`.

---

## Usage

**1. Collect** (root):

```bash
sudo python3 ebpf_probe.py -o ./audit_logs
```

Logs land in `./audit_logs/YYYY-MM-DD/audit_HH.json`. A periodic line reports what share
of traffic resolved through the socket key:

```
[stats] syscall=48213 net=9022 exact=8841 (98.0%) degraded=181 dup_dropped=44 ...
```

| Flag | Purpose |
|---|---|
| `-o, --output` | Log directory |
| `-i, --iface` | Interface for the fallback collector (default: auto-discover) |
| `--cgroup` | cgroup v2 mount point (default `/sys/fs/cgroup`) |
| `--no-kappa` | Skip socket binding; everything degrades |
| `--no-degraded-leg` | Do not attach the raw-socket fallback |
| `--no-coalesce` | Report every artifact access rather than one per window |
| `--coalesce-ms` | Coalescing window, ms (default 5000) |
| `--scan-interval` | Interface discovery period, s (default 2) |
| `--stats-interval` | Seconds between statistics lines (default 60) |

**2. Serve:**

```bash
python3 kexdr_mcp.py
```

Runs as an MCP server over stdio. All output goes to stderr, so the transport stays clean.

**3. Connect a client.** For Gemini CLI, in `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "kexdr": {
      "command": "python3",
      "args": ["/path/to/kexdr_mcp.py"],
      "cwd": "/path/to/keXDR",
      "timeout": 60000
    }
  }
}
```

`cwd` matters: the stitching store `kexdr_memory.db` is created relative to it.

**4. Drive the investigation**, using [`prompt`](./prompt) as a template. It instructs the
client to triage outbound communities first, trace each back through the stitched lineage
to its root cause, submit a verdict, and compile the result into a single HTML report.

---

## MCP tool surface

Read-only tools are always available. Operator tools can be withheld from the same
registry the agent sees by setting `KEXDR_READONLY_REGISTRY=1`.

| Tool | Class | Purpose |
|---|---|---|
| `setup_workspace(host_ip, output_path)` | operator | Point the orchestrator at a host and an output file |
| `ingest_logs(pattern)` | operator | Load a glob of logs and build the graph |
| `write_html_report()` | operator | Render the interactive report |
| `list_communities(only_outbound, include_non_candidates)` | read-only | Communities eligible for serialisation |
| `get_community_topology(community_id)` | read-only | One community's subgraph, budgeted and typed |
| `get_entity(community_id, entity_id)` | read-only | One entity in full |
| `submit_verdict(community_id, verdict, confidence, cited_entities, summary_markdown)` | read-only w.r.t. state | Hand a grounded verdict to the orchestrator |
| `get_alerts()` | read-only | Current alert set |
| `get_pipeline_stats()` | read-only | Counts and active parameters |
| `save_ai_analysis(community_id, markdown)` | annotation | Attach a narrative; changes no detection state |

`submit_verdict` does not act. The orchestrator applies the verdict, and only after
checking that the cited entity ids resolve in the serialised subgraph — a report whose
citations do not resolve is queued for human review rather than acted on.

---

## Configuration

Every tunable is an environment variable, so a change is visible in the run log.

| Variable | Default | Meaning |
|---|---|---|
| `KEXDR_B_MAX` | `200000` | Serialisation budget, bytes |
| `KEXDR_RHO` | `0.7` | Share of the budget allocated before the reserve |
| `KEXDR_QUANT` | `256` | Budget quantisation for the packing step, bytes |
| `KEXDR_OMEGA_CRIT` | `800` | Severity at which a node may draw on the reserve |
| `KEXDR_DELTA_MAX_DAYS` | `7` | Recall horizon and retention, days |
| `KEXDR_THETA_GHOST` / `_MEM` / `_NET` | `0` / `0` / `1` | Candidate predicate thresholds |
| `KEXDR_SUPPRESSION` | `0` | Allow a verdict to remove an alert |
| `KEXDR_TAU_S` | `0.9` | Confidence floor for suppression |
| `KEXDR_READONLY_REGISTRY` | `0` | Withhold operator verbs from the registry |

---

## Repository structure

| File | Description |
|---|---|
| `ebpf_probe.py` | Kernel-side collector |
| `kexdr_mcp.py` | Orchestrator and MCP server |
| `dashboard.html` | Interactive report template |
| [`prompt`](./prompt) | Reference operator prompt for driving the workflow |
| [`CAMPAIGN_DOSSIER.md`](./CAMPAIGN_DOSSIER.md) | Cross-reference for 15 validated campaigns (A1–A15) |
| `attack scenario.pdf` | Attack evidence screenshots |
| `baselines/CAPTAIN.py` | Baseline: differentiable tag propagation |
| `baselines/CONTEXTS.py` | Baseline: Sigma + CVE + SBERT triage |
| `baselines/DEPCOMM.py` | Baseline: random-walk embedding and community summarisation |
| `baselines/HOLMES.py` | Baseline: ATT&CK kill-chain scenario graphs |
| [`logo.svg`](./logo.svg) | Project logo |
| [`LICENSE`](./LICENSE) | Research-only, non-commercial terms |

---

## Baseline reproductions

Standalone reproductions of four representative provenance baselines. Each ingests the
same logs, applies its own detection algorithm, and renders its own HTML visualisation
and text report, so results can be compared on identical input.

| Script | Idea | Core mechanism | Output |
|---|---|---|---|
| `baselines/CAPTAIN.py` | Differentiable tag propagation | A PyTorch model learns per-entity initial integrity tags, per-edge-type propagation rates and per-edge-type alarm thresholds by gradient descent over the graph; an event is anomalous when its learned tag falls below its learned threshold | `captain.html`, `captain.txt` |
| `baselines/CONTEXTS.py` | Knowledge-base-grounded semantic triage | Sigma rules flag candidate process-of-interest nodes, which are scored against a CVE knowledge base with SBERT embeddings; the graph is pruned to those nodes plus the shortest paths between them | `contexts.html` |
| `baselines/DEPCOMM.py` | Summarisation via community structure | Hierarchical random walks feed a Word2Vec model to learn process embeddings; Fuzzy C-Means assigns processes and their resources to overlapping communities, which are compressed and ranked by a four-dimensional InfoPath score | `depcomm.html`, `depcomm.txt` |
| `baselines/HOLMES.py` | ATT&CK kill-chain correlation | An ATT&CK rule set tags nodes; causally connected ones are grouped into high-level scenario graphs by full reachability, and a kill-chain state machine credits a tactic only when it is foundational or has a causally active upstream tactic | `holmes.html`, `holmes.txt` |

All four share the collector's log conventions, so their output can be checked
node-for-node against keXDR's graph on the campaigns in
[`CAMPAIGN_DOSSIER.md`](./CAMPAIGN_DOSSIER.md).

---

## Ground-truth validation

Detection results have been cross-validated against **15 confirmed real-world campaigns
(A1–A15)**, each traced to a specific raw log and corroborated against public CVE records
and vendor reporting — Log4j, Docker API abuse, ActiveMQ RCE, Condi/Orbit botnet,
telnetd RCE, and others. See [`CAMPAIGN_DOSSIER.md`](./CAMPAIGN_DOSSIER.md) for the
per-campaign breakdown.

---

## Dataset

keXDR's telemetry dataset for evaluation is released from **Zenodo** (~70 GB
uncompressed), covering raw eBPF host–network (L4–L7) audit logs and reconstructed
provenance graphs for all campaigns referenced above.

| | |
|---|---|
| **Size** | ~70 GB (decompressed) |
| **Contents** | Raw audit logs, rotated JSON shards, reconstructed graph snapshots |
| **Access** | Will be released after peer review |

<img width="861" height="520" alt="dataset" src="https://github.com/user-attachments/assets/591dccc5-0ada-41d6-a3e4-4320b68ecff3" />

> Released under the same research-only terms as this repository — see [License](#license).

---

## Citation

If you use this code or dataset, please cite the associated paper. A full citation entry
will be added on publication.

## License

Released under a **Research Use Only** licence — see [`LICENSE`](./LICENSE) for full terms.

- ✅ Free to use, modify and redistribute for academic and non-commercial research.
- ❌ Commercial use requires prior written permission.

## Disclaimer

A research prototype released in support of academic work on provenance-based intrusion
detection. It is not a supported security product.
