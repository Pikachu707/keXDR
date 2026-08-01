#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import glob
import re
import torch
import torch.nn as nn
import torch.optim as optim

# ============================================================================
# 1. Enhanced UI Template (with integrated context isolation feature)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CAPTAIN: Adaptive Provenance Analysis</title>
    <script src="https://cdn.staticfile.org/vis-network/9.1.2/dist/vis-network.min.js"></script>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; overflow: hidden; display: flex; height: 100vh; }
        #sidebar-left { width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; z-index: 20; box-shadow: 4px 0 15px rgba(0,0,0,0.5); }
        .sidebar-header { padding: 15px; background: #21262d; border-bottom: 1px solid #30363d; }
        .app-title { font-size: 18px; font-weight: bold; color: #58a6ff; margin-bottom: 5px; }
        .app-subtitle { font-size: 11px; color: #8b949e; }
        #main-area { flex: 1; position: relative; background: #0d1117; }
        #mynetwork { width: 100%; height: 100%; }
        .controls { position: absolute; top: 15px; right: 20px; z-index: 10; display: flex; gap: 10px; }
        .btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; cursor: pointer; border-radius: 6px; font-size: 12px; font-weight: 600; transition: all 0.2s; display: flex; align-items: center; gap: 5px; }
        .btn:hover { background: #30363d; color: #58a6ff; border-color: #58a6ff; }
        .btn.active { background: #1f6feb; border-color: #1f6feb; color: white; }
        .legend { position: absolute; bottom: 20px; right: 20px; background: rgba(22, 27, 34, 0.95); padding: 12px; border-radius: 6px; border: 1px solid #30363d; pointer-events: none; display: flex; flex-direction: column; gap: 8px; backdrop-filter: blur(4px); box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
        .l-item { display: flex; align-items: center; font-size: 11px; color: #8b949e; }
        .shape { display: inline-block; margin-right: 10px; vertical-align: middle; }
        .shape.poi { width: 14px; height: 14px; border-radius: 50%; background: #da3633; border: 2px solid #fff; box-shadow: 0 0 8px #da3633; }
        .shape.proc { width: 10px; height: 10px; border-radius: 50%; background: #2196f3; }
        .shape.file { width: 10px; height: 10px; border-radius: 2px; background: #d29922; }
        .shape.net  { width: 8px; height: 8px; transform: rotate(45deg); background: #238636; }

        #detail-panel { position: fixed; top: 0; right: -480px; width: 480px; height: 100vh; background: #161b22; border-left: 1px solid #30363d; transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1); z-index: 30; display: flex; flex-direction: column; }
        #detail-panel.open { right: 0; }
        .detail-content { flex: 1; overflow-y: auto; padding: 25px; }
        .close-btn { position: absolute; top: 15px; right: 20px; cursor: pointer; color: #8b949e; font-size: 24px; }
        h2 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 0; word-break: break-all; }
        .field-label { font-size: 10px; color: #8b949e; margin-top: 15px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
        .field-value { font-family: 'Consolas', monospace; font-size: 12px; color: #c9d1d9; background: #0d1117; padding: 8px; border: 1px solid #30363d; border-radius: 4px; word-break: break-all; margin-top: 4px; white-space: pre-wrap; }

        .captain-score-box { background: rgba(31, 111, 235, 0.1); border: 1px solid #1f6feb; padding: 15px; border-radius: 6px; margin-bottom: 15px; text-align: center; }
        .captain-score-val { font-size: 24px; font-weight: bold; color: #58a6ff; }
        .captain-score-label { font-size: 10px; color: #8b949e; text-transform: uppercase; }
        .alert-box { background: rgba(218, 54, 51, 0.15); border: 1px solid #da3633; padding: 10px; margin-bottom: 10px; border-radius: 6px; }
        .alert-text { color: #f85149; font-weight: bold; font-size: 12px; }

        /* Filter Indicator (Context Isolation) */
        #filter-indicator { position: absolute; top: 60px; right: 20px; background: rgba(155, 89, 182, 0.2); border: 1px solid #9b59b6; color: #fff; padding: 8px 12px; border-radius: 4px; font-size: 12px; pointer-events: none; display: none; backdrop-filter: blur(4px); z-index: 15; box-shadow: 0 2px 10px rgba(0,0,0,0.5); }
    </style>
</head>
<body>
<div id="sidebar-left">
    <div class="sidebar-header">
        <div class="app-title">CAPTAIN</div>
        <div class="app-subtitle">Differentiable Provenance Analysis</div>
    </div>
    <div style="padding: 15px; font-size: 12px; color: #8b949e;">
        <p><strong>Optimization Status:</strong></p>
        <ul style="padding-left: 15px; margin: 5px 0;">
            <li>Engine: <span style="color:#58a6ff">PyTorch / Gradient Descent</span></li>
            <li>Epochs: <span style="color:#2ea043">50</span></li>
        </ul>
        <div style="margin-top:15px; font-style:italic; opacity:0.7">
            <strong>Interactive Mode:</strong><br>
            Click a node to isolate its <span style="color:#a371f7">Causal Context</span> (Ancestors & Descendants).<br>
            Click empty space to reset.
        </div>
    </div>
</div>
<div id="main-area">
    <div class="controls">
        <button class="btn" onclick="fitGraph()">🔍 Fit Graph</button>
        <button class="btn active" id="btn-physics" onclick="togglePhysics()">⏸️ Pause Physics</button>
    </div>
    <div id="filter-indicator">⚠️ FULL CONTEXT ISOLATION ACTIVE</div>

    <div id="mynetwork"></div>
    <div class="legend">
        <div class="l-item"><div class="shape poi"></div><strong>Low Integrity (i < 0.5)</strong></div>
        <div class="l-item"><div class="shape proc"></div><strong>Process (Blue)</strong></div>
        <div class="l-item"><div class="shape file"></div><strong>File (Orange)</strong></div>
        <div class="l-item"><div class="shape net"></div><strong>Trusted (Green)</strong></div>
    </div>
</div>
<div id="detail-panel">
    <div class="close-btn" onclick="closeDetail()">×</div>
    <div class="detail-content" id="detail-content"></div>
</div>
<script type="text/javascript">
    var data_json = __SNAPSHOTS_JSON__;
    var network = null;
    var nodesDataSet = new vis.DataSet(data_json.nodes);
    var edgesDataSet = new vis.DataSet(data_json.edges);
    var physicsEnabled = true;
    var isFiltered = false; // filter state flag

    var container = document.getElementById('mynetwork');
    var options = {
        nodes: { 
            font: { color: '#c9d1d9', size: 14, face: 'Segoe UI' }, 
            borderWidth: 2,
            shapeProperties: { interpolation: false } 
        },
        edges: { 
            arrows: 'to', 
            smooth: false,
            color: { color: '#30363d', opacity: 0.8 }
        },
        physics: { 
            enabled: true,
            solver: 'forceAtlas2Based', 
            forceAtlas2Based: { gravitationalConstant: -50, springLength: 100, avoidOverlap: 0.5 },
            stabilization: { iterations: 150 }
        },
        interaction: { hover: true, navigationButtons: false, hideEdgesOnDrag: true }
    };
    network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

    // --- Integrated click event handling logic ---
    network.on("click", function (params) {
        if (params.nodes.length > 0) {
            var nodeId = params.nodes[0];
            showDetail(nodesDataSet.get(nodeId));
            isolateContextVis(nodeId); // trigger context isolation
        } else if (params.edges.length > 0) {
            closeDetail();
        } else {
            closeDetail();
            resetVis();
        }
    });

    // --- Core feature: bidirectional context isolation algorithm ---
    function isolateContextVis(rootId) {
        var allEdges = edgesDataSet.get();
        var parentMap = {}; 
        var childMap = {};  

        // Build adjacency lists
        allEdges.forEach(e => {
            if(!parentMap[e.to]) parentMap[e.to] = [];
            parentMap[e.to].push(e.from);
            if(!childMap[e.from]) childMap[e.from] = [];
            childMap[e.from].push(e.to);
        });

        var keep = new Set([rootId]);

        // 1. Trace ancestors
        var stack = [rootId];
        while(stack.length > 0){
            var curr = stack.pop();
            var parents = parentMap[curr] || [];
            parents.forEach(p => {
                if(!keep.has(p)){
                    keep.add(p);
                    stack.push(p);
                }
            });
        }

        // 2. Trace descendants
        stack = [rootId];
        while(stack.length > 0){
            var curr = stack.pop();
            var children = childMap[curr] || [];
            children.forEach(c => {
                if(!keep.has(c)){
                    keep.add(c);
                    stack.push(c);
                }
            });
        }

        // 3. Apply filter effect
        var nodeUpdates = nodesDataSet.getIds().map(id => ({
            id: id, 
            hidden: !keep.has(id), // hide unrelated nodes
            opacity: keep.has(id) ? 1.0 : 0.05
        }));
        nodesDataSet.update(nodeUpdates);

        var edgeUpdates = allEdges.map(e => ({
            id: e.id, 
            hidden: !(keep.has(e.from) && keep.has(e.to)) // hide unrelated edges
        }));
        edgesDataSet.update(edgeUpdates);

        isFiltered = true;
        document.getElementById('filter-indicator').style.display = 'block';
    }

    // --- Core feature: reset view ---
    function resetVis() {
        if(!isFiltered) return;
        var nodeUpdates = nodesDataSet.getIds().map(id => ({id: id, hidden: false, opacity: 1.0}));
        nodesDataSet.update(nodeUpdates);
        var edgeUpdates = edgesDataSet.getIds().map(id => ({id: id, hidden: false}));
        edgesDataSet.update(edgeUpdates);
        isFiltered = false;
        document.getElementById('filter-indicator').style.display = 'none';
    }

    function fitGraph() { if(network) network.fit({animation: {duration: 500, easingFunction: 'easeInOutQuad'}}); }

    function togglePhysics() {
        if(!network) return;
        physicsEnabled = !physicsEnabled;
        network.setOptions({ physics: { enabled: physicsEnabled } });
        var btn = document.getElementById('btn-physics');
        if(physicsEnabled) { btn.innerText = "⏸️ Pause Physics"; btn.classList.add('active'); } 
        else { btn.innerText = "▶️ Resume Physics"; btn.classList.remove('active'); }
    }

    function showDetail(node) {
        var html = '<h2>' + node.label.split("\\n")[0] + '</h2>';
        var extra = node.extra || {};

        if (extra.integrity !== undefined) {
            var score = parseFloat(extra.integrity).toFixed(4);
            var color = score < 0.5 ? '#f85149' : '#2ea043';
            html += '<div class="captain-score-box" style="border-color:' + color + '">';
            html += '<div class="captain-score-val" style="color:' + color + '">' + score + '</div>';
            html += '<div class="captain-score-label">Integrity Score</div>';
            html += '</div>';

            if (score < 0.5) {
                html += '<div class="alert-box"><span class="alert-text">⚠️ Suspicious Activity Detected</span></div>';
            }
        }

        if (extra.cmd) {
            html += '<div class="field-label">Command Line</div>';
            html += '<div class="field-value" style="color:#58a6ff">' + extra.cmd + '</div>';
        }

        for (var key in extra) {
            if (['integrity', 'cmd', 'label', 'shape', 'color', 'font'].indexOf(key) === -1) {
                html += '<div class="field-label">' + key.toUpperCase() + '</div>';
                html += '<div class="field-value">' + extra[key] + '</div>';
            }
        }
        document.getElementById('detail-content').innerHTML = html;
        document.getElementById('detail-panel').classList.add('open');
    }

    function closeDetail() { document.getElementById('detail-panel').classList.remove('open'); }
</script>
</body>
</html>
"""


# ============================================================================
# 2. CAPTAIN Model (PyTorch, with parameter-name sanitization fix)
# ============================================================================
class CaptainModel(nn.Module):
    def __init__(self, node_features, edge_features):
        super().__init__()

        # [Fix] Add an 'f_' prefix to avoid collisions with PyTorch internal
        # attributes (e.g. 'modules') when using arbitrary string keys.
        self._sanitize = lambda k: "f_" + k.replace('.', '_dot_').replace('|', '_pipe_').replace('-', '_dash_')

        # A: Tag initialization (initial integrity)
        self.A = nn.ParameterDict({
            self._sanitize(k): nn.Parameter(torch.tensor(0.5)) for k in node_features
        })

        # G: Propagation rate
        self.G = nn.ParameterDict({
            self._sanitize(k): nn.Parameter(torch.tensor(0.99)) for k in edge_features
        })

        # T: Alarm threshold
        self.T = nn.ParameterDict({
            self._sanitize(k): nn.Parameter(torch.tensor(0.5)) for k in edge_features
        })

    def get_integrity(self, feature_key):
        safe_key = self._sanitize(feature_key)
        if safe_key in self.A:
            return torch.sigmoid(self.A[safe_key])
        return torch.tensor(0.5)

    def get_params(self, edge_key):
        safe_key = self._sanitize(edge_key)
        # Fall back to defaults for unseen edge types
        if safe_key in self.G:
            g = torch.sigmoid(self.G[safe_key])
        else:
            g = torch.tensor(0.99)

        if safe_key in self.T:
            t = torch.sigmoid(self.T[safe_key])
        else:
            t = torch.tensor(0.5)

        return g, t

    def forward(self, time_ordered_events):
        loss = torch.tensor(0.0)
        node_states = {}
        # Hoist method references out of the loop for performance
        get_integrity = self.get_integrity
        get_params = self.get_params

        for ev in time_ordered_events:
            src_id, dst_id = ev['src_id'], ev['dst_id']
            src_feat = ev['src_feat']
            dst_feat = ev['dst_feat']
            edge_feat = ev['edge_feat']

            # Initialize node state on first sight
            if src_id not in node_states:
                node_states[src_id] = get_integrity(src_feat)
            if dst_id not in node_states:
                node_states[dst_id] = get_integrity(dst_feat)

            tag_src = node_states[src_id]
            tag_dst = node_states[dst_id]

            g_e, thr_e = get_params(edge_feat)

            # Propagation logic: taint propagation.
            # Simplified rule: if the source is tainted (low value) and the
            # edge's propagation rate g_e is high, the destination becomes tainted.
            tag_rule = torch.min(tag_src, tag_dst)
            tag_dst_new = g_e * tag_rule + (1 - g_e) * tag_dst

            node_states[dst_id] = tag_dst_new

            # Loss: penalty for deviating from the threshold
            current_loss = torch.relu(thr_e - tag_dst_new).pow(2)
            loss = loss + current_loss

        # Regularization: safe to iterate self.A.values() since it's a ParameterDict
        reg_loss = torch.tensor(0.0)
        # Keep this simple (mean) rather than doing it inside the big loop
        if len(self.A) > 0:
            reg_loss += sum((torch.sigmoid(p) - 0.5).pow(2) for p in self.A.values()) / len(self.A)

        return loss + 0.01 * reg_loss, node_states


# ============================================================================
# 3. Log Parser (fixed version: supports network and file events)
# ============================================================================
class LogParser:
    def __init__(self):
        self.nodes = {}
        self.events = []

    def ingest(self, pattern):
        files = glob.glob(pattern)
        if not files:
            print(f"[-] No files found matching: {pattern}")
            return

        for path in files:
            print(f"[Log] Processing {path}...")
            with open(path, 'r', encoding='utf-8') as f:
                # Try reading the whole file as a JSON array first
                content = f.read().strip()
                if not content:
                    continue

                try:
                    if content.startswith('['):
                        data = json.loads(content)
                        for ev in data:
                            self._proc(ev)
                    else:
                        # Handle JSON Lines format (one JSON object per line)
                        for line in content.splitlines():
                            if line.strip():
                                self._proc(json.loads(line))
                except Exception as e:
                    print(f"[!] Error parsing {path}: {e}")

        print(f"[Parser] Loaded {len(self.nodes)} nodes and {len(self.events)} events.")

    def _proc(self, ev):
        if ev.get('type') != 'SYSCALL':
            return
        pid = ev.get('pid')
        if not pid:
            return

        # 1. Create the source node (process)
        proc_img = ev.get('cmd') or ev.get('comm', 'proc')
        args = ev.get('args', '')
        if isinstance(args, list):
            args = " ".join(args)
        cmd_line = f"{proc_img} {args}".strip()

        src_id = f"p_{pid}"
        # Record the process node
        self._add_node(src_id, f"{proc_img}\n{pid}", 'proc', proc_img, extra={'cmd': cmd_line, 'pid': pid})

        # 2. Resolve the target node (file / network / memfd)
        subtype = ev.get('subtype')
        target_id = None
        target_feat = None
        target_type = 'file'
        target_extra = {}
        edge_type = "unknown"

        # --- [A] File access (OPEN) ---
        if subtype == 'OPEN' and ev.get('filename'):
            fname = ev.get('filename')
            target_id = f"f_{fname}"
            target_feat = fname
            target_extra = {'fullpath': fname}
            edge_type = "open"
            target_type = 'file'

        # --- [B] Network connection (CONNECT) - newly added ---
        elif subtype == 'CONNECT' and ev.get('dip'):
            dip = ev.get('dip')  # destination IP
            dport = ev.get('dport', '')  # destination port

            # Optionally filter out uninteresting local connections
            # if dip in ['127.0.0.1', '::1', '0.0.0.0']: return

            target_id = f"net_{dip}_{dport}"
            target_feat = f"NET:{dip}:{dport}"
            target_extra = {'ip': dip, 'port': dport}
            edge_type = "connect"
            target_type = 'net'  # matches the CSS .shape.net (green diamond)

        # --- [C] Memory-backed file (MEMFD) ---
        elif subtype == 'MEMFD' and ev.get('name'):
            name = ev.get('name')
            target_id = f"mem_{name}_{pid}"
            target_feat = f"MEM:{name}"
            target_type = 'file'
            edge_type = "memfd_create"

        # 3. Create the edge
        if target_id:
            # Only record if a target node exists
            self._add_node(target_id, target_feat.split(':')[-1], target_type, target_feat, extra=target_extra)

            # Edge feature: combines the source process and the operation type
            edge_feat = f"{proc_img}|{edge_type}|{target_feat}"

            self.events.append({
                'src_id': src_id,
                'dst_id': target_id,
                'src_feat': proc_img,      # source feature
                'dst_feat': target_feat,   # destination feature
                'edge_feat': edge_feat,    # edge feature
                'label': edge_type
            })

    def _add_node(self, nid, label, group, feature, extra=None):
        if nid not in self.nodes:
            self.nodes[nid] = {
                'id': nid,
                'label': label,
                'group': group,
                'feature': feature,
                'extra': extra or {}
            }
        else:
            if extra:
                self.nodes[nid]['extra'].update(extra)


# ============================================================================
# 4. Main Execution & 5. Reporting
# ============================================================================
if __name__ == "__main__":
    LOG_PATTERN = "/root/ebpf/logs/2026-02-13/audit_21.json"  # adjust to the actual path
    OUTPUT_HTML = "captain.html"
    OUTPUT_TXT = "captain.txt"  # text report path

    print("=== CAPTAIN Analysis with Context Isolation ===")

    # 1. Parse logs
    parser = LogParser()
    parser.ingest(LOG_PATTERN)

    # 2. Init model
    all_node_feats = set(n['feature'] for n in parser.nodes.values())
    all_edge_feats = set(e['edge_feat'] for e in parser.events)
    print(f"[Init] Features: {len(all_node_feats)} nodes, {len(all_edge_feats)} edge types")

    model = CaptainModel(list(all_node_feats), list(all_edge_feats))
    optimizer = optim.Adam(model.parameters(), lr=0.05)

    # 3. Train
    print("[Train] Running Gradient Descent...")
    final_states = {}
    for epoch in range(50):
        optimizer.zero_grad()
        loss, states = model(parser.events)
        loss.backward()
        optimizer.step()
        if epoch % 10 == 0:
            print(f"  Epoch {epoch}: Loss = {loss.item():.4f}")
        final_states = states

    # 4. Generate visualization data (HTML)
    print("[Visual] Building graph data...")
    vis_nodes = []

    # Helper: get a node's final integrity score
    def get_score(nid, n_feat):
        if nid in final_states:
            return final_states[nid].item()
        sanitized = model._sanitize(n_feat)
        if sanitized in model.A:
            return torch.sigmoid(model.A[sanitized]).item()
        return 0.5

    for nid, node in parser.nodes.items():
        integrity = get_score(nid, node['feature'])
        node['extra']['integrity'] = integrity

        vis_node = {
            'id': nid,
            'label': node['label'],
            'group': node['group'],
            'extra': node['extra'],
            'font': {'color': 'black'}
        }

        if integrity < 0.5:
            vis_node['color'] = {'background': '#da3633', 'border': '#f85149'}
            vis_node['label'] = "🚨 " + vis_node['label']
            if 'group' in vis_node:
                del vis_node['group']
        elif integrity > 0.8:
            vis_node['color'] = {'background': '#238636', 'border': '#2ea043'}
            if 'group' in vis_node:
                del vis_node['group']

        vis_nodes.append(vis_node)

    vis_edges = []
    seen_edges = set()
    for ev in parser.events:
        eid = f"{ev['src_id']}->{ev['dst_id']}:{ev['label']}"
        if eid not in seen_edges:
            vis_edges.append({'from': ev['src_id'], 'to': ev['dst_id'], 'label': ev['label'], 'id': eid})
            seen_edges.add(eid)

    out_json = json.dumps({"nodes": vis_nodes, "edges": vis_edges})

    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE.replace('__SNAPSHOTS_JSON__', out_json))

    print(f"[Done] HTML Graph saved to {OUTPUT_HTML}")

    # ============================================================================
    # 5. Pruning & Attack Graph Reconstruction (event-level adaptive pruning)
    # ============================================================================

    # Helper: get a node's display label
    def get_node_label(nid):
        return parser.nodes[nid]['label'].replace('\n', ' ')

    print("\n" + "=" * 80)
    print("✂️  PRUNING RESULTS (Event-Level Adaptive Thresholding)")
    print("=" * 80)

    pruned_edges = []
    pruned_node_ids = set()

    # --- Step A & B: prune based on events (edges) using the adaptive threshold T ---
    # Logic: for each event e, compute f(e) = tag - thr_e. If f(e) < 0, flag it as anomalous.
    for ev in parser.events:
        # 1. Get the model's learned adaptive threshold thr_e for this edge type
        _, thr_tnsr = model.get_params(ev['edge_feat'])
        thr_e = thr_tnsr.item()

        # 2. Get the tag score associated with this event (the destination
        #    node's final integrity score after being touched by this event)
        tag_score = get_score(ev['dst_id'], ev['dst_feat'])

        # 3. Core decision function f(e)
        f_e = tag_score - thr_e

        # 4. If f(e) < 0, the current trust level fell below the threshold
        #    allowed for this specific operation -> flag it and keep the event
        if f_e < 0:
            # Record the decision context for later inspection/printing
            ev['f_e'] = f_e
            ev['thr_e'] = thr_e
            ev['tag_score'] = tag_score

            pruned_edges.append(ev)
            pruned_node_ids.add(ev['src_id'])
            pruned_node_ids.add(ev['dst_id'])

    # --- Step C: print summary statistics ---
    n_total = len(parser.nodes)
    n_pruned = len(pruned_node_ids)
    e_total = len(parser.events)
    e_pruned = len(pruned_edges)

    print(f"📊 Graph Reduction Stats:")
    print(f"   Nodes:  {n_total} ➔ {n_pruned} \t(Pruned {n_total - n_pruned} benign nodes)")
    print(f"   Events: {e_total} ➔ {e_pruned} \t(Pruned {e_total - e_pruned} benign events)")
    print("-" * 80)

    sorted_ids = []

    # --- Step D: print details of the pruned attack graph ---
    if e_pruned == 0:  # decide "clean" based on the number of anomalous events
        print("✅ System Clean: No anomalies remained after adaptive pruning.")
    else:
        print("🚨 DETECTED ANOMALY SUBGRAPH (The \"Attack Story\"):\n")

        # Sort nodes by ascending final integrity score
        sorted_ids = sorted(list(pruned_node_ids), key=lambda i: get_score(i, parser.nodes[i]['feature']))

        for nid in sorted_ids:
            score = get_score(nid, parser.nodes[nid]['feature'])
            label = get_node_label(nid)
            node_type = parser.nodes[nid]['group'].upper()

            print(f"🔻 [Node] {label}")
            print(f"    ID: {nid} | Type: {node_type} | Final Integrity: \033[91m{score:.4f}\033[0m")

            has_context = False

            # 1. What caused this node to become anomalous (incoming edges in the pruned graph)
            causes = [e for e in pruned_edges if e['dst_id'] == nid]
            for e in causes:
                src_lbl = get_node_label(e['src_id'])
                print(f"    ⬅️  [Caused By] --({e['label']})-- {src_lbl}")
                # Show the specific decision condition, illustrating the adaptive threshold
                print(f"        (Adaptive Check: Tag {e['tag_score']:.4f} < Threshold {e['thr_e']:.4f})")
                has_context = True

            # 2. What this node caused downstream (outgoing edges in the pruned graph)
            effects = [e for e in pruned_edges if e['src_id'] == nid]
            for e in effects:
                dst_lbl = get_node_label(e['dst_id'])
                print(f"    ➡️  [Impacts]   --({e['label']})-- {dst_lbl}")
                # Show the specific decision condition, illustrating the adaptive threshold
                print(f"        (Adaptive Check: Tag {e['tag_score']:.4f} < Threshold {e['thr_e']:.4f})")
                has_context = True

            if not has_context:
                print(f"    (Isolated Anomaly within the pruned set)")

            print("")  # blank line separator

    # --- Step E: save a brief report to file ---
    with open(OUTPUT_TXT, 'w', encoding='utf-8') as f_rpt:
        f_rpt.write("=== CAPTAIN ADAPTIVE PRUNING REPORT ===\n")
        f_rpt.write(f"Nodes Found: {n_pruned}\n")
        f_rpt.write(f"Events Flagged: {e_pruned}\n\n")
        for nid in sorted_ids:
            f_rpt.write(f"Node: {get_node_label(nid)} (Score: {get_score(nid, parser.nodes[nid]['feature']):.4f})\n")

    print(f"[Done] Adaptive Pruning report saved to {OUTPUT_TXT}")
