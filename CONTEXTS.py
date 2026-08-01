#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import re
import glob
import networkx as nx
import numpy as np
from sentence_transformers import SentenceTransformer, util

# Requires PyYAML
try:
    import yaml
except ImportError:
    print("[-] Error: 'PyYAML' is missing. Please run: pip3 install pyyaml")
    sys.exit(1)

# ============================================================================
# 1. Enhanced UI Template (context isolation + black-font support)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Contexts: Semantic Provenance Analysis</title>
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
        .sigma-box { background: rgba(218, 54, 51, 0.15); border: 1px solid #da3633; padding: 10px; margin-bottom: 10px; border-radius: 6px; }
        .sigma-hit-row { display: flex; align-items: start; gap: 8px; margin-bottom: 6px; border-bottom: 1px solid rgba(218, 54, 51, 0.3); padding-bottom: 6px; }
        .sigma-icon { font-size: 14px; }
        .sigma-text { font-size: 12px; color: #f85149; font-weight: 600; line-height: 1.4; }
        .kg-tag { display: inline-block; padding: 2px 6px; font-size: 10px; border-radius: 4px; margin-right: 4px; margin-bottom: 4px; border: 1px solid; }
        .tag-cve { background: #1f2428; color: #d29922; border-color: #d29922; font-weight: bold; }
        .tag-kw { background: #1f2428; color: #a371f7; border-color: #a371f7; }

        /* Context Isolation Indicator */
        #filter-indicator { position: absolute; top: 60px; right: 20px; background: rgba(155, 89, 182, 0.2); border: 1px solid #9b59b6; color: #fff; padding: 8px 12px; border-radius: 4px; font-size: 12px; pointer-events: none; display: none; backdrop-filter: blur(4px); z-index: 15; box-shadow: 0 2px 10px rgba(0,0,0,0.5); }
    </style>
</head>
<body>
<div id="sidebar-left">
    <div class="sidebar-header">
        <div class="app-title">Contexts</div>
        <div class="app-subtitle">Semantic Provenance Analysis</div>
    </div>
    <div style="padding: 15px; font-size: 12px; color: #8b949e;">
        <p><strong>System Status:</strong></p>
        <ul style="padding-left: 15px; margin: 5px 0;">
            <li>Rules Loaded: <span style="color:#58a6ff">Sigma + CVE</span></li>
            <li>Engine: <span style="color:#2ea043">NLP Vector Space</span></li>
            <li>Mode: <span style="color:#d29922">Pruning Active</span></li>
        </ul>
        <div style="margin-top:15px; font-style:italic; opacity:0.7">
            <strong>Interactive Mode:</strong><br>
            Click a node to isolate its <span style="color:#a371f7">Causal Context</span>.<br>
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
        <div class="l-item"><div class="shape poi"></div><strong>Sigma/CVE Rules Hit (POI)</strong></div>
        <div class="l-item"><div class="shape proc"></div><strong>Process (Blue)</strong></div>
        <div class="l-item"><div class="shape file"></div><strong>File (Orange)</strong></div>
        <div class="l-item"><div class="shape net"></div><strong>Network (Green)</strong></div>
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
    var isFiltered = false;

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

    // --- Context Isolation Click Handler ---
    network.on("click", function (params) {
        if (params.nodes.length > 0) {
            var nodeId = params.nodes[0];
            showDetail(nodesDataSet.get(nodeId));
            isolateContextVis(nodeId); // Trigger Isolation
        } else if (params.edges.length > 0) {
            closeDetail();
        } else {
            closeDetail();
            resetVis(); // Trigger Reset
        }
    });

    // --- Context Isolation Logic ---
    function isolateContextVis(rootId) {
        var allEdges = edgesDataSet.get();
        var parentMap = {}; 
        var childMap = {};  

        // Build adjacency
        allEdges.forEach(e => {
            if(!parentMap[e.to]) parentMap[e.to] = [];
            parentMap[e.to].push(e.from);
            if(!childMap[e.from]) childMap[e.from] = [];
            childMap[e.from].push(e.to);
        });

        var keep = new Set([rootId]);

        // 1. Ancestors
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

        // 2. Descendants
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

        // 3. Apply Filter
        var nodeUpdates = nodesDataSet.getIds().map(id => ({
            id: id, 
            hidden: !keep.has(id),
            opacity: keep.has(id) ? 1.0 : 0.05
        }));
        nodesDataSet.update(nodeUpdates);

        var edgeUpdates = allEdges.map(e => ({
            id: e.id, 
            hidden: !(keep.has(e.from) && keep.has(e.to)) 
        }));
        edgesDataSet.update(edgeUpdates);

        isFiltered = true;
        document.getElementById('filter-indicator').style.display = 'block';
    }

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
        var kb = extra.context_kb || {};
        var sigma = extra.sigma_hits || [];
        if (sigma.length > 0) {
             html += '<div class="sigma-box">';
             sigma.forEach(title => { html += '<div class="sigma-hit-row"><span class="sigma-icon">⚠️</span><span class="sigma-text">' + title + '</span></div>'; });
             html += '</div>';
        }
        if ((kb.cves && kb.cves.length > 0) || (kb.keywords && kb.keywords.length > 0)) {
            html += '<div class="field-label">External Context</div>';
            html += '<div style="margin-top:5px">';
            if (kb.cves) kb.cves.forEach(x => html += '<span class="kg-tag tag-cve">' + x.split(':')[0] + '</span>'); 
            if (kb.keywords) kb.keywords.slice(0,8).forEach(x => html += '<span class="kg-tag tag-kw">' + x + '</span>');
            html += '</div>';
            if (kb.cves) {
                 html += '<div class="field-label">Vulnerability Details</div>';
                 kb.cves.forEach(x => html += '<div class="field-value" style="font-size:11px; margin-bottom:4px">' + x + '</div>');
            }
        }
        if (extra.relevance_score) {
             html += '<div class="field-label">Context Relevance Score</div>';
             html += '<div class="field-value">' + extra.relevance_score.toFixed(4) + '</div>';
        }
        if (extra.cmd) {
            html += '<div class="field-label">Command Line</div>';
            html += '<div class="field-value" style="color:#58a6ff">' + extra.cmd + '</div>';
        }
        for (var key in extra) {
            if (['context_kb', 'sigma_hits', 'cmd', 'label', 'shape', 'path_score', 'relevance_score', 'semantic_text', 'font'].indexOf(key) === -1) {
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
# 2. Semantic Embedding Engine (NLP Core)
# ============================================================================
class SemanticEngine:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        print(f"[NLP] Loading SBERT model: {model_name}...")
        self.model = SentenceTransformer(model_name)
        self.cve_embeddings = {}

    def encode_cves(self, cve_db):
        print(f"[NLP] Encoding {len(cve_db)} CVE descriptions into vector space...")
        for cve_id, data in cve_db.items():
            text = f"{data['description']} {' '.join(data.get('keywords', []))}"
            self.cve_embeddings[cve_id] = self.model.encode(text, convert_to_tensor=True)

    def compute_similarity(self, node_text, cve_id):
        if cve_id not in self.cve_embeddings:
            return 0.0
        node_embedding = self.model.encode(node_text, convert_to_tensor=True)
        score = util.cos_sim(node_embedding, self.cve_embeddings[cve_id])
        return float(score[0][0])


# ============================================================================
# 3. Knowledge Base Loader
# ============================================================================
class KnowledgeBaseLoader:
    def __init__(self, cve_path, sigma_dir):
        self.cve_path = cve_path
        self.sigma_dir = sigma_dir
        self.cve_db = {}
        self.sigma_rules = []

    def load(self):
        print("[Loader] Initializing Knowledge Base...")
        self._load_cve_db()
        self._load_sigma_rules()
        return self.cve_db, self.sigma_rules

    def _load_cve_db(self):
        if not os.path.exists(self.cve_path):
            return
        try:
            with open(self.cve_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get('CVE_Items', [])
            for item in items:
                cve_id = item.get('cve_id') or item.get('cveID')
                desc = item.get('description') or item.get('shortDescription')
                if cve_id and desc:
                    tokens = re.split(r'[\s\.,;:\(\)\[\]"\'-]+', desc.lower())
                    keywords = [t for t in tokens if len(t) > 3]
                    self.cve_db[cve_id] = {"description": desc, "keywords": keywords}
            print(f"[Loader] Loaded {len(self.cve_db)} CVEs.")
        except Exception as e:
            print(f"[Loader] CVE Load Error: {e}")

    def _load_sigma_rules(self):
        if not os.path.exists(self.sigma_dir):
            return
        count = 0
        for root, _, files in os.walk(self.sigma_dir):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            docs = list(yaml.safe_load_all(f))
                            for doc in docs:
                                if self._parse_sigma(doc):
                                    count += 1
                    except:
                        pass
        print(f"[Loader] Loaded {count} Sigma Rules.")

    def _parse_sigma(self, doc):
        if not doc or 'detection' not in doc:
            return False
        rule = {
            "title": doc.get('title'),
            "detection": doc.get('detection'),
            "cves": [tag.split('.')[1].upper() + '-' + tag.split('.')[2] for tag in doc.get('tags', []) if
                     tag.startswith('cve.')]
        }
        self.sigma_rules.append(rule)
        return True


# ============================================================================
# 4. CONTEXTS Algorithm Core (Graph + Logic)
# ============================================================================
class ContextsAlgorithm:
    def __init__(self, cve_db, sigma_rules):
        self.cve_db = cve_db
        self.rules = sigma_rules
        self.nlp = SemanticEngine()
        self.nlp.encode_cves(cve_db)
        self.G = nx.DiGraph()

    def build_graph(self, raw_nodes, raw_edges):
        self.G.clear()
        for n in raw_nodes:
            semantic_text = n.get('extra', {}).get('commandline', n['label'])
            if 'curl' in semantic_text or 'wget' in semantic_text:
                semantic_text += " download file network"
            if 'bash' in semantic_text or 'sh' in semantic_text:
                semantic_text += " execute shell"
            if 'nc' in semantic_text:
                semantic_text += " reverse shell network"

            self.G.add_node(n['id'], label=n['label'], type=n['group'], raw_data=n, semantic_text=semantic_text,
                            scores={})

        for e in raw_edges:
            self.G.add_edge(e['from'], e['to'], label=e['label'])
        print(f"[Graph] Built {self.G.number_of_nodes()} nodes.")

    def calculate_relevance(self):
        poi_nodes = set()
        print("[Score] Calculating relevance...")

        for nid in self.G.nodes:
            node = self.G.nodes[nid]
            node_text = node['semantic_text']
            max_score = 0.0
            matched_cves = []

            # 1. Match against Sigma rules
            sigma_hits = self._check_sigma(node['raw_data'])
            if sigma_hits:
                max_score = 1.0
                for rule in sigma_hits:
                    matched_cves.extend(rule['cves'])

            # 2. NLP scoring
            if matched_cves:
                for cve_id in matched_cves:
                    nlp_score = self.nlp.compute_similarity(node_text, cve_id)
                    if nlp_score > 0.3:
                        node['scores'][cve_id] = 0.5 + (0.5 * nlp_score)

            self.G.nodes[nid]['max_score'] = max_score
            if max_score > 0.6:
                poi_nodes.add(nid)

        print(f"[Score] Found {len(poi_nodes)} POI nodes.")
        return list(poi_nodes)

    def prune_graph(self, poi_nodes):
        if not poi_nodes:
            return [], []
        keep_nodes = set(poi_nodes)
        for poi in poi_nodes:
            keep_nodes.update(self.G.predecessors(poi))
            keep_nodes.update(self.G.successors(poi))

        G_undir = self.G.to_undirected()
        poi_list = list(poi_nodes)
        limit = min(len(poi_list), 50)

        for i in range(limit):
            for j in range(i + 1, limit):
                try:
                    if nx.has_path(G_undir, poi_list[i], poi_list[j]):
                        path = nx.shortest_path(G_undir, poi_list[i], poi_list[j])
                        if len(path) <= 6:
                            keep_nodes.update(path)
                except:
                    pass

        final_nodes, final_edges = [], []
        for nid in keep_nodes:
            n = self.G.nodes[nid]['raw_data']
            n['extra']['relevance_score'] = self.G.nodes[nid]['max_score']
            sigma_hits = self._check_sigma(n)
            n['extra']['sigma_hits'] = [r['title'] for r in sigma_hits]
            n['extra']['context_kb'] = {'cves': [], 'keywords': set()}
            for r in sigma_hits:
                for cve in r['cves']:
                    if cve in self.cve_db:
                        desc = self.cve_db[cve]['description'][:60] + "..."
                        n['extra']['context_kb']['cves'].append(f"{cve}: {desc}")
                        n['extra']['context_kb']['keywords'].update(self.cve_db[cve]['keywords'][:5])
            n['extra']['context_kb']['keywords'] = list(n['extra']['context_kb']['keywords'])
            final_nodes.append(n)

        for u, v, d in self.G.edges(data=True):
            if u in keep_nodes and v in keep_nodes:
                final_edges.append(
                    {'from': u, 'to': v, 'label': d['label'], 'id': f"{u}->{v}:{d['label']}"})  # edge ID for hiding
        return final_nodes, final_edges

    def _check_sigma(self, node_data):
        hits = []
        extra = node_data.get('extra', {})
        image = extra.get('image', '').lower()
        commandline = extra.get('commandline', '').lower()

        for rule in self.rules:
            detection = rule.get('detection', {})
            raw_sel = detection.get('selection')
            if not raw_sel:
                continue
            selections = [raw_sel] if isinstance(raw_sel, dict) else raw_sel
            if not isinstance(selections, list):
                continue

            for sel in selections:
                if not isinstance(sel, dict):
                    continue
                block_match = True
                checked_at_least_one = False

                for field_key, pattern in sel.items():
                    if '|' in field_key:
                        field, modifier = field_key.split('|', 1)
                    else:
                        field, modifier = field_key, 'contains'
                    field, modifier = field.lower(), modifier.lower()

                    target = ""
                    if field in ['image', 'process']:
                        target = image
                        checked_at_least_one = True
                    elif field in ['commandline', 'cmd', 'process.command_line']:
                        target = commandline
                        checked_at_least_one = True
                    else:
                        block_match = False
                        break

                    pats = pattern if isinstance(pattern, list) else [pattern]
                    pats = [str(p).lower() for p in pats]
                    match_found = False
                    for p in pats:
                        if modifier == 'endswith':
                            if target.endswith(p):
                                match_found = True
                        elif modifier == 'startswith':
                            if target.startswith(p):
                                match_found = True
                        else:
                            if p in target:
                                match_found = True
                        if match_found:
                            break

                    if not match_found:
                        block_match = False
                        break

                if block_match and checked_at_least_one:
                    hits.append(rule)
                    break
        return hits


# ============================================================================
# 5. Log Parser (rewritten version)
# ============================================================================
class LogParser:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self._seen_nodes = set()
        self._seen_edges = set()

    def ingest(self, pattern):
        files = glob.glob(pattern)
        if not files:
            print(f"[-] No files found matching: {pattern}")
            return

        for path in files:
            print(f"[Log] Processing {path}...")
            with open(path, 'r', encoding='utf-8') as f:
                first_char = f.read(1)
                f.seek(0)
                if first_char == '[':
                    try:
                        data = json.load(f)
                        for ev in data:
                            self._proc(ev)
                    except:
                        pass
                else:
                    for line in f:
                        if line.strip():
                            try:
                                self._proc(json.loads(line))
                            except:
                                pass

    def _add_node(self, nid, label, group, extra=None):
        if nid not in self._seen_nodes:
            self.nodes.append({
                'id': nid,
                'label': label,
                'group': group,
                'extra': extra or {}
            })
            self._seen_nodes.add(nid)

    def _add_edge(self, src, dst, label):
        eid = f"{src}->{dst}:{label}"
        if eid not in self._seen_edges:
            self.edges.append({'from': src, 'to': dst, 'label': label})
            self._seen_edges.add(eid)

    def _proc(self, ev):
        if ev.get('type') != 'SYSCALL':
            return

        pid = ev.get('pid')
        ppid = ev.get('ppid')
        subtype = ev.get('subtype')
        if not pid:
            return

        proc_id = f"p_{pid}"
        binary = ev.get('cmd') or ev.get('comm', 'unknown')
        args = ev.get('args', '')
        if isinstance(args, list):
            args = " ".join(args)
        commandline = f"{binary} {args}".strip()
        comm = ev.get('comm', '')

        self._add_node(proc_id, f"{comm}\n{pid}", 'proc', {
            'image': binary,
            'commandline': commandline,
            'cmd': commandline,
            'cgroup': ev.get('cgroup_id')
        })

        if ppid:
            p_id = f"p_{ppid}"
            self._add_node(p_id, f"PID {ppid}", 'proc', {'cmd': f"Process {ppid}"})
            self._add_edge(p_id, proc_id, 'spawn')

        if subtype == 'OPEN' and ev.get('filename'):
            fname = ev.get('filename')
            fid = f"f_{fname}_{pid}"
            self._add_node(fid, fname.split('/')[-1], 'file', {'fullpath': fname})
            self._add_edge(proc_id, fid, 'open')

        elif subtype == 'DELETE' and ev.get('filename'):
            fname = ev.get('filename')
            fid = f"f_{fname}_{pid}"
            self._add_node(fid, fname.split('/')[-1], 'file', {'fullpath': fname})
            self._add_edge(proc_id, fid, 'delete')

        elif subtype == 'MEMFD' and ev.get('name'):
            name = ev.get('name')
            mem_id = f"mem_{name}_{pid}"
            self._add_node(mem_id, f"MEM: {name}", 'file', {'fullpath': 'memory'})
            self._add_edge(proc_id, mem_id, 'memfd_create')

        elif subtype == 'INJECT' and ev.get('target_pid'):
            target = ev.get('target_pid')
            t_id = f"p_{target}"
            self._add_node(t_id, f"PID {target}", 'proc', {})
            self._add_edge(proc_id, t_id, 'ptrace_inject')


# ============================================================================
# 6. Main Execution
# ============================================================================
if __name__ == "__main__":
    # Configure paths (adjust to your actual environment)
    SIGMA_DIR = "/root/ebpf/rules/sigma/"
    CVE_DB_PATH = "/root/ebpf/rules/cve.json"
    LOG_FILE = "/root/ebpf/logs/2026-02-13/audit_21.json"
    OUTPUT_FILE = "contexts.html"
    ALERT_FILE = "context.txt"

    print("=== Contexts Analysis (Complete) ===")

    # 1. Load knowledge base
    loader = KnowledgeBaseLoader(CVE_DB_PATH, SIGMA_DIR)
    cve_db, sigma_rules = loader.load()

    # 2. Parse logs
    parser = LogParser()
    parser.ingest(LOG_FILE)
    print(f"[Log] Parsed {len(parser.nodes)} events.")

    # 3. Build graph and compute scores
    algo = ContextsAlgorithm(cve_db, sigma_rules)
    algo.build_graph(parser.nodes, parser.edges)

    poi_nodes = algo.calculate_relevance()
    final_nodes, final_edges = algo.prune_graph(poi_nodes)

    # Print the result counts after pruning
    print(f"[Pruning] Graph reduced to {len(final_nodes)} nodes and {len(final_edges)} edges.")

    # ------------------------------------------------------------------------
    # Print alert information and save it to context.txt
    # ------------------------------------------------------------------------
    print(f"\n[Analysis] Generating Alert Report -> {ALERT_FILE}")

    with open(ALERT_FILE, "w", encoding="utf-8") as f_txt:
        # Write the header
        header = f"{'=' * 60}\nCONTEXTS SECURITY ALERT REPORT\n{'=' * 60}\n"
        print(header, end='')  # print to console
        f_txt.write(header)  # write to file

        # Filter and sort alert nodes (prioritize Sigma hits or score > 0.6)
        alerts = [n for n in final_nodes if
                  (n['extra'].get('sigma_hits') or n['extra'].get('relevance_score', 0) > 0.6)]
        # Sort by relevance score, descending
        alerts.sort(key=lambda x: x['extra'].get('relevance_score', 0), reverse=True)

        if not alerts:
            msg = "[+] No high-priority threats detected.\n"
            print(msg)
            f_txt.write(msg)
        else:
            for i, node in enumerate(alerts, 1):
                extra = node.get('extra', {})
                label = node.get('label', 'Unknown').replace('\n', ' ')
                score = extra.get('relevance_score', 0)
                cmd = extra.get('commandline') or extra.get('cmd') or "N/A"
                sigma_hits = extra.get('sigma_hits', [])

                # Get a CVE summary (only the first 3, to keep it concise)
                kb_cves = extra.get('context_kb', {}).get('cves', [])
                cve_summary = [c.split(':')[0] for c in kb_cves[:3]]

                # Build the alert block string
                lines = []
                lines.append(f"[{i}] NODE: {label}")
                lines.append(f"    SCORE: {score:.4f}")
                lines.append(f"    CMD:   {cmd}")

                if sigma_hits:
                    lines.append(f"    SIGMA: {', '.join(sigma_hits)}")
                else:
                    lines.append(f"    SIGMA: (None)")

                if cve_summary:
                    lines.append(f"    CVEs:  {', '.join(cve_summary)}")

                lines.append("-" * 60 + "\n")

                block = "\n".join(lines)

                # Output
                print(block, end='')  # console
                f_txt.write(block)  # file

    print(f"[Done] Alert text report saved to {ALERT_FILE}")

    # ------------------------------------------------------------------------
    # Continue to generate the HTML visualization
    # ------------------------------------------------------------------------
    print("[Visuals] Applying colors and styles...")
    for n in final_nodes:
        # Force black font
        n['font'] = {'color': 'black'}

        is_hit = n['extra'].get('sigma_hits') and len(n['extra']['sigma_hits']) > 0
        if is_hit or n['extra'].get('relevance_score', 0) > 0.6:
            n['color'] = {'background': '#da3633', 'border': '#f85149'}
            n['label'] = "🚨 " + n['label']
            if 'group' in n:
                del n['group']
        else:
            grp = n.get('group', 'proc')
            if grp == 'proc':
                n['color'] = {'background': '#2196f3', 'border': '#2196f3'}
            elif grp == 'net':
                n['color'] = {'background': '#238636', 'border': '#238636'}
            elif grp == 'file':
                n['color'] = {'background': '#d29922', 'border': '#d29922'}

    out_json = json.dumps({"nodes": final_nodes, "edges": final_edges}, ensure_ascii=False)

    # Write the final HTML
    final_html = HTML_TEMPLATE.replace('__SNAPSHOTS_JSON__', out_json)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(final_html)

    print(f"[Done] HTML Visualization saved to {OUTPUT_FILE}")
