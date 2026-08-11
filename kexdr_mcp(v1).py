#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import os
import glob
import sys
import re
import copy
import warnings
import sqlite3
import traceback
from datetime import datetime


try:
    import igraph as ig
    import leidenalg

    LEIDEN_AVAILABLE = True
except ImportError:
    
    LEIDEN_AVAILABLE = False

from mcp.server.fastmcp import FastMCP


warnings.filterwarnings("ignore")

mcp = FastMCP("KeXDR-Server")

# ============================================================================
# 1. HTML (Legend V3: Universal Entities & TimeLinks)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>KeXDR Multi-Verse</title>
     <!-- Inlined at build time -->
    <script>__VIS_JS_CONTENT__</script>
    <script>__MARKED_JS_CONTENT__</script>
    <style>
        /* --- Base Layout --- */
        body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; margin: 0; display: flex; height: 100vh; overflow: hidden; }

        /* --- Sidebar --- */
        #sidebar { width: 320px; background: #1e1e1e; border-right: 1px solid #333; display: flex; flex-direction: column; z-index: 20; box-shadow: 4px 0 15px rgba(0,0,0,0.5); }
        .header { padding: 10px; background: #252526; border-bottom: 1px solid #333; }
        .sel { width: 100%; padding: 6px; background: #121212; color: #fff; border: 1px solid #444; border-radius: 4px; outline: 0; }

        /* Community List (Persistent) */
        .comm-box { flex: 0 0 auto; max-height: 35vh; overflow-y: auto; border-bottom: 1px solid #444; background: #1a1a1a; }
        .comm-header { padding: 8px 15px; font-size: 11px; font-weight: bold; color: #888; text-transform: uppercase; background: #252526; position: sticky; top: 0; }
        .comm-item { padding: 6px 15px; border-bottom: 1px solid #2d2d30; cursor: pointer; font-size: 12px; display: flex; align-items: center; color: #ccc; transition: all 0.2s; }
        .comm-item:hover { background: #2a2d2e; color: #fff; }
        .comm-item.active { background: #37373d; border-left: 3px solid #61dafb; color: #fff; font-weight: bold; }
        .comm-count { margin-left: auto; font-size: 10px; background: #000; padding: 1px 5px; border-radius: 4px; color: #888; }

        /* Node List (Dynamic) */
        .search-box { padding: 8px; border-bottom: 1px solid #333; background: #252526; }
        .search-input { width: 95%; background: #121212; border: 1px solid #444; color: #ccc; padding: 5px; border-radius: 3px; outline: none; }
        .list-box { flex: 1; overflow-y: auto; }
        .item { padding: 8px 15px; border-bottom: 1px solid #2d2d30; cursor: pointer; font-size: 12px; display: flex; align-items: center; color: #bbb; }
        .item:hover { background: #2a2d2e; color: #fff; }
        .item.threat { border-left: 3px solid #e74c3c; background: rgba(231,76,60,0.1); }
        .item.ai-done { border-left: 3px solid #9b59b6; background: rgba(155, 89, 182, 0.1); }
        .item.active-node { background: #204060; color: white; }

        /* --- Badges & Indicators --- */
        .dot { width: 8px; height: 8px; border-radius: 50%; margin-right: 10px; border: 1px solid #000; }
        .badge { font-size: 9px; padding: 1px 4px; border-radius: 3px; margin-left: auto; font-weight: bold; }
        .b-in { background: #00cec9; color: black; } 
        .b-out { background: #d35400; color: white; } 
        .b-host { background: #8e44ad; color: white; }
        .ai-badge { background: #9b59b6; color: white; font-size: 9px; padding: 1px 4px; border-radius: 3px; margin-left: 5px; box-shadow: 0 0 5px #9b59b6; }

        /* --- Main Graph Area --- */
        #main { flex: 1; position: relative; }
        #net { width: 100%; height: 100%; }

        /* --- Controls & Legend --- */
        .ctrls { position: absolute; bottom: 20px; right: 20px; display: flex; gap: 10px; z-index: 25; }
        .btn { background: #2d2d30; color: #ccc; border: 1px solid #444; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn:hover { background: #444; color: #fff; border-color: #61dafb; }
        .btn-ai { border-color: #9b59b6; color: #d0bfff; background: rgba(155, 89, 182, 0.2); }
        .btn-ai:hover { background: #9b59b6; color: white; }

        .legend { 
            position: absolute; bottom: 20px; left: 20px; 
            background: rgba(30,30,30,0.95); padding: 12px; 
            border-radius: 6px; pointer-events: none; font-size: 11px; 
            border: 1px solid #444; display: grid; grid-template-columns: 1fr 1fr; gap: 8px 15px; 
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        .legend-title { grid-column: span 2; font-weight: bold; color: #888; border-bottom: 1px solid #555; margin-bottom: 4px; padding-bottom: 2px; text-transform: uppercase; font-size: 10px; }
        .l-item { display: flex; align-items: center; color: #ccc; }
        .l-shape { width: 12px; height: 12px; margin-right: 8px; display: inline-block; }

        /* Legend Shapes */
        .ls-host { background:#8e44ad; border-radius:2px; }
        .ls-proc { background:#2980b9; border-radius:50%; }
        .ls-file { background:#f1c40f; border-radius:0; } /* Box */
        .ls-out { background:#d35400; transform:rotate(45deg) scale(0.8); } /* Diamond */
        .ls-in { background:#00d2d3; clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%); } /* Star */

        .ls-threat { border:2px solid #e74c3c; background:rgba(231,76,60,0.2); border-radius:50%; box-sizing:border-box; }
        .ls-ghost { border:2px dashed #1abc9c; background:rgba(26,188,156,0.1); border-radius:50%; box-sizing:border-box; }
        .ls-link { width: 15px; height: 0; border-top: 2px dashed #1abc9c; margin-right: 8px; }

        /* --- Detail Panel --- */
        #panel { position: fixed; top: 0; right: -500px; width: 500px; height: 100vh; background: #1e1e1e; border-left: 1px solid #444; transition: right 0.3s; z-index: 30; display: flex; flex-direction: column; box-shadow: -5px 0 20px rgba(0,0,0,0.5); }
        #panel.open { right: 0; }
        .content { flex: 1; overflow-y: auto; padding: 25px; }

        h2 { color: #61dafb; border-bottom: 1px solid #444; padding-bottom: 10px; margin-top: 0; }
        .field-label { font-size: 10px; color: #666; font-weight: 700; margin-top: 10px; letter-spacing: 0.5px; }
        .field-val { font-family: 'Consolas', monospace; font-size: 11px; color: #d4d4d4; background: #121212; padding: 8px; border: 1px solid #333; word-break: break-all; border-radius: 4px; white-space: pre-wrap;}

        .ai-box { background: rgba(155, 89, 182, 0.1); border: 1px solid #9b59b6; padding: 15px; margin-bottom: 20px; border-radius: 4px; color: #e0e0e0; }
        .ai-box h1, .ai-box h2, .ai-box h3 { color: #d0bfff; margin-top: 10px; border-bottom: none; font-size: 14px; }
        .ai-box strong { color: #fff; }

        .ghost-box { border: 1px dashed #1abc9c; padding: 10px; margin-bottom: 10px; color: #1abc9c; background: rgba(26, 188, 156, 0.05); }
        .attck-tag { background: #c0392b; color: white; padding: 2px 5px; border-radius: 3px; font-size: 10px; margin-right: 5px; font-weight: bold; }
    </style>
</head>
<body>
<div id="sidebar">
    <div class="header">
        <select id="sel" class="sel" onchange="loadView(this.value)"></select>
    </div>

    <div class="comm-box">
        <div class="comm-header">Detection Clusters</div>
        <div id="comm-list"></div>
    </div>

    <div class="search-box">
        <input type="text" id="ipSearch" class="search-input" placeholder="Filter nodes..." onkeyup="filterList()">
    </div>
    <div class="list-box">
        <ul id="node-list" style="padding:0;margin:0;list-style:none"></ul>
    </div>

    <div style="padding:8px; text-align:center; color:#555; font-size:10px; border-top:1px solid #333">Host: <span id="host-ip-display"></span></div>
</div>

<div id="main">
    <div id="net"></div>

    <div class="legend">
        <div class="legend-title">Entities</div>
        <div class="l-item"><div class="l-shape ls-host"></div>Host</div>
        <div class="l-item"><div class="l-shape ls-proc"></div>Process</div>
        <div class="l-item"><div class="l-shape ls-file"></div>File</div>
        <div class="l-item"><div class="l-shape ls-out"></div>Net (Out)</div>
        <div class="l-item"><div class="l-shape ls-in"></div>Net (In)</div>
        <div class="l-item"></div> <div class="legend-title" style="margin-top:5px">States & Links</div>
        <div class="l-item"><div class="l-shape ls-threat"></div>Threat</div>
        <div class="l-item"><div class="l-shape ls-ghost"></div>Ghost</div>
        <div class="l-item" style="grid-column: span 2"><div class="ls-link"></div>TimeLink (Stitch)</div>
    </div>

    <div class="ctrls">
        <button class="btn" onclick="loadView('overview')">🏠 Global</button>
        <button class="btn btn-ai" onclick="showAI()">🤖 AI Report</button>
        <button class="btn" onclick="net.fit()">🔍 Fit</button>
        <button class="btn" id="btn-phy" onclick="togglePhy()">🛑 Pause</button>
    </div>
</div>

<div id="panel">
    <div style="position:absolute;top:15px;right:20px;cursor:pointer;font-size:20px" onclick="document.getElementById('panel').classList.remove('open')">✕</div>
    <div class="content" id="p-content"></div>
</div>

<script>
// --- Data Injection ---
var data = __SNAPSHOTS__;
var host = "__HOST__";
var ipMap = __IP_MAP__;

// --- State ---
var net = null;
var nodes = new vis.DataSet();
var edges = new vis.DataSet();
var phy = true;
var currentView = 'overview';

document.getElementById('host-ip-display').innerText = host;

// --- Initialization ---
initUI();
initNetwork();
loadView('overview');

function initUI() {
    var sel = document.getElementById('sel');
    Object.keys(data).sort().forEach(k => {
        if(k === 'overview' || k.startsWith('comm_')) {
            var opt = document.createElement("option"); 
            opt.value = k; 
            opt.text = k==='overview' ? "GLOBAL OVERVIEW" : "Cluster " + k.replace('comm_','#');
            sel.appendChild(opt);
        }
    });

    // Populate Persistent Community List (Only once)
    if(data['overview'] && data['overview'].nodes) {
        var comms = data['overview'].nodes.filter(n => n.group === 'community');
        // Sort: AI analyzed first, then Threats, then Size
        comms.sort((a,b) => {
            var aAI = (a.extra && a.extra.ai_analysis) ? 1 : 0;
            var bAI = (b.extra && b.extra.ai_analysis) ? 1 : 0;
            if (aAI !== bAI) return bAI - aAI;
            return (b.extra.threats||0) - (a.extra.threats||0);
        });

        var cList = document.getElementById('comm-list');
        comms.forEach(c => {
            var div = document.createElement('div');
            div.className = 'comm-item';
            div.id = 'menu-' + c.id; 
            var commKey = 'comm_' + c.id.replace('c_', '');

            // Threat Indicator
            var threatDot = (c.extra.threats > 0) ? `<span style="color:#e74c3c;margin-right:5px">⚠️</span>` : '';
            var aiBadge = (c.extra.ai_analysis) ? `<span class="ai-badge">AI</span>` : '';

            div.innerHTML = `<div class="dot" style="background:${c.color}"></div>${threatDot}Cluster #${c.id.replace('c_','')} ${aiBadge} <span class="comm-count">${c.extra.count}</span>`;

            div.onclick = function() { loadView(commKey); };
            cList.appendChild(div);
        });
    }
}

function loadView(k) {
    if(!data[k]) return;
    currentView = k;
    document.getElementById('sel').value = k;

    // 1. Update Graph Data
    nodes.clear(); edges.clear();
    nodes.add(data[k].nodes); edges.add(data[k].edges);

    // 2. Update Sidebar State (Highlight Active Cluster)
    document.querySelectorAll('.comm-item').forEach(el => el.classList.remove('active'));
    if(k.startsWith('comm_')) {
        var cID = 'menu-c_' + k.replace('comm_', '');
        var activeEl = document.getElementById(cID);
        if(activeEl) {
            activeEl.classList.add('active');
            activeEl.scrollIntoView({behavior: "smooth", block: "nearest"});
        }
    } else {
        // Overview mode: Ensure physics is stable
        if(net) net.setOptions({physics:{solver:'forceAtlas2Based', forceAtlas2Based:{gravitationalConstant:-2000, springLength:200}}});
    }

    // 3. Render Node List (Dynamic Bottom Part)
    renderNodeList(data[k].nodes);

    if(net) {
        net.fit();
        // Use lighter physics for sub-graphs
        if(k !== 'overview') net.setOptions({physics:{solver:'forceAtlas2Based', forceAtlas2Based:{gravitationalConstant:-100, springLength:100}}});
    }
}

function renderNodeList(ns) {
    var l = document.getElementById('node-list'); 
    l.innerHTML = '';

    // Sort: AI -> Threats -> IPs
    var listItems = [];
    ns.forEach(n => {
        // Filter logic: show networks, hosts, and threats
        var relevant = (n.group === 'net' || n.group === 'net_in_agg' || n.group === 'host' || n.group === 'gw');
        var isThreat = n.extra.attck_evidence && n.extra.attck_evidence.length > 0;
        var hasAI = !!n.extra.ai_analysis;

        if(relevant || isThreat || hasAI) {
             var ip = n.extra.ip || n.label.split('\\n')[0];
             listItems.push({id: n.id, label: ip, threat: isThreat, ai: hasAI, group: n.group});
        }
    });

    listItems.sort((a,b) => {
        if(a.ai !== b.ai) return b.ai - a.ai;
        if(a.threat !== b.threat) return b.threat - a.threat;
        return 0;
    });

    listItems.forEach(i => {
        var li = document.createElement('li');
        li.className = 'item' + (i.threat ? ' threat' : '') + (i.ai ? ' ai-done' : '') + (i.group==='gw' ? ' item-gw' : '');

        var badge = '';
        if(i.group==='host') badge='<span class="badge b-host">HOST</span>';
        else if(i.group==='net_in_agg') badge='<span class="badge b-in">IN</span>';
        else if(i.group==='net') badge='<span class="badge b-out">OUT</span>';
        else if(i.group==='gw') badge='<span class="badge" style="background:#7f8c8d;color:white">GW</span>';
        else if(i.group==='proc') badge='<span class="badge" style="background:#2980b9;color:white">PROC</span>';

        if(i.ai) badge = '<span class="ai-badge">AI</span> ' + badge;

        li.innerHTML = `<div class="dot" style="background:${i.threat?'#e74c3c':'#555'}"></div> ${i.label} ${badge}`;
        li.onclick = function() { focusNode(i.id); };
        l.appendChild(li);
    });

    if(listItems.length === 0) l.innerHTML = '<div style="padding:15px;color:#555;font-style:italic;text-align:center">No major endpoints</div>';
}

function initNetwork() {
    var container = document.getElementById('net');
    net = new vis.Network(container, {nodes:nodes, edges:edges}, {
        nodes: { shape: 'dot', font: { color: '#ccc', strokeWidth: 0 } },
        edges: {
                    color: { color: '#555', opacity: 0.5 },
                    arrows: 'to',
                    smooth: { enabled: true, type: 'continuous', roundness: 0.0 } 
                },        interaction: { hover: true, navigationButtons: true },
        physics: { enabled: true }
    });

    net.on("click", function(p) {
        if(p.nodes.length) show(nodes.get(p.nodes[0]));
        else document.getElementById('panel').classList.remove('open');
    });

    net.on("doubleClick", function(p) {
        if(p.nodes.length) {
            var n = nodes.get(p.nodes[0]);
            if(n.group === 'community') loadView('comm_' + n.id.replace('c_',''));
        }
    });
}

function focusNode(nid) {
    net.selectNodes([nid]);
    net.focus(nid, {scale: 1.5, animation: true});
    show(nodes.get(nid));
}

function showAI() {
    var found = nodes.get({filter: function(n){ return n.extra && n.extra.ai_analysis; }});
    if(found.length > 0) {
        focusNode(found[0].id);
    } else {
        alert("No AI Report found in this view.\\n\\nTip: Use the AI agent to analyze this cluster first!");
    }
}

function filterList() {
    var filter = document.getElementById("ipSearch").value.toUpperCase();
    var li = document.getElementById("node-list").getElementsByTagName("li");
    for (var i = 0; i < li.length; i++) {
        var txt = li[i].textContent || li[i].innerText;
        li[i].style.display = txt.toUpperCase().indexOf(filter) > -1 ? "" : "none";
    }
}

function togglePhy() {
    phy = !phy;
    net.setOptions({physics:{enabled:phy}});
    document.getElementById('btn-phy').innerText = phy ? "🛑 Pause" : "▶️ Resume";
}

function show(n) {
    var h = `<h2>${n.label.split('\\n')[0]}</h2>`;

    if(n.extra.ai_analysis) {
        h += `<div class="ai-box"><b>🤖 AI Analysis</b><br>${marked.parse(n.extra.ai_analysis)}</div>`;
    }

    if(n.group === 'ghost') {
        h += `<div class="ghost-box"><b>👻 Historical Context</b><br>${n.extra.desc}</div>`;
    }

    if(n.extra.attck_evidence) {
        n.extra.attck_evidence.forEach(t => {
            h += `<div style="margin-bottom:5px"><span class="attck-tag">${t.tag}</span> <span style="font-size:11px;color:#e74c3c">${t.reason}</span></div>`;
        });
    }

    Object.keys(n.extra).forEach(k => {
        if(!['ai_analysis','attck_evidence','payload','desc','matched_key'].includes(k))
            h += `<div class="field-label">${k.toUpperCase()}</div><div class="field-val">${n.extra[k]}</div>`;
    });

    if(n.extra.payload) {
        h += `<div class="field-label">PAYLOAD</div><div class="field-val" style="max-height:200px;overflow:auto">${n.extra.payload}</div>`;
    }

    if(n.group === 'community') {
        h += `<button class="btn" style="width:100%;background:#0e639c;margin-top:15px" onclick="loadView('comm_${n.id.replace('c_','')}')">📂 Enter Cluster</button>`;
    }

    document.getElementById('p-content').innerHTML = h;
    document.getElementById('panel').classList.add('open');
}
</script>
</body>
</html>
"""

# ============================================================================
# 2. Memory Core (Hippocampus)
# ============================================================================
class Hippocampus:
    def __init__(self, db_path="kexdr_memory.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
       
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS artifacts (
            key TEXT, event_id TEXT, timestamp REAL, desc TEXT, payload TEXT, PRIMARY KEY (key, event_id))''')
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ts ON artifacts (timestamp)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_key ON artifacts (key)")
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS lineage (
                    child_id TEXT PRIMARY KEY, parent_id TEXT, parent_desc TEXT, ts REAL)''')

        self.conn.commit()

    def recall(self, keys):
        results = []
        if not keys: return results
       
        placeholders = ','.join('?' for _ in keys)
        try:
            
            query = f"""
                SELECT event_id, timestamp, desc, payload, key 
                FROM artifacts 
                WHERE key IN ({placeholders}) 
                ORDER BY timestamp DESC
            """
            self.cursor.execute(query, tuple(keys))
         
            rows = self.cursor.fetchall()

            
            key_counts = {}
            for r in rows:
                k = r[4]
                if key_counts.get(k, 0) < 5:
                    results.append({'id': r[0], 'ts': r[1], 'desc': r[2], 'payload': r[3], 'key': k})
                    key_counts[k] = key_counts.get(k, 0) + 1
        except Exception as e:
            sys.stderr.write(f"Recall Error: {e}\n")
        return results

    def remember(self, keys, event_id, ts, desc, payload_json):
        if not keys: return
        data = []
        for k in keys:
            data.append((k, event_id, ts, desc, payload_json))

        try:
            self.cursor.executemany("INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?)", data)
        except Exception as e:
            pass

    def commit_batch(self):
        try:
            self.conn.commit()
        except:
            pass

    
    def prune_old_memories(self, days_retention=7):
        """
        
        """
        try:
            current_ts = datetime.now().timestamp()
          
            cutoff_ts = current_ts - (days_retention * 24 * 3600)

           
            self.cursor.execute("DELETE FROM artifacts WHERE timestamp < ?", (cutoff_ts,))
            deleted_count = self.cursor.rowcount
            self.conn.commit()

           
          
            if deleted_count > 0:
                sys.stderr.write(f"[*] Pruning: Deleted {deleted_count} old artifacts. Optimizing DB...\n")
                try:
                    self.cursor.execute("VACUUM")
                except sqlite3.OperationalError:
                   
                    sys.stderr.write("[!] VACUUM skipped due to locked DB.\n")
            else:
                
                pass

            return deleted_count
        except Exception as e:
       
            sys.stderr.write(f"[!] Prune Error: {e}\n")
            return 0

  

    def register_birth(self, child_id, parent_id, parent_desc, ts):
        try:
            self.cursor.execute("INSERT OR REPLACE INTO lineage VALUES (?,?,?,?)",
                                (child_id, parent_id, parent_desc, ts))
        except:
            pass

    def find_parent(self, child_id):
        try:
            self.cursor.execute("SELECT parent_id, parent_desc FROM lineage WHERE child_id=?", (child_id,))
            return self.cursor.fetchone()
        except:
            return None

# ============================================================================
# 3. Provenance Logic
# ============================================================================
class ProvenancePublicDirect:
    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.nodes = {}
        self.edge_map = {}
     
        self.adj_list = {}
        self.pending_conns = {}
        self.inbound_cache = []
        self.connected_targets = set()
        self.host_node_id = f"host_{self.host_ip.replace('.', '_')}"
        self.L4_TYPE_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        self.L7_PORT_MAP = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                            443: "HTTPS", 3306: "MySQL"}
        self.C_PROC = "#2980b9";
        self.C_FILE = "#f1c40f";
        self.C_GW = "#7f8c8d"
        self.C_REAL = "#d35400";
        self.C_IN = "#27ae60";
        self.C_HOST = "#8e44ad"
        self.C_ALERT = "#e74c3c";
        self.C_MEM = "#8e44ad";
        self.C_IN_AGG = "#00d2d3"
        self.C_PRIV = "#f39c12"
        self.C_DEL = "#c0392b"

    def _get_proto(self, l4, port):
        return self.L7_PORT_MAP.get(port, self.L4_TYPE_MAP.get(l4, "RAW"))

    def add_node(self, nid, label, group, color, shape='dot', border='solid', extra=None):
        if nid not in self.nodes:
            self.nodes[nid] = {'id': nid, 'label': label, 'group': group, 'color': color, 'shape': shape,
                               'extra': extra or {}}
        elif extra and 'payload' in extra:
            c = self.nodes[nid]['extra'].get('payload', '')
            if len(c) < 5000: self.nodes[nid]['extra']['payload'] = (c + "\n" + extra['payload']).strip()

    def add_edge(self, src, dst, label, color="#555", style="solid"):
        key = (src, dst, label)
        if key not in self.edge_map:
            self.edge_map[key] = {'count': 1, 'color': color, 'style': style}
        else:
            self.edge_map[key]['count'] += 1
        self.connected_targets.add(dst)
        self.connected_targets.add(src)
    
        if src != dst:
            if src not in self.adj_list:
                self.adj_list[src] = set()
            self.adj_list[src].add(dst)

    def _id_proc(self, p, c):
        return f"p_{c}_{p}"

    def _id_net(self, i, p):
        return f"net_{i}_{p}"

    def _id_file(self, n, c):
        return f"f_{hash(n + str(c))}"

    def _id_gw(self, i):
        return f"gw_{i}"

    def ingest(self, fpath):
        self.add_node(self.host_node_id, f"HOST\n{self.host_ip}", "host", self.C_HOST, "box", "solid",
                      {'ip': self.host_ip})
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            self.process_event(json.loads(line))
                        except:
                            pass
        except Exception as e:
            sys.stderr.write(f"Error reading {fpath}: {e}\n")

    def process_event(self, ev):
        etype = ev.get('type')
        pid = ev.get('pid');
        cg = ev.get('cgroup_id', 0);
        comm = ev.get('comm', 'u')
        ts = ev.get('timestamp', '')

        if etype == 'NETWORK':
            dip = ev.get('dst_ip')
            dport = int(ev.get('dst_port', 0) or 0)
            raw_payload = ev.get('payload_info', '').strip()

        
            if dip == self.host_ip:
                src_ip = ev.get('src_ip')
                if not src_ip: return

              
                proto_name = ev.get('subtype')
                if not proto_name or proto_name == 'NETWORK':
                    proto_name = self._get_proto(ev.get('proto_id', 6), dport)

                rid = f"src_{src_ip}_{dport}"

            
                payload_entry = ""
                if raw_payload:
                    short_ts = str(ts).split('T')[-1].split('.')[0] if 'T' in str(ts) else ts
                    payload_entry = f"[{short_ts}] {raw_payload}"

              
                self.add_node(
                    rid,
                    f"{src_ip}\n(To :{dport})",  
                    'net_in_agg',
                    self.C_IN_AGG,
                    'star',  
                    'solid',
                    {
                        'ip': src_ip,  
                        'port': str(dport),
                        'protocol': proto_name,
                        'payload': payload_entry,
                        'time': ts
                    }
                )

             
                self.add_edge(rid, self.host_node_id, f"{proto_name}", self.C_IN_AGG)

           
            elif dip:
                rid = self._id_net(dip, dport)
                proto = self._get_proto(ev.get('proto_id', 6), dport)

                
                payload_entry = ""
                if raw_payload:
                    payload_entry = f">>> {raw_payload}"

                self.add_node(
                    rid,
                    f"{dip}:{dport}",
                    'net',
                    self.C_REAL,
                    'diamond',
                    'solid',
                    {
                        'ip': dip,
                        'port': str(dport),
                        'time': ts,
                        'payload': payload_entry 
                    }
                )

            
                if dport in self.pending_conns:
                    for c in reversed(self.pending_conns[dport]):
                        c['matched'] = True
                        if c['is_infra']:
                            self.add_node(c['gw_id'], f"GW\n{c['gw_ip']}", 'gw', self.C_GW, 'square', 'dashed',
                                          {'ip': c['gw_ip'], 'time': ts})
                            self.add_edge(c['proc_id'], c['gw_id'], "conn")
                            self.add_edge(c['gw_id'], rid, proto, self.C_REAL)
                        else:
                            self.add_edge(c['proc_id'], rid, proto, self.C_REAL)
                        break

        elif pid:
            proc_id = self._id_proc(pid, cg)
            self.add_node(proc_id, f"{comm}\n{pid}", 'proc', self.C_PROC, 'dot', 'solid',
                          {'pid': str(pid), 'cmd': f"{comm} {ev.get('args', '')}",
                           'payload': ev.get('payload_info', ''),'time': ts})
            if ev.get('ppid'):
                pid_p = self._id_proc(ev.get('ppid'), cg)
                self.add_node(pid_p, f"PID {ev.get('ppid')}", 'proc', self.C_PROC, 'dot', 'solid',
                              {'pid': str(ev.get('ppid'))})
                self.add_edge(pid_p, proc_id, "spawn")

            if ev.get('subtype') == 'OPEN' and ev.get('filename'):
                fname = ev.get('filename')
                fid = self._id_file(fname, cg)
                self.add_node(fid, os.path.basename(fname), 'file', self.C_FILE, 'box', 'solid', {'path': fname,'time': ts})
                self.add_edge(proc_id, fid, "open")

          
            if ev.get('subtype') == 'MMAP':
                prot = ev.get('prot', '')
                if ev.get('is_exec'):
                    self.nodes[proc_id]['extra']['risk_mmap'] = prot
                if 'WRITE' in prot and 'EXEC' in prot:
                    self.add_edge(proc_id, proc_id, "RWX\nShellcode", "#e74c3c", "solid")

            
                if ev.get('filename'):
                    fname = ev.get('filename')
                    fid = self._id_file(fname, cg)
                    prot_label = ev.get('prot', 'MAP')

                    self.add_node(fid, os.path.basename(fname), 'file', self.C_FILE, 'box', 'solid',
                                  {'path': fname,'time': ts})
                    self.add_edge(proc_id, fid, f"mmap({prot_label})", color="#1abc9c", style="dashed")


            if ev.get('subtype') == 'MEMFD':
                mem_name = ev.get('name', 'anonymous')
                self.add_edge(proc_id, proc_id, f"MEMFD\n{mem_name}", "#e67e22", "dashed")
                if proc_id in self.nodes:
                    self.nodes[proc_id]['extra']['memfd_name'] = mem_name

            if ev.get('subtype') == 'INJECT':
                req_name = ev.get('request_name', 'PTRACE')
                target_pid = ev.get('target_pid')

                self.nodes[proc_id]['extra']['ptrace_req'] = req_name

          
                if target_pid and target_pid != 0:
                    target_id = self._id_proc(target_pid, cg)

                    if target_id not in self.nodes:
                        self.add_node(target_id, f"Target\n{target_pid}", 'proc', self.C_PROC, 'dot', 'solid',
                                      {'pid': str(target_pid)})

             
                    edge_label = f"{req_name.replace('PTRACE_', '')}"
                    self.add_edge(proc_id, target_id, edge_label, color="#9b59b6", style="dashed")

            if ev.get('subtype') == 'SETUID':
                target_uid = ev.get('target_uid')
                self.add_edge(proc_id, proc_id, f"SETUID({target_uid})", self.C_PRIV, "solid")
                if proc_id in self.nodes:
                    self.nodes[proc_id]['extra']['risk_priv'] = True


            if ev.get('subtype') == 'DELETE':
                fname = ev.get('filename')
                if fname:
                    fid = self._id_file(fname, cg)
                    self.add_node(fid, os.path.basename(fname), 'file', self.C_FILE, 'box', 'solid',
                                  {'path': fname, 'time': ts})
                    self.add_edge(proc_id, fid, "unlink", self.C_DEL, "dashed")

            if ev.get('subtype') == 'CONNECT':
                dip = ev.get('dst_ip');
                dport = int(ev.get('dst_port', 0) or 0)
                if dip and dport > 0:
                    is_infra = dip.startswith('10.') or dip.startswith('192.168.') or dip == '127.0.0.1'
                    if dport not in self.pending_conns: self.pending_conns[dport] = []
                    self.pending_conns[dport].append(
                        {'is_infra': is_infra, 'gw_id': self._id_gw(dip), 'gw_ip': dip, 'proc_id': proc_id,
                         'dst_port': dport, 'matched': False})

    def process_unmatched(self):
        for port, clist in self.pending_conns.items():
            for c in clist:
                if not c['matched']:
                    self.add_edge(c['proc_id'], self._id_net(c['gw_ip'], c['dst_port']), "attempt", self.C_REAL,
                                  "dashed")

    def get_data(self):
        fn = []
        if self.host_node_id in self.nodes:
            fn.append(self.nodes[self.host_node_id])

        for nid, n in self.nodes.items():
            if nid == self.host_node_id: continue
            if n['group'] in ['net', 'net_in_agg', 'gw']:
                if nid in self.connected_targets: fn.append(n)
            else:
                fn.append(n)

        fids = set(n['id'] for n in fn)
        eo = []

        for (s, d, l), i in self.edge_map.items():
            if s in fids and d in fids:
                edge_obj = {
                    'from': s,
                    'to': d,
                    'label': l,
                    'color': i['color'],
                    'font': {'size': 10, 'align': 'middle'}, # Add font alignment so the label reads better
                    'extra': i.get('extra')
                }

                if i.get('style') == 'dashed':
                    edge_obj['dashes'] = True

                if s == d:
                    edge_obj['smooth'] = {'type': 'curvedCW', 'roundness': 0.4}

                eo.append(edge_obj)

        return fn, eo

# ============================================================================
# 4. Orchestrator
# ============================================================================
class AttckMapper:
    def __init__(self):
        self.rules = [
            # =========================================================================
            # TACTIC: RECONNAISSANCE (TA0043) 
            # =========================================================================
            {'id': 'T1595.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-h|-t|scan|--script'),
             'cmd': re.compile(r'nikto|nessus|openvas|sqlmap|nuclei|acunetix'),
             'desc': 'Vulnerability Scanning Activity (vulnerability scanning tools)'},

            {'id': 'T1595.001', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-p|-sS|-sT|--rate|-oG'),
             'cmd': re.compile(r'nmap|masscan|zmap|naabu|rustscan'),
             'desc': 'Active Port Scanning'},

            {'id': 'T1593.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-w|-m|spider|crawl|--depth'),
             'cmd': re.compile(r'cewl|gospider|hakrawler|wget --mirror|photon'),
             'desc': 'Web Spidering/Wordlist Generation'},

            {'id': 'T1594', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-u|-w|-x|dir|fuzz'),
             'cmd': re.compile(r'gobuster|dirb|dirsearch|ffuf|feroxbuster'),
             'desc': 'Web Directory/File Brute Forcing'},

            {'id': 'T1590.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'axfr|enum|brute|subdomain'),
             'cmd': re.compile(r'dnsenum|dnsrecon|sublist3r|amass|fierce|dig axfr'),
             'desc': 'DNS Enumeration/Zone Transfer'},

            {'id': 'T1596', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'search|query|host|ip'),
             'cmd': re.compile(r'shodan|censys|searchsploit'),
             'desc': 'Querying Technical Databases'},

            # =========================================================================
            # TACTIC: RESOURCE DEVELOPMENT (TA0042) 
            # =========================================================================
            {'id': 'T1587.001', 'phase': 'Resource Development',
             'pattern': re.compile(r'-o|build|dist|pyinstaller|cx_Freeze'),
             'cmd': re.compile(r'gcc|make|go build|cargo build|pyinstaller|msfvenom'),
             'desc': 'Malware Compilation/Building on Host'},

            {'id': 'T1587.003', 'phase': 'Resource Development',
             'pattern': re.compile(r'req -new|-newkey|-days|-selfsigned|-keyout'),
             'cmd': re.compile(r'openssl|keytool|makecert|certutil'),
             'desc': 'Generating Self-Signed Certificates'},

            {'id': 'T1588.002', 'phase': 'Resource Development',
             'pattern': re.compile(r'exploitdb|github\.com.*(sqlmap|metasploit|covenant|sliver|havoc)|packetstorm'),
             'cmd': re.compile(r'git clone|wget|curl'),
             'desc': 'Downloading Hacking Tools/Exploits'},

            {'id': 'T1608.001', 'phase': 'Resource Development',
             'pattern': re.compile(r's3 cp|blob upload|push|ftp://'),
             'cmd': re.compile(r'aws|az|gsutil|git|scp|ftp|curl -T'),
             'desc': 'Staging/Uploading Malware to External Infrastructure'},

            {'id': 'T1583.004', 'phase': 'Resource Development',
             'pattern': re.compile(r'run-instances|create-instances|vm create|droplet create'),
             'cmd': re.compile(r'aws ec2|az vm|doctl compute|gcloud compute'),
             'desc': 'Provisioning Rogue Cloud Instances'},

            # =========================================================================
            # TACTIC: INITIAL ACCESS (TA0001) 
            # =========================================================================
            {'id': 'T1190', 'phase': 'Initial Access',
             'pattern': re.compile(r'java|php|node|httpd|tomcat|jboss|nginx|apache|struts|weblogic'),
             'cmd': re.compile(r'bash|sh|powershell|cmd\.exe|/bin/sh|/bin/bash'),
             'desc': 'Web process spawning shell (potential RCE)'},

            {'id': 'T1133', 'phase': 'Initial Access',
             'pattern': re.compile(r'bash -i|/dev/tcp/|nc -e|exec sh|0>&1'),
             'cmd': re.compile(r'bash|sh|nc|ncat|netcat|socat|openssl'),
             'desc': 'Reverse Shell Execution'},

            {'id': 'T1091', 'phase': 'Initial Access',
             'pattern': re.compile(r'/dev/sd[b-z][0-9]|/media/|/mnt/usb'),
             'cmd': re.compile(r'mount'),
             'desc': 'Mounting Removable Media'},

            {'id': 'T1195', 'phase': 'Initial Access',
             'pattern': re.compile(r'http://|https://|git://|\.sh|\.py'),
             'cmd': re.compile(r'npm install|pip install|gem install|go get'),
             'desc': 'Suspicious Package Installation (supply-chain/malicious package)'},

            {'id': 'T1199', 'phase': 'Initial Access',
             'pattern': re.compile(r'ssh-rsa|ssh-ed25519'),
             'cmd': re.compile(r'echo.*authorized_keys|tee.*authorized_keys'),
             'desc': 'Trusted Relationship Setup (adding SSH public key)'},

            # =========================================================================
            # TACTIC: EXECUTION (TA0002) 
            # =========================================================================
            {'id': 'T1059.004', 'phase': 'Execution',
             'pattern': re.compile(r'-c|--eval|\.sh|\.bash|\|.*bash|\|.*sh'),
             'cmd': re.compile(r'bash|sh|dash|zsh|ksh|fish'),
             'desc': 'Unix Shell Script Execution'},

            {'id': 'T1059.006', 'phase': 'Execution',
             'pattern': re.compile(r'-c|import socket|import subprocess|import os'),
             'cmd': re.compile(r'python|python2|python3'),
             'desc': 'Python Script/Inline Execution'},

            {'id': 'T1609', 'phase': 'Execution',
             'pattern': re.compile(r'exec|run|attach|cp'),
             'cmd': re.compile(r'docker|kubectl|podman|crictl|ctr'),
             'desc': 'Container Execution/Administration'},

            {'id': 'T1569.002', 'phase': 'Execution',
             'pattern': re.compile(r'start|stop|restart|reload|status'),
             'cmd': re.compile(r'systemctl|service|rc-service|initctl'),
             'desc': 'System Service Execution'},

            {'id': 'T1053.001', 'phase': 'Execution',
             'pattern': re.compile(r'now|tomorrow|next|:'),
             'cmd': re.compile(r'at|atq|atrm'),
             'desc': 'Scheduled Execution via At'},

            {'id': 'T1204.002', 'phase': 'Execution',
             'pattern': re.compile(r'/tmp/|/var/tmp/|/dev/shm/|/var/www/'),
             'cmd': re.compile(r'\./|bash|sh|python|perl'),
             'desc': 'Execution from Suspicious Directory'},

            {'id': 'T1072', 'phase': 'Execution',
             'pattern': re.compile(r'shell|command|cmd\.run|exec'),
             'cmd': re.compile(r'ansible|salt|puppet|chef-client'),
             'desc': 'Abuse of Software Deployment Tools'},

            # =========================================================================
            # TACTIC: PERSISTENCE (TA0003) 
            # =========================================================================
            {'id': 'T1053.003', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/cron|/var/spool/cron|crontab'),
             'cmd': re.compile(r'echo|cp|mv|vi|nano|crontab'),
             'desc': 'Cron job modification'},

            {'id': 'T1053.006', 'phase': 'Persistence',
             'pattern': re.compile(r'\.timer'),
             'cmd': re.compile(r'systemctl start|systemctl enable'),
             'desc': 'Systemd Timer creation/modification'},

            {'id': 'T1547.001', 'phase': 'Persistence',
             'pattern': re.compile(
                 r'/etc/rc\.local|/etc/init\.d|\.bashrc|\.bash_profile|\.zshrc|/etc/profile|\.profile'),
             'cmd': re.compile(r'echo|cat >>|vi|nano|tee'),
             'desc': 'Shell startup/RC script modification'},

            {'id': 'T1543.002', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/systemd/system/|/lib/systemd/system/|\.service'),
             'cmd': re.compile(r'echo|vi|nano|cp|systemctl enable'),
             'desc': 'Systemd Service creation'},

            {'id': 'T1136.001', 'phase': 'Persistence',
             'pattern': re.compile(r'-u 0|-o|-g 0|root|sudo|wheel'),
             'cmd': re.compile(r'useradd|adduser|usermod'),
             'desc': 'Suspicious Local Account Creation'},

            {'id': 'T1547.006', 'phase': 'Persistence',
             'pattern': re.compile(r'\.ko'),
             'cmd': re.compile(r'insmod|modprobe|lsmod'),
             'desc': 'Kernel Module Loading (potential rootkit)'},

            {'id': 'T1505.003', 'phase': 'Persistence',
             'pattern': re.compile(r'/var/www/|/usr/share/nginx/|\.php|\.jsp|\.asp'),
             'cmd': re.compile(r'echo|cat >>|cp|mv|wget|curl'),
             'desc': 'Web Shell Creation'},

            {'id': 'T1574.006', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/ld\.so\.preload'),
             'cmd': re.compile(r'echo|vi|nano|tee'),
             'desc': 'Global Library Hijacking via ld.so.preload'},

            # =========================================================================
            # TACTIC: PRIVILEGE ESCALATION (TA0004) 
            # =========================================================================
            {'id': 'T1548.001', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'u\+s|g\+s|4[0-9]{3}|2[0-9]{3}'),
             'cmd': re.compile(r'chmod'),
             'desc': 'Setuid/Setgid bit set'},

            {'id': 'T1548.003', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/etc/sudoers|/etc/sudoers\.d'),
             'cmd': re.compile(r'echo|vi|nano|visudo|cp|tee'),
             'desc': 'Sudoers file modification'},

            {'id': 'T1548.003-2', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-S|-l|su\s+-'),
             'cmd': re.compile(r'sudo|doas|pkexec'),
             'desc': 'Suspicious Sudo/Polkit Usage'},

            {'id': 'T1574.006', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'LD_PRELOAD|LD_LIBRARY_PATH'),
             'cmd': re.compile(r'export|env'),
             'desc': 'Shared Library Injection (LD_PRELOAD)'},

            {'id': 'T1068', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-o|Makefile|\.c|\.cpp'),
             'cmd': re.compile(r'gcc|cc|clang|make|g\+\+'),
             'desc': 'Compiling Code on Host (potential exploit build)'},

            {'id': 'T1055.008', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-p|attach'),
             'cmd': re.compile(r'gdb|strace|ptrace'),
             'desc': 'Process Injection via Ptrace/GDB'},

            {'id': 'T1611', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/host|/proc/1/ns|docker\.sock|cgroup'),
             'cmd': re.compile(r'mount|docker|nsenter|capsh'),
             'desc': 'Container Escape Attempt'},

            # =========================================================================
            # TACTIC: DEFENSE EVASION (TA0005) 
            # =========================================================================
            {'id': 'T1070.002', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/var/log|/var/adm|/var/audit'),
             'cmd': re.compile(r'rm|truncate|shred|unlink|echo "" >|cat /dev/null >'),
             'desc': 'Log deletion or clearing'},

            {'id': 'T1070.003', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'\.bash_history|\.zsh_history|HISTFILESIZE=0|unset HISTFILE|history -c'),
             'cmd': re.compile(r'rm|export|unset|set \+o history|ln -sf /dev/null'),
             'desc': 'Clearing or Disabling Shell History'},

            {'id': 'T1070.006', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'-r|-t|--reference'),
             'cmd': re.compile(r'touch'),
             'desc': 'Timestomping (tampering with file timestamps)'},

            {'id': 'T1562.001', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'setenforce 0|/etc/selinux/config|aa-teardown|stop auditd|ufw disable|iptables -F'),
             'cmd': re.compile(r'setenforce|service|systemctl|ufw|iptables|apparmor_parser'),
             'desc': 'Disabling Security Tools'},

            {'id': 'T1564.001', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/\.[^/]+|/\.\s+$|/\.\.$'),
             'cmd': re.compile(r'mkdir|touch|cp|mv'),
             'desc': 'Creation of Hidden Files/Directories'},

            {'id': 'T1036', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/bin/sh|/bin/bash|/usr/bin/python'),
             'cmd': re.compile(r'cp.* /tmp/|cp.* /dev/shm/|cp.* /var/tmp/|mv'),
             'desc': 'Masquerading (disguising as a legitimate system tool)'},

            {'id': 'T1027.002', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'-d|-o'),
             'cmd': re.compile(r'upx'),
             'desc': 'Software Packing/Unpacking (UPX)'},

            {'id': 'T1027', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'base64|openssl|uudecode|xxd'),
             'cmd': re.compile(r'base64 -d|openssl enc -d|decode|rev'),
             'desc': 'Data decoding/obfuscation'},

            {'id': 'T1222', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'\+i|-i|\+a|-a'),
             'cmd': re.compile(r'chattr'),
             'desc': 'File attribute modification (immutable/lock)'},

            {'id': 'T1620', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'memfd_create'),
             'cmd': re.compile(r'.*'),
             'desc': 'Fileless execution via memfd'},

            # Additional rules
            {'id': 'T1611-enhanced', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'--privileged|--cap-add|SYS_ADMIN|sys_ptrace'),
             'cmd': re.compile(r'docker run|kubectl|podman|runc'),
             'desc': 'Privileged Container Execution'},

            {'id': 'T1611-mount', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/proc/self/exe|/etc/shadow|/etc/hostname'),
             'cmd': re.compile(r'cat|grep|find.*-name'),
             'desc': 'Container attempting to access host files'},

            # =========================================================================
            # TACTIC: CREDENTIAL ACCESS (TA0006) 
            # =========================================================================
            {'id': 'T1003.008', 'phase': 'Credential Access',
             'pattern': re.compile(r'/etc/shadow|/etc/passwd|/etc/master\.passwd|/etc/security/opasswd'),
             'cmd': re.compile(r'cat|grep|awk|sed|less|more|head|tail|vi|nano'),
             'desc': 'Access to System Password Files'},

            {'id': 'T1003.007', 'phase': 'Credential Access',
             'pattern': re.compile(r'/proc/\d+/mem|/proc/\d+/maps|mimipenguin|linikatz'),
             'cmd': re.compile(r'dd|cat|gdb|strings'),
             'desc': 'Process Memory Dumping for Credentials'},

            {'id': 'T1555.003', 'phase': 'Credential Access',
             'pattern': re.compile(r'Login Data|Cookies|signons\.sqlite|logins\.json'),
             'cmd': re.compile(r'sqlite3|cat|grep|cp'),
             'desc': 'Browser Password/Cookie Database Access'},

            {'id': 'T1555.005', 'phase': 'Credential Access',
             'pattern': re.compile(r'\.kdbx|\.keepass|lastpass'),
             'cmd': re.compile(r'find|locate|ls|cp'),
             'desc': 'Password Manager Database Search'},

            {'id': 'T1552.001', 'phase': 'Credential Access',
             'pattern': re.compile(r'\.aws/credentials|\.azure/|\.gcloud/|\.kube/config|\.docker/config\.json'),
             'cmd': re.compile(r'cat|grep|less|more|head|tail'),
             'desc': 'Cloud/Container Credential File Access'},

            {'id': 'T1552.003', 'phase': 'Credential Access',
             'pattern': re.compile(r'password|passwd|pwd|credentials|token|api_key|secret'),
             'cmd': re.compile(r'grep|cat .*history'),
             'desc': 'Grepping Shell History for Credentials'},

            {'id': 'T1552.004', 'phase': 'Credential Access',
             'pattern': re.compile(r'id_rsa|id_dsa|id_ed25519|\.pem|\.ppk|\.key'),
             'cmd': re.compile(r'cat|grep|cp|mv'),
             'desc': 'SSH Private Key Access'},

            {'id': 'T1110', 'phase': 'Credential Access',
             'pattern': re.compile(r'-l|-P|-C|-M'),
             'cmd': re.compile(r'hydra|medusa|ncrack|patator|john|hashcat'),
             'desc': 'Brute Force or Password Cracking'},

            # =========================================================================
            # TACTIC: DISCOVERY (TA0007) 
            # =========================================================================
            {'id': 'T1082', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'uname|lscpu|lshw|lsblk|free|hostnamectl|dmidecode|uptime'),
             'desc': 'System Information Discovery'},

            {'id': 'T1033', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'whoami|id|w|who|last|users'),
             'desc': 'System Owner/User Discovery'},

            {'id': 'T1087', 'phase': 'Discovery',
             'pattern': re.compile(r'/etc/passwd|passwd'),
             'cmd': re.compile(r'cat|grep|cut|awk|getent'),
             'desc': 'Account Discovery'},

            {'id': 'T1069', 'phase': 'Discovery',
             'pattern': re.compile(r'group'),
             'cmd': re.compile(r'groups|getent group|cat /etc/group'),
             'desc': 'Permission Groups Discovery'},

            {'id': 'T1016', 'phase': 'Discovery',
             'pattern': re.compile(r'-a|addr|route|rules|status'),
             'cmd': re.compile(r'ifconfig|ip|route|netstat|iptables|ufw|nmcli'),
             'desc': 'System Network Configuration Discovery'},

            {'id': 'T1018', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'arp|ping|fping|ip neighbor'),
             'desc': 'Remote System Discovery'},

            {'id': 'T1046', 'phase': 'Discovery',
             'pattern': re.compile(r'-z|-sS|-sT|-p'),
             'cmd': re.compile(r'nc|netcat|nmap|masscan|telnet'),
             'desc': 'Network Service Discovery (port scanning)'},

            {'id': 'T1057', 'phase': 'Discovery',
             'pattern': re.compile(r'aux|ef|-e'),
             'cmd': re.compile(r'ps|top|htop|pgrep|pidof'),
             'desc': 'Process Discovery'},

            {'id': 'T1083', 'phase': 'Discovery',
             'pattern': re.compile(r'-name|-iname|-type f|id_rsa|\.conf|\.bak'),
             'cmd': re.compile(r'find|locate|ls -R|tree|grep -r'),
             'desc': 'File and Directory Discovery'},

            {'id': 'T1518', 'phase': 'Discovery',
             'pattern': re.compile(r'-qa|list|installed|--version'),
             'cmd': re.compile(r'rpm|dpkg|yum|apt|snap|pip|docker images'),
             'desc': 'Software Discovery (installed software)'},

            {'id': 'T1040', 'phase': 'Discovery',
             'pattern': re.compile(r'-i|any|eth0|wlan0'),
             'cmd': re.compile(r'tcpdump|tshark|ngrep|wireshark'),
             'desc': 'Network Sniffing'},

            # =========================================================================
            # TACTIC: LATERAL MOVEMENT (TA0008) 
            # =========================================================================
            {'id': 'T1021.004', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-i|ProxyCommand|StrictHostKeyChecking=no|-R|-L|-D'),
             'cmd': re.compile(r'ssh|scp|sftp'),
             'desc': 'SSH/SCP Lateral Movement or Tunneling'},

            {'id': 'T1021.002', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'//|\\\\|-U|-c'),
             'cmd': re.compile(r'smbclient|mount\.cifs|mount -t cifs|rpcclient'),
             'desc': 'SMB/CIFS Access (Windows share access)'},

            {'id': 'T1021.001', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'/v|/u|::'),
             'cmd': re.compile(r'xfreerdp|rdesktop|remmina|vncviewer'),
             'desc': 'RDP/VNC Client Usage'},

            {'id': 'T1021.006', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-i|-u|-p'),
             'cmd': re.compile(r'evil-winrm|winrm'),
             'desc': 'WinRM Usage'},

            {'id': 'T1563.002', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-S|SSH_AUTH_SOCK'),
             'cmd': re.compile(r'ssh'),
             'desc': 'Potential SSH Session Hijacking'},

            {'id': 'T1570', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'rsync'),
             'desc': 'Lateral Tool Transfer via Rsync'},

            {'id': 'T1550', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-k|-t|/tmp/krb5cc'),
             'cmd': re.compile(r'kinit|klist|kvno'),
             'desc': 'Kerberos Ticket Manipulation'},

            # =========================================================================
            # TACTIC: COLLECTION (TA0009) 
            # =========================================================================
            {'id': 'T1560', 'phase': 'Collection',
             'pattern': re.compile(r'-c.*zf|cf|czf|\.tar|\.zip|\.gz|\.7z|\.rar'),
             'cmd': re.compile(r'tar|zip|gzip|bzip2|7z|rar'),
             'desc': 'Archive/Compression of collected data'},

            {'id': 'T1074', 'phase': 'Collection',
             'pattern': re.compile(r'/tmp/|/var/tmp/|/dev/shm/'),
             'cmd': re.compile(r'cp|mv|tar|zip'),
             'desc': 'Data Staging in temporary directories'},

            {'id': 'T1115', 'phase': 'Collection',
             'pattern': re.compile(r'-o|-selection clipboard|-i'),
             'cmd': re.compile(r'xclip|xsel|pbcopy|pbpaste'),
             'desc': 'Clipboard data collection'},

            {'id': 'T1113', 'phase': 'Collection',
             'pattern': re.compile(r'-window root|-quality|\.png|\.jpg'),
             'cmd': re.compile(r'scrot|import|screencapture|xwd|gnome-screenshot|spectacle'),
             'desc': 'Screen capture activity'},

            {'id': 'T1056.001', 'phase': 'Collection',
             'pattern': re.compile(r'/dev/input/event|--start --log'),
             'cmd': re.compile(r'showkey|logkeys|thc-vlogger'),
             'desc': 'Keylogging/Input Capture'},

            {'id': 'T1123', 'phase': 'Collection',
             'pattern': re.compile(r'-d|--duration|-f cd'),
             'cmd': re.compile(r'arecord|rec|ffmpeg|audacity'),
             'desc': 'Audio capture'},

            {'id': 'T1114', 'phase': 'Collection',
             'pattern': re.compile(r'/var/mail|/var/spool/mail'),
             'cmd': re.compile(r'cat|grep|less|head|tail|fetchmail'),
             'desc': 'Local Email Collection'},

            # =========================================================================
            # TACTIC: COMMAND AND CONTROL (TA0011) 
            # =========================================================================
            {'id': 'T1071', 'phase': 'Command and Control',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'curl|wget|nc|ncat|netcat|socat|telnet'),
             'desc': 'Common Download/C2 utilities'},

            {'id': 'T1090', 'phase': 'Command and Control',
             'pattern': re.compile(r'tcp-listen|forward|proxy|tunnel'),
             'cmd': re.compile(r'socat|ngrok|frpc|frps|chisel|gost|websocat'),
             'desc': 'Proxy/Tunneling tool usage'},

            {'id': 'T1219', 'phase': 'Command and Control',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'teamviewer|anydesk|logmein|vncserver|screen|tmux'),
             'desc': 'Remote Access Software/Terminal Multiplexing'},

            {'id': 'T1105', 'phase': 'Command and Control',
             'pattern': re.compile(r'-O|--output|-o'),
             'cmd': re.compile(r'curl|wget'),
             'desc': 'Ingress Tool Transfer'},

            # =========================================================================
            # TACTIC: EXFILTRATION (TA0010) 
            # =========================================================================
            {'id': 'T1048', 'phase': 'Exfiltration',
             'pattern': re.compile(r'put|mput|upload|STOR'),
             'cmd': re.compile(r'ftp|lftp|tftp|sftp'),
             'desc': 'Exfiltration via FTP/SFTP'},

            {'id': 'T1567', 'phase': 'Exfiltration',
             'pattern': re.compile(r'copy|sync|upload|--upload-file|-T'),
             'cmd': re.compile(r'rclone|gdrive|mega-cmd|aws|gsutil|az|curl'),
             'desc': 'Exfiltration to Cloud Storage/Web Service'},

            {'id': 'T1020', 'phase': 'Exfiltration',
             'pattern': re.compile(r'/dev/tcp/|/dev/udp/'),
             'cmd': re.compile(r'bash|sh|ksh|zsh'),
             'desc': 'Exfiltration via network redirection (direct socket transfer)'},

            {'id': 'T1052', 'phase': 'Exfiltration',
             'pattern': re.compile(r'/dev/sd[b-z]|/media/|/mnt/usb'),
             'cmd': re.compile(r'mount|dd|cp'),
             'desc': 'Exfiltration to Physical Medium'},

            # =========================================================================
            # TACTIC: IMPACT (TA0040) 
            # =========================================================================
            {'id': 'T1485', 'phase': 'Impact',
             'pattern': re.compile(r'-rf|--no-preserve-root|if=/dev/zero|if=/dev/urandom'),
             'cmd': re.compile(r'rm|shred|dd|wipe|srm'),
             'desc': 'Data destruction attempt'},

            {'id': 'T1486', 'phase': 'Impact',
             'pattern': re.compile(r'--encrypt|-c|--passphrase'),
             'cmd': re.compile(r'gpg|openssl|7z|zip|ccrypt|bcrypt'),
             'desc': 'File Encryption/Ransomware Behavior'},

            {'id': 'T1496', 'phase': 'Impact',
             'pattern': re.compile(r'stratum\+tcp|pool|user|nicehash|minergate'),
             'cmd': re.compile(r'xmrig|minerd|cpuminer|ethminer|cgminer'),
             'desc': 'Cryptomining Activity'},

            {'id': 'T1489', 'phase': 'Impact',
             'pattern': re.compile(r'stop|disable|kill'),
             'cmd': re.compile(r'systemctl|service|rc-service|killall|pkill'),
             'desc': 'Stopping System Services'},

            {'id': 'T1529', 'phase': 'Impact',
             'pattern': re.compile(r'-h|-r|now|0|6'),
             'cmd': re.compile(r'shutdown|reboot|halt|poweroff|init'),
             'desc': 'System Shutdown/Reboot'},

            {'id': 'T1561.002', 'phase': 'Impact',
             'pattern': re.compile(r'if=/dev/zero|if=/dev/urandom|of=/dev/sd|of=/dev/vd'),
             'cmd': re.compile(r'dd|cat|cp'),
             'desc': 'Disk Wiping Activity'},

            {'id': 'T1491', 'phase': 'Impact',
             'pattern': re.compile(r'>|/var/www/html|index\.html|/etc/motd'),
             'cmd': re.compile(r'echo|cp|mv|cat'),
             'desc': 'Website/System Defacement'}
        ]

    def check_node(self, node):
        import shlex
        matches = []


        extra = node.get('extra', {})
        cmd_full = str(extra.get('cmd', '')).strip()

        desc = str(extra.get('desc', '')).strip()

        if node.get('group') == 'memfd':
            matches.append({'tag': "T1620", 'reason': "Reflective Code Loading (memfd)"})


        if extra.get('risk_mmap'):
            prot = extra['risk_mmap']          
            if 'WRITE' in prot and 'EXEC' in prot:
                matches.append({'tag': "T1055", 'reason': f"Process Injection / Shellcode (W+X): {prot}"})
            else:
                matches.append({'tag': "T1620", 'reason': f"Executable Memory Mapping: {prot}"})

   
        if extra.get('ptrace_req'):
            req = extra['ptrace_req']

   
            if 'POKETEXT' in req or 'POKEDATA' in req:
                matches.append({'tag': "T1055", 'reason': f"Code Injection via {req}"})

            elif 'ATTACH' in req:
                matches.append({'tag': "T1055", 'reason': f"Process Attachment via {req}"})

            elif 'TRACEME' in req:
                matches.append({'tag': "T1622", 'reason': "Anti-Debugging Check (TRACEME)"})

     
            elif 'PEEK' in req:
                matches.append({'tag': "T1003", 'reason': f"Memory Scraping via {req}"})


        if extra.get('risk_priv'):
            matches.append({'tag': "T1548", 'reason': "Privilege Escalation (setuid syscall detected)"})


        try:
            argv = shlex.split(cmd_full)
        except ValueError:
            argv = cmd_full.split()

        if not argv:
            return matches

        binary_path = argv[0]  # e.g., "/usr/bin/curl" or "curl"
        binary_name = os.path.basename(binary_path)  # e.g., "curl"

        args_str = " ".join(argv[1:])

        # 4. Iterate through the rules to find a match
        for r in self.rules:
            rule_id = r.get('id')
            tool_regex = r.get('cmd')  
            args_regex = r.get('pattern') 

            is_binary_match = False

            if tool_regex:
                if tool_regex.search(binary_name):
                    is_binary_match = True
                elif tool_regex.search(binary_path):
                    is_binary_match = True
            else:
       
                is_binary_match = True

            if not is_binary_match:
                continue

      
            if args_regex:
                if args_regex.search(args_str) or args_regex.search(cmd_full) or (desc and args_regex.search(desc)):
                    if not any(m['tag'] == rule_id for m in matches):
                        matches.append({'tag': rule_id, 'reason': r.get('desc')})

        return matches


class MultiSliceOrchestrator:
    def __init__(self):
        self.host_ip = "127.0.0.1"
        self.output_path = "report.html"
        self.mapper = AttckMapper()
        self.mem = Hippocampus()
        self.snaps = {}
        self.g_nodes = {}
        self.g_edges = {}
        self.ghosts = []
        self.ghost_edges = []
        self.colors = ["#e6194b", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0"]

    def process(self, pattern):
        try:
            self.mem.prune_old_memories(days_retention=7)
            # -----------------------------------------------------
            files = sorted(glob.glob(pattern))
            if not files: return "No files found"

            self.snaps, self.g_nodes, self.g_edges = {}, {}, {}
            self.ghosts, self.ghost_edges = [], []

            builder = ProvenancePublicDirect(self.host_ip)
            processed_ids = set()

            for i, fpath in enumerate(files):
                slice_name = os.path.basename(fpath)
                sys.stderr.write(f"[*] Ingesting {slice_name}\n")

                builder.ingest(fpath)

                curr_keys = list(builder.nodes.keys())
                new_nodes = [builder.nodes[nid] for nid in curr_keys if nid not in processed_ids]

                if new_nodes:
                    self._stitch(new_nodes, builder, slice_name)

                    self._reconstruct_lineage(new_nodes, builder)

          
                self._register_lineage(builder)

                for nid in curr_keys: processed_ids.add(nid)
                self.mem.commit_batch()

            builder.process_unmatched()
            nodes, edges = builder.get_data()

            for n in nodes:
                threats = self.mapper.check_node(n)
                if threats:
                    n['extra']['attck_evidence'] = threats
                    n['color'] = "#e74c3c"
                self.g_nodes[n['id']] = copy.deepcopy(n)

            for g in self.ghosts: self.g_nodes[g['id']] = g
            for e in edges:
                edge_key = f"{e['from']}>{e['to']}>{e.get('label', '')}"
                self.g_edges[edge_key] = e

            for ge in self.ghost_edges:
                edge_key = f"{ge['from']}>{ge['to']}>{ge.get('label', '')}"
                self.g_edges[edge_key] = ge

            self._cluster()
            return f"Processed {len(files)} files. Nodes: {len(self.g_nodes)} (Ghosts: {len(self.ghosts)})"
        except Exception as e:
            return f"Error: {str(e)}"


    def _register_lineage(self, builder):
        ts = datetime.now().timestamp()
        for src_id, dst_set in builder.adj_list.items():
            parent = builder.nodes.get(src_id)
            if not parent or parent['group'] != 'proc': continue
            for dst_id in dst_set:
                child = builder.nodes.get(dst_id)
                if child and child['group'] == 'proc':
                    self.mem.register_birth(child['id'], parent['id'], parent['label'], ts)

    def _reconstruct_lineage(self, new_nodes, builder):
        for n in new_nodes:
            if n['group'] != 'proc': continue

            has_parent = False
            for pid, neighbors in builder.adj_list.items():
                if n['id'] in neighbors:
                    parent = builder.nodes.get(pid)
                    if parent and parent['group'] == 'proc':
                        has_parent = True;
                        break
            if has_parent: continue

            birth_record = self.mem.find_parent(n['id'])
            if birth_record:
                pid, pdesc = birth_record
                if pid in builder.nodes:
                    key = (pid, n['id'], 'Ancestry')
                    if key not in builder.edge_map:
                        builder.add_edge(pid, n['id'], label="Spawn(R)", color="#1abc9c", style="dashed")
                else:
                    gid = f"ghost_parent_{pid}"
                    if not any(g['id'] == gid for g in self.ghosts):
                        self.ghosts.append({
                            'id': gid, 'label': f"👻 Parent\n{pdesc}", 'group': 'ghost',
                            'color': '#1abc9c', 'shape': 'dot', 'extra': {'desc': "Restored Lineage"}
                        })
                        self.ghost_edges.append({
                            'from': gid, 'to': n['id'], 'label': 'Spawn(R)', 'color': '#1abc9c', 'dashes': True
                        })

    def _is_ignorable_ip(self, ip):
        if not ip: return True
        if ip.startswith("127.") or ip == "0.0.0.0" or ip == "::1": return True

        common_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114", "223.5.5.5"}
        if ip in common_dns: return True

        if ip.startswith("224.") or ip.startswith("239."): return True

        return False

    def _stitch(self, new_nodes, builder, slice_name):
      
        ts = datetime.now().timestamp()

        for n in new_nodes:
            keys = set()

            if n['group'] == 'file':
                keys.add(f"FILE:{n['extra'].get('path')}")
            elif n['group'] in ['net', 'net_in_agg', 'gw']:
                ip = n['extra'].get('ip')
                if not self._is_ignorable_ip(ip):
                    keys.add(f"IP:{ip}")

            neighbor_ids = builder.adj_list.get(n['id'], set())
            for dst_id in neighbor_ids:
                target = builder.nodes.get(dst_id)
                if target:
                    if target['group'] == 'file':
                        keys.add(f"FILE:{target['extra'].get('path')}")
                    elif target['group'] in ['net', 'net_in_agg', 'gw']:
                        ip = target['extra'].get('ip')
                        if not self._is_ignorable_ip(ip):
                            keys.add(f"IP:{ip}")

            if not keys: continue

            query_keys = list(keys)
            history = self.mem.recall(query_keys)

            for h in history:
                if h['desc'].endswith(f"({slice_name})"): continue

                hist_event_id = h['id']

                if hist_event_id in builder.nodes:
                    hist_node = builder.nodes[hist_event_id]

                    if hist_node['group'] == n['group']:
                        continue

                    is_already_connected = False
                    if hist_event_id in builder.adj_list.get(n['id'], set()): is_already_connected = True
                    if n['id'] in builder.adj_list.get(hist_event_id, set()): is_already_connected = True
                    if is_already_connected: continue

                    edge_key = (hist_event_id, n['id'], 'TimeJump')
                    if edge_key not in builder.edge_map:
                        builder.add_edge(
                            hist_event_id,
                            n['id'],
                            label="TimeJump",
                            color="#1abc9c",  
                            style="dashed"
                        )

                else:
                    is_self_ref = False
                    if n['group'] == 'file' and h['key'].startswith("FILE:"): is_self_ref = True
                    if n['group'] in ['net', 'gw'] and h['key'].startswith("IP:"): is_self_ref = True
                    if is_self_ref: continue

                    gid = f"ghost_{hist_event_id}"
                    if not any(g['id'] == gid for g in self.ghosts):
                        self.ghosts.append({
                            'id': gid,
                            'label': f"👻 History\n{h['desc']}",
                            'group': 'ghost',
                            'color': '#1abc9c',  
                            'shape': 'dot',
                            'extra': {'desc': f"Linked via {h['key']}", 'payload': h['payload']}
                        })
                        self.ghost_edges.append({
                            'from': gid, 'to': n['id'],
                            'label': 'TimeJump',
                            'color': '#1abc9c',  
                            'dashes': True
                        })

            should_remember = False
            if n['group'] in ['file', 'net', 'net_in_agg', 'gw']:
                should_remember = True
            elif n['extra'].get('attck_evidence'):
                should_remember = True
            elif n['group'] == 'proc' and len(neighbor_ids) > 0:
                should_remember = True

            if should_remember:
                short_lbl = n['label'].split('\n')[0]
                self.mem.remember(query_keys, n['id'], ts, f"{short_lbl} ({slice_name})",
                                  json.dumps(n.get('extra', {})))

    def _cluster(self):
        self.ip_to_comm = {}

        if not LEIDEN_AVAILABLE or not self.g_nodes:
            self.snaps['overview'] = {'nodes': list(self.g_nodes.values()), 'edges': list(self.g_edges.values())}
            for n in self.g_nodes.values():
                if 'ip' in n.get('extra', {}):
                    self.ip_to_comm[n['extra']['ip']] = 'overview'
            return

        g_nodes = list(self.g_nodes.values())
        id2idx = {n['id']: i for i, n in enumerate(g_nodes)}
        idx2id = {i: n['id'] for i, n in enumerate(g_nodes)}

        g = ig.Graph(directed=True)
        g.add_vertices(len(g_nodes))
        edges = []
        for e in self.g_edges.values():
            if e['from'] in id2idx and e['to'] in id2idx:
                edges.append((id2idx[e['from']], id2idx[e['to']]))
        g.add_edges(edges)

        part = leidenalg.find_partition(g, leidenalg.ModularityVertexPartition)

        ov_nodes = []
        for i, mems in enumerate(part):
            is_threat_cluster = False
            for idx in mems:
                nid = idx2id[idx]
                if self.g_nodes[nid].get('extra', {}).get('attck_evidence'):
                    is_threat_cluster = True
                    break

            if len(mems) <= 1 and not is_threat_cluster:
                continue

            c_nodes = []
            mem_ids = set()
            tc = 0
            comm_key = f"comm_{i}"

            for idx in mems:
                nid = idx2id[idx]
                mem_ids.add(nid)
                n = copy.deepcopy(self.g_nodes[nid])
                if n.get('extra', {}).get('attck_evidence'): tc += 1
                c_nodes.append(n)

                if 'ip' in n.get('extra', {}):
                    self.ip_to_comm[n['extra']['ip']] = comm_key

            c_edges = [e for e in self.g_edges.values() if e['from'] in mem_ids and e['to'] in mem_ids]
            self.snaps[comm_key] = {'nodes': c_nodes, 'edges': c_edges}

            ov_nodes.append({
                'id': f"c_{i}",
                'label': f"Cluster #{i}\n({len(mems)} Nodes)",
                'group': 'community',
                'color': self.colors[i % len(self.colors)],
                'extra': {'count': len(mems), 'threats': tc}
            })

        self.snaps['overview'] = {'nodes': ov_nodes, 'edges': []}

    def write(self):
        import urllib.request

        vis_path = "vis-network.min.js"
        marked_path = "marked.min.js"

        if not os.path.exists(vis_path):
            urllib.request.urlretrieve(
                "https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js",
                vis_path
            )
        if not os.path.exists(marked_path):
            urllib.request.urlretrieve(
                "https://cdnjs.cloudflare.com/ajax/libs/marked/4.3.0/marked.min.js",
                marked_path
            )

        with open(vis_path) as f:
            vis_js = f.read()
        with open(marked_path) as f:
            marked_js = f.read()

        out = json.dumps(self.snaps).replace('</script>', '<\\/script>')
        ip_map_json = json.dumps(self.ip_to_comm).replace('</script>', '<\\/script>')

        h = HTML_TEMPLATE \
            .replace('__VIS_JS_CONTENT__', vis_js) \
            .replace('__MARKED_JS_CONTENT__', marked_js) \
            .replace('__SNAPSHOTS__', out) \
            .replace('__HOST__', self.host_ip) \
            .replace('__IP_MAP__', ip_map_json)

        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(h)
        return self.output_path


service = MultiSliceOrchestrator()


# ============================================================================
# MCP Tools
# ============================================================================
@mcp.tool()
def setup_workspace(host_ip: str, output_path: str) -> str:
    service.host_ip = host_ip;
    service.output_path = output_path;
    return "OK"


@mcp.tool()
def ingest_logs(pattern: str) -> str:
    return service.process(pattern)


@mcp.tool()
def list_communities(only_outbound: bool = False) -> str:
    valid = []
    for k, d in service.snaps.items():
        if not k.startswith('comm_'): continue

        if len(d['nodes']) <= 1: continue

        if only_outbound:
            if any(n.get('group') == 'net' for n in d['nodes']): valid.append(k)
        else:
            valid.append(k)
    return json.dumps(valid)


@mcp.tool()
def get_community_topology(community_id: str) -> str:
    d = service.snaps.get(community_id)
    if not d: return "Not found"
    budget = 48000
    nodes = d['nodes'];
    edges = d['edges']

    def score(n):
        s = 0
        if n['extra'].get('attck_evidence'): s += 1000
        if n['group'] == 'ghost': s += 800
        if n['group'] == 'net': s += 500
        if n['group'] == 'proc': s += 50
        return s

    sorted_nodes = sorted(nodes, key=score, reverse=True)
    final = [];
    kept = set();
    curr = 0
    for n in sorted_nodes:
        cmd = n['extra'].get('cmd', '')
        limit = 200 if n['extra'].get('attck_evidence') else 100
        if len(cmd) > limit: cmd = cmd[:limit] + ".."
        sn = {'id': n['id'], 'label': n['label'].split('\n')[0], 'type': n['group'], 'cmd': cmd}
        if n['extra'].get('attck_evidence'): sn['THREAT'] = [t['tag'] for t in n['extra']['attck_evidence']]
        if n['group'] == 'ghost': sn['GHOST_CONTEXT'] = n['extra'].get('desc')
        c = len(json.dumps(sn))
        if curr + c < budget * 0.7:
            final.append(sn); kept.add(n['id']); curr += c
        else:
            if score(n) >= 800 and curr < budget: final.append(sn); kept.add(n['id']); curr += c
    e_out = [f"{e['from']}->{e['to']}" for e in edges if e['from'] in kept and e['to'] in kept]
    return json.dumps({'nodes': final, 'edges': e_out})


@mcp.tool()
def save_ai_analysis(community_id: str, markdown: str) -> str:
    if community_id in service.snaps:
        ns = service.snaps[community_id]['nodes']
        if ns:
            if 'extra' not in ns[0]: ns[0]['extra'] = {}
            ns[0]['extra']['ai_analysis'] = markdown
        if 'overview' in service.snaps:
            oid = community_id.replace('comm_', 'c_')
            for n in service.snaps['overview']['nodes']:
                if n['id'] == oid:
                    if 'extra' not in n: n['extra'] = {}
                    n['extra']['ai_analysis'] = markdown
    return "Saved"


@mcp.tool()
def write_html_report() -> str: return service.write()


if __name__ == "__main__": mcp.run()
