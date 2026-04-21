#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 文件名: kexdr_server.py

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

# 依赖库检查
try:
    import igraph as ig
    import leidenalg

    LEIDEN_AVAILABLE = True
except ImportError:
    # 仅作为警告
    LEIDEN_AVAILABLE = False

from mcp.server.fastmcp import FastMCP

# 抑制警告
warnings.filterwarnings("ignore")

mcp = FastMCP("KeXDR-Server")

# ============================================================================
# 1. HTML 前端模板 (Legend V3: Universal Entities & TimeLinks)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>KeXDR Multi-Verse</title>
     <!-- 改为构建时内嵌 -->
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
        # 优化：为 key 和 timestamp 建立索引，加快 Recall 和 Prune 的速度
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS artifacts (
            key TEXT, event_id TEXT, timestamp REAL, desc TEXT, payload TEXT, PRIMARY KEY (key, event_id))''')
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ts ON artifacts (timestamp)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_key ON artifacts (key)")
        # [Table 2 - 新增] Lineage (用于进程寻亲)
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS lineage (
                    child_id TEXT PRIMARY KEY, parent_id TEXT, parent_desc TEXT, ts REAL)''')

        self.conn.commit()

    def recall(self, keys):
        results = []
        if not keys: return results
        # 使用 IN 查询优化批量检索
        placeholders = ','.join('?' for _ in keys)
        try:
            # 限制每个 Key 最多返回最近的 5 条记录，防止爆炸
            query = f"""
                SELECT event_id, timestamp, desc, payload, key 
                FROM artifacts 
                WHERE key IN ({placeholders}) 
                ORDER BY timestamp DESC
            """
            self.cursor.execute(query, tuple(keys))
            # 在应用层做 Limit 逻辑或者稍微放宽 SQL
            rows = self.cursor.fetchall()

            # 简单的内存过滤，确保每个 Key 不过多
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

    # [修复版] 清理功能 - 位于 Hippocampus 类内部
    def prune_old_memories(self, days_retention=7):
        """
        删除超过 days_retention 天的历史记录，并整理数据库碎片
        """
        try:
            current_ts = datetime.now().timestamp()
            # 计算截止时间戳
            cutoff_ts = current_ts - (days_retention * 24 * 3600)

            # 1. 执行删除
            self.cursor.execute("DELETE FROM artifacts WHERE timestamp < ?", (cutoff_ts,))
            deleted_count = self.cursor.rowcount
            self.conn.commit()

            # 2. 执行 VACUUM (回收物理空间)
            # 注意：这里改用 sys.stderr.write 防止破坏 MCP 协议
            if deleted_count > 0:
                sys.stderr.write(f"[*] Pruning: Deleted {deleted_count} old artifacts. Optimizing DB...\n")
                try:
                    self.cursor.execute("VACUUM")
                except sqlite3.OperationalError:
                    # 如果数据库被锁定，跳过 VACUUM，不影响主流程
                    sys.stderr.write("[!] VACUUM skipped due to locked DB.\n")
            else:
                # 调试信息发往 stderr
                # sys.stderr.write("[*] Pruning: Database is clean.\n")
                pass

            return deleted_count
        except Exception as e:
            # 错误信息发往 stderr
            sys.stderr.write(f"[!] Prune Error: {e}\n")
            return 0

    # ==========================================
    # [修复点] 以下两个方法必须与上面方法平级缩进
    # ==========================================

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
        # [NEW] 邻接索引：{ src_id: {dst_id1, dst_id2, ...} }
        # 使用 set 避免同一对节点间因多条不同类型的边导致重复记录
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
        # [新增] 权限提升(金) 和 删除(深红) 的颜色定义
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
        # 自循环边只存入 edge_map 用于渲染，不写入 adj_list
        # 否则 _stitch 会把节点自身当作邻居导致错误的 TimeJump
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

            # --- [A] 入站流量 (Inbound) ---
            if dip == self.host_ip:
                src_ip = ev.get('src_ip')
                if not src_ip: return

                # 1. 确定协议
                proto_name = ev.get('subtype')
                if not proto_name or proto_name == 'NETWORK':
                    proto_name = self._get_proto(ev.get('proto_id', 6), dport)

                # 2. [关键修改] 生成聚合节点 ID
                # 现在的 ID 由 [源IP] + [目标端口] 组成
                # 这样同一个 IP 访问同一个端口会聚合在一起，不同 IP 分开
                rid = f"src_{src_ip}_{dport}"

                # 3. 构造 Payload 日志
                # 既然节点已经是确定的 src_ip 了，日志里只记录时间即可
                payload_entry = ""
                if raw_payload:
                    short_ts = str(ts).split('T')[-1].split('.')[0] if 'T' in str(ts) else ts
                    payload_entry = f"[{short_ts}] {raw_payload}"

                # 4. 创建节点
                self.add_node(
                    rid,
                    f"{src_ip}\n(To :{dport})",  # Label 显示 源IP
                    'net_in_agg',
                    self.C_IN_AGG,
                    'star',  # 保持星形，表示外部源
                    'solid',
                    {
                        'ip': src_ip,  # [关键] 这里现在是确切的 Source IP
                        'port': str(dport),
                        'protocol': proto_name,
                        'payload': payload_entry,
                        'time': ts
                    }
                )

                # 5. 连接到主机
                # 边上的标签显示协议
                self.add_edge(rid, self.host_node_id, f"{proto_name}", self.C_IN_AGG)

            # --- [B] 出站流量 (Outbound) ---
            elif dip:
                rid = self._id_net(dip, dport)
                proto = self._get_proto(ev.get('proto_id', 6), dport)

                # [重点修改] 处理出站 Payload
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
                        'payload': payload_entry  # <--- 这里之前漏掉了，现在加上
                    }
                )

                # 处理连接关联 (Connection Matching)
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

            # [新增] 处理内存映射 (MMAP)
            if ev.get('subtype') == 'MMAP':
                prot = ev.get('prot', '')
                # 1. 检测高危可执行内存 (Shellcode/Injection 痕迹)
                if ev.get('is_exec'):
                    self.nodes[proc_id]['extra']['risk_mmap'] = prot
                # W+X 可写可执行内存：绘制红色自循环边，直接可见
                if 'WRITE' in prot and 'EXEC' in prot:
                    self.add_edge(proc_id, proc_id, "RWX\nShellcode", "#e74c3c", "solid")

                # 2. 如果 eBPF 捕获到了映射的文件名 (File-backed mapping)
                # 这种通常是加载 .so 库或读取大文件
                if ev.get('filename'):
                    fname = ev.get('filename')
                    fid = self._id_file(fname, cg)
                    prot_label = ev.get('prot', 'MAP')

                    self.add_node(fid, os.path.basename(fname), 'file', self.C_FILE, 'box', 'solid',
                                  {'path': fname,'time': ts})
                    # 使用虚线表示 mmap，区别于普通的 open
                    self.add_edge(proc_id, fid, f"mmap({prot_label})", color="#1abc9c", style="dashed")

            # =========================================================
            # [新增] 处理无文件执行 (MEMFD)
            # =========================================================
            if ev.get('subtype') == 'MEMFD':
                mem_name = ev.get('name', 'anonymous')
                # 橙色虚线自循环，表示进程在内存中匿名执行代码
                self.add_edge(proc_id, proc_id, f"MEMFD\n{mem_name}", "#e67e22", "dashed")
                if proc_id in self.nodes:
                    self.nodes[proc_id]['extra']['memfd_name'] = mem_name


            # =========================================================
            # [新增] 处理 PTRACE 注入/调试事件 (适配新的 Agent)
            # =========================================================
            if ev.get('subtype') == 'INJECT':
                req_name = ev.get('request_name', 'PTRACE')
                target_pid = ev.get('target_pid')

                # 记录高危标记到当前节点，供 AttckMapper 使用
                self.nodes[proc_id]['extra']['ptrace_req'] = req_name

                # 如果有目标进程 ID，且不是自己调试自己 (TRACEME 且 target=0 或 target=ppid)
                # 注意：Agent 发来的 TRACEME target_pid 可能是 PPID，也可能是 0，视实现而定
                if target_pid and target_pid != 0:
                    # 我们假设目标进程在同一个 Cgroup 中 (通常如此)
                    target_id = self._id_proc(target_pid, cg)

                    # 确保目标节点存在 (即使它还没产生日志)
                    if target_id not in self.nodes:
                        self.add_node(target_id, f"Target\n{target_pid}", 'proc', self.C_PROC, 'dot', 'solid',
                                      {'pid': str(target_pid)})

                    # 绘制注入连线：紫色虚线
                    # 连线方向：发起者(Tracer) -> 受害者(Target)
                    edge_label = f"{req_name.replace('PTRACE_', '')}"
                    self.add_edge(proc_id, target_id, edge_label, color="#9b59b6", style="dashed")

            # =========================================================
            # [新增] 处理权限提升 (SETUID)
            # =========================================================
            if ev.get('subtype') == 'SETUID':
                target_uid = ev.get('target_uid')
                # 1. 添加自循环边表示状态变更，使用金色实线
                self.add_edge(proc_id, proc_id, f"SETUID({target_uid})", self.C_PRIV, "solid")
                # 2. 标记节点风险，供 AttckMapper 分析
                if proc_id in self.nodes:
                    self.nodes[proc_id]['extra']['risk_priv'] = True

            # =========================================================
            # [新增] 处理文件删除 (DELETE/UNLINK)
            # =========================================================
            if ev.get('subtype') == 'DELETE':
                fname = ev.get('filename')
                if fname:
                    fid = self._id_file(fname, cg)
                    # 确保文件节点存在 (可能文件是在监控开始前创建的)
                    self.add_node(fid, os.path.basename(fname), 'file', self.C_FILE, 'box', 'solid',
                                  {'path': fname, 'time': ts})
                    # 添加删除连线，使用深红色虚线
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
        # 1. 收集节点
        if self.host_node_id in self.nodes:
            fn.append(self.nodes[self.host_node_id])

        for nid, n in self.nodes.items():
            if nid == self.host_node_id: continue
            # 过滤逻辑：只保留有连接的网络/网关节点
            if n['group'] in ['net', 'net_in_agg', 'gw']:
                if nid in self.connected_targets: fn.append(n)
            else:
                fn.append(n)

        fids = set(n['id'] for n in fn)
        eo = []

        # 2. 收集边
        for (s, d, l), i in self.edge_map.items():
            # 确保边的起点和终点都在当前的节点列表中
            if s in fids and d in fids:
                edge_obj = {
                    'from': s,
                    'to': d,
                    'label': l,
                    'color': i['color'],
                    'font': {'size': 10, 'align': 'middle'}, # 加上字体对齐，让标签好看点
                    'extra': i.get('extra')
                }

                if i.get('style') == 'dashed':
                    edge_obj['dashes'] = True

                # ==========================================
                # 【照抄 TR-PCI 逻辑】：
                # 丢弃 selfReference 这种花里胡哨的属性，直接用 curvedCW 即可！
                # ==========================================
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
            # TACTIC: RECONNAISSANCE (TA0043) - 侦察
            # =========================================================================
            {'id': 'T1595.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-h|-t|scan|--script'),
             'cmd': re.compile(r'nikto|nessus|openvas|sqlmap|nuclei|acunetix'),
             'desc': 'Vulnerability Scanning Activity (漏洞扫描工具)'},

            {'id': 'T1595.001', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-p|-sS|-sT|--rate|-oG'),
             'cmd': re.compile(r'nmap|masscan|zmap|naabu|rustscan'),
             'desc': 'Active Port Scanning (主动端口扫描)'},

            {'id': 'T1593.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-w|-m|spider|crawl|--depth'),
             'cmd': re.compile(r'cewl|gospider|hakrawler|wget --mirror|photon'),
             'desc': 'Web Spidering/Wordlist Generation (爬虫/字典生成)'},

            {'id': 'T1594', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'-u|-w|-x|dir|fuzz'),
             'cmd': re.compile(r'gobuster|dirb|dirsearch|ffuf|feroxbuster'),
             'desc': 'Web Directory/File Brute Forcing (Web目录爆破)'},

            {'id': 'T1590.002', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'axfr|enum|brute|subdomain'),
             'cmd': re.compile(r'dnsenum|dnsrecon|sublist3r|amass|fierce|dig axfr'),
             'desc': 'DNS Enumeration/Zone Transfer (DNS枚举/区域传输)'},

            {'id': 'T1596', 'phase': 'Reconnaissance',
             'pattern': re.compile(r'search|query|host|ip'),
             'cmd': re.compile(r'shodan|censys|searchsploit'),
             'desc': 'Querying Technical Databases (查询技术数据库)'},

            # =========================================================================
            # TACTIC: RESOURCE DEVELOPMENT (TA0042) - 资源开发
            # =========================================================================
            {'id': 'T1587.001', 'phase': 'Resource Development',
             'pattern': re.compile(r'-o|build|dist|pyinstaller|cx_Freeze'),
             'cmd': re.compile(r'gcc|make|go build|cargo build|pyinstaller|msfvenom'),
             'desc': 'Malware Compilation/Building on Host (恶意软件编译)'},

            {'id': 'T1587.003', 'phase': 'Resource Development',
             'pattern': re.compile(r'req -new|-newkey|-days|-selfsigned|-keyout'),
             'cmd': re.compile(r'openssl|keytool|makecert|certutil'),
             'desc': 'Generating Self-Signed Certificates (生成自签名证书)'},

            {'id': 'T1588.002', 'phase': 'Resource Development',
             'pattern': re.compile(r'exploitdb|github\.com.*(sqlmap|metasploit|covenant|sliver|havoc)|packetstorm'),
             'cmd': re.compile(r'git clone|wget|curl'),
             'desc': 'Downloading Hacking Tools/Exploits (下载黑客工具)'},

            {'id': 'T1608.001', 'phase': 'Resource Development',
             'pattern': re.compile(r's3 cp|blob upload|push|ftp://'),
             'cmd': re.compile(r'aws|az|gsutil|git|scp|ftp|curl -T'),
             'desc': 'Staging/Uploading Malware to External Infrastructure (上传工具到暂存区)'},

            {'id': 'T1583.004', 'phase': 'Resource Development',
             'pattern': re.compile(r'run-instances|create-instances|vm create|droplet create'),
             'cmd': re.compile(r'aws ec2|az vm|doctl compute|gcloud compute'),
             'desc': 'Provisioning Rogue Cloud Instances (非法购买/启动云主机)'},

            # =========================================================================
            # TACTIC: INITIAL ACCESS (TA0001) - 初始访问
            # =========================================================================
            {'id': 'T1190', 'phase': 'Initial Access',
             'pattern': re.compile(r'java|php|node|httpd|tomcat|jboss|nginx|apache|struts|weblogic'),
             'cmd': re.compile(r'bash|sh|powershell|cmd\.exe|/bin/sh|/bin/bash'),
             'desc': 'Web process spawning shell (Web服务启动Shell/RCE)'},

            {'id': 'T1133', 'phase': 'Initial Access',
             'pattern': re.compile(r'bash -i|/dev/tcp/|nc -e|exec sh|0>&1'),
             'cmd': re.compile(r'bash|sh|nc|ncat|netcat|socat|openssl'),
             'desc': 'Reverse Shell Execution (反弹Shell连接)'},

            {'id': 'T1091', 'phase': 'Initial Access',
             'pattern': re.compile(r'/dev/sd[b-z][0-9]|/media/|/mnt/usb'),
             'cmd': re.compile(r'mount'),
             'desc': 'Mounting Removable Media (挂载USB设备)'},

            {'id': 'T1195', 'phase': 'Initial Access',
             'pattern': re.compile(r'http://|https://|git://|\.sh|\.py'),
             'cmd': re.compile(r'npm install|pip install|gem install|go get'),
             'desc': 'Suspicious Package Installation (供应链/恶意包安装)'},

            {'id': 'T1199', 'phase': 'Initial Access',
             'pattern': re.compile(r'ssh-rsa|ssh-ed25519'),
             'cmd': re.compile(r'echo.*authorized_keys|tee.*authorized_keys'),
             'desc': 'Trusted Relationship Setup (添加SSH公钥)'},

            # =========================================================================
            # TACTIC: EXECUTION (TA0002) - 执行
            # =========================================================================
            {'id': 'T1059.004', 'phase': 'Execution',
             'pattern': re.compile(r'-c|--eval|\.sh|\.bash|\|.*bash|\|.*sh'),
             'cmd': re.compile(r'bash|sh|dash|zsh|ksh|fish'),
             'desc': 'Unix Shell Script Execution (Shell脚本/管道执行)'},

            {'id': 'T1059.006', 'phase': 'Execution',
             'pattern': re.compile(r'-c|import socket|import subprocess|import os'),
             'cmd': re.compile(r'python|python2|python3'),
             'desc': 'Python Script/Inline Execution (Python执行)'},

            {'id': 'T1609', 'phase': 'Execution',
             'pattern': re.compile(r'exec|run|attach|cp'),
             'cmd': re.compile(r'docker|kubectl|podman|crictl|ctr'),
             'desc': 'Container Execution/Administration (容器内命令执行)'},

            {'id': 'T1569.002', 'phase': 'Execution',
             'pattern': re.compile(r'start|stop|restart|reload|status'),
             'cmd': re.compile(r'systemctl|service|rc-service|initctl'),
             'desc': 'System Service Execution (系统服务控制)'},

            {'id': 'T1053.001', 'phase': 'Execution',
             'pattern': re.compile(r'now|tomorrow|next|:'),
             'cmd': re.compile(r'at|atq|atrm'),
             'desc': 'Scheduled Execution via At (At计划任务)'},

            {'id': 'T1204.002', 'phase': 'Execution',
             'pattern': re.compile(r'/tmp/|/var/tmp/|/dev/shm/|/var/www/'),
             'cmd': re.compile(r'\./|bash|sh|python|perl'),
             'desc': 'Execution from Suspicious Directory (临时目录执行)'},

            {'id': 'T1072', 'phase': 'Execution',
             'pattern': re.compile(r'shell|command|cmd\.run|exec'),
             'cmd': re.compile(r'ansible|salt|puppet|chef-client'),
             'desc': 'Abuse of Software Deployment Tools (运维工具滥用)'},

            # =========================================================================
            # TACTIC: PERSISTENCE (TA0003) - 持久化
            # =========================================================================
            {'id': 'T1053.003', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/cron|/var/spool/cron|crontab'),
             'cmd': re.compile(r'echo|cp|mv|vi|nano|crontab'),
             'desc': 'Cron job modification (Cron任务修改)'},

            {'id': 'T1053.006', 'phase': 'Persistence',
             'pattern': re.compile(r'\.timer'),
             'cmd': re.compile(r'systemctl start|systemctl enable'),
             'desc': 'Systemd Timer creation/modification (Systemd定时器)'},

            {'id': 'T1547.001', 'phase': 'Persistence',
             'pattern': re.compile(
                 r'/etc/rc\.local|/etc/init\.d|\.bashrc|\.bash_profile|\.zshrc|/etc/profile|\.profile'),
             'cmd': re.compile(r'echo|cat >>|vi|nano|tee'),
             'desc': 'Shell startup/RC script modification (Shell启动项修改)'},

            {'id': 'T1543.002', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/systemd/system/|/lib/systemd/system/|\.service'),
             'cmd': re.compile(r'echo|vi|nano|cp|systemctl enable'),
             'desc': 'Systemd Service creation (恶意服务创建)'},

            {'id': 'T1136.001', 'phase': 'Persistence',
             'pattern': re.compile(r'-u 0|-o|-g 0|root|sudo|wheel'),
             'cmd': re.compile(r'useradd|adduser|usermod'),
             'desc': 'Suspicious Local Account Creation (后门账号创建)'},

            {'id': 'T1547.006', 'phase': 'Persistence',
             'pattern': re.compile(r'\.ko'),
             'cmd': re.compile(r'insmod|modprobe|lsmod'),
             'desc': 'Kernel Module Loading (加载内核模块/Rootkit)'},

            {'id': 'T1505.003', 'phase': 'Persistence',
             'pattern': re.compile(r'/var/www/|/usr/share/nginx/|\.php|\.jsp|\.asp'),
             'cmd': re.compile(r'echo|cat >>|cp|mv|wget|curl'),
             'desc': 'Web Shell Creation (WebShell写入)'},

            {'id': 'T1574.006', 'phase': 'Persistence',
             'pattern': re.compile(r'/etc/ld\.so\.preload'),
             'cmd': re.compile(r'echo|vi|nano|tee'),
             'desc': 'Global Library Hijacking via ld.so.preload (全局库劫持)'},

            # =========================================================================
            # TACTIC: PRIVILEGE ESCALATION (TA0004) - 提权
            # =========================================================================
            {'id': 'T1548.001', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'u\+s|g\+s|4[0-9]{3}|2[0-9]{3}'),
             'cmd': re.compile(r'chmod'),
             'desc': 'Setuid/Setgid bit set (设置SUID位)'},

            {'id': 'T1548.003', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/etc/sudoers|/etc/sudoers\.d'),
             'cmd': re.compile(r'echo|vi|nano|visudo|cp|tee'),
             'desc': 'Sudoers file modification (修改sudoers文件)'},

            {'id': 'T1548.003-2', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-S|-l|su\s+-'),
             'cmd': re.compile(r'sudo|doas|pkexec'),
             'desc': 'Suspicious Sudo/Polkit Usage (Sudo滥用)'},

            {'id': 'T1574.006', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'LD_PRELOAD|LD_LIBRARY_PATH'),
             'cmd': re.compile(r'export|env'),
             'desc': 'Shared Library Injection (LD_PRELOAD注入)'},

            {'id': 'T1068', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-o|Makefile|\.c|\.cpp'),
             'cmd': re.compile(r'gcc|cc|clang|make|g\+\+'),
             'desc': 'Compiling Code on Host (主机编译漏洞利用)'},

            {'id': 'T1055.008', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-p|attach'),
             'cmd': re.compile(r'gdb|strace|ptrace'),
             'desc': 'Process Injection via Ptrace/GDB (进程注入)'},

            {'id': 'T1611', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/host|/proc/1/ns|docker\.sock|cgroup'),
             'cmd': re.compile(r'mount|docker|nsenter|capsh'),
             'desc': 'Container Escape Attempt (容器逃逸)'},

            # =========================================================================
            # TACTIC: DEFENSE EVASION (TA0005) - 防御规避
            # =========================================================================
            {'id': 'T1070.002', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/var/log|/var/adm|/var/audit'),
             'cmd': re.compile(r'rm|truncate|shred|unlink|echo "" >|cat /dev/null >'),
             'desc': 'Log deletion or clearing (清除日志)'},

            {'id': 'T1070.003', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'\.bash_history|\.zsh_history|HISTFILESIZE=0|unset HISTFILE|history -c'),
             'cmd': re.compile(r'rm|export|unset|set \+o history|ln -sf /dev/null'),
             'desc': 'Clearing or Disabling Shell History (清除历史记录)'},

            {'id': 'T1070.006', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'-r|-t|--reference'),
             'cmd': re.compile(r'touch'),
             'desc': 'Timestomping (篡改文件时间戳)'},

            {'id': 'T1562.001', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'setenforce 0|/etc/selinux/config|aa-teardown|stop auditd|ufw disable|iptables -F'),
             'cmd': re.compile(r'setenforce|service|systemctl|ufw|iptables|apparmor_parser'),
             'desc': 'Disabling Security Tools (禁用安全工具)'},

            {'id': 'T1564.001', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/\.[^/]+|/\.\s+$|/\.\.$'),
             'cmd': re.compile(r'mkdir|touch|cp|mv'),
             'desc': 'Creation of Hidden Files/Directories (创建隐藏文件)'},

            {'id': 'T1036', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'/bin/sh|/bin/bash|/usr/bin/python'),
             'cmd': re.compile(r'cp.* /tmp/|cp.* /dev/shm/|cp.* /var/tmp/|mv'),
             'desc': 'Masquerading (伪装系统工具)'},

            {'id': 'T1027.002', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'-d|-o'),
             'cmd': re.compile(r'upx'),
             'desc': 'Software Packing/Unpacking (UPX加壳)'},

            {'id': 'T1027', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'base64|openssl|uudecode|xxd'),
             'cmd': re.compile(r'base64 -d|openssl enc -d|decode|rev'),
             'desc': 'Data decoding/obfuscation (数据混淆/解码)'},

            {'id': 'T1222', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'\+i|-i|\+a|-a'),
             'cmd': re.compile(r'chattr'),
             'desc': 'File attribute modification (文件锁定/不可变)'},

            {'id': 'T1620', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'memfd_create'),
             'cmd': re.compile(r'.*'),
             'desc': 'Fileless execution via memfd (无文件执行)'},

            # 新增规则
            {'id': 'T1611-enhanced', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'--privileged|--cap-add|SYS_ADMIN|sys_ptrace'),
             'cmd': re.compile(r'docker run|kubectl|podman|runc'),
             'desc': 'Privileged Container Execution (特权容器执行)'},

            {'id': 'T1611-mount', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/proc/self/exe|/etc/shadow|/etc/hostname'),
             'cmd': re.compile(r'cat|grep|find.*-name'),
             'desc': 'Container attempting to access host files (容器访问宿主机文件)'},

            # =========================================================================
            # TACTIC: CREDENTIAL ACCESS (TA0006) - 凭证获取
            # =========================================================================
            {'id': 'T1003.008', 'phase': 'Credential Access',
             'pattern': re.compile(r'/etc/shadow|/etc/passwd|/etc/master\.passwd|/etc/security/opasswd'),
             'cmd': re.compile(r'cat|grep|awk|sed|less|more|head|tail|vi|nano'),
             'desc': 'Access to System Password Files (读取密码文件)'},

            {'id': 'T1003.007', 'phase': 'Credential Access',
             'pattern': re.compile(r'/proc/\d+/mem|/proc/\d+/maps|mimipenguin|linikatz'),
             'cmd': re.compile(r'dd|cat|gdb|strings'),
             'desc': 'Process Memory Dumping for Credentials (内存抓取凭证)'},

            {'id': 'T1555.003', 'phase': 'Credential Access',
             'pattern': re.compile(r'Login Data|Cookies|signons\.sqlite|logins\.json'),
             'cmd': re.compile(r'sqlite3|cat|grep|cp'),
             'desc': 'Browser Password/Cookie Database Access (读取浏览器凭证)'},

            {'id': 'T1555.005', 'phase': 'Credential Access',
             'pattern': re.compile(r'\.kdbx|\.keepass|lastpass'),
             'cmd': re.compile(r'find|locate|ls|cp'),
             'desc': 'Password Manager Database Search (搜寻密码管理器数据库)'},

            {'id': 'T1552.001', 'phase': 'Credential Access',
             'pattern': re.compile(r'\.aws/credentials|\.azure/|\.gcloud/|\.kube/config|\.docker/config\.json'),
             'cmd': re.compile(r'cat|grep|less|more|head|tail'),
             'desc': 'Cloud/Container Credential File Access (读取云/容器凭证)'},

            {'id': 'T1552.003', 'phase': 'Credential Access',
             'pattern': re.compile(r'password|passwd|pwd|credentials|token|api_key|secret'),
             'cmd': re.compile(r'grep|cat .*history'),
             'desc': 'Grepping Shell History for Credentials (从历史记录搜寻密码)'},

            {'id': 'T1552.004', 'phase': 'Credential Access',
             'pattern': re.compile(r'id_rsa|id_dsa|id_ed25519|\.pem|\.ppk|\.key'),
             'cmd': re.compile(r'cat|grep|cp|mv'),
             'desc': 'SSH Private Key Access (读取SSH私钥)'},

            {'id': 'T1110', 'phase': 'Credential Access',
             'pattern': re.compile(r'-l|-P|-C|-M'),
             'cmd': re.compile(r'hydra|medusa|ncrack|patator|john|hashcat'),
             'desc': 'Brute Force or Password Cracking (暴力破解/密码爆破)'},

            # =========================================================================
            # TACTIC: DISCOVERY (TA0007) - 发现
            # =========================================================================
            {'id': 'T1082', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'uname|lscpu|lshw|lsblk|free|hostnamectl|dmidecode|uptime'),
             'desc': 'System Information Discovery (系统信息发现)'},

            {'id': 'T1033', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'whoami|id|w|who|last|users'),
             'desc': 'System Owner/User Discovery (用户/身份发现)'},

            {'id': 'T1087', 'phase': 'Discovery',
             'pattern': re.compile(r'/etc/passwd|passwd'),
             'cmd': re.compile(r'cat|grep|cut|awk|getent'),
             'desc': 'Account Discovery (账号枚举)'},

            {'id': 'T1069', 'phase': 'Discovery',
             'pattern': re.compile(r'group'),
             'cmd': re.compile(r'groups|getent group|cat /etc/group'),
             'desc': 'Permission Groups Discovery (权限组发现)'},

            {'id': 'T1016', 'phase': 'Discovery',
             'pattern': re.compile(r'-a|addr|route|rules|status'),
             'cmd': re.compile(r'ifconfig|ip|route|netstat|iptables|ufw|nmcli'),
             'desc': 'System Network Configuration Discovery (网络配置发现)'},

            {'id': 'T1018', 'phase': 'Discovery',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'arp|ping|fping|ip neighbor'),
             'desc': 'Remote System Discovery (远程主机发现)'},

            {'id': 'T1046', 'phase': 'Discovery',
             'pattern': re.compile(r'-z|-sS|-sT|-p'),
             'cmd': re.compile(r'nc|netcat|nmap|masscan|telnet'),
             'desc': 'Network Service Discovery (端口扫描)'},

            {'id': 'T1057', 'phase': 'Discovery',
             'pattern': re.compile(r'aux|ef|-e'),
             'cmd': re.compile(r'ps|top|htop|pgrep|pidof'),
             'desc': 'Process Discovery (进程发现)'},

            {'id': 'T1083', 'phase': 'Discovery',
             'pattern': re.compile(r'-name|-iname|-type f|id_rsa|\.conf|\.bak'),
             'cmd': re.compile(r'find|locate|ls -R|tree|grep -r'),
             'desc': 'File and Directory Discovery (文件与目录发现)'},

            {'id': 'T1518', 'phase': 'Discovery',
             'pattern': re.compile(r'-qa|list|installed|--version'),
             'cmd': re.compile(r'rpm|dpkg|yum|apt|snap|pip|docker images'),
             'desc': 'Software Discovery (已安装软件发现)'},

            {'id': 'T1040', 'phase': 'Discovery',
             'pattern': re.compile(r'-i|any|eth0|wlan0'),
             'cmd': re.compile(r'tcpdump|tshark|ngrep|wireshark'),
             'desc': 'Network Sniffing (网络嗅探)'},

            # =========================================================================
            # TACTIC: LATERAL MOVEMENT (TA0008) - 横向移动
            # =========================================================================
            {'id': 'T1021.004', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-i|ProxyCommand|StrictHostKeyChecking=no|-R|-L|-D'),
             'cmd': re.compile(r'ssh|scp|sftp'),
             'desc': 'SSH/SCP Lateral Movement or Tunneling (SSH移动/隧道)'},

            {'id': 'T1021.002', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'//|\\\\|-U|-c'),
             'cmd': re.compile(r'smbclient|mount\.cifs|mount -t cifs|rpcclient'),
             'desc': 'SMB/CIFS Access (访问Windows共享)'},

            {'id': 'T1021.001', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'/v|/u|::'),
             'cmd': re.compile(r'xfreerdp|rdesktop|remmina|vncviewer'),
             'desc': 'RDP/VNC Client Usage (远程桌面连接)'},

            {'id': 'T1021.006', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-i|-u|-p'),
             'cmd': re.compile(r'evil-winrm|winrm'),
             'desc': 'WinRM Usage (WinRM远程管理)'},

            {'id': 'T1563.002', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-S|SSH_AUTH_SOCK'),
             'cmd': re.compile(r'ssh'),
             'desc': 'Potential SSH Session Hijacking (SSH会话劫持)'},

            {'id': 'T1570', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'rsync'),
             'desc': 'Lateral Tool Transfer via Rsync (使用Rsync传输工具)'},

            {'id': 'T1550', 'phase': 'Lateral Movement',
             'pattern': re.compile(r'-k|-t|/tmp/krb5cc'),
             'cmd': re.compile(r'kinit|klist|kvno'),
             'desc': 'Kerberos Ticket Manipulation (Kerberos票据操作)'},

            # =========================================================================
            # TACTIC: COLLECTION (TA0009) - 收集
            # =========================================================================
            {'id': 'T1560', 'phase': 'Collection',
             'pattern': re.compile(r'-c.*zf|cf|czf|\.tar|\.zip|\.gz|\.7z|\.rar'),
             'cmd': re.compile(r'tar|zip|gzip|bzip2|7z|rar'),
             'desc': 'Archive/Compression of collected data (打包/压缩数据)'},

            {'id': 'T1074', 'phase': 'Collection',
             'pattern': re.compile(r'/tmp/|/var/tmp/|/dev/shm/'),
             'cmd': re.compile(r'cp|mv|tar|zip'),
             'desc': 'Data Staging in temporary directories (临时目录暂存数据)'},

            {'id': 'T1115', 'phase': 'Collection',
             'pattern': re.compile(r'-o|-selection clipboard|-i'),
             'cmd': re.compile(r'xclip|xsel|pbcopy|pbpaste'),
             'desc': 'Clipboard data collection (剪贴板窃取)'},

            {'id': 'T1113', 'phase': 'Collection',
             'pattern': re.compile(r'-window root|-quality|\.png|\.jpg'),
             'cmd': re.compile(r'scrot|import|screencapture|xwd|gnome-screenshot|spectacle'),
             'desc': 'Screen capture activity (屏幕截图)'},

            {'id': 'T1056.001', 'phase': 'Collection',
             'pattern': re.compile(r'/dev/input/event|--start --log'),
             'cmd': re.compile(r'showkey|logkeys|thc-vlogger'),
             'desc': 'Keylogging/Input Capture (键盘记录)'},

            {'id': 'T1123', 'phase': 'Collection',
             'pattern': re.compile(r'-d|--duration|-f cd'),
             'cmd': re.compile(r'arecord|rec|ffmpeg|audacity'),
             'desc': 'Audio capture (录音)'},

            {'id': 'T1114', 'phase': 'Collection',
             'pattern': re.compile(r'/var/mail|/var/spool/mail'),
             'cmd': re.compile(r'cat|grep|less|head|tail|fetchmail'),
             'desc': 'Local Email Collection (邮件窃取)'},

            # =========================================================================
            # TACTIC: COMMAND AND CONTROL (TA0011) - 命令与控制
            # =========================================================================
            {'id': 'T1071', 'phase': 'Command and Control',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'curl|wget|nc|ncat|netcat|socat|telnet'),
             'desc': 'Common Download/C2 utilities (常用下载/C2工具)'},

            {'id': 'T1090', 'phase': 'Command and Control',
             'pattern': re.compile(r'tcp-listen|forward|proxy|tunnel'),
             'cmd': re.compile(r'socat|ngrok|frpc|frps|chisel|gost|websocat'),
             'desc': 'Proxy/Tunneling tool usage (代理/隧道工具)'},

            {'id': 'T1219', 'phase': 'Command and Control',
             'pattern': re.compile(r'.*'),
             'cmd': re.compile(r'teamviewer|anydesk|logmein|vncserver|screen|tmux'),
             'desc': 'Remote Access Software/Terminal Multiplexing (远控软件/终端复用)'},

            {'id': 'T1105', 'phase': 'Command and Control',
             'pattern': re.compile(r'-O|--output|-o'),
             'cmd': re.compile(r'curl|wget'),
             'desc': 'Ingress Tool Transfer (下载恶意文件)'},

            # =========================================================================
            # TACTIC: EXFILTRATION (TA0010) - 数据渗漏
            # =========================================================================
            {'id': 'T1048', 'phase': 'Exfiltration',
             'pattern': re.compile(r'put|mput|upload|STOR'),
             'cmd': re.compile(r'ftp|lftp|tftp|sftp'),
             'desc': 'Exfiltration via FTP/SFTP (FTP文件上传)'},

            {'id': 'T1567', 'phase': 'Exfiltration',
             'pattern': re.compile(r'copy|sync|upload|--upload-file|-T'),
             'cmd': re.compile(r'rclone|gdrive|mega-cmd|aws|gsutil|az|curl'),
             'desc': 'Exfiltration to Cloud Storage/Web Service (上传至云存储)'},

            {'id': 'T1020', 'phase': 'Exfiltration',
             'pattern': re.compile(r'/dev/tcp/|/dev/udp/'),
             'cmd': re.compile(r'bash|sh|ksh|zsh'),
             'desc': 'Exfiltration via network redirection (Socket直接回传)'},

            {'id': 'T1052', 'phase': 'Exfiltration',
             'pattern': re.compile(r'/dev/sd[b-z]|/media/|/mnt/usb'),
             'cmd': re.compile(r'mount|dd|cp'),
             'desc': 'Exfiltration to Physical Medium (物理介质复制)'},

            # =========================================================================
            # TACTIC: IMPACT (TA0040) - 影响
            # =========================================================================
            {'id': 'T1485', 'phase': 'Impact',
             'pattern': re.compile(r'-rf|--no-preserve-root|if=/dev/zero|if=/dev/urandom'),
             'cmd': re.compile(r'rm|shred|dd|wipe|srm'),
             'desc': 'Data destruction attempt (数据破坏/擦除)'},

            {'id': 'T1486', 'phase': 'Impact',
             'pattern': re.compile(r'--encrypt|-c|--passphrase'),
             'cmd': re.compile(r'gpg|openssl|7z|zip|ccrypt|bcrypt'),
             'desc': 'File Encryption/Ransomware Behavior (勒索加密)'},

            {'id': 'T1496', 'phase': 'Impact',
             'pattern': re.compile(r'stratum\+tcp|pool|user|nicehash|minergate'),
             'cmd': re.compile(r'xmrig|minerd|cpuminer|ethminer|cgminer'),
             'desc': 'Cryptomining Activity (挖矿劫持)'},

            {'id': 'T1489', 'phase': 'Impact',
             'pattern': re.compile(r'stop|disable|kill'),
             'cmd': re.compile(r'systemctl|service|rc-service|killall|pkill'),
             'desc': 'Stopping System Services (停止关键服务)'},

            {'id': 'T1529', 'phase': 'Impact',
             'pattern': re.compile(r'-h|-r|now|0|6'),
             'cmd': re.compile(r'shutdown|reboot|halt|poweroff|init'),
             'desc': 'System Shutdown/Reboot (系统关闭/重启)'},

            {'id': 'T1561.002', 'phase': 'Impact',
             'pattern': re.compile(r'if=/dev/zero|if=/dev/urandom|of=/dev/sd|of=/dev/vd'),
             'cmd': re.compile(r'dd|cat|cp'),
             'desc': 'Disk Wiping Activity (磁盘擦除)'},

            {'id': 'T1491', 'phase': 'Impact',
             'pattern': re.compile(r'>|/var/www/html|index\.html|/etc/motd'),
             'cmd': re.compile(r'echo|cp|mv|cat'),
             'desc': 'Website/System Defacement (网站/系统篡改)'}
        ]

    def check_node(self, node):
        import shlex
        matches = []

        # 1. 获取原始命令行字符串
        extra = node.get('extra', {})
        cmd_full = str(extra.get('cmd', '')).strip()

        # 这里的 desc 和 group 保留你原本的辅助逻辑
        # [修改点 1] 提取 desc 并保留
        desc = str(extra.get('desc', '')).strip()

        if node.get('group') == 'memfd':
            matches.append({'tag': "T1620", 'reason': "Reflective Code Loading (memfd)"})

        # [新增] MMAP 高危权限检测 (Shellcode/注入)
        # 这个标记是在 ProvenancePublicDirect.process_event 中打上的
        if extra.get('risk_mmap'):
            prot = extra['risk_mmap']            # 如果包含 WRITE 和 EXEC (W+X)，这是极高危的 Shellcode 特征
            if 'WRITE' in prot and 'EXEC' in prot:
                matches.append({'tag': "T1055", 'reason': f"Process Injection / Shellcode (W+X): {prot}"})
            else:
                matches.append({'tag': "T1620", 'reason': f"Executable Memory Mapping: {prot}"})

        # =========================================================
        # [新增] Ptrace 威胁映射
        # =========================================================
        if extra.get('ptrace_req'):
            req = extra['ptrace_req']

            # 场景 A: 代码注入 (T1055 Process Injection)
            # POKETEXT/POKEDATA 意味着正在修改另一个进程的内存
            if 'POKETEXT' in req or 'POKEDATA' in req:
                matches.append({'tag': "T1055", 'reason': f"Code Injection via {req}"})

            # 场景 B: 进程依附 (T1055 / T1548)
            # 强行 Attach 到另一个进程，通常用于转储凭证或劫持控制流
            elif 'ATTACH' in req:
                matches.append({'tag': "T1055", 'reason': f"Process Attachment via {req}"})

            # 场景 C: 反调试/自我保护 (T1622 Debugger Evasion)
            # 恶意软件常用 TRACEME 来检测是否已经被分析人员调试
            elif 'TRACEME' in req:
                matches.append({'tag': "T1622", 'reason': "Anti-Debugging Check (TRACEME)"})

            # 场景 D: 其它读取 (T1003 Credential Dumping)
            # 读取内存可能是在窃取密码
            elif 'PEEK' in req:
                matches.append({'tag': "T1003", 'reason': f"Memory Scraping via {req}"})

        # =========================================================
        # [新增] 权限提升威胁映射 (T1548)
        # =========================================================
        if extra.get('risk_priv'):
            matches.append({'tag': "T1548", 'reason': "Privilege Escalation (setuid syscall detected)"})

        # 2. 预处理：命令行分词 (Tokenization)
        # 这是降低误报的关键步骤。将 "bash -c 'echo hi'" 分割为 ["bash", "-c", "echo hi"]
        try:
            # 使用 shlex 处理引号和转义，模拟 Shell 行为
            argv = shlex.split(cmd_full)
        except ValueError:
            # 如果 shlex 解析失败（例如引号不闭合），回退到简单的空格分割
            argv = cmd_full.split()

        if not argv:
            return matches

        # 3. 分离 Binary 和 Arguments
        binary_path = argv[0]  # e.g., "/usr/bin/curl" 或 "curl"
        binary_name = os.path.basename(binary_path)  # e.g., "curl"

        # 将参数重新组合成字符串，用于正则匹配 (不包含 binary 本身)
        # 这样 pattern 正则就不会误匹配到工具名
        args_str = " ".join(argv[1:])

        # 4. 遍历规则进行匹配
        for r in self.rules:
            rule_id = r.get('id')
            tool_regex = r.get('cmd')  # 对应规则中的 'cmd' (工具名)
            args_regex = r.get('pattern')  # 对应规则中的 'pattern' (参数特征)

            is_binary_match = False

            # --- 阶段一：匹配工具 (Binary Matching) ---
            if tool_regex:
                # 策略 A: 精确匹配文件名 (推荐)
                # 检查 binary_name 是否包含正则 (例如 python3 匹配 python)
                if tool_regex.search(binary_name):
                    is_binary_match = True
                # 策略 B: 某些规则可能写了全路径，检查完整路径
                elif tool_regex.search(binary_path):
                    is_binary_match = True
            else:
                # 如果规则没定义 cmd (罕见)，则默认跳过 binary 检查，直接查参数
                # 这种通常是通用行为检测，如 "Finding credentials in generic files"
                is_binary_match = True

            # 如果工具名都不对，直接跳过该规则 (Performance Boost & FP Reduction)
            if not is_binary_match:
                continue

            # --- 阶段二：匹配参数 (Arguments Matching) ---
                # [修改点 2] 在参数匹配阶段，同时也扫描 desc 字段
            if args_regex:
                # 逻辑变更为：搜参数 OR 搜完整命令 OR 搜描述信息
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
            # --- [新增] : 防止数据库无限膨胀，清理超过 7 天的旧记忆 ---
            self.mem.prune_old_memories(days_retention=7)
            # -----------------------------------------------------
            files = sorted(glob.glob(pattern))
            if not files: return "No files found"

            # 重置当前分析状态
            self.snaps, self.g_nodes, self.g_edges = {}, {}, {}
            self.ghosts, self.ghost_edges = [], []

            builder = ProvenancePublicDirect(self.host_ip)
            processed_ids = set()

            for i, fpath in enumerate(files):
                slice_name = os.path.basename(fpath)
                sys.stderr.write(f"[*] Ingesting {slice_name}\n")

                # 1. 摄取日志
                builder.ingest(fpath)

                # 2. 识别本切片新增的节点
                curr_keys = list(builder.nodes.keys())
                new_nodes = [builder.nodes[nid] for nid in curr_keys if nid not in processed_ids]

                # 3. 执行“第二个版本”的高级缝合逻辑
                if new_nodes:
                    self._stitch(new_nodes, builder, slice_name)

                    # B. [新增] 族谱重构 (彻底解决托孤)
                    # 对所有新出现的进程节点进行“寻亲”
                    self._reconstruct_lineage(new_nodes, builder)

                # C. [新增] 登记出生信息 (为未来做准备)
                # 遍历当前图中的所有连线，如果发现是 spawn 关系，就存入 lineage 表
                self._register_lineage(builder)

                for nid in curr_keys: processed_ids.add(nid)
                self.mem.commit_batch()

            # 4. 构建全局图结构
            builder.process_unmatched()
            nodes, edges = builder.get_data()

            # 处理威胁检测与 Ghost 集成
            for n in nodes:
                threats = self.mapper.check_node(n)
                if threats:
                    n['extra']['attck_evidence'] = threats
                    n['color'] = "#e74c3c"
                self.g_nodes[n['id']] = copy.deepcopy(n)

            # 将缝合产生的幽灵节点加入全局
            for g in self.ghosts: self.g_nodes[g['id']] = g
            # 【关键防御】：加上 label 作为键值一部分，防止同一节点的自循环边(比如既有 RWX 又有 MEMFD)被字典互相覆盖
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

        # ==========================================
        # [新增] 把这两个新方法加到类里
        # ==========================================

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

            # 检查图里是否已有父亲
            has_parent = False
            for pid, neighbors in builder.adj_list.items():
                if n['id'] in neighbors:
                    parent = builder.nodes.get(pid)
                    if parent and parent['group'] == 'proc':
                        has_parent = True;
                        break
            if has_parent: continue

            # 查库寻亲
            birth_record = self.mem.find_parent(n['id'])
            if birth_record:
                pid, pdesc = birth_record
                if pid in builder.nodes:
                    # 父亲在图里，连虚线
                    key = (pid, n['id'], 'Ancestry')
                    if key not in builder.edge_map:
                        builder.add_edge(pid, n['id'], label="Spawn(R)", color="#1abc9c", style="dashed")
                else:
                    # 父亲不在，创建 Ghost
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
        # 1. 忽略本地回环和全零
        if ip.startswith("127.") or ip == "0.0.0.0" or ip == "::1": return True

        # 2. 忽略常见公共 DNS (Google, Cloudflare, AliDNS等)
        # 实际生产中这里应该是一个 Config List
        common_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114", "223.5.5.5"}
        if ip in common_dns: return True

        # 3. (可选) 忽略多播地址
        if ip.startswith("224.") or ip.startswith("239."): return True

        return False

    def _stitch(self, new_nodes, builder, slice_name):
        """
        [V7 最终优化版 - 青色回归]
        全维度缝合 + 智能IP过滤 + 消除同类噪音 + 颜色恢复为青色(#1abc9c)
        """
        ts = datetime.now().timestamp()

        for n in new_nodes:
            # --- 1. 关联键提取 ---
            keys = set()

            # A. 自身属性
            if n['group'] == 'file':
                keys.add(f"FILE:{n['extra'].get('path')}")
            elif n['group'] in ['net', 'net_in_agg', 'gw']:
                ip = n['extra'].get('ip')
                if not self._is_ignorable_ip(ip):
                    keys.add(f"IP:{ip}")

            # B. 邻居关联
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

            # --- 2. 记忆检索与缝合 ---
            query_keys = list(keys)
            history = self.mem.recall(query_keys)

            for h in history:
                if h['desc'].endswith(f"({slice_name})"): continue

                hist_event_id = h['id']

                # [SITUATION A] 实体直连
                if hist_event_id in builder.nodes:
                    hist_node = builder.nodes[hist_event_id]

                    # [同类抑制] 防止文件连文件，IP连IP
                    if hist_node['group'] == n['group']:
                        continue

                    # [物理连接去重] 如果已经有实线连接，不画虚线
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
                            color="#1abc9c",  # <--- 改回青色
                            style="dashed"
                        )

                # [SITUATION B] 幽灵节点
                else:
                    # [同类抑制]
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
                            'color': '#1abc9c',  # <--- 改回青色
                            'shape': 'dot',
                            'extra': {'desc': f"Linked via {h['key']}", 'payload': h['payload']}
                        })
                        self.ghost_edges.append({
                            'from': gid, 'to': n['id'],
                            'label': 'TimeJump',
                            'color': '#1abc9c',  # <--- 改回青色
                            'dashes': True
                        })

            # --- 3. 记忆存储 ---
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
        # 初始化全局 IP 映射表 (IP -> Community Key)
        self.ip_to_comm = {}

        if not LEIDEN_AVAILABLE or not self.g_nodes:
            self.snaps['overview'] = {'nodes': list(self.g_nodes.values()), 'edges': list(self.g_edges.values())}
            # Fallback: 如果没有聚类，所有 IP 都映射到 overview
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
            # [Smart Filtering] Ignore noise (clusters with 1 node), UNLESS it is a Threat
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

                # [NEW] Populate IP Map
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

        # 首次运行时下载，之后缓存到本地
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

        # [修改点] 双重保险：再次检查节点数量
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
