#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import re
import glob
import shlex
import networkx as nx
import networkx.algorithms.community as nx_comm
from collections import defaultdict
import numpy as np
import random
import itertools
import math  # <--- make sure this import is present
from gensim.models import Word2Vec
import skfuzzy as fuzz  # Fuzzy C-Means library used in the paper
from collections import defaultdict

# ============================================================================
# 1. Interactive UI Template (community view + style fixes + black-font support)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Contexts: Community Investigation</title>
    <script src="https://cdn.staticfile.org/vis-network/9.1.2/dist/vis-network.min.js"></script>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; overflow: hidden; display: flex; height: 100vh; }

        #sidebar-left { width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; z-index: 20; box-shadow: 4px 0 15px rgba(0,0,0,0.5); }
        .sidebar-header { padding: 15px; background: #21262d; border-bottom: 1px solid #30363d; }
        .app-title { font-size: 18px; font-weight: bold; color: #58a6ff; margin-bottom: 5px; }
        .app-subtitle { font-size: 11px; color: #8b949e; }

        #comm-list-container { flex: 1; overflow-y: auto; padding: 10px; }
        .comm-item { 
            padding: 10px; margin-bottom: 8px; border-radius: 6px; 
            background: #21262d; border: 1px solid #30363d; cursor: pointer; 
            transition: all 0.2s; display: flex; justify-content: space-between; align-items: center;
        }
        .comm-item:hover { background: #30363d; border-color: #58a6ff; }
        .comm-item.active { background: rgba(88, 166, 255, 0.15); border-color: #58a6ff; }
        .comm-title { font-size: 13px; font-weight: 600; color: #c9d1d9; }
        .comm-meta { font-size: 11px; color: #8b949e; margin-top: 2px; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; }
        .badge-red { background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid rgba(218, 54, 51, 0.4); }

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
        .shape.comm { width: 12px; height: 12px; border-radius: 50%; background: #2196f3; }
        .shape.net { width: 8px; height: 8px; transform: rotate(45deg); background: #238636; }
        .shape.file { width: 10px; height: 10px; border-radius: 2px; background: #d29922; }

        #detail-panel { position: fixed; top: 0; right: -480px; width: 480px; height: 100vh; background: #161b22; border-left: 1px solid #30363d; transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1); z-index: 30; display: flex; flex-direction: column; }
        #detail-panel.open { right: 0; }
        .detail-content { flex: 1; overflow-y: auto; padding: 25px; }
        .close-btn { position: absolute; top: 15px; right: 20px; cursor: pointer; color: #8b949e; font-size: 24px; }
        h2 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 0; word-break: break-all; }
        .field-label { font-size: 10px; color: #8b949e; margin-top: 15px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
        .field-value { font-family: 'Consolas', monospace; font-size: 12px; color: #c9d1d9; background: #0d1117; padding: 8px; border: 1px solid #30363d; border-radius: 4px; word-break: break-all; margin-top: 4px; white-space: pre-wrap; }
        .attck-box { background: rgba(218, 54, 51, 0.1); border: 1px solid #da3633; padding: 10px; margin-bottom: 15px; border-radius: 6px; }
        .attck-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }
        .attck-id { background: #da3633; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .attck-desc { font-size: 13px; color: #ffaeb6; font-weight: 600; }

        #filter-indicator { position: absolute; top: 60px; right: 20px; background: rgba(155, 89, 182, 0.2); border: 1px solid #9b59b6; color: #fff; padding: 8px 12px; border-radius: 4px; font-size: 12px; pointer-events: none; display: none; backdrop-filter: blur(4px); z-index: 15; box-shadow: 0 2px 10px rgba(0,0,0,0.5); }
    </style>
</head>
<body>
<div id="sidebar-left">
    <div class="sidebar-header">
        <div class="app-title">Contexts</div>
        <div class="app-subtitle">Community Analysis (Full)</div>
    </div>
    <div id="comm-list-container">
        </div>
    <div style="padding: 15px; font-size: 11px; color: #8b949e; border-top: 1px solid #30363d;">
        Click a node to isolate context.<br>
        Click empty space to reset.
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
        <div class="l-item"><div class="shape poi"></div><strong>MITRE TTP Hit</strong></div>
        <div class="l-item"><div class="shape comm"></div><strong>Community Member</strong></div>
        <div class="l-item"><div class="shape net"></div><strong>Network Node</strong></div>
        <div class="l-item"><div class="shape file"></div><strong>File Node</strong></div>
    </div>
</div>

<div id="detail-panel">
    <div class="close-btn" onclick="closeDetail()">×</div>
    <div class="detail-content" id="detail-content"></div>
</div>

<script type="text/javascript">
    var allData = __COMMUNITIES_JSON__; 
    var network = null;
    var physicsEnabled = true;
    var container = document.getElementById('mynetwork');
    var currentNodes = null;
    var currentEdges = null;
    var isFiltered = false;

    var options = {
        nodes: { 
            font: { color: 'white', size: 14, face: 'Segoe UI' }, 
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

    function init() {
        var listContainer = document.getElementById('comm-list-container');
        var keys = Object.keys(allData).sort(function(a,b) { 
            var countA = allData[a].threat_count || 0;
            var countB = allData[b].threat_count || 0;
            return countB - countA; 
        });

        keys.forEach(function(key) {
            var comm = allData[key];
            var div = document.createElement('div');
            div.className = 'comm-item';
            div.id = 'comm-btn-' + key;
            div.onclick = function() { loadCommunity(key); };

            var html = '<div>';
            html += '<div class="comm-title">Community #' + key + '</div>';
            html += '<div class="comm-meta">' + comm.nodes.length + ' entities</div>';
            html += '</div>';

            if (comm.threat_count > 0) {
                html += '<span class="badge badge-red">' + comm.threat_count + ' Alerts</span>';
            }

            div.innerHTML = html;
            listContainer.appendChild(div);
        });

        if (keys.length > 0) {
            loadCommunity(keys[0]);
        }
    }

    function loadCommunity(key) {
        var items = document.querySelectorAll('.comm-item');
        items.forEach(el => el.classList.remove('active'));
        var activeBtn = document.getElementById('comm-btn-' + key);
        if(activeBtn) activeBtn.classList.add('active');

        isFiltered = false;
        document.getElementById('filter-indicator').style.display = 'none';

        var commData = allData[key];
        currentNodes = new vis.DataSet(commData.nodes);
        currentEdges = new vis.DataSet(commData.edges);

        if (network) {
            network.setData({ nodes: currentNodes, edges: currentEdges });
        } else {
            network = new vis.Network(container, { nodes: currentNodes, edges: currentEdges }, options);
            network.on("click", function (params) {
                if (params.nodes.length > 0) {
                    var nodeId = params.nodes[0];
                    showDetail(currentNodes.get(nodeId));
                    isolateContextVis(nodeId);
                }
                else if (params.edges.length > 0) {
                    closeDetail();
                } 
                else {
                    closeDetail();
                    resetVis();
                }
            });
        }
        setTimeout(fitGraph, 100);
    }

    function isolateContextVis(rootId) {
        if (!currentNodes || !currentEdges) return;
        var allEdges = currentEdges.get();
        var parentMap = {}; 
        var childMap = {};  

        allEdges.forEach(e => {
            if(!parentMap[e.to]) parentMap[e.to] = [];
            parentMap[e.to].push(e.from);
            if(!childMap[e.from]) childMap[e.from] = [];
            childMap[e.from].push(e.to);
        });

        var keep = new Set([rootId]);
        var stack = [rootId];
        while(stack.length > 0){
            var curr = stack.pop();
            var parents = parentMap[curr] || [];
            parents.forEach(p => {
                if(!keep.has(p)){ keep.add(p); stack.push(p); }
            });
        }
        stack = [rootId];
        while(stack.length > 0){
            var curr = stack.pop();
            var children = childMap[curr] || [];
            children.forEach(c => {
                if(!keep.has(c)){ keep.add(c); stack.push(c); }
            });
        }

        var nodeUpdates = currentNodes.getIds().map(id => ({
            id: id, 
            hidden: !keep.has(id),
            opacity: keep.has(id) ? 1.0 : 0.05
        }));
        currentNodes.update(nodeUpdates);

        var edgeUpdates = allEdges.map(e => ({
            id: e.id, 
            hidden: !(keep.has(e.from) && keep.has(e.to))
        }));
        currentEdges.update(edgeUpdates);

        isFiltered = true;
        document.getElementById('filter-indicator').style.display = 'block';
    }

    function resetVis() {
        if(!isFiltered || !currentNodes || !currentEdges) return;
        var nodeUpdates = currentNodes.getIds().map(id => ({id: id, hidden: false, opacity: 1.0}));
        currentNodes.update(nodeUpdates);
        var edgeUpdates = currentEdges.getIds().map(id => ({id: id, hidden: false}));
        currentEdges.update(edgeUpdates);
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
        if (!node) return;
        var html = '<h2>' + node.label.split("\\n")[0] + '</h2>';
        var extra = node.extra || {};
        var attacks = extra.attck_hits || [];

        if (extra.community_id !== undefined) {
             html += '<div style="margin-bottom:15px;"><span style="background:#30363d; padding:4px 8px; border-radius:4px; font-size:11px; color:#8b949e;">Louvain Community #' + extra.community_id + '</span></div>';
        }

        if (attacks.length > 0) {
             html += '<div class="field-label">Threat Detection</div>';
             attacks.forEach(hit => { 
                 html += '<div class="attck-box">';
                 html += '<div class="attck-header">';
                 html += '<span class="attck-id">' + hit.tag + '</span>';
                 html += '</div>';
                 html += '<div class="attck-desc">' + hit.reason + '</div>';
                 html += '</div>';
             });
        }

        if (extra.cmd) {
            html += '<div class="field-label">Command Line</div>';
            html += '<div class="field-value" style="color:#58a6ff">' + extra.cmd + '</div>';
        }

        for (var key in extra) {
            if (['attck_hits', 'cmd', 'label', 'shape', 'path_score', 'relevance_score', 'community_id', 'group', 'color', 'font', 'id'].indexOf(key) === -1) {
                html += '<div class="field-label">' + key.toUpperCase() + '</div>';
                html += '<div class="field-value">' + extra[key] + '</div>';
            }
        }
        document.getElementById('detail-content').innerHTML = html;
        document.getElementById('detail-panel').classList.add('open');
    }
    function closeDetail() { document.getElementById('detail-panel').classList.remove('open'); }

    init();
</script>
</body>
</html>
"""


# ============================================================================
# 2. MITRE ATT&CK Mapper (With Net Exclusion)
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
             'desc': 'Vulnerability Scanning Activity'},
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
             'desc': 'Web process spawning shell (Web Service RCE)'},
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
             'desc': 'Suspicious Package Installation'},
            {'id': 'T1199', 'phase': 'Initial Access',
             'pattern': re.compile(r'ssh-rsa|ssh-ed25519'),
             'cmd': re.compile(r'echo.*authorized_keys|tee.*authorized_keys'),
             'desc': 'Trusted Relationship Setup (SSH Key Addition)'},

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
             'desc': 'Systemd Service creation (Malicious Service)'},
            {'id': 'T1136.001', 'phase': 'Persistence',
             'pattern': re.compile(r'-u 0|-o|-g 0|root|sudo|wheel'),
             'cmd': re.compile(r'useradd|adduser|usermod'),
             'desc': 'Suspicious Local Account Creation'},
            {'id': 'T1547.006', 'phase': 'Persistence',
             'pattern': re.compile(r'\.ko'),
             'cmd': re.compile(r'insmod|modprobe|lsmod'),
             'desc': 'Kernel Module Loading (Rootkit)'},
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
             'desc': 'Compiling Code on Host (Exploit Compilation)'},
            {'id': 'T1055.008', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'-p|attach'),
             'cmd': re.compile(r'gdb|strace|ptrace'),
             'desc': 'Process Injection via Ptrace/GDB'},
            {'id': 'T1611', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/host|/proc/1/ns|docker\.sock|cgroup'),
             'cmd': re.compile(r'mount|docker|nsenter|capsh'),
             'desc': 'Container Escape Attempt'},
            {'id': 'T1611-enhanced', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'--privileged|--cap-add|SYS_ADMIN|sys_ptrace'),
             'cmd': re.compile(r'docker run|kubectl|podman|runc'),
             'desc': 'Privileged Container Execution'},
            {'id': 'T1611-mount', 'phase': 'Privilege Escalation',
             'pattern': re.compile(r'/proc/self/exe|/etc/shadow|/etc/hostname'),
             'cmd': re.compile(r'cat|grep|find.*-name'),
             'desc': 'Container attempting to access host files'},

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
             'desc': 'Timestomping (modifying file timestamps)'},
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
             'desc': 'Masquerading (Disguising as system tools)'},
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
             'desc': 'File attribute modification (Locked/Immutable)'},
            {'id': 'T1620', 'phase': 'Defense Evasion',
             'pattern': re.compile(r'memfd_create'),
             'cmd': re.compile(r'.*'),
             'desc': 'Fileless execution via memfd'},

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
             'desc': 'Network Service Discovery (Port Scan)'},
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
             'desc': 'Software Discovery'},
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
             'desc': 'SMB/CIFS Access'},
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
             'desc': 'Ingress Tool Transfer (Downloading malicious files)'},

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
             'desc': 'Exfiltration via network redirection'},
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
        if node.get('group') == 'net':
            return []
        if node.get('group') == 'file':
            return []
        node_id = str(node.get('id', ''))
        if node_id.startswith('n_') or node_id.startswith('net_'):
            return []

        matches = []
        extra = node.get('extra', {})
        cmd_full = str(extra.get('cmd', '')).strip()

        for r in self.rules:
            if r['pattern'].search(cmd_full):
                matches.append({'tag': r['id'], 'reason': r['desc']})
        return matches


class DepCommAlgorithm:
    def __init__(self):
        print("[Engine] Initializing Strict DEPCOMM Academic Pipeline...")
        self.mapper = AttckMapper()
        self.G = nx.DiGraph()
        self.communities = {}

    def build_graph(self, raw_nodes, raw_edges):
        self.G.clear()
        for n in raw_nodes:
            node_type = 'proc' if n['group'] == 'proc' else 'resource'
            self.G.add_node(n['id'], label=n['label'], type=node_type, raw_data=n)
        for e in raw_edges:
            self.G.add_edge(e['from'], e['to'], label=e['label'])
        print(
            f"[Graph] Base Provenance Graph Built: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges.")

    # ============================================================================
    # Core 1: Hierarchical Random Walk (Section IV-C)
    # ============================================================================
    def _hierarchical_random_walk(self, num_walks=10, walk_length=200):
        # [Following the paper] Section VI explicitly sets walk length to 200
        print("[DEPCOMM] Executing Hierarchical Random Walks (length=200)...")
        walks = []
        proc_nodes = [n for n, d in self.G.nodes(data=True) if d['type'] == 'proc']

        for node in proc_nodes:
            for _ in range(num_walks):
                walk = [node]
                curr = node
                for _ in range(walk_length - 1):
                    successors = list(self.G.successors(curr))
                    predecessors = list(self.G.predecessors(curr))
                    neighbors = successors + predecessors
                    if not neighbors:
                        break

                    # Abstraction of the S1-S8 strategy: data-flow direction
                    # (towards downstream/child processes) gets a higher weight
                    weights = []
                    for nbr in neighbors:
                        weight = 1.0
                        if nbr in successors:
                            weight = 5.0 if self.G.nodes[nbr]['type'] == 'proc' else 3.0
                        else:
                            weight = 2.0 if self.G.nodes[nbr]['type'] == 'proc' else 1.0
                        weights.append(weight)

                    weights = np.array(weights) / sum(weights)
                    next_node = np.random.choice(neighbors, p=weights)
                    walk.append(next_node)
                    curr = next_node
                walks.append(walk)
        return walks, proc_nodes

    def learn_representation(self):
        walks, proc_nodes = self._hierarchical_random_walk()
        print("[DEPCOMM] Learning Node Representations via SkipGram (Word2Vec)...")

        # [Following the paper] Section VI: window size=20, dimensions=20.
        # Dropped the previously forced epochs=50 override.
        model = Word2Vec(walks, vector_size=20, window=20, min_count=1, sg=1, workers=4)

        embeddings = []
        node_mapping = []
        for n in proc_nodes:
            if n in model.wv:
                embeddings.append(model.wv[n])
                node_mapping.append(n)

        return np.array(embeddings), node_mapping

    # ============================================================================
    # Core 2: FCM Overlapping Community Detection
    # (Section IV-C, strictly reproduces the 0.8 threshold and full resource assignment)
    # ============================================================================
    def detect_process_centric_communities(self, embeddings, node_mapping):
        # Dynamically compute C (to keep the code runnable in the absence of
        # the paper's full FPC-selection function)
        optimal_c = max(3, min(10, len(node_mapping) // 10 + 1))
        print(f"[DEPCOMM] Running Fuzzy C-Means clustering with C={optimal_c}...")

        data = embeddings.T
        cntr, u, u0, d, jm, p, fpc = fuzz.cluster.cmeans(
            data, c=optimal_c, m=2, error=0.005, maxiter=1000, init=None
        )

        comm_map = defaultdict(list)

        # 1. [Following the paper] Process-node overlap decision: strictly follows
        #    lambda = 0.8 * max_j{u_ij}, with no cap on the number of memberships
        for i, node in enumerate(node_mapping):
            max_u = np.max(u[:, i])
            threshold = 0.8 * max_u
            for c_idx in range(optimal_c):
                if u[c_idx, i] >= threshold:
                    comm_map[node].append(c_idx)

        # 2. [Following the paper] Resource-node association: as long as a process
        #    neighbor exists, a full replica is created into that community -- no voting
        for node, d in self.G.nodes(data=True):
            if d['type'] == 'resource':
                neighbors = list(self.G.successors(node)) + list(self.G.predecessors(node))
                for nbr in neighbors:
                    if nbr in comm_map:
                        for c_idx in comm_map[nbr]:
                            if c_idx not in comm_map[node]:
                                comm_map[node].append(c_idx)

        return comm_map

    # ============================================================================
    # Core 3: Graph Compression (Section IV-D)
    # ============================================================================
    def compress_communities(self, comm_map):
        """
        Implements Process-based and Resource-based Pattern compression,
        removing large amounts of redundant nodes.
        """
        print("[DEPCOMM] Executing Graph Compression (Process & Resource Patterns)...")
        nodes_to_remove = set()
        merge_map = {}

        parent_to_children = defaultdict(list)
        for u, v, d in self.G.edges(data=True):
            if d['label'] == 'spawn':
                parent_to_children[u].append(v)

        # 1. Merge redundant sibling processes with the same parent and command line
        #    (Process-based Pattern)
        for parent, children in parent_to_children.items():
            cmd_groups = defaultdict(list)
            for child in children:
                if self.G.nodes[child]['type'] == 'proc':
                    cmd = self.G.nodes[child]['raw_data'].get('extra', {}).get('cmd', '')
                    cmd_groups[cmd].append(child)

            for cmd, group in cmd_groups.items():
                if len(group) > 1:
                    keeper = group[0]
                    self.G.nodes[keeper]['raw_data']['label'] += f"\n[Merged x{len(group)}]"
                    for duplicate in group[1:]:
                        merge_map[duplicate] = keeper
                        nodes_to_remove.add(duplicate)

        # 2. Redirect edges and rebuild the topology
        edges_to_add = []
        for u, v, d in self.G.edges(data=True):
            if u in nodes_to_remove or v in nodes_to_remove:
                new_u = merge_map.get(u, u)
                new_v = merge_map.get(v, v)
                if new_u != new_v:
                    edges_to_add.append((new_u, new_v, d))

        self.G.add_edges_from([(u, v, d) for u, v, d in edges_to_add])
        self.G.remove_nodes_from(nodes_to_remove)

        # 3. Update the community mapping so it no longer references removed nodes
        for old, new in merge_map.items():
            if old in comm_map:
                if new in comm_map:
                    comm_map[new] = list(set(comm_map[new] + comm_map[old]))
                del comm_map[old]

        print(f"[DEPCOMM] Compression Complete. Removed {len(nodes_to_remove)} redundant nodes.")

    # ============================================================================
    # Core 4: InfoPath Extraction and 4-Dimensional Scoring (Section IV-E)
    # ============================================================================
    def extract_and_rank_infopaths(self, comm_map, poi_nodes):
        print("[DEPCOMM] Extracting and scoring InfoPaths (4-Dimension Formula)...")

        node_freq = {n: self.G.degree(n) for n in self.G.nodes()}

        for node, cids in comm_map.items():
            if node in self.G:
                for cid in cids:
                    if cid not in self.communities:
                        self.communities[cid] = {'nodes': set(), 'infopaths': []}
                    self.communities[cid]['nodes'].add(node)

        for cid, comm_data in self.communities.items():
            nodes = comm_data['nodes']
            sub_G = self.G.subgraph(nodes)

            inputs = [n for n in nodes if sub_G.in_degree(n) == 0 or self.G.nodes[n]['type'] == 'resource']
            outputs = [n for n in nodes if sub_G.out_degree(n) == 0 or n in poi_nodes]

            paths = []
            for src, dst in itertools.product(inputs[:10], outputs[:10]):
                if src != dst and nx.has_path(sub_G, src, dst):
                    for path in nx.all_simple_paths(sub_G, src, dst, cutoff=8):
                        paths.append(path)

            ranked_paths = []
            for p in paths:
                # Implementation of Formula 1-3 features
                f_poi = 1.0 if any(n in poi_nodes for n in p) else 0.0
                f_iot = 0.5 * ((1 if self.G.nodes[p[0]]['type'] == 'proc' else 0) +
                               (1 if self.G.nodes[p[-1]]['type'] == 'proc' else 0))

                uniq_sum = sum([1.0 / (math.log(node_freq[n] + 1) + 1) for n in p])
                f_uniq = uniq_sum / len(p)

                f_time = math.exp(-0.1 * len(p))

                score = (f_poi * 0.4) + (f_iot * 0.2) + (f_uniq * 0.2) + (f_time * 0.2)
                ranked_paths.append((score, p))

            ranked_paths.sort(key=lambda x: x[0], reverse=True)
            comm_data['infopaths'] = ranked_paths[:3]

    # ============================================================================
    # Pipeline runner
    # ============================================================================
    def run_pipeline(self):
        poi_nodes = []
        for nid, data in self.G.nodes(data=True):
            hits = self.mapper.check_node(data['raw_data'])
            if hits:
                poi_nodes.append(nid)
                data['raw_data']['extra']['attck_hits'] = hits

        embeddings, node_mapping = self.learn_representation()

        if len(node_mapping) > 0:
            # optimal_c=10 override removed here
            comm_map = self.detect_process_centric_communities(embeddings, node_mapping)
        else:
            comm_map = {n: [0] for n in self.G.nodes()}

        # Run graph compression
        self.compress_communities(comm_map)

        # Extract and score InfoPaths
        self.extract_and_rank_infopaths(comm_map, poi_nodes)

        final_nodes = []
        for nid, cids in comm_map.items():
            if nid in self.G:
                n_data = self.G.nodes[nid]['raw_data']
                n_data['extra']['community_ids'] = cids
                final_nodes.append(n_data)

        final_edges = [{'from': u, 'to': v, 'label': d['label']} for u, v, d in self.G.edges(data=True)]

        return final_nodes, final_edges, self.communities
# ============================================================================
# 4. Log Parser (Updated Robust Logic)
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
            return
        for path in files:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    first = f.read(1)
                    f.seek(0)
                    if first == '[':
                        try:
                            for ev in json.load(f):
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
            except:
                pass

    def _add_node(self, nid, label, group, extra=None):
        if nid not in self._seen_nodes:
            self.nodes.append({'id': nid, 'label': label, 'group': group, 'extra': extra or {}})
            self._seen_nodes.add(nid)

    def _add_edge(self, src, dst, label):
        eid = f"{src}->{dst}:{label}"
        if eid not in self._seen_edges:
            self.edges.append({'from': src, 'to': dst, 'label': label})
            self._seen_edges.add(eid)

    def _proc(self, ev):
        # [FIX] Core fix: removed all `type` filtering.
        # As long as the log entry has a PID we try to process it, so
        # type=PATH or type=CWD entries can be picked up too.
        pid = ev.get('pid')
        if not pid:
            return

        proc_id = f"p_{pid}"
        binary = ev.get('cmd') or ev.get('comm', 'unknown')
        args = " ".join(ev.get('args', [])) if isinstance(ev.get('args'), list) else ev.get('args', '')
        cmdline = f"{binary} {args}".strip()

        self._add_node(proc_id, f"{ev.get('comm', '')}\n{pid}", 'proc', {
            'cmd': cmdline, 'image': binary, 'cgroup': ev.get('cgroup_id'),
            'risk_mmap': ev.get('risk_mmap'), 'ptrace_req': ev.get('ptrace_request')
        })

        if ev.get('ppid') and str(ev.get('ppid')) != "0":
            p_id = f"p_{ev.get('ppid')}"
            self._add_node(p_id, f"PID {ev.get('ppid')}", 'proc', {'cmd': f"Process {ev.get('ppid')}"})
            self._add_edge(p_id, proc_id, 'spawn')

        subtype = ev.get('subtype', '')

        # [FIX] Robust file detection: any filename/path/name field containing
        # a slash is treated as a file node
        fpath = ev.get('filename') or ev.get('path') or ev.get('name')
        if fpath and isinstance(fpath, str) and fpath != '(null)' and '/' in fpath:
            fid = f"f_{fpath}_{pid}"
            self._add_node(fid, fpath.split('/')[-1], 'file', {'fullpath': fpath})
            self._add_edge(proc_id, fid, 'open')

        # [FIX] Robust network detection
        remote_ip = ev.get('dst_ip') or ev.get('dip') or ev.get('daddr') or ev.get('remote_ip')
        remote_port = ev.get('dport') or ev.get('sport')

        if remote_ip and remote_ip not in ['0.0.0.0', '127.0.0.1', '::1', '::', '']:
            port_str = str(remote_port) if remote_port else "0"
            net_id = f"n_{remote_ip}_{port_str}"
            self._add_node(net_id, f"{remote_ip}:{port_str}", 'net', {'ip': remote_ip, 'port': port_str})
            edge_label = 'traffic'
            if subtype:
                edge_label = subtype.lower()
            elif 'bind' in cmdline or 'listen' in cmdline:
                edge_label = 'bind'
            else:
                edge_label = 'connect'
            self._add_edge(proc_id, net_id, edge_label)

        # Memfd
        if subtype == 'MEMFD' or 'memfd_create' in cmdline:
            name = ev.get('name', 'unknown')
            mem_id = f"mem_{name}_{pid}"
            self._add_node(mem_id, f"MEM: {name}", 'memfd', {'fullpath': 'memory'})
            self._add_edge(proc_id, mem_id, 'memfd_create')


# ============================================================================
# 5. Main (With DEPCOMM Pipeline & Alert Export)
# ============================================================================
if __name__ == "__main__":
    import copy

    # Configure input/output paths
    LOG_FILE = "/root/ebpf/logs/2026-02-13/audit_21.json"
    OUTPUT_HTML = "depcomm.html"
    OUTPUT_TXT = "depcomm.txt"  # detailed alert text file

    COMMUNITY_COLORS = [
        "#7fc97f", "#beaed4", "#fdc086", "#ffff99", "#386cb0",
        "#f0027f", "#bf5b17", "#666666", "#17becf", "#bcbd22"
    ]

    STYLE_NET = {'background': '#238636', 'border': '#238636'}
    STYLE_THREAT = {'background': '#da3633', 'border': '#f85149'}
    STYLE_FILE = {'background': '#d29922', 'border': '#d29922'}

    print("=== DEPCOMM: Graph Summarization & Community Analysis ===")

    # 1. Parse logs
    parser = LogParser()
    print(f"[Engine] Ingesting logs from: {LOG_FILE}")
    parser.ingest(LOG_FILE)
    if not parser.nodes:
        sys.exit("No nodes found via LogParser.")

    # 2. Build the graph and run the DEPCOMM core pipeline
    algo = DepCommAlgorithm()
    algo.build_graph(parser.nodes, parser.edges)

    # Core pipeline: representation learning, FCM overlapping clustering,
    # graph compression, InfoPath extraction
    final_nodes, final_edges, communities_data = algo.run_pipeline()

    # 3. Group data and extract alerts
    # Note: an `infopaths` field is added here to support the UI
    comm_groups = defaultdict(lambda: {"nodes": [], "edges": [], "threat_count": 0, "infopaths": []})
    node_comm_map = defaultdict(list)

    # List used to store the detailed alert text
    alert_logs = []
    alert_logs.append(f"=== Security Alerts Report ===")
    alert_logs.append(f"Source: {LOG_FILE}")
    alert_logs.append(f"Total Nodes Processed: {len(final_nodes)}\n")

    print(f"\n[Alerts] Processing {len(final_nodes)} nodes for threats & styling...")

    for n in final_nodes:
        nid = str(n.get('id', ''))
        raw_group = n.get('group', 'proc')
        extra = n.get('extra', {})

        # Get all community IDs this node belongs to (overlapping nodes can have several)
        cids = extra.get('community_ids', [0])
        hits = extra.get('attck_hits', [])

        # --- Styling logic ---
        # 1. Network nodes
        is_network = (raw_group == 'net') or nid.startswith('n_') or nid.startswith('net_') or ':' in n['label']
        if is_network:
            n['color'] = STYLE_NET
            n['shape'] = 'diamond'
            n['font'] = {'color': 'white'}
            if 'attck_hits' in extra:
                del extra['attck_hits']  # network nodes are usually not flagged as attack sources, to avoid false positives

        # 2. Threat nodes (the main focus)
        elif hits:
            n['color'] = STYLE_THREAT
            n['shape'] = 'dot'
            n['font'] = {'color': 'white'}

            # --- Detailed printing and logging ---
            cmd_detail = extra.get('cmd', 'N/A')
            fullpath = extra.get('fullpath', 'N/A')

            for hit in hits:
                # When logging an alert, list every community it touches
                cids_str = ",".join(map(str, cids))
                log_header = f"[Community #{cids_str}] 🚨 {hit['tag']} - {hit['reason']}"
                log_body = f"    Node: {n['label'].splitlines()[0]} ({nid})"
                log_cmd = f"    Command/Path: {cmd_detail if raw_group == 'proc' else fullpath}"

                print(log_header)
                print(log_cmd)

                alert_logs.append(log_header)
                alert_logs.append(log_body)
                alert_logs.append(log_cmd)
                alert_logs.append("-" * 60)

            # Update the node label so the tags show up in the UI
            tags = list(set([h['tag'] for h in hits]))
            if '🚨' not in n['label']:
                n['label'] = f"🚨 {n['label']}\n[{','.join(tags)}]"

        # 3. File nodes
        elif raw_group == 'file':
            n['color'] = STYLE_FILE
            n['shape'] = 'box'
            n['font'] = {'color': 'black'}

        # 4. Normal process nodes
        else:
            n['font'] = {'color': 'white'}
            n['shape'] = 'dot'
            # Color is taken from its primary community (first in the list)
            primary_cid = cids[0]
            try:
                c_idx = int(primary_cid)
                col = COMMUNITY_COLORS[c_idx % len(COMMUNITY_COLORS)]
                n['color'] = {'background': col, 'border': col}
            except:
                n['color'] = {'background': '#2196f3', 'border': '#2196f3'}

        # Strip extra fields to reduce JSON size
        if 'group' in n:
            del n['group']

        # Core DEPCOMM behavior: replication.
        # Push this node into every community container it belongs to.
        for cid in cids:
            cid_str = str(cid)
            if hits:
                comm_groups[cid_str]['threat_count'] += 1
            # Store into the UI data group; once serialized to JSON, the
            # shared Python object reference becomes an independent copy
            # in each community's JSON array.
            comm_groups[cid_str]['nodes'].append(n)
            node_comm_map[nid].append(cid_str)

    # 4. Edge assignment logic (keep only edges internal to a single community)
    for e in final_edges:
        src = e['from']
        dst = e['to']
        src_cids = node_comm_map.get(src, [])
        dst_cids = node_comm_map.get(dst, [])

        # Find communities shared by both endpoints of the edge
        shared_cids = set(src_cids).intersection(set(dst_cids))
        for cid in shared_cids:
            comm_groups[cid]['edges'].append(e)

    # 5. Attach InfoPaths to the frontend data
    for cid, data in communities_data.items():
        cid_str = str(cid)
        if cid_str in comm_groups:
            # Only pass the node-ID path to keep the payload small
            comm_groups[cid_str]['infopaths'] = [
                {"score": round(score, 4), "path": path} for score, path in data.get('infopaths', [])
            ]

    # 6. Save the HTML report
    out_json = json.dumps(comm_groups, ensure_ascii=False)
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE.replace('__COMMUNITIES_JSON__', out_json))

    # 7. Save the TXT alert details
    if len(alert_logs) > 3:  # more than just the header
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(alert_logs))
        print(f"\n[Done] 🚨 Detailed alerts saved to: {OUTPUT_TXT}")
    else:
        print("\n[Done] No threats detected via MITRE mapping.")

    print(f"[Done] Interactive DEPCOMM summary graph saved to: {OUTPUT_HTML}")
