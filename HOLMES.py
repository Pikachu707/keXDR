#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import re
import glob
import shlex
import networkx as nx

# ============================================================================
# 1. Full UI Template (dedicated HOLMES HSG display)
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HOLMES: High-level Scenario Graph (HSG)</title>
    <script src="https://cdn.staticfile.org/vis-network/9.1.2/dist/vis-network.min.js"></script>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; overflow: hidden; display: flex; height: 100vh; }
        #sidebar-left { width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; z-index: 20; box-shadow: 4px 0 15px rgba(0,0,0,0.5); }
        .sidebar-header { padding: 15px; background: #21262d; border-bottom: 1px solid #30363d; }
        .app-title { font-size: 18px; font-weight: bold; color: #58a6ff; margin-bottom: 5px; }
        .app-subtitle { font-size: 11px; color: #8b949e; }
        #hsg-list-container { flex: 1; overflow-y: auto; padding: 10px; }
        .hsg-item { padding: 10px; margin-bottom: 8px; border-radius: 6px; background: #21262d; border: 1px solid #30363d; cursor: pointer; transition: all 0.2s; }
        .hsg-item:hover { background: #30363d; border-color: #58a6ff; }
        .hsg-item.active { background: rgba(88, 166, 255, 0.15); border-color: #58a6ff; }
        .hsg-title { font-size: 13px; font-weight: 600; color: #c9d1d9; }
        .hsg-meta { font-size: 11px; color: #8b949e; margin-top: 5px; display: flex; justify-content: space-between;}
        .badge { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; background: #da3633; color: white;}
        #main-area { flex: 1; position: relative; background: #0d1117; }
        #mynetwork { width: 100%; height: 100%; }
        .controls { position: absolute; top: 15px; right: 20px; z-index: 10; display: flex; gap: 10px; }
        .btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; cursor: pointer; border-radius: 6px; font-size: 12px; font-weight: 600; transition: all 0.2s; }
        .btn:hover { background: #30363d; color: #58a6ff; border-color: #58a6ff; }
        .legend { position: absolute; bottom: 20px; right: 20px; background: rgba(22, 27, 34, 0.95); padding: 12px; border-radius: 6px; border: 1px solid #30363d; pointer-events: none; display: flex; flex-direction: column; gap: 8px; }
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
        .field-label { font-size: 10px; color: #8b949e; margin-top: 15px; font-weight: bold; text-transform: uppercase; }
        .field-value { font-family: 'Consolas', monospace; font-size: 12px; color: #c9d1d9; background: #0d1117; padding: 8px; border: 1px solid #30363d; border-radius: 4px; word-break: break-all; margin-top: 4px; white-space: pre-wrap; }
        .attck-box { background: rgba(218, 54, 51, 0.1); border: 1px solid #da3633; padding: 10px; margin-bottom: 15px; border-radius: 6px; }
        .attck-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }
        .attck-id { background: #da3633; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .attck-desc { font-size: 13px; color: #ffaeb6; font-weight: 600; }
        .attck-phase { font-size: 10px; color: #8b949e; margin-top: 4px; font-style: italic; }
    </style>
</head>
<body>
<div id="sidebar-left">
    <div class="sidebar-header">
        <div class="app-title">HOLMES</div>
        <div class="app-subtitle">High-level Scenario Graphs (HSG)</div>
    </div>
    <div id="hsg-list-container"></div>
</div>
<div id="main-area">
    <div class="controls">
        <button class="btn" onclick="fitGraph()">🔍 Fit Graph</button>
    </div>
    <div id="mynetwork"></div>
    <div class="legend">
        <div class="l-item"><div class="shape poi"></div><strong>TTP Node (Threat)</strong></div>
        <div class="l-item"><div class="shape proc"></div><strong>Process (Info Flow)</strong></div>
        <div class="l-item"><div class="shape file"></div><strong>File (Info Flow)</strong></div>
        <div class="l-item"><div class="shape net"></div><strong>Network (Info Flow)</strong></div>
    </div>
</div>
<div id="detail-panel">
    <div class="close-btn" onclick="closeDetail()">×</div>
    <div class="detail-content" id="detail-content"></div>
</div>
<script type="text/javascript">
    var all_hsgs = __HSG_JSON__;
    var network = null;
    var container = document.getElementById('mynetwork');
    var options = {
        nodes: { font: { color: 'black', size: 14, face: 'Segoe UI' }, borderWidth: 2 },
        edges: { arrows: 'to', smooth: false, color: { color: '#30363d', opacity: 0.8 } },
        physics: { enabled: true, solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -50, springLength: 100 } }
    };

    function init() {
        var listContainer = document.getElementById('hsg-list-container');
        if (all_hsgs.length === 0) {
            listContainer.innerHTML = '<div style="padding:15px; color:#8b949e; text-align:center;">No APT Alerts (Graph Pruned)</div>';
            return;
        }
        all_hsgs.sort((a,b) => b.score - a.score); 

        all_hsgs.forEach((hsg, idx) => {
            var div = document.createElement('div');
            div.className = 'hsg-item';
            div.id = 'hsg-btn-' + idx;
            div.onclick = function() { loadHSG(idx); };
            var tacticsHTML = hsg.tactics.map(t => `<div style="font-size:10px; color:#8b949e;">- ${t}</div>`).join('');
            div.innerHTML = `
                <div class="hsg-title">HSG Alert #${idx+1}</div>
                <div class="hsg-meta"><span>Severity Score:</span><span class="badge">${hsg.score}</span></div>
                <div style="margin-top:8px;">${tacticsHTML}</div>
            `;
            listContainer.appendChild(div);
        });
        loadHSG(0);
    }

    function loadHSG(idx) {
        document.querySelectorAll('.hsg-item').forEach(el => el.classList.remove('active'));
        document.getElementById('hsg-btn-' + idx).classList.add('active');
        var hsg = all_hsgs[idx];
        if(network) { network.destroy(); }
        network = new vis.Network(container, { nodes: new vis.DataSet(hsg.nodes), edges: new vis.DataSet(hsg.edges) }, options);
        network.on("click", function (params) {
            if (params.nodes.length > 0) { showDetail(hsg.nodes.find(n => n.id === params.nodes[0])); } 
            else { closeDetail(); }
        });
    }

    function fitGraph() { if(network) network.fit({animation: {duration: 500}}); }

    function showDetail(node) {
        if(!node) return;
        var html = '<h2>' + node.label.split("\\n")[0] + '</h2>';
        var extra = node.extra || {};
        var attacks = extra.attck_hits || [];
        if (attacks.length > 0) {
             html += '<div class="field-label">Threat Detection</div>';
             attacks.forEach(hit => { 
                 html += `<div class="attck-box">
                            <div class="attck-header"><span class="attck-id">${hit.tag}</span></div>
                            <div class="attck-desc">${hit.reason}</div>
                            <div class="attck-phase">Kill Chain Phase: ${hit.tactic}</div>
                          </div>`;
             });
        }
        if (extra.cmd) { html += '<div class="field-label">Command Line</div><div class="field-value" style="color:#58a6ff">' + extra.cmd + '</div>'; }
        for (var key in extra) {
            if (['attck_hits', 'cmd', 'label'].indexOf(key) === -1) {
                html += '<div class="field-label">' + key.toUpperCase() + '</div><div class="field-value">' + extra[key] + '</div>';
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
# 2. MITRE ATT&CK Mapper (English Only)
# ============================================================================
class AttckMapper:
    def __init__(self):

        # Core HOLMES mechanism: each kill-chain phase (Tactic) carries a
        # different severity weight
        self.tactic_weights = {
            'Initial Access': 3,
            'Execution': 1,
            'Privilege Escalation': 3,
            'Defense Evasion': 2,
            'Credential Access': 3,
            'Discovery': 1,
            'Lateral Movement': 3,
            'Collection': 2,
            'Command and Control': 3,
            'Impact': 3,
            'Resource Development': 1,
            'Reconnaissance': 1
        }

        # State-machine precondition index:
        # Phase 1-2 are entry/foundational stages; Phase 3-5 are advanced
        # stages that must have a causally-active upstream node to fire.
        self.tactic_phases = {
            'Reconnaissance': 1, 'Resource Development': 1,
            'Initial Access': 1,
            'Execution': 2, 'Persistence': 2, 'Privilege Escalation': 2, 'Defense Evasion': 2,
            'Credential Access': 3, 'Discovery': 3, 'Lateral Movement': 3,
            'Collection': 4, 'Command and Control': 4,
            'Exfiltration': 5, 'Impact': 5
        }

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
        if node.get('group') == 'net' or str(node.get('id', '')).startswith('n_'):
            return []

        matches = []
        extra = node.get('extra', {})
        cmd_full = str(extra.get('cmd', '')).strip()

        # Hard-coded detection for RWE memory injection
        if extra.get('risk_mmap'):
            if 'WRITE' in extra['risk_mmap'] and 'EXEC' in extra['risk_mmap']:
                matches.append({'tag': "T1055", 'tactic': 'Privilege Escalation', 'reason': "Process Injection (W+X)"})

        try:
            argv = shlex.split(cmd_full)
        except:
            argv = cmd_full.split()

        if not argv:
            return matches

        binary_name = os.path.basename(argv[0])
        args_str = " ".join(argv[1:])

        for r in self.rules:
            if r.get('cmd') and not r['cmd'].search(binary_name):
                continue
            if r.get('pattern') and (r['pattern'].search(args_str) or r['pattern'].search(cmd_full)):
                if not any(m['tag'] == r['id'] for m in matches):
                    # Read r['phase'] and r['desc'] from the rule, but always
                    # export as 'tactic' / 'reason' to match the HOLMES engine's schema
                    matches.append({
                        'tag': r['id'],
                        'tactic': r['phase'],
                        'reason': r['desc']
                    })

        return matches


# ============================================================================
# 3. HOLMES Core Algorithm (HSG & Severity Scoring)
# ============================================================================
class HolmesAlgorithm:
    def __init__(self, severity_threshold=5.0):
        print("[HOLMES Engine] Initializing State Machine & HSG Builder...")
        self.mapper = AttckMapper()
        self.G = nx.DiGraph()
        self.severity_threshold = severity_threshold

    def build_graph(self, raw_nodes, raw_edges):
        self.G.clear()
        for n in raw_nodes:
            self.G.add_node(n['id'], label=n['label'], type=n['group'], raw_data=n)
        for e in raw_edges:
            self.G.add_edge(e['from'], e['to'], label=e['label'])
        print(f"[Graph] Base Provenance Graph built: {self.G.number_of_nodes()} nodes.")

    def run_hsg_pipeline(self):
        poi_nodes = []
        for nid in self.G.nodes:
            raw_node = self.G.nodes[nid]['raw_data']
            hits = self.mapper.check_node(raw_node)
            if hits:
                poi_nodes.append(nid)
                raw_node['extra']['attck_hits'] = hits
                self.G.nodes[nid]['is_poi'] = True
            else:
                self.G.nodes[nid]['is_poi'] = False

        # ---------------------------------------------------------------------
        # Core fix 1: extract the full causal-information-flow subgraph
        # (Full Provenance Subgraph)
        # ---------------------------------------------------------------------
        # Precompute the global descendants/ancestors of every POI, which
        # greatly speeds up extraction of the full subgraph.
        descendants_map = {p: nx.descendants(self.G, p) for p in poi_nodes}
        ancestors_map = {p: nx.ancestors(self.G, p) for p in poi_nodes}

        # Build a directed reachability graph between POIs
        poi_reachability = nx.DiGraph()
        poi_reachability.add_nodes_from(poi_nodes)

        for u in poi_nodes:
            for v in poi_nodes:
                if u != v and v in descendants_map[u]:
                    poi_reachability.add_edge(u, v)

        hsgs_raw = []
        # Group causally-connected POIs into a single "campaign"
        # (weakly connected component)
        poi_components = list(nx.weakly_connected_components(poi_reachability))

        for comp in poi_components:
            comp_pois = list(comp)
            hsg_nodes = set(comp_pois)

            # Get every path node between any two causally-linked POIs
            # (avoids the lossy shortest_path approach).
            # Rationale: in a directed graph, all path nodes from A to B equal
            # the intersection of A's descendants and B's ancestors.
            for i in range(len(comp_pois)):
                for j in range(len(comp_pois)):
                    if i != j and poi_reachability.has_edge(comp_pois[i], comp_pois[j]):
                        u, v = comp_pois[i], comp_pois[j]
                        path_nodes = descendants_map[u].intersection(ancestors_map[v])
                        hsg_nodes.update(path_nodes)

            if len(hsg_nodes) > 1:
                hsgs_raw.append(self.G.subgraph(list(hsg_nodes)).copy())

        # ---------------------------------------------------------------------
        # Core fix 2: strict kill-chain state-machine transitions
        # ---------------------------------------------------------------------
        final_hsgs = []
        STYLE_NET = {'background': '#238636', 'border': '#238636'}
        STYLE_THREAT = {'background': '#da3633', 'border': '#f85149'}
        STYLE_PROC = {'background': '#2196f3', 'border': '#2196f3'}
        STYLE_FILE = {'background': '#d29922', 'border': '#d29922'}

        for hsg in hsgs_raw:
            hsg_pois = [n for n in hsg.nodes if self.G.nodes[n].get('is_poi')]
            hsg_reach = poi_reachability.subgraph(hsg_pois)

            # Use a topological sort so the state machine advances in the
            # direction of temporal causality
            try:
                topo_order = list(nx.topological_sort(hsg_reach))
            except nx.NetworkXUnfeasible:
                topo_order = hsg_pois  # rare cycle-fallback path

            active_tactics = set()
            node_is_active = {n: False for n in hsg_pois}

            for poi in topo_order:
                node_data = hsg.nodes[poi]['raw_data']
                hits = node_data.get('extra', {}).get('attck_hits', [])

                # Check the causal precondition: does this node have an
                # already-active upstream node in the graph topology?
                upstream_pois = [u for u in hsg_pois if hsg_reach.has_edge(u, poi)]
                has_active_upstream = any(node_is_active[u] for u in upstream_pois)

                for hit in hits:
                    tactic = hit['tactic']
                    phase = self.mapper.tactic_phases.get(tactic, 5)

                    # Strict state-machine check:
                    # Directly allow activation for Phase <= 2 foundational
                    # intrusion actions (Initial Access, Execution, PrivEsc, etc.)
                    # Require causal-chain support for Phase >= 3 advanced
                    # actions (Lateral Movement, C2, Exfiltration). If the
                    # prerequisite intrusion hasn't been confirmed, treat the
                    # action as benign and discard it.
                    if phase <= 2 or has_active_upstream:
                        node_is_active[poi] = True
                        active_tactics.add(tactic)

            # Important: only tactics that passed the state-machine
            # precondition check and were "legitimately activated" count
            # toward the total score
            score = sum(self.mapper.tactic_weights.get(t, 1) for t in active_tactics)

            # Anything below the severity threshold is treated as benign
            # noise and pruned outright
            if score < self.severity_threshold:
                continue

            # --- The rendering/export logic below is unchanged ---
            hsg_export_nodes = []
            for nid in hsg.nodes:
                n = hsg.nodes[nid]['raw_data'].copy()
                raw_group = n.get('group', 'proc')
                is_net = (raw_group == 'net') or str(nid).startswith('n_')

                if is_net:
                    n['color'], n['shape'], n['font'] = STYLE_NET, 'diamond', {'color': 'white'}
                elif n.get('extra', {}).get('attck_hits'):
                    n['color'], n['shape'], n['font'] = STYLE_THREAT, 'dot', {'color': 'white'}
                    tags = list(set([h['tag'] for h in n['extra']['attck_hits']]))
                    if '🚨' not in n['label']: n['label'] = f"🚨 {n['label']}\n[{','.join(tags)}]"
                else:
                    if raw_group == 'file':
                        n['color'], n['shape'], n['font'] = STYLE_FILE, 'box', {'color': 'black'}
                    else:
                        n['color'], n['shape'], n['font'] = STYLE_PROC, 'dot', {'color': 'white'}

                if 'group' in n: del n['group']
                hsg_export_nodes.append(n)

            hsg_export_edges = [{'from': u, 'to': v, 'label': d['label']} for u, v, d in hsg.edges(data=True)]

            final_hsgs.append({
                'score': score,
                'tactics': list(active_tactics),  # only show legitimately activated tactics
                'nodes': hsg_export_nodes,
                'edges': hsg_export_edges
            })

        print(
            f"[HOLMES] Pruning complete. {len(final_hsgs)} HSGs exceeded severity threshold ({self.severity_threshold}).")
        return final_hsgs


# ============================================================================
# 4. Log Parser (Updated with Robust Network Logic)
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
            try:
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
            except Exception as e:
                print(f"[-] Error reading {path}: {e}")

    def _add_node(self, nid, label, group, extra=None):
        if nid not in self._seen_nodes:
            self.nodes.append({
                'id': nid, 'label': label, 'group': group, 'extra': extra or {}
            })
            self._seen_nodes.add(nid)

    def _add_edge(self, src, dst, label):
        eid = f"{src}->{dst}:{label}"
        if eid not in self._seen_edges:
            self.edges.append({'from': src, 'to': dst, 'label': label})
            self._seen_edges.add(eid)

    def _proc(self, ev):
        # Accepts both SYSCALL and Network-style events
        etype = ev.get('type')
        # Added SOCKADDR to capture more low-level network structures
        if etype not in ['SYSCALL', 'NETWORK', 'SOCKET', 'EXECVE', 'SOCKADDR']:
            return

        pid = ev.get('pid')
        ppid = ev.get('ppid')
        subtype = ev.get('subtype', '')

        if not pid:
            return

        # Build the process ID
        proc_id = f"p_{pid}"

        # Extract key fields
        binary = ev.get('cmd') or ev.get('comm', 'unknown')
        args = ev.get('args', '')
        if isinstance(args, list):
            args = " ".join([str(x) for x in args])
        commandline = f"{binary} {args}".strip()
        comm = ev.get('comm', '')

        risk_mmap = ev.get('risk_mmap')
        ptrace_req = ev.get('ptrace_request')

        # 1. Make sure the process node exists
        self._add_node(proc_id, f"{comm}\n{pid}", 'proc', {
            'cmd': commandline,
            'image': binary,
            'cgroup': ev.get('cgroup_id'),
            'risk_mmap': risk_mmap,
            'ptrace_req': ptrace_req
        })

        if ppid and str(ppid) != "0":
            p_id = f"p_{ppid}"
            self._add_node(p_id, f"PID {ppid}", 'proc', {'cmd': f"Process {ppid}"})
            self._add_edge(p_id, proc_id, 'spawn')

        # 2. Auxiliary relation: file operations
        if subtype in ['OPEN', 'CREAT'] and ev.get('filename'):
            fname = ev.get('filename')
            fid = f"f_{fname}_{pid}"  # simple file-ID generation
            self._add_node(fid, fname.split('/')[-1], 'file', {'fullpath': fname})
            self._add_edge(proc_id, fid, 'open')

        # ====================================================================
        # Network-node association logic (mirrors the TR-PCI script's approach)
        # ====================================================================
        # Try multiple fields to obtain the IP; no longer strictly requires subtype == CONNECT
        remote_ip = ev.get('dst_ip') or ev.get('dip') or ev.get('daddr') or ev.get('remote_ip')
        remote_port = ev.get('dport') or ev.get('sport')

        # Filter out loopback and invalid IPs
        if remote_ip and remote_ip not in ['0.0.0.0', '127.0.0.1', '::1', '::', '']:
            port_str = str(remote_port) if remote_port else "0"
            net_id = f"n_{remote_ip}_{port_str}"

            # Create the network node
            self._add_node(net_id, f"{remote_ip}:{port_str}", 'net', {
                'ip': remote_ip,
                'port': port_str,
                'proto': ev.get('l4_proto') or ev.get('fam', 'tcp')
            })

            # Smart edge-label inference
            edge_label = 'traffic'
            if subtype and subtype not in ['unknown', '']:
                edge_label = subtype.lower()
            elif 'bind' in commandline or 'listen' in commandline:
                edge_label = 'bind'
            else:
                edge_label = 'connect'  # default assumption: outbound connection

            self._add_edge(proc_id, net_id, edge_label)

        # 3. Auxiliary relation: MEMFD (fileless execution)
        if subtype == 'MEMFD' or 'memfd_create' in commandline:
            name = ev.get('name', 'unknown')
            mem_id = f"mem_{name}_{pid}"
            self._add_node(mem_id, f"MEM: {name}", 'memfd', {'fullpath': 'memory'})
            self._add_edge(proc_id, mem_id, 'memfd_create')


# ============================================================================
# 5. Main Execution
# ============================================================================
if __name__ == "__main__":
    LOG_FILE = "/root/ebpf/logs/2026-02-13/audit_21.json"
    OUTPUT_FILE = "holmes.html"
    ALERT_TXT_FILE = "holmes.txt"

    print("=== HOLMES: APT Detection via HSG Correlation ===")

    # 1. Parse the raw logs
    parser = LogParser()
    parser.ingest(LOG_FILE)
    if not parser.nodes:
        sys.exit("[-] No events parsed. Exiting.")

    # 2. Run the HOLMES core pipeline (includes graph pruning)
    # Severity threshold set to 5.0, meaning only combinations of multiple
    # tactics (e.g. Initial Access + C&C) will produce an alert graph
    algo = HolmesAlgorithm(severity_threshold=5.0)
    algo.build_graph(parser.nodes, parser.edges)

    final_hsgs = algo.run_hsg_pipeline()

    # 3. Emit a plain-text report
    alert_buffer = [
        "=" * 60,
        "HOLMES APT ALERT REPORT",
        f"Log Source: {LOG_FILE}",
        f"Detected {len(final_hsgs)} Critical High-level Scenario Graphs (HSG)",
        "=" * 60 + "\n"
    ]

    for idx, hsg in enumerate(final_hsgs):
        alert_buffer.append(f"🔴 [HSG Alert #{idx + 1}] Severity Score: {hsg['score']}")
        alert_buffer.append(f"   Kill Chain Phases Detected: {', '.join(hsg['tactics'])}")
        alert_buffer.append("   Threat Nodes Involved:")
        for node in hsg['nodes']:
            if node.get('extra', {}).get('attck_hits'):
                label = node['label'].split('\n')[0].replace('🚨 ', '')
                cmd = node.get('extra', {}).get('cmd', 'N/A')
                alert_buffer.append(f"      - {label} | CMD: {cmd}")
        alert_buffer.append("-" * 60 + "\n")

    with open(ALERT_TXT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(alert_buffer))
    print(f"\n[Done] Text report saved to {ALERT_TXT_FILE}")

    # 4. Generate the HTML
    out_json = json.dumps(final_hsgs, ensure_ascii=False)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE.replace('__HSG_JSON__', out_json))

    print(f"[Done] Interactive HSG Visualizer saved to {OUTPUT_FILE}")
