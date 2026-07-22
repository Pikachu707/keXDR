# keXDR Ground-Truth Campaign Dossier (A1–A15)

**Sources reconciled in this document:**
1. `attack_scenario.pdf` — raw SIEM/eBPF provenance-graph screenshots (audit-06/07/10/12/14/17/18/21/23.json)
2. `keXDR` — *"Kernel Native Host-Network Collaboration Attack Provenance Solution"* (NDSS 2027 submission), Table I(B), Table IIA, Table IV, Fig. 5, Fig. 6
3. Public vulnerability advisories and vendor threat-intel reports (current as of 2026-07-22)

This README is the single cross-reference point: for each of the 15
confirmed campaigns (A1–A15), it shows which raw audit file backs it, what
the paper reports about it, and which public reference(s) independently
corroborate the CVE/malware family.

---

## How to read this table

| Column | Meaning |
|---|---|
| **A-ID** | Campaign ID from paper Table I(B)/Table IV |
| **CVE / Threat Family** | As labeled in the paper |
| **Raw SIEM File** | Audit JSON file in `attack_scenario.pdf` that contains the forensic evidence |
| **Screenshot Evidence** | What was actually visible in the raw provenance-graph screenshot |
| **AV Split (E/N)** | Endpoint vs. Network share of the kill-chain (paper Table IB) |
| **K-Full Precision** | keXDR's local window detection precision with LLM (paper Table IB) |
| **Ref.** | Citation number(s) — see **References** section below |

---

## Master Table (A1–A15)

| A-ID | CVE / Threat Family | Raw SIEM File | Screenshot Evidence | AV (E/N) | K-Full | Ref. |
|---|---|---|---|---|---|---|
| **A1** | CVE-2017-5645 (LOG4J) | `audit-17.json` (2026-01-13) | IOC `178.16.52(.)208`, domain `rootcanary(.)com` | 30%/70% | 1.00 | [1]–[3] |
| **A2** | CVE-2024-4110 (DOCKER) | `audit-06.json` (2026-01-14) | `portainer`/`sh` stealth-chain node, IOC `45.59.101(.)178` | 10%/90% | 0.99 | [4]–[6] |
| **A3** | CVE-2025-54068 (LIVEWIRE) | `audit-07.json` (2026-01-14) | IOC `178.128.242(.)134`, tagged "MirAI malware" | 20%/80% | 0.98 | [7]–[9] |
| **A4** | CVE-2025-55182 (NEXTJS) | `audit-18.json` (2026-01-14) | Command line captured verbatim: `/bin/chmod 777 logicdr.sh`; IOC `193.142.147(.)209` | 85%/15% | 1.00 | [10]–[13] |
| **A5** | Condi/Orbit Botnet | `audit-10.json` (2026-01-15), parts 00–07 | Repeated `dropbear` spawns; Stealth-C2 IOCs `83.168.105(.)129`, `15.184.16(.)243`, `91.108.9(.)49`, `162.19.37(.)118`, `171.225.223(.)29`, `191.96.229(.)137`, `96.30.193(.)133`, `46.205.203(.)114`, `83.168.94(.)237` | 15%/85% | 1.00 | [14]–[16] |
| **A6** | CoinMiner Campaign (wgOh1s3 & lrt → poop[.]me) | `audit-10.json`, "CoinMiner" + "Possible botnet Activities" segments | Same file as A5 — reflects the wgOh1s3 pivot in paper Fig. 6 (Condi dropper → wgOh1s3 hub → lrt cryptominer) | 70%/30% | 0.99 | [15] |
| **A7** | CVE-2025-55182 (NEXTJS) | `audit-12.json` (2026-01-16) | Command line captured verbatim: `/usr/bin/chmod +x [script].sh`; PID 2248793 | 75%/25% | 1.00 | [11], [12], [13] |
| **A8** | CoinMiner Variant (dab593mn & lrt → api.snavpcraft[.]io) | `audit-14.json` (2026-01-18) | "Stealth C2/Hidden C2 Sink" node, IOC `85.234.131(.)209`; `portainer` process chain | 85%/15% | 0.98 | [17], [18] |
| **A9** | CVE-2024-4110 (DOCKER) | `audit-14.json` (2026-01-18) — same file as A8, captioned "Docker and CoinMiner Variant" | Docker exploitation chain preceding the coinminer drop; paper groups A6–A8 as "Mixed RCE & CoinMiner" (Table IIA) | 10%/90% | 1.00 | [4]–[6] |
| **A10** | CVE-2026-24061 (TELNETD) | `audit-23.json` (2026-02-04) | Large starburst fan-out from single telnetd-exploited host; crontab-based persistence | 40%/60% | 0.99 | [19]–[22] |
| **A11** | CVE-2026-24061 (TELNETD) | `audit-12.json` (2026-02-05) | Second starburst graph, red Shellcode(RWX) edge, consistent with xmrig hand-off | 80%/20% | 0.99 | [19], [21], [23] |
| **A12** | CVE-2023-46604 (ACTIVEMQ) | `audit-21.json` (2026-02-13) | Root of the ActiveMQ graph; `C1 CompilerThread` and `softirq` nodes visible in same file | 95%/5% | 1.00 | [24], [25] |
| **A13** | CVE-2023-46604 (ACTIVEMQ) | `audit-21.json` — same file as A12/A14/A15 | `rondo`/`rando`-named process branch, `ptrace` target PIDs 459/461 (T1055.008) | 95%/5% | 1.00 | [26], [27] |
| **A14** | CVE-2023-46604 (ACTIVEMQ) | `audit-21.json` | Node explicitly labeled `C1 CompilerThread`, red Shellcode(RWX) edge — the fileless case named in Section IV-B1 | 98%/2% | 0.98 | [28] |
| **A15** | CVE-2023-46604 (ACTIVEMQ) | `audit-21.json` | Node explicitly labeled `softirq`, RWX shellcode edge — also named in Section IV-B1 | 97%/3% | 0.99 | [28], [29] |

---

## Paper Table IIA grouping cross-check

| Paper Group | A-IDs | Raw Audit File(s) |
|---|---|---|
| Mixed Container RCE & Botnet | A1–A4 | `audit-17.json`, `audit-06.json`, `audit-07.json`, `audit-18.json` |
| Condi/Orbit Botnet | A5 | `audit-10.json` |
| Mixed RCE & CoinMiner | A6–A8 | `audit-10.json` (CoinMiner segment), `audit-14.json` |
| CVE-2024-4110 (Docker) | A9 | `audit-14.json` |
| Telnetd RCE | A10–A11 | `audit-23.json`, `audit-12.json` (02-05) |
| ActiveMQ Fileless | A12–A15 | `audit-21.json` |


---

## References

**CVE-2017-5645 (Apache Log4j Socket-Server Deserialization) — A1**
1. pimps, "CVE-2017-5645 — Apache Log4j RCE due to Insecure Deserialization," GitHub advisory, 2017-04-17. https://github.com/pimps/CVE-2017-5645/blob/master/log4j%20advisory.txt
2. Red Hat, "RHSA-2017:1801 — rh-java-common-log4j security update," Red Hat Customer Portal, 2017. https://access.redhat.com/errata/RHSA-2017:1801
3. Palo Alto Networks Unit 42, "Another Apache Log4j Vulnerability Is Actively Exploited in the Wild (CVE-2021-44228) (Updated)," 2024. https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/

**CVE-2024-4110 / CVE-2024-41110 (Docker) — A2, A9**
4. Akamai, "Off Your Docker: Exposed APIs Are Targeted in New Malware Strain," Akamai Security Research Blog, 2025. https://www.akamai.com/blog/security-research/new-malware-targeting-docker-apis-akamai-hunt
5. BleepingComputer, "Exposed Docker APIs Continue to Be Used for Cryptojacking," 2018. https://www.bleepingcomputer.com/news/security/exposed-docker-apis-continue-to-be-used-for-cryptojacking/
6. SecurityWeek, "Exposed Docker APIs Likely Exploited to Build Botnet," 2025. https://www.securityweek.com/exposed-docker-apis-likely-exploited-to-build-botnet/

**CVE-2025-54068 (Livewire RCE) + Mirai — A3**
7. GitHub Security Advisory, "Livewire is vulnerable to remote command execution during component property update hydration," GHSA-29cq-5w36-x7w3, 2025-07-17 (updated 2025-11-10). https://github.com/advisories/GHSA-29cq-5w36-x7w3
8. Synacktiv, "Livewire: remote command execution through unmarshaling," Synacktiv Publications, 2025. https://www.synacktiv.com/en/publications/livewire-remote-command-execution-through-unmarshaling
9. JoeSandboxCloud, "Mirai malware," analysis report, 2026. https://www.joesandbox.com/analysis/1849501/0/html

**CVE-2025-55182 / CVE-2025-66478 (React Server Components "React2Shell", Next.js) — A4, A7**
10. React, "Critical Security Vulnerability in React Server Components," React.dev Blog, 2025-12-03. https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
11. Google Cloud Threat Intelligence Group, "Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)," Google Cloud Blog, 2025-12-13. https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182
12. Microsoft Threat Intelligence, "Defending against the CVE-2025-55182 (React2Shell) vulnerability in React Server Components," Microsoft Security Blog, 2026-04-08. https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/
13. Palo Alto Networks Unit 42, "Exploitation of Critical Vulnerability in React Server Components (Updated December 12)," 2026-02-19. https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/

**Condi/Orbit Botnet + CoinMiner (wgOh1s3 pivot) — A5, A6**
14. Fortinet FortiGuard Labs, "Condi DDoS Botnet Spreads via TP-Link's CVE-2023-1389," 2023-06-20. https://www.fortinet.com/blog/threat-research/condi-ddos-botnet-spreads-via-tp-links-cve-2023-1389
15. Eclypsium, "Eclypsium Discovers Two New Malware Variants Targeting Network Infrastructure," 2026-03-16. https://eclypsium.com/blog/condibot-monaco-malware-network-infrastructure/
16. SANS Internet Storm Center, "CVE-2023-1389: A New Means to Expand Botnets," ISC Diary. https://isc.sans.edu/diary/30418

**CoinMiner Variant — A8**
17. Trend Micro, "Compromised Docker Hub Accounts Abused for Cryptomining Linked to TeamTNT," Trend Micro Research, 2021-11-09. https://www.trendmicro.com/en_us/research/21/k/compromised-docker-hub-accounts-abused-for-cryptomining-linked-t.html
18. securityonline.info, "Beyond Cryptominers: A New Malware Strain Is Hijacking Exposed Docker APIs," 2025-09-10. https://securityonline.info/beyond-cryptominers-a-new-malware-strain-is-hijacking-exposed-docker-apis/

**CVE-2026-24061 (GNU InetUtils telnetd Authentication Bypass) — A10, A11**
19. Offsec, "CVE-2026-24061 – GNU InetUtils telnetd Authentication Bypass Vulnerability," 2026-02-06. https://www.offsec.com/blog/cve-2026-24061/
20. SafeBreach, "Root Cause Analysis & PoC Exploit for CVE-2026-24061," SafeBreach Labs, 2026-02-19. https://www.safebreach.com/blog/safebreach-labs-root-cause-analysis-and-poc-exploit-for-cve-2026-24061/
21. Canadian Centre for Cyber Security, "AL26-002 — Vulnerability affecting GNU Inetutils Telnetd — CVE-2026-24061," 2026-01-22. https://www.cyber.gc.ca/en/alerts-advisories/al26-002-vulnerability-affecting-gnu-inetutils-telnetd-cve-2026-24061
22. Picus Security, "CVE-2026-24061: Critical Telnetd Flaw Grants Root Access," Picus Threat Library, 2026-03-03. https://www.picussecurity.com/resource/blog/cve-2026-24061-critical-telnetd-flaw-grants-root-access
23. TXOne Networks, "Root via Telnet: Active Exploitation of CVE-2026-24061 (GNU inetutils)," 2026-01-26. https://www.txone.com/blog/cve-2026-24061-gnu-inetutils-telnet-exploitation/

**CVE-2023-46604 (Apache ActiveMQ OpenWire Deserialization RCE) — A12–A15**
24. Rapid7, "Suspected Exploitation of Apache ActiveMQ CVE-2023-46604," Rapid7 Blog, 2023-11-01. https://www.rapid7.com/blog/post/2023/11/01/etr-suspected-exploitation-of-apache-activemq-cve-2023-46604/
25. Greenbone, "CVE-2023-46604: Apache ActiveMQ Actively Exploited For RCE," Greenbone Community Blog, 2023-12-18. https://community.greenbone.net/blog/cve-2023-46604-apache-activemq-actively-exploited-for-rce/
26. Arctic Wolf, "Exploitation of CVE-2023-46604 Leading to Ransomware," Arctic Wolf Labs, 2025-01-15. https://arcticwolf.com/resources/blog/tellmethetruth-exploitation-of-cve-2023-46604-leading-to-ransomware/
27. Cybereason, "Beware of the Messengers, Exploiting ActiveMQ Vulnerability," Cybereason Blog. https://www.cybereason.com/blog/beware-of-the-messengers-exploiting-activemq-vulnerability
28. Trend Micro, "CVE-2023-46604 (Apache ActiveMQ) Vulnerability Exploited to Infect Systems With Cryptominers and Rootkits," Trend Micro Research, 2023-11-20. https://www.trendmicro.com/en_us/research/23/k/cve-2023-46604-exploited-by-kinsing.html
29. SonicWall, "Apache ActiveMQ Remote Code Execution (CVE_2023_46604)," SonicWall Capture Labs Threat Research. https://www.sonicwall.com/blog/apache-activemq-remote-code-execution-cve_2023_46604
