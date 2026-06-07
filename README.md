# Home Lab SOC & Detection Lab
Home lab documenting offensive and defensive security operations/techniques. Each entry covers an attack simulation and how it was detected using Sysmon and Splunk.


## Overview
A home lab documenting offensive and defensive security techniques using Sysmon and Splunk. Each entry covers an attack simulation, full detection methodology, process lineage analysis, and MITRE ATT&CK mapping. Each investigation includes vendor-agnostic Sigma detection rules authored from confirmed attack behavior observed during analysis.

## Lab Setup
- **Attacker:** Kali Linux
- **Target:** Windows 10 VM
- **SIEM:** Splunk Enterprise
- **Logging:** Sysmon (SwiftOnSecurity config)
- **AD:** Windows Server 2022 (mydfir.local)
- **Domain Controller:** Windows Server 2022

## Attacks & Detections
| # | Attack | Tools Used | Status |
|---|--------|------------|--------|
| 01 | Reverse TCP Shell | Kali, Metasploit, msfvenom, Splunk | Complete |
| 02 | RDP Brute Force & AD Attack | Crowbar, xfreerdp, Atomic Red Team, Splunk | Complete |


## Automation & Scripting
Attack investigations are extended with Python automation where applicable. Each script lives within its relevant attack folder and mirrors real SOC triage workflows — programmatically querying Splunk for attack events and enriching IOCs against external threat intelligence APIs.
#### See 02-rdp-brute-force/Python_Script_VT_Enrichment/ for an example that queries Splunk for RDP brute force events and automatically enriches attacker IPs against VirusTotal.

## Detection Engineering
Each investigation includes vendor-agnostic Sigma detection rules (YAML) authored from confirmed attack behavior observed during analysis. Rules target behavioral indicators rather than static IOCs, making them resilient to attacker modifications between attacks. All rules are convertible to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM using sigmac or pySigma.

## MITRE ATT&CK Coverage
Techniques identified and mapped across both investigations span Execution, Persistence, privilege scalation, defense evasion, Credential Access, Lateral Movement, and Command & Control tactics.


