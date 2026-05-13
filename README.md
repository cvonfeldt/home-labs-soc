# home-lab-soc
Home lab documenting offensive and defensive security operations/techniques. Each entry covers an attack simulation and how it was detected using Sysmon and Splunk.


# Home Lab - SOC & Detection Lab

## Overview
A home lab documenting offensive and defensive security techniques using 
Sysmon and Splunk. Each entry covers an attack simulation and detection.

## Lab Setup
- **Attacker:** Kali Linux
- **Target:** Windows 10 VM
- **SIEM:** Splunk Enterprise
- **Logging:** Sysmon (SwiftOnSecurity config)
- **AD:** Windows AD Server

## Attacks & Detections
| # | Attack | Tools Used | Status |
|---|--------|------------|--------|
| 01 | Reverse TCP Shell | Kali, Metasploit, msfvenom, splunk | Complete
| 02 | RDP Brute Force & AD Attack | Crowbar, xfreerdp, Atomic Red Team, splunk | Complete
| 03 | BOTS splunk | Splunk, OSint (virustotal, threatminer, etc.) | Complete


