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
| 01 | Reverse TCP Shell | Kali, Metasploit, msfvenom, Splunk | Complete
| 02 | RDP Brute Force & AD Attack | Crowbar, xfreerdp, Atomic Red Team, Splunk | Complete


