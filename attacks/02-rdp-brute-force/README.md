# 02 - RDP Brute Force & Active Directory Attack Detection

## Overview
This documents a simulated RDP brute force attack against a domain-joined Windows 10 machine using a Kali Linux attacker VM. Active Directory was configured on Windows Server 2022 as the domain controller. A password list was used to brute force RDP credentials for a domain user. Atomic Red Team was also used to simulate additional post-compromise techniques. All activity was detected and logged using Sysmon and Splunk.

## Lab Environment

| Role | OS | IP |
|------|----|----|
| Attacker | Kali Linux | 192.168.10.250 |
| Target | Windows 10 | 192.168.10.5 |
| Domain Controller | Windows Server 2022 | 192.168.10.7 |
| SIEM | Ubuntu 22.04 (Splunk) | 192.168.10.10 |

**Tools Used:** Crowbar, xfreerdp, Splunk Enterprise, Splunk Universal Forwarder, Sysmon (Olaf Hartong config), Atomic Red Team, Invoke-AtomicRedTeam
---
<br> 

## Environment Setup

### 1. Active Directory
Configured Windows Server 2022 as a domain controller for mydfir.local. Created organizational units (IT, HR) and domain users including jsmart.

![Active Directory OUs and Users](screenshots/ad-users-and-computers.png)

<br> 

### 2. Domain Join Verification
Confirmed Windows 10 target machine successfully joined the mydfir.local domain.

![Windows 10 Domain Join](screenshots/windows10-domain-joined.png)

<br> 

### 3. Configure Logging
Installed Splunk Universal Forwarder and Sysmon (Olaf Hartong config) on both Windows 10 and Windows Server 2022. Configured inputs.conf to forward Security, Application, System, and Sysmon logs to the Splunk SIEM at index=endpoint. Verified both machines are sending logs to Splunk.

![Splunk Both Hosts Sending Logs](screenshots/splunk-both-hosts.png)

---
<br> 

## Environment Setup

### 1. RDP Brute Force
Enabled RDP on the Windows 10 target and added the domain user jsmart to the Remote Desktop Users group. From Kali, simulated a brute force attack by attempting multiple incorrect passwords followed by the correct one (attempted crowbar bruteforce attack but ran into compatibility issues, so simulated with xfreerdp):

```bash
xfreerdp /v:192.168.10.5 /u:jsmart /p:wrongpassword /cert:ignore
xfreerdp /v:192.168.10.5 /u:jsmart /p:Hello123 /cert:ignore
xfreerdp /v:192.168.10.5 /u:jsmart /p:Password1 /cert:ignore
xfreerdp /v:192.168.10.5 /u:jsmart /p:Summer2026 /cert:ignore
xfreerdp /v:192.168.10.5 /u:jsmart /p:<correct password> /cert:ignore
```

![Kali xfreerdp Attack](screenshots/kali-xfreerdp-attack.png)

<br> 

### 2. Atomic Red Team
Installed Invoke-AtomicRedTeam on Windows 10 and ran the following MITRE ATT&CK techniques:

- **T1136.001** - Create Local Account: created backdoor admin account (NewLocalUser)
- **T1059.001** - PowerShell Command Execution: simulated malicious PowerShell activity

![Atomic Red Team T1136.001 Running](screenshots/atomic-red-team-t1136.png)
---
<br> 

## Detection

### 1. RDP Brute Force - Failed Logins
Query:index=endpoint EventCode=4625

What it shows:
- Multiple failed login attempts against jsmart from source IP 192.168.10.250 (Kali)
- Rapid succession of failures indicates automated or manual brute force activity

![Event ID 4625 - Failed Logins](screenshots/event-id-4625-failed-logins.png)

<br> 

### 2. RDP Brute Force - Successful Login
Query: index=endpoint EventCode=4624 jsmart

What it shows:
- Successful RDP login from 192.168.10.250 (Kali) after multiple failures
- Pattern of 4625s followed by a 4624 from the same source IP is a classic brute force indicator
- Logon Type 10 confirms Remote Interactive (RDP) session established

![Event ID 4624 - Successful Login](screenshots/event-id-4624-successful-login.png)
<br> 
<br> 

### 3. Atomic Red Team - User Account Created
Query: index=endpoint EventCode=4720

What it shows:
- New local account NewLocalUser created on the target machine
- Simulates attacker creating a backdoor account for persistent access
- Account was added to Administrators group — privilege escalation indicator

![Event ID 4720 - User Created](screenshots/event-id-4720-user-created.png)
<br> 
<br> 

### 4. Atomic Red Team - PowerShell Execution
Query: index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

What it shows:
- Sysmon captured process creation events during PowerShell execution tests
- Suspicious PowerShell activity logged even when Windows Defender blocked execution

![Sysmon - PowerShell Execution](screenshots/sysmon-powershell.png)
<br> 
<br> 

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Evidence |
|---|---|---|---|
| T1110.001 | Brute Force: Password guessing | Credential Access | Multiple Event ID 4625 failures from 192.168.10.250 (Kali) against domain user jsmart in rapid succession |
| T1021.001 | Remote Services:RDP | lateral movement | Successful RDP login (Event ID 4624, Logon Type 10) from attacker IP following brute force - session established on port 3389 |
| T1136.001 | Create Local Account | Persistence | New local account NewLocalUser created post-compromise via Atomic Red Team T1136.001 - confirmed in Event ID 4720 |
| T1098 | Account Manipulation | Privilege Escalation | NewLocalUser added to Administrators group post-creation - confirmed via Event ID 4732 |

<br> 

## Key Indicators of Compromise (IOCs)

| Indicator | Value |
|-----------|-------|
| Attacker IP | 192.168.10.250 |
| Target IP | 192.168.10.5 |
| Protocol | RDP (Port 3389) |
| Targeted user | mydfir\jsmart |
| Backdoor account | NewLocalUser |

<br> 

## Detection Summary
Splunk captured the full attack chain:
- Multiple failed RDP login attempts from the attacker IP (4625)
- Successful RDP login following brute force (4624)
- New local administrator account created post-compromise (4720)
- Suspicious PowerShell and process activity captured by Sysmon

A defender should alert on multiple 4625 events from the same source IP in a short timeframe, especially followed by a 4624. Any new local account creation (4720) on a domain-joined machine outside of standard IT processes should also be investigated immediately.
