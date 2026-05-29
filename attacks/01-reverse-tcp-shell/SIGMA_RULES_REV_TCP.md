# Sigma Detection Rules - Home Lab Investigations
 
These rules were authored based on confirmed attack behavior identified during hands-on home lab simulations. Each rule targets a behavioral indicator observed during the attack rather than static IOCs like filenames or IP addresses, making them resilient to attacker modifications between campaigns.
 
**All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).**
 
---
<br>

## Rule 1 - Executable Spawning Command Shell from User-Writable Directory
 
**What it detects:** An executable running from a user-writable directory (`Downloads`, `AppData`, `Temp`) spawning `cmd.exe` as a child process. In the Meterpreter investigation, `resume4.pdf.exe` executed from `C:\Users\chan\Downloads\` and immediately spawned `cmd.exe` to establish the reverse shell session.
 
**Why it's evasion-resistant:** An attacker can rename their payload to anything, but they cannot avoid the parent-child relationship that appears when a Meterpreter palyoad executes. A legitimate file downloaded by a user - a PDF, an image, a document - has no reason to ever spawn a command interpreter. This relationship is anomalous regardless of what the file is named or where it came from. The user-writable directory filter also eliminates most false positives since legitimate software typically executes from `Program Files` or `Windows` directories, not user download folders.
 
```yaml
title: Executable Spawning Command Shell from User-Writable Directory
status: experimental
description: >
    Detects an executable running from a user-writable directory spawning cmd.exe
    or powershell.exe as a child process. Indicative of a malicious payload
    executing and establishing a reverse shell or running post-exploitation
    commands. Observed during Meterpreter reverse TCP shell lab where
    resume4.pdf.exe spawned cmd.exe from the Downloads directory.
author: Chandler VonFeldt
date: 2026/04/25
references:
    - https://attack.mitre.org/techniques/T1059/003/
    - https://attack.mitre.org/techniques/T1204/002/
tags:
    - attack.execution
    - attack.t1059.003
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains:
            - '\Users\'
            - '\Downloads\'
            - '\AppData\'
            - '\Temp\'
            - '\Desktop\'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    filter:
        ParentImage|contains:
            - '\Program Files\'
            - '\Windows\'
            - '\System32\'
    condition: selection and not filter
falsepositives:
    - Some legitimate installers that execute from user directories
    - Developer tools running from user-managed paths
level: high
```
 
---
<br> 

## Rule 2 - Outbound Network Connection from User-Writable Directory on Non-Standard Port
 
**Investigation:** Meterpreter Reverse TCP Shell (Home Lab - 01)
 
**What it detects:** A process executing from a user-writable directory initiating an outbound TCP connection on a non-standard port. In the Meterpreter investigation, `resume4.pdf.exe` initiated an outbound TCP connection from `C:\Users\chan\Downloads\` to the attacker's machine on port 4444 - the default Metasploit listener port - confirmed via Sysmon Event ID 3.
 
**Why it's evasion-resistant:** An attacker can change the port from 4444 to anything, but they cannot avoid the fact that their payload needs to make an outbound network connection to establish the reverse shell. A file sitting in a user's Downloads folder has no legitimate reason to initiate outbound TCP connections to external IPs on non-standard ports. This rule targets that behavior rather than the specific port number, making it resilient to simple port changes. Combined with Rule 1, these two rules cover both the execution and the network phases of a reverse shell attack.
 
```yaml
title: Outbound Network Connection from User-Writable Directory on Non-Standard Port
status: experimental
description: >
    Detects a process executing from a user-writable directory initiating an
    outbound TCP connection on a non-standard port. Indicative of a reverse
    shell or C2 beacon establishing a connection back to the attacker's
    machine. Observed during Meterpreter reverse TCP shell lab where
    resume4.pdf.exe connected outbound to attacker IP on port 4444 (default
    Metasploit listener port) from the Downloads directory.
author: Chandler VonFeldt
date: 2026/04/25
references:
    - https://attack.mitre.org/techniques/T1571/
    - https://attack.mitre.org/techniques/T1095/
tags:
    - attack.command_and_control
    - attack.t1571
    - attack.t1095
logsource:
    category: network_connection
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image|contains:
            - '\Users\'
            - '\Downloads\'
            - '\AppData\'
            - '\Temp\'
            - '\Desktop\'
        Initiated: 'true'
        DestinationPort|gt: 1024
    filter:
        DestinationPort:
            - 80
            - 443
            - 8080
            - 8443
    condition: selection and not filter
falsepositives:
    - Legitimate applications installed in user directories making outbound connections
    - Some development tools and package managers
level: high
```
 
---
<br> 

## The combination of Rule 1 and Rule 2 creates layered detection across two phases of the same attack - execution and network callout - meaning an attacker would need to evade both rules simultaneously to avoid detection entirely.
