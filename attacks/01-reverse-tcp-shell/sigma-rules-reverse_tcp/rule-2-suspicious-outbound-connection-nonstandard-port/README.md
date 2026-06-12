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
 
