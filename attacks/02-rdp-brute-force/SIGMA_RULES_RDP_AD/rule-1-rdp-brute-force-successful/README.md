## Rule 1 - RDP Brute Force Followed by Successful Login from Same Source

**Investigation:** RDP Brute Force & AD Attack (Home Lab - 02)
 
**What it detects:** Multiple failed login attempts (Event ID 4625) from a single source IP followed by a successful login (Event ID 4624) with Logon Type 10 (Remote Interactive/RDP) from the same source IP within a short timeframe. In the RDP brute force investigation, multiple failed attempts against `jsmart` from `192.168.10.250` (Kali) were followed by a successful RDP session from the same IP after the correct password was found.
 
**Why it's evasion-resistant:** An attacker cannot avoid generating failed login events during a brute force - that's the nature of the technique. Regardless of what username they target, what password list they use, or what tool they use (Crowbar, Hydra, xfreerdp, etc.), the pattern of multiple 4625s followed by a 4624 from the same source IP within a short window is the behavioral fingerprint of a successful brute force. The Logon Type 10 filter specifically scopes this to RDP sessions, reducing false positives from other authentication mechanisms.
 
```yaml
title: RDP Brute Force Followed by Successful Login from Same Source
status: experimental
description: >
    Detects multiple failed RDP login attempts from a single source IP followed
    by a successful RDP login from the same IP within a short timeframe.
    Indicative of a successful RDP brute force attack. Observed during home lab
    simulation where Kali Linux (192.168.10.250) brute forced RDP credentials
    for domain user jsmart on a Windows 10 domain-joined machine.
author: Chandler VonFeldt
date: 2026/04/25
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://attack.mitre.org/techniques/T1021/001/
tags:
    - attack.credential_access
    - attack.t1110.001
    - attack.lateral_movement
    - attack.t1021.001
logsource:
    category: authentication
    product: windows
detection:
    failed_login:
        EventID: 4625
        LogonType: 10
    successful_login:
        EventID: 4624
        LogonType: 10
    timeframe: 5m
    condition: failed_login | count() > 5 and successful_login
falsepositives:
    - Legitimate users mistyping their password multiple times before succeeding
    - Automated service accounts with misconfigured credentials
level: high
```
 
