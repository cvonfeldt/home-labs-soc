# Sigma Detection Rules - RDP Brute Force & Active Directory Attack
 
These rules were authored based on confirmed attack behavior identified during a hands-on home lab simulation of an RDP brute force attack against a domain-joined Windows 10 machine with Active Directory configured on Windows Server 2022. Each rule targets a behavioral indicator observed during the attack rather than static IOCs like specific usernames or IP addresses, making them resilient to attacker modifications between campaigns.
 
**All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).**
 
---
<br>

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
 
---
<br> 

## Rule 2 - New Local Account Created on Domain-Joined Machine

**Investigation:** RDP Brute Force & AD Attack (Home Lab - 02)
 
**What it detects:** A new local user account being created (Event ID 4720) on a domain-joined machine outside of standard IT provisioning processes. In the RDP brute force investigation, Atomic Red Team technique T1136.001 was used to create a backdoor local administrator account (`NewLocalUser`) post-compromise, simulating an attacker establishing persistent access after gaining an initial foothold via RDP.
 
**Why it's evasion-resistant:** In a properly managed enterprise environment, local account creation on domain-joined machines should essentially never happen outside of controlled IT processes - domain accounts are used instead. Any Event ID 4720 on a domain-joined machine is therefore immediately suspicious regardless of what the account is named, who creates it, or what method is used. An attacker can name their backdoor account anything they want but they cannot avoid generating a 4720 event when creating it. The addition to the Administrators group compounds the severity significantly.
 
```yaml
title: New Local Account Created on Domain-Joined Machine
status: experimental
description: >
    Detects creation of a new local user account on a domain-joined Windows
    machine. In domain environments local account creation is rarely legitimate
    and is a strong indicator of an attacker establishing a backdoor for
    persistent access. Observed during home lab simulation using Atomic Red Team
    T1136.001 where NewLocalUser was created and added to the Administrators
    group post-RDP compromise.
author: Chandler VonFeldt
date: 2026/04/25
references:
    - https://attack.mitre.org/techniques/T1136/001/
    - https://attack.mitre.org/techniques/T1098/
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.privilege_escalation
    - attack.t1098
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4720
    filter:
        SubjectUserName|endswith:
            - '$'
    condition: selection and not filter
falsepositives:
    - Legitimate local account creation by IT administrators during provisioning
    - Break-glass emergency accounts created by authorized personnel
level: high
```
---

## The combination of Rule 1 and Rule 2 covers two distinct phases of the same attack - initial access via brute force and post-compromise persistence via backdoor account creation - meaning both the entry point and the follow-on activity are detected independently.
