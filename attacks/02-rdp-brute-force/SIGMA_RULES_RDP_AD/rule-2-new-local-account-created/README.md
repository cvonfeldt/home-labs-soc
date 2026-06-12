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
