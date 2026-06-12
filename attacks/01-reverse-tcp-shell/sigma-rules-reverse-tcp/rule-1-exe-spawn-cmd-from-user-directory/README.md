## Rule 1 - Executable Spawning Command Shell from User-Writable Directory

**Investigation:** Meterpreter Reverse TCP Shell (Home Lab - 01)

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
 
