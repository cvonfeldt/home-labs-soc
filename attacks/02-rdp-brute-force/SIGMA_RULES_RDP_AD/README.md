# Sigma Detection Rules - RDP Brute Force & Active Directory Attack
 
#### These rules were authored based on confirmed attack behavior identified during a hands-on home lab simulation of an RDP brute force attack against a domain-joined Windows 10 machine with Active Directory configured on Windows Server 2022. Each rule targets a behavioral indicator observed during the attack rather than static IOCs like specific usernames or IP addresses, making them resilient to attacker modifications between campaigns.

#### The combination of Rule 1 and Rule 2 covers two distinct phases of the same attack - initial access via brute force and post-compromise persistence via backdoor account creation - meaning both the entry point and the follow-on activity are detected independently.
 
## All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).

