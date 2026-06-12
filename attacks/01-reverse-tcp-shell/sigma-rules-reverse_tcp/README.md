# Sigma Detection Rules - Reverse TCP Shell Attack
 
#### These rules were authored based on confirmed attack behavior identified during hands-on home lab simulations. Each rule targets a behavioral indicator observed during the attack rather than static IOCs like filenames or IP addresses, making them resilient to attacker modifications between campaigns.

#### The combination of Rule 1 and Rule 2 creates layered detection across two phases of the same attack - execution and network callout - meaning an attacker would need to evade both rules simultaneously to avoid detection entirely.
 
## All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).
 
