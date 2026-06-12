
# Sigma Detection Rules - DNS Tunneling Detection
 
#### This rule was authored based on confirmed attack behavior identified during a hands-on home lab simulation of DNS-based C2 communication using dnscat2 and PowerShell-generated DNS tunneling traffic against a Windows 10 machine monitored by Sysmon. The rule targets behavioral indicators observed during the attack rather than static IOCs like specific domain names or IP addresses, making it resilient to attacker modifications between campaigns.

#### The rule detects high entropy subdomain patterns in DNS queries - the core characteristic of DNS tunneling regardless of which tool or domain an attacker uses. This means the detection fires on the technique itself (T1071.004) rather than any specific implementation of it.
 
## All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).
