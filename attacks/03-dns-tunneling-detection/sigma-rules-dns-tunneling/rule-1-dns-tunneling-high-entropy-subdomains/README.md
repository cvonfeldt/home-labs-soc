## Rule 1 - High Entropy DNS Subdomain Queries Indicative of DNS Tunneling
**Investigation:** DNS Tunneling Detection (Home Lab - 03)
 
**What it detects:** DNS queries where the subdomain portion contains 20 or 
more random alphanumeric characters, captured via Sysmon Event ID 22. In the 
DNS tunneling simulation, dnscat2 and PowerShell generated hundreds of queries 
with 32-character random subdomains to `tunnel.evil.com` - each subdomain 
encoding data being exfiltrated through the DNS channel.
 
**Why it's evasion-resistant:** An attacker cannot avoid generating high 
entropy subdomains when using DNS tunneling - encoding data into subdomains 
is the fundamental mechanism of the technique. Regardless of what domain they 
register, what tool they use (dnscat2, iodine, DNScat, custom malware), or 
what data they're exfiltrating, the subdomain strings will always look like 
random gibberish compared to legitimate human-readable subdomains like 
`mail.google.com` or `cdn.cloudflare.com`. The 20-character length threshold 
specifically targets encoded payloads while excluding legitimate long 
subdomains used by CDNs and analytics platforms.
 
```yaml
title: High Entropy DNS Subdomain Queries Indicative of DNS Tunneling
id: 9f4e2c1a-3b5d-7e8f-9a0b-1c2d3e4f5a6b
status: experimental
description: >
    Detects potential DNS tunneling activity via high entropy subdomain queries
    captured by Sysmon Event ID 22. Subdomains containing 20 or more random
    alphanumeric characters are indicative of data being encoded and 
    exfiltrated through the DNS channel. Observed during home lab simulation
    where PowerShell-generated DNS tunneling traffic produced 32-character
    random subdomains at high volume to tunnel.evil.com.
notes: >
    QueryName is the Sysmon field name per the Sigma specification.
    In environments where Sysmon logs are ingested as raw XML (e.g. Splunk 
    without a Sysmon add-on), QueryName must be extracted via regex from the 
    raw event before this rule can be applied. See lab documentation for 
    the applicable SPL rex extraction.
author: Chandler VonFeldt
date: 2026/06/12
references:
    - https://attack.mitre.org/techniques/T1071/004/
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        EventID: 22
        QueryName|re: '[a-z0-9]{20,}\.'
    condition: selection
falsepositives:
    - Legitimate CDN providers using hash-based subdomains
    - Some analytics and telemetry platforms with long subdomains
level: medium
```
