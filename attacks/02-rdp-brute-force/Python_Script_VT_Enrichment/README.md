# RDP Brute Force - Splunk + VirusTotal IP Enrichment Script

## Overview
Python script that automates the triage workflow for RDP brute force investigations. The script queries Splunk for failed login events (Event ID 4625), extracts the source IPs responsible for the failed attempts, filters out internal/private addresses, and automatically enriches any public IPs against the VirusTotal API - outputting a formatted triage report that a SOC analyst would otherwise have to produce manually.

This script extends the RDP brute force investigation documented in `02-rdp-brute-force/` by automating the pivot from detection to threat intelligence enrichment.

---
<br>

## How It Works

```
Splunk REST API Query (Event ID 4625)
→ Extract source IPs with failed login counts
→ Filter private/internal IP ranges
→ VirusTotal API enrichment per public IP
→ Formatted triage report output
```

---
<br>

## Sample Output

```
Querying Splunk for failed RDP logins (Event ID 4625)...

Found 4 source IPs - enriching with VirusTotal...
============================================================

Source IP:     192.168.10.250
Failed Logins: 23
[Private IP - skipped]
------------------------------------------------------------

Source IP:     203.0.113.45
Failed Logins: 23
AS Owner:      DigitalOcean LLC
Country:       NL
Reputation:    -5
Malicious:     12
Suspicious:    3
Harmless:      41
------------------------------------------------------------
```

Note: In this lab environment all attacker IPs are private (192.168.x.x) since the attack was simulated locally. In a real SOC environment with public attacker IPs, the VirusTotal enrichment fields would populate with full threat intelligence data as shown in the example above.

---
<br>

## Requirements

```
pip install requests
```

- Python 3.12+
- Splunk Enterprise with REST API enabled (port 8089)
- VirusTotal API key (free tier at virustotal.com)

---
<br>

## Configuration

Edit the following variables at the top of `enrich_ip.py`:

```python
VT_API_KEY   = "your_virustotal_api_key"
SPLUNK_HOST  = "https://your-splunk-host:8089"
SPLUNK_USER  = "your_splunk_username"
SPLUNK_PASS  = "your_splunk_password"
```

---
<br>

## Usage

```
python enrich_ip.py
```

---
<br> 

## Detection Context

This script targets the same attack pattern documented in the parent investigation:

| Event ID | Description | MITRE Technique |
|---|---|---|
| 4625 | Failed logon attempt | T1110.001 - Brute Force: Password Guessing |
| 4624 | Successful logon after brute force | T1021.001 - Remote Services: RDP |

The script aggregates 4625 events by source IP and count - a high count from a single external IP in a short timeframe is a strong indicator of automated brute force activity.

---
<br>

## Key Skills Demonstrated
- Python REST API Integration (Splunk + VirusTotal)
- Automated SOC Triage Workflow
- Threat Intelligence Enrichment
- Private IP Filtering & Input Validation
- Splunk Search Job API (async query submission + polling)
