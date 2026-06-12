# Script Walkthrough - enrich_ip.py

## Overview
This document walks through the logic of `enrich_ip.py` section by section. The script automates the triage workflow for RDP brute force investigations by querying Splunk for failed login events and enriching attacker IPs against VirusTotal. I will document the walkthrough with the thoughtprocess that I had when writing it in the first place.

---
<br>

## Imports & Configuration

```python
import requests
import time
import urllib3

urllib3.disable_warnings()

VT_API_KEY  = "redacted"
SPLUNK_HOST = "https://192.168.10.10:8089"
SPLUNK_USER = "cvonfeldt"
SPLUNK_PASS = "redacted"
```

For the imports, `requests` handles all HTTP calls to both the Splunk REST API and the VirusTotal API. `urllib3.disable_warnings()` suppresses SSL certificate warnings - Splunk uses a self-signed cert in this lab environment so every HTTPS call would otherwise print a warning. In production, credentials would be pulled from environment variables or a secrets manager rather than hardcoded.

For the variables, we want to put our VirusTotal and splunk web API info into variables that we will use in the next part. I will note right now that reading this from the top down it seems a bit out of order, since different functions work at different parts in the main function which is at the bottom.

---
<br>

## Splunk Query Function

```python
def query_splunk(search_query):
    response = requests.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        auth=(SPLUNK_USER, SPLUNK_PASS),
        data={"search": search_query, "output_mode": "json"},
        verify=False
    )

    sid = response.json()["sid"]

    while True:
        status = requests.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            params={"output_mode": "json"},
            verify=False
        ).json()
        if status["entry"][0]["content"]["dispatchState"] == "DONE":
            break
        time.sleep(1)

    results = requests.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        auth=(SPLUNK_USER, SPLUNK_PASS),
        params={"output_mode": "json"},
        verify=False
    ).json()

    return results["results"]
```

Splunk's REST API is asynchronous - you can't just send a query and get results back immediately. The workflow has three steps:

1. **Submit the job** - POST the search query to `/services/search/jobs`. Splunk returns a job ID (`sid`).
2. **Poll for completion** - repeatedly send GET requests until for job status until `dispatchState` returns `DONE`, so that we know the query has been run and results have been returned fully.
3. **Fetch results** - GET the query results with "return results" using the `sid` from step 1.

This mirrors exactly what happens in the Splunk web UI when you run a search - it's the same API under the hood.

---
<br>

## VirusTotal Enrichment Function

```python
def enrich_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()
    attributes = data["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})

    return {
        "as_owner": attributes.get("as_owner", "N/A"),
        "country": attributes.get("country", "N/A"),
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }
```

Makes a GET request to the VirusTotal v3 using the IP address we got in the splunk query, authenticated with the `x-apikey` header. The response is a deeply nested JSON object - this function drills into `data.attributes` to extract the fields most useful for triage:

- `as_owner` - the organization that owns the IP block (e.g. DigitalOcean, AWS, known bulletproof hosting)
- `country` - country of origin
- `reputation` - community reputation score (negative = known bad)
- `malicious` - number of security vendors that flagged the IP
- `suspicious` / `harmless` - additional vendor verdicts for context

Returns `None` if the API call fails.

---
<br>

## Private IP Filter

```python
def is_private_ip(ip):
    return ip.startswith(("192.168.", "10.", "172.16.", "127.", "-"))
```

VirusTotal doesn't have meaningful threat intelligence for private IPs - querying them would just waste API calls. This helper function is a boolean that checks whether the brute force attacker IP is private or not.

---
<br>

## Main Function

```python
def main():
    print("Querying Splunk for failed RDP logins (Event ID 4625)...")

    results = query_splunk(
        "search index=endpoint source=\"WinEventLog:Security\" EventCode=4625 "
        "| stats count by Source_Network_Address | sort -count"
    )

    if not results:
        print("No results found.")
        return

    print(f"\nFound {len(results)} source IPs - enriching with VirusTotal...\n")
    print("=" * 60)

    for r in results:
        ip = r.get("Source_Network_Address", "N/A")
        count = r.get("count", "N/A")

        print(f"\nSource IP:     {ip}")
        print(f"Failed Logins: {count}")

        if ip and ip != "N/A" and not is_private_ip(ip):
            vt = enrich_ip(ip)
            if vt:
                print(f"AS Owner:      {vt['as_owner']}")
                print(f"Country:       {vt['country']}")
                print(f"Reputation:    {vt['reputation']}")
                print(f"Malicious:     {vt['malicious']}")
                print(f"Suspicious:    {vt['suspicious']}")
                print(f"Harmless:      {vt['harmless']}")
            else:
                print("VT Enrichment: Failed")
        print("-" * 60)
```

Responsible for the full workflow. The SPL query groups failed login events by source IP and sorts by count descending - so the most frequent brute force sources appear first. For each result it prints the IP and login count, then enriches public IPs with VirusTotal API. The output is formatted to be readable as a triage report.

The SPL query used:
```
index=endpoint source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort -count
```

- `index=endpoint` - the index where Windows Security logs are forwarded
- `source="WinEventLog:Security"` - filters to the Windows Security event log specifically
- `EventCode=4625` - failed logon events only
- `stats count by Source_Network_Address` - aggregates by attacker IP
- `sort -count` - highest volume attackers first
