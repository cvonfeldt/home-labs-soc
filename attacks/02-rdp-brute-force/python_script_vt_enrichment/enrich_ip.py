import requests
import sys
import time
import urllib3

urllib3.disable_warnings()

VT_API_KEY = "a16cb5715b1de23645445b7d39985f0363f1ed2fde2174ab5216ca6727034e7c"
SPLUNK_HOST = "https://192.168.10.10:8089"
SPLUNK_USER = "cvonfeldt"
SPLUNK_PASS = "Dcsd164788ac$"

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

def is_private_ip(ip):
    return ip.startswith(("192.168.", "10.", "172.16.", "127.", "-"))


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

if __name__ == "__main__":
    main()
