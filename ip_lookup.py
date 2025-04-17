import requests
from dotenv import load_dotenv
import os

# Explicitly tell dotenv where to find the file
load_dotenv(dotenv_path=".env")

# Get the API key
API_KEY = os.getenv("VT_API_KEY")

# Debug: check if the key was loaded
if not API_KEY:
    print("❌ API key not loaded. Check your .env file format and name.")
    exit()

# Define headers
HEADERS = {
    "x-apikey": API_KEY
}

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

def get_ip_info(ip_address):
    url = f"{BASE_URL}/{ip_address}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None

def print_ip_summary(data):
    attr = data["data"]["attributes"]

    print(f"\n📍 IP Information Summary")
    print(f"Country: {attr.get('country', 'N/A')}")
    print(f"ASN: {attr.get('asn', 'N/A')}")
    print(f"Network: {attr.get('network', 'N/A')}")

    stats = attr.get("last_analysis_stats", {})
    print("\n🛡️ Last Analysis Stats:")
    print(f"Malicious: {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless: {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")

    if "resolutions" in attr:
        print("\n🌐 Resolved Hostnames:")
        for r in attr["resolutions"][:5]:
            print(f" - {r['hostname']} (last seen {r['last_resolved']})")

if __name__ == "__main__":
    ip = input("Enter an IP address: ").strip()
    result = get_ip_info(ip)

    if result:
        print_ip_summary(result)
