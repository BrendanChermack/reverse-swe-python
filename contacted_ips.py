import requests
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": API_KEY}
BASE_URL = "https://www.virustotal.com/api/v3/files"

def get_contacted_ips(file_hash):
    url = f"{BASE_URL}/{file_hash}/contacted_ips"
    res = requests.get(url, headers=HEADERS)
    if res.status_code == 200:
        return res.json().get("data", [])
    else:
        print(f"Error {res.status_code}: {res.text}")
        return []

def get_network_location(file_hash):
    url = f"{BASE_URL}/{file_hash}"
    res = requests.get(url, headers=HEADERS)
    if res.status_code == 200:
        return res.json()["data"]["attributes"].get("network_location", None)
    return None

if __name__ == "__main__":
    sha256 = input("Enter SHA256 hash of file: ").strip()


    netloc = get_network_location(sha256)
    if netloc:
        print(f"\n Network Location: {netloc}")

    contacted_ips = get_contacted_ips(sha256)
    print("\n Contacted IPs:")
    if contacted_ips:
        for ip_entry in contacted_ips:
            print(f" - {ip_entry['id']}")
    else:
        print(" - None found in relationship data.")
