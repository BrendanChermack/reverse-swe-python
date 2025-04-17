import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def get_behavior_report(file_id: str):
    url = f"{BASE_URL}/files/{file_id}/behaviour"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Failed to get behavior report: {response.status_code}")
        return {}
    return response.json()

def extract_imports(behavior_data):
    imports = []
    for sandbox in behavior_data.get("data", []):
        for entry in sandbox.get("attributes", {}).get("imports", []):
            dll = entry.get("library_name", "Unknown DLL")
            functions = entry.get("imported_functions", [])
            imports.append((dll, functions))
    return imports

def display_imports(imports):
    print("\n🧩 Imports from behavior report:")
    if not imports:
        print("No imports found.")
    for dll, funcs in imports:
        print(f"{dll}:")
        for func in funcs:
            print(f"  - {func}")

# Run as standalone script
if __name__ == "__main__":
    file_id = input("Enter SHA256 or file_id: ").strip()
    behavior_data = get_behavior_report(file_id)
    imports = extract_imports(behavior_data)
    display_imports(imports)
