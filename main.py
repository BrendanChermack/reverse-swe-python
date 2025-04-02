import os, json
import requests
from dotenv import load_dotenv

load_dotenv()

url = "https://www.virustotal.com/api/v3/files"

payload = { "password": "ia400" }

headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
}
with open("./malicious-files/Mal1.zip", "rb") as f:
    files = { "file": ("Mal1.zip", f, "application/x-zip-compressed") }
    response = requests.post(url, headers=headers, files=files, data=payload)

print(response.text)

data = response.json()
url = data["data"]["links"]["self"]

response = requests.get(url, headers=headers)
print(response.text)