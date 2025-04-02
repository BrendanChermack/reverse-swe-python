import os, json
import requests
from dotenv import load_dotenv



def mal_uploader(mal_file_path: str, password=None):
  load_dotenv()

  url = "https://www.virustotal.com/api/v3/files"

  payload = { "password": f"{password}" }

  headers = {
      "accept": "application/json",
      "x-apikey": os.getenv("VT_API_KEY")
  }
  with open(f"{mal_file_path}", "rb") as f:
      files = { "file": ("Mal1.zip", f, "application/x-zip-compressed") }
      response = requests.post(url, headers=headers, files=files, data=payload)

  print(response.text)

  data = response.json()
  url = data["data"]["links"]["self"]

  response = requests.get(url, headers=headers)
  print(response.text)
  return response.text

res = mal_uploader("./malicious-files/Mal1.zip", "ia400")
print(res)