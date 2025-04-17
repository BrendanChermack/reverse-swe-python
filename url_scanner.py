import requests, os
from dotenv import load_dotenv

def url_scanning(url: str):
  
  load_dotenv()
  vt_url = "https://www.virustotal.com/api/v3/urls"

  payload = { "url": f"{url}" }
  headers = {
      "accept": "application/json",
      "x-apikey": os.getenv("VT_API_KEY"),
      "content-type": "application/x-www-form-urlencoded"
  }

  response = requests.post(vt_url, data=payload, headers=headers)
  data = response.json()
  url = data["data"]["links"]["self"]
  response = requests.get(url, headers=headers)
  return response.text
response = url_scanning("https://www.aliexpress.us/?src=google&albch=fbrnd&acnt=347-178-5672&isdl=y&aff_short_key=UneMJZVf&albcp=1981704397&albag=70726251563&slnk=&trgt=kwd-14802285088&plac=&crea=593863253429&netw=g&device=c&mtctp=e&memo1=&albbt=Google_7_fbrnd&aff_platform=google&albagn=888888&isSmbActive=false&isSmbAutoCall=false&needSmbHouyi=false&gad_source=1&gclid=CjwKCAjwwLO_BhB2EiwAx2e-3-bxFWncSpkJcT-kGHjMVq5bPRav4b8TInmXBmTdxYZZr4IK7Ww4jxoCI5wQAvD_BwE&gatewayAdapt=glo2usa")
# print(response)