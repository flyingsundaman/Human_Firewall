import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

api_key = "REDACTED_GOPHISH_API_KEY"
url = "https://gophish:3333/api/campaigns"

headers = {
    "Authorization": f"Bearer {api_key}"
}

try:
    res = requests.get(url, headers=headers, verify=False)
    print("Status code:", res.status_code)
    if res.status_code == 200:
        campaigns = res.json()
        print(f"Total campaigns in GoPhish: {len(campaigns)}")
        for c in campaigns:
            print(f"ID={c.get('id')}, Name='{c.get('name')}', Status='{c.get('status')}'")
            timeline = c.get('timeline', [])
            print(f"  Timeline events: {len(timeline)}")
            for e in timeline[:10]:
                print(f"    Email: {e.get('email')}, Message: {e.get('message')}, Time: {e.get('time')}")
except Exception as e:
    print("Error:", e)
