"""Call the bridge from any model provider's local tool-execution loop."""
import json
import urllib.request

def call(port, token, endpoint, **body):
    request=urllib.request.Request(f'http://127.0.0.1:{port}/{endpoint}',
        data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=40) as response:
        return json.load(response)
