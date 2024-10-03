import requests
import json

payload = {
    "text":"""
        🍴c🍇🍎'_'🌭'_'🌭'c'🌭'l'🌭'a'🌭's'🌭's'🌭'_'🌭'_'🍏🍴
        🍴c🍇join🦀list🦀c🦞🦞🍴
        🍴m🍇🍎'_'🌭'_'🌭'm'🌭'r'🌭'o'🌭'_'🌭'_'🍏🍴
        🍴m🍇join🦀list🦀m🦞🦞🍴
        🍴s🍇🍎'_'🌭'_'🌭's'🌭'u'🌭'b'🌭'c'🌭'l'🌭'a'🌭's'🌭's'🌭'e'🌭's'🌭'_'🌭'_'🍏🍴
        🍴s🍇join🦀list🦀s🦞🦞🍴
        🍴a🍇str🥚c🥚m🍎1🍏🥚s🦀🦞🍎429🍏🦀🦞🍴
        🥢a🥢
    """
}


r = requests.post("http://localhost:8001/chef/upload", json=payload)

new_path = r.json()['url']

r = requests.get(f"http://localhost:8001{new_path}")

print(r.text)