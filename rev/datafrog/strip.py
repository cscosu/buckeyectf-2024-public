

with open("dist/src/main.rs", "r") as f:
    lines = f.read().split("\n")

stripped = ""
for l in lines:
    if not l.strip().startswith("//"):
        stripped += l + "\n"

with open("dist/src/main_stripped.rs", "w") as f:
    f.write(stripped)

