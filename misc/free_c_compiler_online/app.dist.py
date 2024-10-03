from flask import (
    Flask,
    json,
    jsonify,
    request,
    render_template,
)
from pathlib import Path
from uuid import uuid4, UUID
import os
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
import subprocess

app = Flask(__name__)
storage_path = Path(__file__).parent / "storage"

os.system("podman pull docker.io/library/gcc:latest")


@app.get("/")
def get_index():
    return render_template("index.html")


@app.get("/<id>")
def get_result(id):
    id = str(UUID(id))
    try:
        code = Path(storage_path, id, "main.c").read_text()
        output = Path(storage_path, id, "output.txt").read_text()
    except FileNotFoundError:
        raise NotFound()
    if output == "":
        output = "[no output yet, try refreshing]"
    return render_template("result.html", code=code, output=output)


@app.post("/run")
def post_run():
    if request.json is None:
        raise UnsupportedMediaType()
    code = request.json["code"]
    if not isinstance(code, str):
        raise BadRequest()
    id = run_code(code)
    return jsonify({"id": id})


def run_code(code):
    if len(code) > 10000:
        raise Forbidden()
    id = uuid4()
    folder = Path(storage_path, str(id))
    folder.mkdir(parents=True)
    Path(folder, "main.c").write_text(code)

    os.system(
        f"podman run --timeout 5 --detach -v {str(folder.absolute())}:/mnt --workdir /mnt gcc "
        + "sh -c 'gcc main.c > output.txt 2>&1 && ./a.out | head -c 1000 >> output.txt'"
    )

    subprocess.Popen(f"sleep 60; rm -r {folder.absolute()}", shell=True)

    return id


print("started")
