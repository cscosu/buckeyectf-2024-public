from flask import Flask, send_from_directory, abort
from pathlib import Path

app = Flask(__name__)

base = Path(__file__).parent

@app.route('/')
def serve_index():
    return send_from_directory(base, "index.html")

@app.route('/<path:filename>')
def serve_file(filename):
    full_path = Path(base, filename)

    if full_path.name == "flag.txt":
        return "Forbidden", 403

    if full_path.is_dir():
        return "Is a directory", 400

    if full_path.exists():
        return send_from_directory(base, filename, mimetype="text/plain")
    else:
        return "Not found", 404
