from homecooked import SubRouter, Response, TemplateResponse, Request, JSONResponse
from homecooked.utils import is_safe_path
import os
chef_router = SubRouter()

UPLOAD_DIR = "/tmp/uploads"

@chef_router.get("/")
async def index():
    return TemplateResponse(
        "chef.html", {
            "title": "Chef",
    })

@chef_router.post("/upload")
async def upload(request : Request):
    data = await request.json()
    
    if 'text' not in data:
        return JSONResponse({"error": "text not in body"}, 400)
    
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)

    filename = os.urandom(16).hex() + ".meal"

    with open(os.path.join(UPLOAD_DIR, filename), "w") as f:
        f.write(data['text'])

    url = f"/chef/download/{filename}"

    return JSONResponse({"url": url})

@chef_router.get("/download/{filename:path}")
async def get_file(request : Request, filename: str):
    if not is_safe_path(filename, UPLOAD_DIR):
        return JSONResponse({"error": "Invalid path"}, 400)
    
    filename = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(filename):
        return JSONResponse({"error": "File not found"}, 404)
        
    with open(filename, "r") as f:
        text = f.read()

    if filename.endswith(".meal"):
        os.remove(filename)

    return TemplateResponse.from_string(text, {})