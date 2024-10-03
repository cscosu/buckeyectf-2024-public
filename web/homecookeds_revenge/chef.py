from homecooked import SubRouter, Response, TemplateResponse, Request, JSONResponse

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
    
    if not isinstance(data['text'], str):
        return JSONResponse({"error": "text must be a string"}, 400)

    return TemplateResponse.from_string(data['text'], {})