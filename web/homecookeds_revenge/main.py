from homecooked import App, TemplateResponse
from chef import chef_router

app = App()
app.add_subrouter("/chef", chef_router)

@app.get("/")
async def index():
    return TemplateResponse(
        "index.html", {
            "title": "Homecooked",
    })

@app.get("/docs/meal")
async def meal():
    return TemplateResponse(
        "meal_docs.html", {
            "title": "Meal Docs",
    })

@app.get("/docs/homecooked")
async def homecooked():
    return TemplateResponse(
        "homecooked_docs.html", {
            "title": "Homecooked Docs",
    })