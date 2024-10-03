from homecooked.request import Request
from homecooked.response import Response

class Middleware():
    def __init__(self, app = None, path = '') -> None:
        self.app = app
        self.path = path

        if app is not None:
            app.router.add_middleware(self, self.path)

    def init_app(self, app):
        self.app = app
        app.router.add_middleware(self, self.path)

    async def __call__(self, request : Request, next) -> Response:
        return await next(request)
