import json
from typing import Dict, Any
from homecooked.meal.meal import MealManager

class Response:
    def __init__(
        self, body : Any, status=200, headers : Dict[str, str] = None, mime_type : str = None, encoding : str = None
    ) -> None:
        self.status = status
        self.headers = headers if headers is not None else {}
        self.body = body
        self.mime_type = mime_type
        self.encoding = encoding

    @property
    def error(self):
        return self.status >= 400

    async def write(self, send, head=False) -> None:
        if self.headers.get("Content-Type") is None and self.mime_type is None:
            self.headers["Content-Type"] = "text/html"
        elif self.mime_type is not None:
            self.headers["Content-Type"] = self.mime_type

        if self.encoding is not None:
            self.headers["Content-Encoding"] = self.encoding

        self.body = self.body if isinstance(self.body, bytes) else self.body.encode("utf-8")
        self.headers["Content-Length"] = str(len(self.body))

        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [
                    [k.encode("utf-8"), v.encode("utf-8")]
                    for k, v in self.headers.items()
                ],
            }
        )

        if not head:
            await send(
                {
                    "type": "http.response.body",
                    "body": (
                        self.body
                    ),
                }
            )
        else:
            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                }
            )

class JSONResponse(Response):
    def __init__(self, body : Dict[Any, Any], status=200, headers=None) -> None:
        super().__init__(body, status, headers)
        self.headers["Content-Type"] = "application/json"

    async def write(self, send, head=False) -> None:
        self.body = json.dumps(self.body)
        await super().write(send, head)

class TemplateResponse(Response):
    def __init__(self, template, context=None, status=200, headers=None, as_string = False) -> None:
        super().__init__(template, status, headers)
        self.context = context if context is not None else {}
        self.headers["Content-Type"] = "text/html"
        self.as_string = as_string

    async def write(self, send, template_manager, head=False) -> None:
        template = self.body
        try:
            if self.as_string:
                self.body = MealManager.interpret_string(template, self.context)
            else:
                self.body = template_manager.interpret(template, self.context)
        except Exception as e:
            self.body = e
            self.status = 500
            raise e
        await super().write(send, head)

    @classmethod
    def from_string(cls, templ_string, context=None, status=200, headers=None):
        return cls(templ_string, context if context is not None else {}, status, headers, as_string=True)