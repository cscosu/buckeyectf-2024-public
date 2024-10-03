from homecooked.response import Response
from homecooked.request import Request

async def bad_request_handler(request : Request) -> Response:
    return Response("Bad Request", 400)

async def unauthorized_handler(request : Request) -> Response:
    return Response("Unauthorized", 401)

async def forbidden_handler(request : Request) -> Response:
    return Response("Forbidden", 403)

async def not_found_handler(request : Request) -> Response:
    return Response("Not Found", 404)

async def method_not_allowed_handler(request : Request) -> Response:
    return Response("Method Not Allowed", 405)

async def not_acceptable_handler(request : Request) -> Response:
    return Response("Not Acceptable", 406)

async def request_timeout_handler(request : Request) -> Response:
    return Response("Request Timeout", 408)

async def server_error_handler(request : Request) -> Response:
    return Response("Internal Server Error", 500)

async def not_implemented_handler(request : Request) -> Response:
    return Response("Not Implemented", 501)
