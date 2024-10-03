from typing import Callable
from homecooked.exceptions.defaults import (
    bad_request_handler,
    unauthorized_handler,
    forbidden_handler,
    not_found_handler,
    method_not_allowed_handler,
    not_acceptable_handler,
    request_timeout_handler,
    server_error_handler,
    not_implemented_handler
)

class HTTPException(Exception):
    code : int = -1
    message : str = None

    def __init__(self):
        super().__init__((self.code, self.message))

class BadRequest(HTTPException):
    code = 400
    message = "Bad Request"

class Unauthorized(HTTPException):
    code = 401
    message = "Unauthorized"

class Forbidden(HTTPException):
    code = 403
    message = "Forbidden"

class NotFound(HTTPException):
    code = 404
    message = "Not Found"

class MethodNotAllowed(HTTPException):
    code = 405
    message = "Method Not Allowed"

class NotAcceptable(HTTPException):
    code = 406
    message = "Not Acceptable"

class RequestTimeout(HTTPException):
    code = 408
    message = "Request Timeout"

class ServerError(HTTPException):
    code = 500
    message = "Internal Server Error"

class NotImplemented(HTTPException):
    code = 501
    message = "Not Implemented"


class ExceptionHandler():
    def __init__(self) -> None:
        self.handlers = { 
            BadRequest.code: bad_request_handler,
            Unauthorized.code: unauthorized_handler,
            Forbidden.code: forbidden_handler,
            NotFound.code: not_found_handler,
            MethodNotAllowed.code: method_not_allowed_handler,
            NotAcceptable.code: not_acceptable_handler,
            RequestTimeout.code: request_timeout_handler,
            ServerError.code: server_error_handler,
            NotImplemented.code: not_implemented_handler
        }

    def add_handler(self, code : int | HTTPException, handler : Callable) -> None:
        if isinstance(code, HTTPException):
            code = code.code

        self.handlers[code] = handler

    def get_handler(self, code : int | HTTPException) -> Callable:
        if isinstance(code, HTTPException):
            code = code.code

        return self.handlers.get(code)