from enum import Enum

class HTTPMethods(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

TXT_FILE_EXT = {
    'txt',
    'md',
    'rst',
    'html',
    'css',
    'js',
    'json',
    'xml',
    'yaml',
    'yml',
    'csv',
    'tsv',
    'ini',
    'cfg',
    'conf',
    'env',
    'log',
    'htaccess',
    'gitignore',
    'dockerignore',
    'gitattributes',
    'gitmodules',
    'gitkeep',
    'editorconfig',
}