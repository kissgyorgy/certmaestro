from .interfaces import IBackend
from . import register_backend

@register_backend
class MySQLBackend(IBackend):
    name = 'MySQL'
    description = 'Storing certificates in a MySQL database'
    threadsafe = True
