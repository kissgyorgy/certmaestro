from .interfaces import IBackend
from . import register_backend


@register_backend
class PostgreSQLBackend(IBackend):
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
    threadsafe = True
