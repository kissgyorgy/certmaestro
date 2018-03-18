from .interfaces import IBackend


class PostgreSQLBackend(IBackend):
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
    threadsafe = True
