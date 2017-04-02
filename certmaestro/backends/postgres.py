from .interfaces import IBackend


class PostgresBackend(IBackend):
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
    threadsafe = True
