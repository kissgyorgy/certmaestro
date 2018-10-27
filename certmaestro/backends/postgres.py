from .interfaces import IBackend


class Backend(IBackend):
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
    threadsafe = True
