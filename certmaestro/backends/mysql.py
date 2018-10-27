from .interfaces import IBackend


class Backend(IBackend):
    name = 'MySQL'
    description = 'Storing certificates in a MySQL database'
    threadsafe = True
