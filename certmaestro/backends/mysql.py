from .interfaces import IBackend


class MySQLBackend(IBackend):
    name = 'MySQL'
    description = 'Storing certificates in a MySQL database'
    threadsafe = True
