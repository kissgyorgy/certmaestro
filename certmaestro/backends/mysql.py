from zope.interface import implementer
from .interfaces import IBackend


@implementer(IBackend)
class MySQLBackend:
    name = 'MySQL'
    description = 'Storing certificates in a MySQL database'
    threadsafe = True
