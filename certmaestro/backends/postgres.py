from zope.interface import implementer
from .interfaces import IBackend


@implementer(IBackend)
class PostgresBackend:
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
