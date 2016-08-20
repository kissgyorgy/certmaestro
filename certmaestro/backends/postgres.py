from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
class PostgresConfig:
    name = 'PostgreSQL'
    desc = 'Storing certificates in a PostgreSQL database'


@implementer(IBackend)
class PostgresBackend:
    ...
