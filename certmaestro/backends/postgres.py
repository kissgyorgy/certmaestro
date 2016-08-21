from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
class PostgresConfig:
    ...


@implementer(IBackend)
class PostgresBackend:
    name = 'PostgreSQL'
    description = 'Storing certificates in a PostgreSQL database'
