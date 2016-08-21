from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
class MySQLConfig:
    ...


@implementer(IBackend)
class MySQLBackend:
    name = 'MySQL'
    description = 'Storing certificates in a MySQL database'
