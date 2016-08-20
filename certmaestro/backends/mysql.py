from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
class MySQLConfig:
    name = 'MySQL'
    desc = 'Storing certificates in a MySQL database'


@implementer(IBackend)
class MySQLBackend:
    ...
