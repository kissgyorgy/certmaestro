from zope.interface import implementer
from .base import IBackendConfig, IBackend


@implementer(IBackendConfig)
class MySQLConfig:
    ...


@implementer(IBackend)
class MySQLBackend:
    ...
