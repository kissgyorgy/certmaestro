from zope.interface import implementer
from .base import IConfig, IBackend


@implementer(IConfig)
class MySQLConfig:
    ...


@implementer(IBackend)
class MySQLBackend:
    ...
