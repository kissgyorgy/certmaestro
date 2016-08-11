from zope.interface import implementer
from .base import IConfig, IBackend


@implementer(IConfig)
class PostgresConfig:
    ...


@implementer(IBackend)
class PostgresBackend:
    ...
