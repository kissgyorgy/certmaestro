from zope.interface import implementer
from .base import IBackendConfig, IBackend


@implementer(IBackendConfig)
class PostgresConfig:
    ...


@implementer(IBackend)
class PostgresBackend:
    ...
