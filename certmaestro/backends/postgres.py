from zope.interface import implementer
from .base import IBackendConfig, IBackend
from ..config import DictLikeMixin


@implementer(IBackendConfig)
class PostgresConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class PostgresBackend:
    ...
