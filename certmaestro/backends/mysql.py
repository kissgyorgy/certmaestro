from zope.interface import implementer
from .base import IBackendConfig, IBackend
from ..config import DictLikeMixin


@implementer(IBackendConfig)
class MySQLConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class MySQLBackend:
    ...
