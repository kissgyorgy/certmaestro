from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend
from ..config import DictLikeMixin


@implementer(IBackendConfig)
class MySQLConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class MySQLBackend:
    ...
