from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend
from ..config import DictLikeMixin


@implementer(IBackendConfig)
class FileConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class FileBackend:
    ...
