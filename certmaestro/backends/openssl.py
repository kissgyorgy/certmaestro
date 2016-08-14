from zope.interface import implementer
from .base import IBackendConfig, IBackend
from .interfaces import IBackendConfig, IBackend
from ..config import DictLikeMixin


@implementer(IBackendConfig)
class OpenSSLConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class OpenSSLBackend:
    ...
