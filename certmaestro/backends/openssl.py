from zope.interface import implementer
from .base import IBackendConfig, IBackend


@implementer(IBackendConfig)
class OpenSSLConfig:
    ...


@implementer(IBackend)
class OpenSSLBackend:
    ...
