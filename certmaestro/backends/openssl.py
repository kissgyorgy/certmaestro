from zope.interface import implementer
from .base import IConfig, IBackend


@implementer(IConfig)
class OpenSSLConfig:
    ...


@implementer(IBackend)
class OpenSSLBackend:
    ...
