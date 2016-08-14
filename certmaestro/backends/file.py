from zope.interface import implementer
from .base import IBackendConfig, IBackend


@implementer(IBackendConfig)
class FileConfig:
    ...


@implementer(IBackend)
class FileBackend:
    ...
