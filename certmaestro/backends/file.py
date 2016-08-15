from zope.interface import implementer
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
class FileConfig:
    ...


@implementer(IBackend)
class FileBackend:
    ...
