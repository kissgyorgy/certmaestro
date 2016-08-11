from zope.interface import implementer
from .base import IConfig, IBackend


@implementer(IConfig)
class FileConfig:
    ...


@implementer(IBackend)
class FileBackend:
    ...
