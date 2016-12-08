from zope.interface import implementer
from .interfaces import IBackend


@implementer(IBackend)
class FileBackend:
    ...
