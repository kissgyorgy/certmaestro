from zope.interface import implementer
from .interfaces import IBackend


@implementer(IBackend)
class FileBackend:
    name = 'File'
    description = 'Certificates are simply stored in files'
