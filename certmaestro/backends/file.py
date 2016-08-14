from zope.interface import implementer
from .base import IBackendConfig, IBackend
from ..config import section_param, DictLikeMixin  # noqa


@implementer(IBackendConfig)
class FileConfig(DictLikeMixin):
    ...


@implementer(IBackend)
class FileBackend:
    ...
