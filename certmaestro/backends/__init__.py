from ..exceptions import BackendError
from .file import FileBackend
from .mysql import MySQLBackend
from .openssl import OpenSSLBackend
from .postgres import PostgresBackend
from .vault import VaultBackend


_BACKENDS = [
    VaultBackend,
    FileBackend,
    PostgresBackend,
    OpenSSLBackend,
    MySQLBackend,
]
NUM_BACKENDS = len(_BACKENDS)


def get_backend(config):
    BackendCls = next(b for b in _BACKENDS if b.name == config.backend_name)
    init_param_names = set(p.name for p in BackendCls.init_requires)
    extra_parameters = set(config.backend_config) - init_param_names
    if extra_parameters:
        paramlist = ', '.join(extra_parameters)
        raise BackendError(f"Invalid parameters in certmaestro config: {paramlist}")
    return BackendCls(**config.backend_config)


def get_backend_cls(choice):
    return _BACKENDS[choice - 1]


def enumerate_backends():
    for i, BackendCls in enumerate(_BACKENDS):
        yield i + 1, BackendCls.name, BackendCls.description
