from ..exceptions import BackendError
from .file import FileBackend
from .mysql import MySQLBackend
from .openssl import OpenSSLBackend
from .postgres import PostgresBackend
from .vault import VaultBackend


BACKENDS = [
    VaultBackend,
    FileBackend,
    PostgresBackend,
    OpenSSLBackend,
    MySQLBackend,
]


def get_backend(config):
    BackendCls = next(b for b in BACKENDS if b.name == config.backend_name)
    init_param_names = set(p.name for p in BackendCls.init_requires)
    extra_parameters = set(config.backend_config) - init_param_names
    if extra_parameters:
        paramlist = ', '.join(extra_parameters)
        raise BackendError(f"Invalid parameters in certmaestro config: {paramlist}")
    return BackendCls(**config.backend_config)
