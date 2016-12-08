from .file import FileBackend
from .mysql import MySQLBackend
from .openssl import OpenSSLBackend
from .postgres import PostgresBackend
from .vault import VaultBackend


BACKENDS = {
    'File': FileBackend,
    'Vault': VaultBackend,
    'Postgres': PostgresBackend,
    'OpenSSL': OpenSSLBackend,
    'MySQL': MySQLBackend,
}


def get_backend(config):
    BackendCls = BACKENDS[config.backend_name]
    return BackendCls(**config.backend_config)
