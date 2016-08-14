from .file import FileConfig, FileBackend
from .mysql import MySQLConfig, MySQLBackend
from .openssl import OpenSSLConfig, OpenSSLBackend
from .postgres import PostgresConfig, PostgresBackend
from .vault import VaultConfig, VaultBackend


BACKENDS = {
    'file': (FileConfig, FileBackend),
    'vault': (VaultConfig, VaultBackend),
    'postgres': (PostgresConfig, PostgresBackend),
    'openssl': (OpenSSLConfig, OpenSSLBackend),
    'mysql': (MySQLConfig, MySQLBackend),
}


def get_backend(config):
    BackendConfig, BackendCls = BACKENDS[config.backend_name]
    backend_config = BackendConfig(**config.backend_config)
    backend = BackendCls(backend_config)
    return backend
