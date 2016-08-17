from ..exceptions import BackendConfigurationError, BackendError
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
    BackendConfig, BackendCls = BACKENDS[config.backend_section]
    try:
        backend_config = BackendConfig(**config.backend_config)
        return BackendCls(backend_config)
    except (ValueError, BackendError) as e:
        defaults = BackendConfig.get_defaults()
        defaults.update(config.backend_config)
        required = BackendConfig.required
        raise BackendConfigurationError(backend_name=BackendConfig.name, message=str(e),
                                        required=required, defaults=defaults)
