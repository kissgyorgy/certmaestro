from typing import Mapping
from importlib import import_module
import attr
from ..exceptions import BackendError
from ..config import Param


# we only want to store human readable section names in certmaestro.ini, so we need to pair
# those names to actual Python classes, otherwise we would need to store those in the .ini
# name: (module, BackendClass)
_BACKEND_NAME_CLASS_MAP = {
    # 'Vault': ('.vault', 'VaultBackend'),
    'OpenSSL': ('.openssl', 'OpenSSLBackend'),
    # 'Easy-RSA 2.X': ('.easy_rsa', 'EasyRSA2Backend'),
    # 'PostgreSQL': ('.postgres', 'PostgreSQLBackend'),
    # 'MySQL': ('.mysql', 'MySQLBackend'),
    # Not sure if this should be user visible, because it's an implementation detail.
    # It will be explicitly imported if necessary.
    # 'Twisted Vault': ('.vault', 'TwistedVaultBackend'),
}


def register_backend(cls):
    _BACKEND_NAME_CLASS_MAP[cls.name] = (cls.__module__, cls.__name__)
    print('Registered', cls.name)
    print('NAME MAP', _BACKEND_NAME_CLASS_MAP)
    return cls


def load_all_backends():
    """This function eagerly loads all backends.
    It will be needed at setup, to be able to offer all backends the user can choose from. After
    setup, only the relevant backend will be imported, mostly to avoid unnecessary dependencies
    and faster startup time.
    """
    from .vault import VaultBackend
    from .openssl import OpenSSLBackend
    from .easy_rsa import EasyRSA2Backend
    from .postgres import PostgreSQLBackend
    from .mysql import MySQLBackend
    return [VaultBackend, OpenSSLBackend, EasyRSA2Backend, PostgreSQLBackend, MySQLBackend]


def _load_backend(backend_name):
    module_name, cls_name = _BACKEND_NAME_CLASS_MAP[backend_name]
    module = import_module(module_name, package='certmaestro.backends')
    return getattr(module, cls_name)


# This function is not needed at setup at all. It's either load_all_backends or get_backend.
def get_backend(config):
    BackendCls = _load_backend(config.backend_name)
    init_param_names = set(p.name for p in BackendCls.init_requires)
    extra_parameters = set(config.backend_config) - init_param_names
    if extra_parameters:
        paramlist = ', '.join(extra_parameters)
        raise BackendError(f"Invalid parameters in certmaestro config: {paramlist}")
    params = make_params(BackendCls.init_requires, config.backend_config)
    return BackendCls(**params)


def make_params(params, values: Mapping) -> dict:
    rv = {}
    for param in params:
        value = values.get(param.name, param.default)
        if value is not None and param.convert is not None:
            value = param.convert(value)
        rv[param.name] = value
    return rv


class BackendBuilder:
    """Helps to setup the backend by the defined Params in init_requires and setup_requires."""

    def __init__(self, backend_class, default_values=None):
        self._backend_class = backend_class
        # to avoid accidentally changing params on the backend class
        self.init_requires = tuple(p.copy() for p in backend_class.init_requires)
        self.setup_requires = tuple(p.copy() for p in backend_class.setup_requires)
        self._values = default_values or dict()

    def __iter__(self):
        for param in (self.init_requires + self.setup_requires):
            values = attr.asdict(param)
            values['default'] = self._values.get(param.name, param.default)
            yield Param(**values)

    def validate(self):
        for param in self:
            if param.default is None:
                raise ValueError(f'Parameter "{param.name}" is needed')

        try:
            return self._backend_class(**self.init_params)
        except BackendError as e:
            raise ValueError(str(e))

        backend.validate_setup(**self.setup_params)

    def is_valid(self):
        try:
            self.validate()
            return True
        except ValueError:
            return False

    def __setitem__(self, name, value):
        if name not in (param.name for param in self):
            raise AttributeError(f'Name "{name}" is not found in this builder')
        # TODO: convert here?
        self._values[name] = value

    def __getitem__(self, name):
        return self._values.get(name)

    @property
    def init_params(self):
        return make_params(self.init_requires, self._values)

    @property
    def setup_params(self):
        return make_params(self.setup_requires, self._values)

    def setup_backend(self):
        backend = self._backend_class(**self.init_params)
        backend.setup(**self.setup_params)
        return backend

    @property
    def backend_name(self):
        return self._backend_class.name
