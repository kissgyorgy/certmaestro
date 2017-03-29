from typing import Mapping
import attr
from ..exceptions import BackendError
from .mysql import MySQLBackend
from .openssl import OpenSSLBackend
from .postgres import PostgresBackend
from .vault import VaultBackend
from .easy_rsa import EasyRSA2Backend
from ..config import Param


BACKENDS = [
    VaultBackend,
    OpenSSLBackend,
    EasyRSA2Backend,
    PostgresBackend,
    MySQLBackend,
]


def get_backend(config):
    BackendCls = next(b for b in BACKENDS if b.name == config.backend_name)
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
        self._check_missing()
        backend = self._validate_init()
        backend.validate_setup(**self.setup_params)

    def _check_missing(self):
        for param in self:
            if param.default is None:
                raise ValueError(f'Parameter "{param.name}" is needed')

    def _validate_init(self):
        try:
            return self._backend_class(**self.init_params)
        except BackendError as e:
            raise ValueError(str(e))

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
