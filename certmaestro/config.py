from os import makedirs
from os.path import expanduser, realpath, dirname
from configparser import ConfigParser, RawConfigParser
import attr
from .exceptions import BackendError


class Config:
    DEFAULT_PATH = expanduser('~/.config/certmaestro/certmaestro.ini')

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        self._cfg = ConfigParser()
        with open(path) as f:
            self._cfg.read_file(f)

    @classmethod
    def make_new(cls, path=DEFAULT_PATH):
        self = object.__new__(cls)
        makedirs(dirname(path), exist_ok=True)
        self.path = path
        self._cfg = ConfigParser()
        self._cfg.add_section('certmaestro')
        return self

    def __repr__(self):
        full_path = expanduser(realpath(self.path))
        return f'<Certmaestro Config: {full_path}>'

    def __getitem__(self, name):
        return self._cfg.get('certmaestro', name)

    def __setitem__(self, name, value):
        self._cfg.set('certmaestro', name, value)

    def reload(self):
        self._cfg.read(self.path)

    def save(self):
        with open(self.path, 'w') as configfile:
            self._cfg.write(configfile)

    @property
    def backend_name(self):
        return self._cfg.get('certmaestro', 'backend')

    @backend_name.setter
    def backend_name(self, value):
        self._cfg.add_section(value)
        self._cfg.set('certmaestro', 'backend', value)

    @property
    def backend_config(self):
        return self._cfg[self.backend_name]


def strtobool(value):
    """Convert boolean values the same way as ConfigParser does."""
    if isinstance(value, bool):
        return value
    value = value.lower()
    if value not in RawConfigParser.BOOLEAN_STATES:
        raise ValueError(f'Not a boolean: {value}')
    return RawConfigParser.BOOLEAN_STATES[value]


def starts_with_http(value):
    if not value.startswith('http://') and not value.startswith('https://'):
        raise ValueError('URL needs to start with http:// or https://')


@attr.s(slots=True, cmp=False)
class Param:
    name = attr.ib()
    help = attr.ib()
    default = attr.ib(default=None)
    validator = attr.ib(default=None)
    convert = attr.ib(default=None)

    def __iter__(self):
        return iter([self.name, self.help, self.default])

    def copy(self):
        return self.__class__(**attr.asdict(self))


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
        self._validate_params()
        backend = self._validate_init()
        backend.validate_setup(**self.setup_params)

    def _validate_params(self):
        for param in self:
            value = self._values.get(param.name, param.default)
            if value is None:
                raise ValueError('Parameter %r is needed' % param.name)
            if param.convert is not None:
                value = param.convert(value)
                self._values[param.name] = value
            if param.validator is not None:
                param.validator(value)

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
            raise AttributeError('Name %r is not found in this builder' % name)
        # TODO: convert here?
        self._values[name] = value

    def __getitem__(self, name):
        return self._values.get(name)

    @property
    def all_params(self):
        return {par.name: self._values.get(par.name, par.default) for par in self}

    @property
    def init_params(self):
        return {par.name: self._values.get(par.name, par.default) for par in self.init_requires}

    @property
    def setup_params(self):
        return {par.name: self._values.get(par.name, par.default) for par in self.setup_requires}

    def setup_backend(self):
        backend = self._backend_class(**self.init_params)
        backend.setup(**self.setup_params)
        return backend
