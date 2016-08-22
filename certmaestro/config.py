from os.path import expanduser, realpath
from configparser import ConfigParser, RawConfigParser
import attr


class Config:
    DEFAULT_PATH = expanduser('~/.config/certmaestro/certmaestro.ini')

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        self._cfg = ConfigParser()
        self._cfg.read_file(open(path))
        self.is_reconfigured = False

    def __repr__(self):
        return '<Certmaestro Config: %s>' % realpath(self.path)

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
    def backend_section(self):
        return self._cfg.get('certmaestro', 'backend')

    @property
    def backend_config(self):
        return self._cfg[self.backend_section]


def strtobool(value):
    """Convert boolean values the same way as ConfigParser does."""
    if isinstance(value, bool):
        return value
    value = value.lower()
    if value not in RawConfigParser.BOOLEAN_STATES:
        raise ValueError('Not a boolean: %s' % value)
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
        default = str(self.default) if self.default is not None else None
        return iter([self.name, self.help, default])


class BackendBuilder:
    """Helps to setup the backend by the defined Params in init_requires and setup_requires."""

    def __iter__(self):
        return iter(self.init_requires + self.setup_requires)

    def validate(self):
        for param in self:
            value = getattr(self, param.name, param.default)
            if value is None:
                raise ValueError('Parameter %r is needed' % param.name)
            if param.validator is None:
                continue
            param.validator(value)

    def is_valid(self):
        try:
            self.validate()
            return True
        except ValueError:
            return False

    def __setitem__(self, name, value):
        if name not in (p.name for p in self):
            raise AttributeError('Name %r is not found in this builder' % name)
        super().__setattr__(name, value)

    def __getitem__(self, name):
        return getattr(self, name, None)

    @property
    def all_params(self):
        return {par.name: getattr(self, par.name, par.default) for par in self}

    @property
    def init_params(self):
        return {par.name: getattr(self, par.name, par.default) for par in self.init_requires}

    @property
    def setup_params(self):
        return {par.name: getattr(self, par.name, par.default) for par in self.setup_requires}

    def setup_backend(self):
        backend = self.backend_class(**self.init_params)
        backend.setup(**self.setup_params)
        return backend
