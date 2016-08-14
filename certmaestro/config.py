from os.path import expanduser, realpath
from configparser import ConfigParser, RawConfigParser


class Config:
    DEFAULT_PATH = expanduser('~/.config/certmaestro/certmaestro.ini')

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        cfg = ConfigParser()
        cfg.read_file(open(path))
        self._cfg = cfg

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
    def backend_name(self):
        return self._cfg.get('certmaestro', 'backend')

    @property
    def backend_config(self):
        return self._cfg[self.backend_name]


class DictLikeMixin:
    """Make backend config act like a dictionary."""

    def __iter__(self):
        return ((attr_name, getattr(self, attr_name))
                for attr_name in self.__slots__)

    def __getitem__(self, name):
        return getattr(self, name)

    def __setitem__(self, name, value):
        setattr(self, name, value)


def getbool(value):
    """Convert boolean values the same way as ConfigParser does."""
    if value.lower() not in RawConfigParser.BOOLEAN_STATES:
        raise ValueError('Not a boolean: %s' % value)
    return RawConfigParser.BOOLEAN_STATES[value.lower()]


def starts_with_http(instance, attribute, value):
    if not value.startswith('http://') and not value.startswith('https://'):
        raise ValueError('URL needs to start with http:// or https://')
