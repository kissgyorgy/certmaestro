from os.path import expanduser, realpath
from configparser import ConfigParser, RawConfigParser


class Config:
    DEFAULT_PATH = expanduser('~/.config/certmaestro/certmaestro.ini')

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        self._cfg = ConfigParser()
        self._cfg.read_file(open(path))

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


def getbool(value):
    """Convert boolean values the same way as ConfigParser does."""
    if value.lower() not in RawConfigParser.BOOLEAN_STATES:
        raise ValueError('Not a boolean: %s' % value)
    return RawConfigParser.BOOLEAN_STATES[value.lower()]


def starts_with_http(instance, attribute, value):
    if not value.startswith('http://') and not value.startswith('https://'):
        raise ValueError('URL needs to start with http:// or https://')
