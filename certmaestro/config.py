from os.path import expanduser, realpath
from configparser import ConfigParser


class Config:
    DEFAULT_PATH = expanduser('~/.config/certmaestro/certmaestro.ini')

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        cfg = ConfigParser()
        cfg.read_file(open(path))
        self._cfg = cfg

    def __str__(self):
        return 'Certmaestro Config Path: {}\n'.format(realpath(self.path))

    def __repr__(self):
        return '<Certmaestro Config: %s>' % realpath(self.path)

    def reload(self):
        self._cfg.read(self.path)

    def save(self):
        with open(self.path, 'w') as configfile:
            self._cfg.write(configfile)

    def delete(self):
        ...

    @property
    def backend_name(self):
        return self._cfg.get('certmaestro', 'backend')

    @property
    def backend_config(self):
        return self._cfg[self.backend_name]


class section_param:
    """Descriptor for backend configs to directly read from ConfigParser sections."""

    def __init__(self, name, default=None):
        self.name = name
        self.default = default

    def __get__(self, obj, cls=None):
        return obj._section.get(self.name, self.default)

    def __set__(self, obj, value):
        obj._section[self.name] = value
