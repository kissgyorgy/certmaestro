from pathlib import Path
from configparser import ConfigParser, RawConfigParser
import attr


CERT_FIELDS = (
    ('common_name', 'Common Name'),
    ('country', 'Country'),
    ('state', 'State'),
    ('locality', 'Locality'),
    ('org_name', 'Organization name'),
    ('org_unit', 'Organizational Unit'),
    ('email', 'Email address')
)


class Config:
    DEFAULT_PATH = Path('~/.config/certmaestro/certmaestro.ini').expanduser()

    def __init__(self, path: Path=DEFAULT_PATH):
        self.path = path.resolve()
        self._cfg = ConfigParser()
        with self.path.open() as f:
            self._cfg.read_file(f)

    @classmethod
    def make_new(cls, path: Path=DEFAULT_PATH):
        self = object.__new__(cls)
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cfg = ConfigParser()
        self._cfg.add_section('certmaestro')
        return self

    def __repr__(self):
        return f'<Certmaestro Config: {self.path}>'

    def __getitem__(self, name):
        return self._cfg.get('certmaestro', name)

    def __setitem__(self, name, value):
        self._cfg.set('certmaestro', name, value)

    def reload(self):
        self._cfg.read(self.path)

    def save(self):
        with self.path.open('w') as configfile:
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
