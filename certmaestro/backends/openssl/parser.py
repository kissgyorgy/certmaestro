import re
import mmap
from pathlib import Path
import attr
from configparser import (
    Interpolation, InterpolationSyntaxError, InterpolationMissingOptionError,
    ConfigParser
)
from ...wrapper import FromFileMixin, SerialNumber


class OpenSSLInterpolation(Interpolation):
    """Interpolation that is able to handle OpenSSL's special $dir values."""

    _KEYCRE = re.compile(r"\$\{?(\w*)\}?")

    def before_get(self, parser, section, option, value, defaults):
        dollar_ind = value.find('$')
        if dollar_ind == -1:
            return value

        colon_ind = value.find('::')
        if colon_ind != -1 and value[dollar_ind + 1:colon_ind] == 'ENV':
            env_name = value[colon_ind + 2:]
            return parser.env.get(env_name)

        m = self._KEYCRE.match(value[dollar_ind:])
        if m is None:
            raise InterpolationSyntaxError(option, section,
                                           "bad interpolation variable reference {value}")
        var = parser.optionxform(m.group(1))
        try:
            val = defaults[var]
        except KeyError:
            raise InterpolationMissingOptionError(option, section, value, var) from None

        return val + value[m.end():]


class OpenSSLConfigParser(ConfigParser):

    _DEFAULT_INTERPOLATION = OpenSSLInterpolation()
    # OpenSSL section names usually contains space before and after
    SECTCRE = re.compile(r"\[\s*(?P<header>\w*)\s*\]")

    def __init__(self, *args, env=None, **kwargs):
        self.env = env
        super().__init__(*args, **kwargs)


@attr.s
class OpenSSLDbEntry:
    status = attr.ib()
    expiration = attr.ib()
    revocation = attr.ib()
    serial_number = attr.ib()
    filename = attr.ib()
    dist_name = attr.ib()


class OpenSSLDbParser(FromFileMixin):
    """Parses OpenSSL's index.txt certificate database.
    Every line in the file contains information about certificates. The format is the following:
    1. Status flag (V=valid, R=revoked, E=expired).
    2. Expiration date in YYMMDDHHMMSSZ format.
    3. Revocation date in YYMMDDHHMMSSZ[,reason] format. Empty if not revoked.
    4. Serial number in hex.
    5. Filename or literal string ‘unknown’.
    6. Distinguished name.
    from: http://pki-tutorial.readthedocs.io/en/latest/cadb.html
    """

    def __init__(self, db_file: Path):
        self._file = db_file
        if not self._is_db_empty():
            # have to keep the reference to the opened file
            self._open_file = db_file.open('r+b')
            self._mm = mmap.mmap(self._open_file.fileno(), 0)
        else:
            self._open_file = None
            self._mm = None

    def _is_db_empty(self):
        return self._file.stat().st_size == 0

    def __iter__(self):
        # it can have content since we last tried
        if self._is_db_empty():
            return iter(())
        self._mm.seek(0)
        return self._iter_file()

    def __del__(self):
        if self._open_file is not None:
            self._open_file.close()
            self._mm.close()

    def _iter_file(self):
        for line in iter(self._mm.readline, b''):
            columns = line.rstrip().decode().split('\t')
            status, expiration, revocation, serial, filename, dist_name = columns
            serial_number = SerialNumber(serial)
            yield OpenSSLDbEntry(status, expiration, revocation, serial_number, filename,
                                 dist_name)

    def get_by_serial_number(self, serial_str: str):
        for entry in self:
            if entry.serial_number == SerialNumber(serial_str):
                return entry
