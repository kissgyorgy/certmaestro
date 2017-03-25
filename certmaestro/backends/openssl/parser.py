import re
from configparser import (
    Interpolation, InterpolationSyntaxError, InterpolationMissingOptionError,
    ConfigParser
)

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
