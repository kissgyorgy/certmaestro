from configparser import Interpolation


class OpenSSLInterpolation(Interpolation):
    """Interpolation that is able to handle OpenSSL's special $dir values."""

    def before_get(self, parser, section, option, value, defaults):
        import q; q(value)
        return value

    def before_set(self, parser, section, option, value):
        return value

    def before_read(self, parser, section, option, value):
        return value

    def before_write(self, parser, section, option, value):
        return value
