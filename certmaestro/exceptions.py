class ConfigurationError(Exception):
class CertmaestroError(Exception):
    """Base Exception for all kinds of Certmaestro related errors."""


    """Something is wrong with Certmaestro's configuration.
    It's possible that we can't even find the backend because of this.
    """


class BackendConfigurationError(Exception):
    """Something is wrong with the backend configuration."""

    def __init__(self, backend_name, message, required, defaults):
        self.backend_name = backend_name
        self.message = message
        self.required = required
        self.defaults = defaults


class BackendError(Exception):
    """Something is wrong with the backend, the configuration might be good.
    e.g. Cannot connect.
    """


class UrlParseError(ValueError, CertmaestroError):
    "Raised when parse_url or similar fails to parse the URL input."

    def __init__(self, location):
        super().__init__("Failed to parse: %s" % location)
        self.location = location
