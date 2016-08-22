from zope.interface import Interface, Attribute


class IBackendBuilder(Interface):
    backend_class = Attribute()
    init_requires = Attribute('Parameters required for backend initialization'
                              'like url or file path')
    setup_requires = Attribute('Parameters required for setting up backend for the first time')


class IBackend(Interface):

    def check_config(self):
        """Integrity and other checks if everything is ok with the configuration.
        e.g. Can connect, every file are there, checksums are ok, etc.
        """

    def init(self, **kwargs):
        """Initialize configuration with backend specific parameters."""

    def get_ca_cert(self):
        """Get CA certificate."""

    def issue_cert(self, common_name):
        """Issue a new cert for a Common Name."""

    def revoke_cert(self, serial_number):
        """Revoke certificate by serial number."""

    def get_cert_list(self):
        """Get the list of all the issued certificates."""

    def get_cert(self, serial):
        """Get certificate."""

    def get_crl(self):
        """Get certificate revocation list."""
