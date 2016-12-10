from zope.interface import Interface, Attribute


class IBackend(Interface):
    init_requires = Attribute('Params required for backend init like url or file path')
    setup_requires = Attribute('Param required for setting up backend for the first time')
    version = Attribute('Backend software or library version.')

    def validate_setup(self, **kwargs):
        """Check if setup would be successful."""

    def setup(self, **kwargs):
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
