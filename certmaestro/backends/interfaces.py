from typing import Iterator
from zope.interface import Interface, Attribute
from ..wrapper import PrivateKey, Cert, Crl


class IBackend(Interface):
    init_requires = Attribute('Params required for backend init like url or file path')
    setup_requires = Attribute('Param required for setting up backend for the first time')
    version = Attribute('Backend software or library version.')

    def validate_setup(self, **kwargs):
        """Check if setup would be successful."""

    def setup(self, **kwargs):
        """Initialize configuration with backend specific parameters."""

    def get_ca_cert(self) -> Cert:
        """Get CA certificate."""

    def issue_cert(self, common_name) -> (PrivateKey, Cert):
        """Issue a new cert for a Common Name."""

    def revoke_cert(self, serial_str):
        """Revoke certificate by serial number."""

    def get_cert_list(self) -> Iterator[Cert]:
        """Get the list of all the issued certificates."""

    def get_cert(self, serial_str) -> Cert:
        """Get certificate."""

    def get_crl(self) -> Crl:
        """Get certificate revocation list."""
