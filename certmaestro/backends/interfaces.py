from typing import Iterator
from abc import ABCMeta, abstractmethod
from ..wrapper import PrivateKey, Cert, RevokedCert, Crl


class IBackend(metaclass=ABCMeta):
    @property
    @abstractmethod
    def name(self):
        """Official name of the backend."""

    @property
    @abstractmethod
    def description(self):
        """One-line description about the backend."""

    @property
    @abstractmethod
    def threadsafe(self):
        """Tells if the backend can be used from multiple threads."""

    @property
    @abstractmethod
    def init_requires(self):
        """Params required for backend init like url or file path."""

    @property
    def setup_requires(self):
        """Param required for setting up backend for the first time."""

    @property
    @abstractmethod
    def version(self):
        """Backend software or library version."""

    def validate_setup(self, **kwargs):
        """Check if setup would be successful."""

    def setup(self, **kwargs):
        """Initialize configuration with backend specific parameters."""

    def get_ca_cert(self) -> Cert:
        """Get CA certificate."""

    def issue_cert(self, common_name) -> (PrivateKey, Cert):
        """Issue a new cert for a Common Name."""

    def revoke_cert(self, serial: str) -> RevokedCert:
        """Revoke certificate by serial number."""

    def list_certs(self) -> Iterator[Cert]:
        """Get the list of all the issued certificates."""

    def get_cert(self, serial: str) -> Cert:
        """Get certificate."""

    def get_crl(self) -> Crl:
        """Get certificate revocation list."""
