from zope.interface import implementer
import hvac
from requests.exceptions import RequestException
from ..exceptions import BackendError
from ..wrapper import Cert, Crl
from ..config import starts_with_http, strtobool, Param
from .interfaces import IBackend


@implementer(IBackend)
class VaultBackend:
    name = 'Vault'
    description = "Hashicorp's Vault: https://www.vaultproject.io"

    init_requires = (
        Param('url', default='http://localhost:8200', validator=starts_with_http,
              help='URL of the Vault server'),
        Param('token', help='Token for accessing Vault'),
        Param('mount_point', default='pki', help="Mount point of the 'pki' secret backend"),
        Param('role', help='Role issuing certificates'),
    )

    setup_requires = (
        Param('common_name', help='Common Name for root certificate'),
        Param('allowed_domains', help='Allowed domains'),
        Param('max_lease_ttl', default=87600, convert=int, help='Max lease ttl (hours)'),
        Param('allow_subdomains', default=True, convert=strtobool, help='Allow subdomains?'),
        Param('role_max_ttl', default=72, convert=int, help='Role max TTL (hours)')
    )

    def __init__(self, url, token, mount_point, role):
        self._client = hvac.Client(url, token)
        # normalize mount_point to naked, so we can consistently use in strings
        self.mount_point = mount_point[:-1] if mount_point.endswith('/') else mount_point
        self.role = role

        try:
            is_authenticated = self._client.is_authenticated()
        except RequestException as e:
            # Every kind of error which happened during connecting to Vault
            raise BackendError('Could not connect to Vault server. Check address and credentials!')

        if not is_authenticated:
            raise BackendError('Invalid connection credentials!')

    def __str__(self):
        return f'<VaultBackend: {self._url}>\n'

    def _get_max_lease_ttl(self):
        tune_url = f'/sys/mounts/{self.mount_point}/tune'
        return self._client.read(tune_url)['max_lease_ttl']

    def _get_settings(self):
        role_url = f'{self.mount_point}/roles/{self.role}'
        return self._client.read(role_url)['data']

    def validate_setup(self, **setup_params):
        """Check if setup would be successful."""
        secret_backends = self._client.list_secret_backends()
        if f'{self.mount_point}/' in secret_backends['data']:
            raise ValueError('Secret backend already exists!')

    def setup(self, *, common_name, max_lease_ttl, allowed_domains, allow_subdomains, role_max_ttl):  # noqa
        self._client.enable_secret_backend('pki', mount_point=self.mount_point)
        ttl = f'{max_lease_ttl}h'
        # vault mount-tune -max-lease-ttl=87600h pki
        self._client.write(f'sys/mounts/{self.mount_point}/tune', max_lease_ttl=ttl)
        self._client.write(f'{self.mount_point}/root/generate/internal',
                           common_name=common_name, ttl=ttl)
        # $ vault write pki/roles/example-dot-com
        #       allowed_domains="example.com" allow_subdomains="true" max_ttl="72h"
        max_ttl = f'{role_max_ttl}h'
        self._client.write(f'{self.mount_point}/roles/{self.role}', max_ttl=max_ttl,
                           allowed_domains=allowed_domains, allow_subdomains=allow_subdomains)

    def get_ca_cert(self) -> Cert:
        res = self._client.read(f'{self.mount_point}/cert/ca')
        return Cert(res['data']['certificate'])

    def issue_cert(self, common_name):
        return self._client.write(f'{self.mount_point}/issue/{self.role}', common_name=common_name)

    def revoke_cert(self, serial_number):
        return self._client.write(f'{self.mount_point}/revoke', serial_number=serial_number)

    def get_cert_list(self):
        res = self._client.list(f'{self.mount_point}/certs')
        for serial_number in res['data']['keys']:
            yield self.get_cert(serial_number)

    def get_cert(self, serial_number) -> Cert:
        res = self._client.read(f'{self.mount_point}/cert/{serial_number}')
        pem_data = res['data']['certificate']
        return Cert(pem_data)

    def get_crl(self) -> Crl:
        res = self._client.read(f'{self.mount_point}/cert/crl')
        pem_data = res['data']['certificate']
        return Crl(pem_data)
