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
        self.mount_point = mount_point
        self.role = role

        try:
            is_authenticated = self._client.is_authenticated()
        except RequestException as e:
            # Every kind of error which happened during connecting to Vault
            raise BackendError(str(e))

        if not is_authenticated:
            raise BackendError('Invalid connection credentials!')

    def __str__(self):
        return '<VaultBackend: %s>\n' % self._url

    def _get_max_lease_ttl(self):
        return self._client.read('/sys/mounts/%s/tune' % self.mount_point)['max_lease_ttl']

    def _get_settings(self):
        role_url = '{}/roles/{}'.format(self.mount_point, self.role)
        return self._client.read(role_url)['data']

    def setup(self, *, common_name, max_lease_ttl, allowed_domains, allow_subdomains,
              role_max_ttl):
        self._client.enable_secret_backend('pki', mount_point=self.mount_point)
        ttl = '%sh' % max_lease_ttl
        # vault mount-tune -max-lease-ttl=87600h pki
        self._client.write('sys/mounts/{}/tune'.format(self.mount_point), max_lease_ttl=ttl)
        self._client.write('{}/root/generate/internal'.format(self.mount_point),
                           common_name=common_name, ttl=ttl)
        # $ vault write pki/roles/example-dot-com
        #       allowed_domains="example.com" allow_subdomains="true" max_ttl="72h"
        max_ttl = '%sh' % role_max_ttl
        self._client.write('{}/roles/{}'.format(self.mount_point, self.role), max_ttl=max_ttl,
                           allowed_domains=allowed_domains, allow_subdomains=allow_subdomains)

    def get_ca_cert(self) -> Cert:
        res = self._client.read('{}/cert/ca'.format(self.mount_point))
        return Cert(res['data']['certificate'])

    def issue_cert(self, common_name):
        issue_url = '{}/issue/{}'.format(self.mount_point, self.role)
        return self._client.write(issue_url, common_name=common_name)

    def revoke_cert(self, serial_number):
        return self._client.write('{}/revoke'.format(self.mount_point),
                                  serial_number=serial_number)

    def get_cert_list(self):
        res = self._client.list('{}/certs'.format(self.mount_point))
        for serial_number in res['data']['keys']:
            yield self.get_cert(serial_number)

    def get_cert(self, serial_number) -> Cert:
        res = self._client.read('{}/cert/{}'.format(self.mount_point, serial_number))
        pem_data = res['data']['certificate']
        return Cert(pem_data)

    def get_crl(self) -> Crl:
        res = self._client.read('{}/cert/crl'.format(self.mount_point))
        pem_data = res['data']['certificate']
        return Crl(pem_data)
