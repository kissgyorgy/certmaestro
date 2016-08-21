from zope.interface import implementer
import hvac
import attr
from requests.exceptions import RequestException
from ..exceptions import BackendError
from ..wrapper import Cert, Crl
from ..config import starts_with_http, strtobool
from .interfaces import IBackendConfig, IBackend


@attr.s(slots=True, cmp=False)
class VaultInitParams:
    common_name = attr.ib()
    allowed_domains = attr.ib()
    mount_point = attr.ib(default='pki')
    max_lease_ttl = attr.ib(default=87600, convert=int)
    allow_subdomains = attr.ib(default=True, convert=strtobool)
    role_max_ttl = attr.ib(default=72, convert=int)

    help = [
        ('common_name', 'Common Name for root certificate'),
        ('max_lease_ttl', 'Max lease ttl (hours)'),
        ('allowed_domains', 'Allowed domains'),
        ('allow_subdomains', 'Allow subdomains?'),
        ('role_max_ttl', 'Role max ttl (hours)'),
    ]


@implementer(IBackendConfig)
@attr.s(slots=True, cmp=False)
class VaultConfig:
    role = attr.ib()
    token = attr.ib(repr=False)
    url = attr.ib(default='http://localhost:8200', validator=starts_with_http)
    mount_point = attr.ib(default='pki')

    help = [
        ('url', 'URL of the Vault server'),
        ('token', 'Token for accessing Vault'),
        ('role', 'Role issuing certificates'),
        ('mount_point', "Mount point of the 'pki' secret backend"),
    ]

    @classmethod
    def get_defaults(cls):
        return {att.name: att.default for att in cls.__attrs_attrs__
                if att.default is not attr.NOTHING}


@implementer(IBackend)
class VaultBackend:
    name = 'Vault'
    description = "Hashicorp's Vault: https://www.vaultproject.io"

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
        return Cert(self._client.read('{}/ca/pem'.format(self.mount_point)))

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
