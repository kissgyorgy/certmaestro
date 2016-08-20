from zope.interface import implementer
import hvac
import attr
from requests.exceptions import RequestException
from ..exceptions import BackendError
from ..wrapper import Cert, Crl
from ..config import starts_with_http, getbool
from .interfaces import IBackendConfig, IBackend


@implementer(IBackendConfig)
@attr.s(slots=True, cmp=False)
class VaultConfig:
    name = 'Vault'

    common_name = attr.ib()
    token = attr.ib(repr=False)
    role = attr.ib()
    allowed_domains = attr.ib()
    url = attr.ib(default='http://localhost:8200', validator=starts_with_http)
    mount_point = attr.ib(default='pki')
    max_lease_ttl = attr.ib(default=87600, convert=int)
    allow_subdomains = attr.ib(default=True, convert=getbool)
    role_max_ttl = attr.ib(default=72, convert=int)

    required = [
        ('url', 'URL of the Vault server'),
        ('token', 'Token for accessing Vault'),
        ('common_name', 'Common Name for root certificate'),
        ('mount_point', "Mount point of the 'pki' secret backend"),
        ('max_lease_ttl', 'Max lease ttl (hours)'),
        ('role', 'Role issuing certificates'),
        ('allowed_domains', 'Allowed domains'),
        ('allow_subdomains', 'Allow subdomains?'),
        ('role_max_ttl', 'Role max ttl (hours)'),
    ]

    @classmethod
    def get_defaults(cls):
        return {att.name: att.default for att in cls.__attrs_attrs__
                if att.default is not attr.NOTHING}


@implementer(IBackend)
class VaultBackend:

    def __init__(self, config: VaultConfig):
        self.config = config
        self._client = hvac.Client(self.config.url, self.config.token)

        try:
            is_authenticated = self._client.is_authenticated()
        except RequestException as e:
            # Every kind of error which happened during connecting to Vault
            raise BackendError(str(e))

        if not is_authenticated:
            raise BackendError('Invalid connection credentials!')

    def __str__(self):
        return '<VaultBackend: {}>\n'.format(self.config.url)

    @property
    def max_lease_ttl(self):
        url = '/sys/mounts/%s/tune' % self.mount_point
        return self._client.read(url)['max_lease_ttl']

    def init(self, *, mount_point, max_lease_ttl, common_name, role, allowed_domains,
             allow_subdomains, role_max_ttl):
        self._client.enable_secret_backend('pki', mount_point=mount_point)
        ttl = '%sh' % max_lease_ttl
        # vault mount-tune -max-lease-ttl=87600h pki
        self._client.write('sys/mounts/{}/tune'.format(mount_point), max_lease_ttl=ttl)
        self._client.write('pki/root/generate/internal', common_name=common_name, ttl=ttl)
        # $ vault write pki/roles/example-dot-com
        #       allowed_domains="example.com" allow_subdomains="true" max_ttl="72h"
        max_ttl = '%sh' % role_max_ttl
        self._client.write('pki/roles/%s' % role, allowed_domains=allowed_domains,
                           allow_subdomains=allow_subdomains, max_ttl=max_ttl)

    def get_ca_cert(self) -> Cert:
        return Cert(self._client.read('pki/ca/pem'))

    def issue_cert(self, common_name):
        issue_url = 'pki/issue/%s' % self.config.role
        return self._client.write(issue_url, common_name=common_name)

    def revoke_cert(self, serial_number):
        return self._client.write('pki/revoke', serial_number=serial_number)

    def get_cert_list(self):
        res = self._client.list('pki/certs')
        for serial_number in res['data']['keys']:
            yield self.get_cert(serial_number)

    def get_cert(self, serial_number) -> Cert:
        res = self._client.read('pki/cert/%s' % serial_number)
        pem_data = res['data']['certificate']
        return Cert(pem_data)

    def get_crl(self) -> Crl:
        res = self._client.read('pki/cert/crl')
        pem_data = res['data']['certificate']
        return Crl(pem_data)
