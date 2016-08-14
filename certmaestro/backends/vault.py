from zope.interface import implementer
import hvac
from ..wrapper import Cert, Crl
from ..config import section_param
from .base import IBackendConfig, IBackend


@implementer(IBackendConfig)
class VaultConfig:
    name = 'Vault'
    url = section_param('url', 'http://localhost:8200')
    common_name = section_param('common_name')
    mount_point = section_param('mount_point', 'pki')
    token = section_param('token')
    max_lease_ttl = section_param('max_lease_ttl', 87600)
    role = section_param('role')
    allowed_domains = section_param('allowed_domains')
    allow_subdomains = section_param('allow_subdomains', True)
    role_max_ttl = section_param('role_max_ttl', 72)

    check_config_requires = [
        ('url', 'URL of the Vault server'),
        ('token', 'Token for accessing Vault'),
    ]
    init_requires = [
        ('common_name', 'Common Name for root certificate'),
        ('mount_point', "Mount point of the 'pki' secret backend"),
        ('max_lease_ttl', 'Max lease ttl (hours)'),
        ('role', 'Role issuing certificates'),
        ('allowed_domains', 'Allowed domains'),
        ('allow_subdomains', 'Allow subdomains?'),
        ('role_max_ttl', 'Role max ttl (hours)'),
    ]

    def __init__(self, section):
        self._section = section

    def __str__(self):
        return "Backend: {}\nPath: {}\nToken: {}".format(self.name, self.url, self.token)


@implementer(IBackend)
class VaultBackend:

    def __init__(self, config: VaultConfig):
        self.config = config
        self._client = hvac.Client(self.config.url, self.config.token)

    def check_config(self):
        return self._client.is_authenticated()

    def __str__(self):
        return '<VaultBackend: {}>\n'.format(self.config.url)

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
