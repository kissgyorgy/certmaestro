from zope.interface import implementer
import hvac
from ..config import section_param
from .base import IConfig, IBackend


@implementer(IConfig)
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

    def check_config(self):
        self.client = hvac.Client(self.config.url, self.config.token)
        return self.client.is_authenticated()

    def __str__(self):
        return '<VaultBackend: {}>\n'.format(self.config.url)

    def init(self, *, mount_point, max_lease_ttl, common_name, role, allowed_domains,
             allow_subdomains, role_max_ttl):
        self.client.enable_secret_backend('pki', mount_point=mount_point)
        ttl = '%sh' % max_lease_ttl
        # vault mount-tune -max-lease-ttl=87600h pki
        self.client.write('sys/mounts/{}/tune'.format(mount_point), max_lease_ttl=ttl)
        self.client.write('pki/root/generate/internal', common_name=common_name, ttl=ttl)
        # $ vault write pki/roles/example-dot-com
        #       allowed_domains="example.com" allow_subdomains="true" max_ttl="72h"
        max_ttl = '%sh' % role_max_ttl
        self.client.write('pki/roles/%s' % role, allowed_domains=allowed_domains,
                          allow_subdomains=allow_subdomains, max_ttl=max_ttl)

    def get_ca_cert(self):
        return self.client.read('pki/cert/ca')

    def issue_cert(self, common_name):
        issue_url = 'pki/issue/%s' % self.config.role
        return self.client.write(issue_url, common_name=common_name)

    def get_cert_list(self):
        cert_list_url = '/pki/certs/?list=true'
        return self.client.read(cert_list_url)

    def get_cert(self, serial):
        cert_detail_url = '/pki/cert/%s' % serial
        return self.client.read(cert_detail_url)