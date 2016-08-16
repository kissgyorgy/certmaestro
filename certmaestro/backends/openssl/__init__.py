from os.path import exists, isdir
from configparser import ConfigParser
from zope.interface import implementer
import attr
from ..interfaces import IBackendConfig, IBackend
from ...wrapper import Cert
from .configparser import OpenSSLInterpolation


@implementer(IBackendConfig)
@attr.s(slots=True, cmp=False)
class OpenSSLConfig:
    name = "OpenSSL"

    file_path = attr.ib()
    dir_path = attr.ib()

    check_config_requires = [
        ('file_path', 'Path to the openssl config file (usually openssl.cnf)'),
        ('dir_path', 'Path to the default_ca directory '
         '(dir value in the openss.cnf)')
    ]


@implementer(IBackend)
class OpenSSLBackend:

    def __init__(self, config):
        self.config = config

        self._cnf = ConfigParser(interpolation=OpenSSLInterpolation)
        self._cnf.read_file(open(config.file_path))

    def check_config(self):
        if exists(self.config.file_path) and isdir(self.config.dir_path):
            return True
        return False

    def init(self, **kwargs):
        ...

    def get_ca_cert(self):
        ca_section = self._cnf[' ca ']['default_ca']
        ca_cert_path = self._cnf[' %s ' % ca_section]['certificate']
        return Cert.from_file(ca_cert_path)

    def issue_cert(self, common_name):
        ...

    def revoke_cert(self, serial_number):
        ...

    def get_cert_list(self):
        ...

    def get_cert(self, serial):
        ...

    def get_crl(self):
        ...
