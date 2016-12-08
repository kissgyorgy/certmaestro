from os.path import exists, isdir
from configparser import ConfigParser
from zope.interface import implementer
from ..interfaces import IBackend
from ...wrapper import Cert
from .configparser import OpenSSLInterpolation


@implementer(IBackend)
class OpenSSLBackend:
    name = 'OpenSSL'
    description = 'command line tools with openssl.cnf, https://www.openssl.org'

    init_requires = [
        ('file_path', 'Path to the openssl config file (usually openssl.cnf)'),
        ('dir_path', 'Path to the default_ca directory (dir value in the openss.cnf)')
    ]

    def __init__(self, file_path, dir_path):
        self._file_path = file_path
        self._dir_path = dir_path
        self._cnf = ConfigParser(interpolation=OpenSSLInterpolation)
        self._cnf.read_file(open(file_path))

    def check_config(self):
        if exists(self._file_path) and isdir(self._dir_path):
            return True
        return False

    def init(self, **kwargs):
        ...

    def get_ca_cert(self):
        ca_section = self._cnf[' ca ']['default_ca']
        ca_cert_path = self._cnf[f' {ca_section} ']['certificate']
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
