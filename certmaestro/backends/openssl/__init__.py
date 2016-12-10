from os.path import isfile, isdir, join
from zope.interface import implementer
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from ...wrapper import Cert, Crl
from ...config import Param
from ...exceptions import BackendError
from ..interfaces import IBackend
from .parser import OpenSSLConfigParser


@implementer(IBackend)
class OpenSSLBackend:
    name = 'OpenSSL'
    description = 'Command line tools with openssl.cnf, https://www.openssl.org'

    init_requires = (
        Param('config_path', help='Path to the openssl config file (usually openssl.cnf)'),
        Param('root_dir', help='Working directory for the OpenSSL files and directories. Relative '
                               'directory definitions in config file are compared to this.'),
        Param('crl_path', help='Path to the Certificate Revocation List file (usually crl.pem)'),
    )

    def __init__(self, config_path, root_dir, crl_path):
        if not isdir(root_dir):
            raise BackendError('Root dir is not a directory')
        self._root_dir = root_dir

        if not isfile(config_path):
            raise BackendError('Config path is not a file')
        self._config_path = config_path

        if not isfile(crl_path):
            raise BackendError('Crl path is not a file')
        self._crl_path = crl_path

        self._cnf = OpenSSLConfigParser()
        with open(config_path) as f:
            self._cnf.read_file(f)

    def get_ca_cert(self):
        ca_section_name = self._cnf['ca']['default_ca']
        ca_section = self._cnf[ca_section_name]
        ca_cert_path = join(self._root_dir, ca_section['certificate'])
        return Cert.from_file(ca_cert_path)


    def get_crl(self):
        return Crl.from_file(self._crl_path)

    @property
    def version(self) -> str:
        return openssl_backend.openssl_version_text()
