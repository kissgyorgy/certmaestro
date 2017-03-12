import os
from os.path import isfile, join, isdir
import subprocess
from zope.interface import implementer
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from ...wrapper import Cert, Key, Crl, SerialNumber
from ...config import Param
from ...exceptions import BackendError
from ..interfaces import IBackend
from .parser import OpenSSLConfigParser


@implementer(IBackend)
class OpenSSLBackend:
    name = 'OpenSSL'
    description = 'Command line tools with openssl.cnf, https://www.openssl.org'

    init_requires = (
        Param('command_path', help='Path to the openssl binary'),
        Param('config_path', help='Path to the openssl config file (usually openssl.cnf)'),
        Param('root_dir', help='Working directory for the OpenSSL files and directories. Relative '
                               'directory definitions in config file are compared to this.'),
        Param('crl_path', help='Path to the Certificate Revocation List file (usually crl.pem)'),
    )

    def __init__(self, command_path, config_path, root_dir, crl_path):
        if not os.access(command_path, os.F_OK | os.X_OK):
            raise BackendError('OpenSSL command is not executable')
        self._command_path = command_path

        if not isdir(root_dir):
            raise BackendError("OpenSSL config directory (root_dir) doesn't exist")
        if not os.access(root_dir, os.R_OK | os.W_OK | os.X_OK):
            raise BackendError('OpenSSL config directory (root_dir) should have "rwx" permissions')
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

    @property
    def _ca_section(self):
        ca_section_name = self._cnf['ca']['default_ca']
        return self._cnf[ca_section_name]

    @property
    def _new_certs_dir(self):
        return join(self._root_dir, self._ca_section['new_certs_dir'])

    @property
    def _certs_dir(self):
        certs_dir = self._ca_section['certs']
        if certs_dir:
            return join(self._root_dir, certs_dir)
        else:
            return join(self._root_dir, self._ca_section['dir'], 'certs')

    def _openssl_command(self, main_command, *params):
        command = [self._command_path, main_command, '-config', self._config_path, *params]
        subprocess.run(command)

    def get_ca_cert(self):
        ca_cert_path = join(self._root_dir, self._ca_section['certificate'])
        return Cert.from_file(ca_cert_path)

    def issue_cert(self, common_name):
        basename = join(self._certs_dir, common_name)
        key_path = basename + '.key'
        csr_path = basename + '.csr'
        crt_path = basename + '.crt'
        self._openssl_command('req', '-newkey', 'rsa', '-keyout', key_path, '-out', csr_path)
        self._openssl_command('ca', '-out', crt_path, '-infiles', csr_path)

    def get_cert(self, serial_str: str) -> Cert:
        serial_hex = SerialNumber(serial_str).as_hex()
        cert_path = join(self._new_certs_dir, f'{serial_hex}.pem')
        return Cert.from_file(cert_path)

    def get_cert_list(self):
        for cert_filename in os.listdir(self._new_certs_dir):
            cert_path = join(self._new_certs_dir, cert_filename)
            yield Cert.from_file(cert_path)

    def get_crl(self):
        return Crl.from_file(self._crl_path)

    @property
    def version(self) -> str:
        return openssl_backend.openssl_version_text()
