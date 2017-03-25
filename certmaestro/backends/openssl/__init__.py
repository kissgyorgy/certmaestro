import os
import shutil
from typing import Optional, Mapping
from pathlib import Path
from subprocess import run, PIPE
from typing import Iterator
from zope.interface import implementer
from ...wrapper import Cert, PrivateKey, Crl, SerialNumber
from ...config import Param
from ...exceptions import BackendError
from ...csr import CsrPolicy, CsrBuilder
from ..interfaces import IBackend
from .parser import OpenSSLConfigParser


@implementer(IBackend)
class OpenSSLBackend:
    name = 'OpenSSL'
    description = 'Command line tools with openssl.cnf, https://www.openssl.org'

    init_requires = (
        Param('openssl_binary', help='Path to the openssl binary', convert=Path),
        Param('config_file', help='Path to the openssl config file (usually openssl.cnf)',
              convert=Path),
        Param('root_dir', help='Working directory for the OpenSSL files and directories. Relative '
                               'directory definitions in config file are compared to this.',
              convert=Path),
        Param('crl_file', help='Path to the Certificate Revocation List file (usually crl.pem)',
              convert=Path),
    )

    def __init__(self, openssl_binary: Path, config_file: Path, root_dir: Path, crl_file: Path,
                 env: Optional[Mapping]=None):
        if not self._check_file(openssl_binary):
            openssl_binary = Path(shutil.which(openssl_binary))
        if not self._check_file(openssl_binary):
            raise BackendError('OpenSSL command not found')
        if not os.access(openssl_binary, os.X_OK):
            raise BackendError('OpenSSL command is not executable')
        self._openssl_binary = openssl_binary

        if not root_dir.is_dir():
            raise BackendError("OpenSSL config directory (root_dir) doesn't exist")
        if not os.access(root_dir, os.R_OK | os.W_OK | os.X_OK):
            raise BackendError('OpenSSL config directory (root_dir) should have "rwx" permissions')
        self._root_dir = root_dir

        if not config_file.is_file():
            raise BackendError('Config path is not a file')
        self._config_path = config_file

        # The CRL file not always exists, we should allow this and generate on demand
        self._crl_file = crl_file

        if env is None:
            env = os.environ.copy()
        self._cnf = OpenSSLConfigParser(inline_comment_prefixes=('#', ';'), env=env)

        with config_file.open() as f:
            self._cnf.read_file(f)

    @staticmethod
    def _check_file(openssl_binary):
        return openssl_binary.is_file() and os.access(openssl_binary, os.F_OK)

    @property
    def _ca_section(self):
        ca_section_name = self._cnf['ca']['default_ca']
        return self._cnf[ca_section_name]

    @property
    def _distinguished_name_section(self):
        section_name = self._cnf['req']['distinguished_name']
        return self._cnf[section_name]

    @property
    def _policy_section(self):
        section_name = self._ca_section['policy']
        return self._cnf[section_name]

    @property
    def _new_certs_dir(self):
        return self._root_dir / self._ca_section['new_certs_dir']

    @property
    def _certs_dir(self):
        certs_dir = self._ca_section['certs']
        if certs_dir:
            return self._root_dir / certs_dir
        else:
            return self._root_dir / self._ca_section['dir'] / 'certs'

    def _openssl(self, main_command, *params, input=None):
        command = [self._openssl_binary, main_command, '-config', self._config_path, *params]
        result = run(command, stdout=PIPE, stderr=PIPE, input=input, check=True,
                     universal_newlines=True)
        return result.stdout

    def get_ca_cert(self) -> Cert:
        ca_cert_path = self._root_dir / self._ca_section['certificate']
        return Cert.from_file(ca_cert_path)

    def _adapt_policy(self, policy):
        policy = policy.lower()
        if policy == 'supplied':
            return CsrPolicy.REQUIRED
        elif policy == 'match':
            return CsrPolicy. FROMCA
        elif policy == 'optional':
            return CsrPolicy.OPTIONAL

    def get_csr_policy(self):
        psec = self._policy_section
        return {
            'common_name': self._adapt_policy(psec['commonName']),
            'country': self._adapt_policy(psec['countryName']),
            'state': self._adapt_policy(psec['stateOrProvinceName']),
            'locality': self._adapt_policy(psec['localityName']),
            'org_name': self._adapt_policy(psec['organizationName']),
            'org_unit': self._adapt_policy(psec['organizationalUnitName']),
            'email': self._adapt_policy(psec['emailAddress']),
        }

    def get_csr_defaults(self):
        dnsec = self._distinguished_name_section
        return {
            'common_name': dnsec.get('commonName_default'),
            'country': dnsec.get('countryName_default'),
            'state': dnsec.get('stateOrProvinceName_default'),
            'locality': dnsec.get('localityName_default'),
            'org_name': dnsec.get('organizationName_default'),
            'org_unit': dnsec.get('organizationalUnitName_default'),
            'email': dnsec.get('emailAddress_default'),
        }

    def issue_cert(self, csr: CsrBuilder) -> (PrivateKey, Cert):
        # openssl req -newkey rsa -nodes -subj "/C=HU/ST=Pest megye/L=Budapest/O=Company/CN=Domain"
        key_and_csr_pem = self._openssl('req', '-newkey', 'rsa', '-nodes', '-subj', csr.subject)
        key_pem, csr_pem = self._split_pem(key_and_csr_pem)
        cert_pem = self._openssl('ca', '-batch', '-notext', '-in', '/dev/stdin', input=csr_pem)
        cert = Cert(cert_pem)
        serial_hex = cert.serial_number.as_hex()
        self._save_pem(cert_pem, serial_hex + '.pem')
        self._save_pem(key_pem, serial_hex + '.key')
        return PrivateKey(key_pem), cert

    def _split_pem(self, key_and_csr_pem: str):
        end_text = '-----END PRIVATE KEY-----'
        # new line is included at the end
        key_pem_end = key_and_csr_pem.find(end_text) + len(end_text)
        key_pem = key_and_csr_pem[:key_pem_end]
        csr_pem = key_and_csr_pem[key_pem_end + 1:]  # new line excluded from the start
        return key_pem, csr_pem

    def _save_pem(self, pem_data: str, filename: str):
        path = self._certs_dir / filename
        path.write_text(pem_data)

    def get_cert(self, serial_str: str) -> Cert:
        serial_hex = SerialNumber(serial_str).as_hex()
        cert_path = self._new_certs_dir / f'{serial_hex}.pem'
        return Cert.from_file(cert_path)

    def get_cert_list(self) -> Iterator[Cert]:
        for cert_path in self._new_certs_dir.iterdir():
            yield Cert.from_file(cert_path)

    def get_crl(self):
        return Crl.from_file(self._crl_file)

    @property
    def version(self) -> str:
        result = run([self._openssl_binary, 'version'], stdout=PIPE, universal_newlines=True)
        return result.stdout.rstrip()
