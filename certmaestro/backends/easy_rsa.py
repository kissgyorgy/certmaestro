import os
from pathlib import Path
from typing import Iterator
from subprocess import run, PIPE, DEVNULL
from ..wrapper import PrivateKey, Cert, RevokedCert, SerialNumber, Crl
from ..config import Param
from ..exceptions import BackendError
from ..csr import CsrBuilder
from .interfaces import IBackend
from .openssl import OpenSSLBackend, OpenSSLDbParser


class EasyRSA2Backend(IBackend):
    name = 'Easy-RSA 2.X'
    description = "OpenVPN's simple shell-based CA utility: https://github.com/OpenVPN/easy-rsa"
    threadsafe = False

    init_requires = (
        Param('root_dir', help=f'Where the files of {name} are stored '
                                '(where the file named "vars" is found)',
              convert=Path),
    )

    def __init__(self, root_dir: Path):
        if not root_dir.is_dir():
            raise BackendError('Root dir is not a directory')
        self._root_dir = root_dir
        vars_file = root_dir / 'vars'
        if not vars_file.exists():
            raise BackendError('"vars" file not found')
        if not vars_file.is_file():
            raise BackendError('"vars" file is not a file')
        self._vars_file = vars_file
        self._env = self._get_full_env()
        self._openssl_backend = self._make_openssl_backend()
        self._db = OpenSSLDbParser(self._key_dir / 'index.txt')

    def _get_full_env(self):
        varnames = ('EASY_RSA', 'OPENSSL', 'PKCS11TOOL', 'GREP', 'KEY_CONFIG', 'KEY_DIR',
                    'PKCS11_MODULE_PATH', 'PKCS11_PIN', 'KEY_SIZE', 'CA_EXPIRE', 'KEY_EXPIRE',
                    'KEY_COUNTRY', 'KEY_PROVINCE', 'KEY_CITY', 'KEY_ORG', 'KEY_EMAIL', 'KEY_OU',
                    'KEY_NAME', 'KEY_CN')
        # we need to prefix the first variable name with $ also.
        variablename_lines = '$' + '\n$'.join(varnames)
        # We use stderr, because we want to skip echo NOTE: line which is on stdout.
        # Could be parsing with regexp or something but seemed easier and safer this way.
        # If there is something on stderr, a CalledProcessError is raised anyway (hopefully :D).
        command = f'. {self._vars_file} && printf "{variablename_lines}" >&2'
        result = run(command, shell=True, stdout=DEVNULL, stderr=PIPE, universal_newlines=True,
                     cwd=self._root_dir, check=True)
        var_values = result.stderr.splitlines()
        env = dict(zip(varnames, var_values))
        # we need to merge it with the current process's env
        env.update(os.environ)
        return env

    @property
    def _key_dir(self):
        return Path(self._env['KEY_DIR'])

    def _make_openssl_backend(self):
        openssl_binary = Path(self._env['OPENSSL'])
        config_file = Path(self._env['KEY_CONFIG'])
        crl_file = self._key_dir / 'crl.pem'
        return OpenSSLBackend(openssl_binary, config_file, self._root_dir, crl_file, env=self._env)

    def _run(self, *params):
        result = run(params, cwd=self._root_dir, stdout=PIPE, stderr=PIPE, env=self._env,
                     check=True, universal_newlines=True)
        return result.stdout

    def get_ca_cert(self) -> Cert:
        return Cert.from_file(self._key_dir / 'ca.crt')

    def get_csr_policy(self):
        return self._openssl_backend.get_csr_policy()

    def get_csr_defaults(self):
        return self._openssl_backend.get_csr_defaults()

    def issue_cert(self, csr: CsrBuilder) -> (PrivateKey, Cert):
        self._run('pkitool', '--batch', csr.common_name)
        key_path = self._key_dir / f'{csr.common_name}.key'
        cert_path = self._key_dir / f'{csr.common_name}.crt'
        return PrivateKey.from_file(key_path), Cert.from_file(cert_path)

    def revoke_cert(self, serial: str) -> RevokedCert:
        entry = self._db.get_by_serial(serial)
        # TODO: check for CalledProcessError and raise RevocationError()
        self._run('revoke-full', entry.name.common_name)
        for rc in Crl.from_file(self._key_dir / 'crl.pem'):
            if rc.serial_number == SerialNumber(serial):
                return rc

    def get_cert_list(self) -> Iterator[Cert]:
        for entry in self._db:
            filename = entry.serial_number.as_hex() + '.pem'
            yield Cert.from_file(self._key_dir / filename)

    def get_cert(self, serial: str) -> Cert:
        serial_hex = SerialNumber(serial).as_hex()
        cert_path = self._key_dir / f'{serial_hex}.pem'
        return Cert.from_file(cert_path)

    @property
    def version(self) -> str:
        pkitool_version = self._run('pkitool', '--version').rstrip()
        return f'{self.name} ({pkitool_version})'
