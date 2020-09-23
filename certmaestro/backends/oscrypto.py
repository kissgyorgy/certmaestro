from pathlib import Path
from oscrypto import asymmetric
from certbuilder import CertificateBuilder, pem_armor_certificate
from ..csr import CsrBuilder
from ..wrapper import PrivateKey, Cert, SerialNumber
from .interfaces import IBackend
from . import register_backend


@register_backend
class Backend:
    def __init__(self):
        self._cert_dir = Path('~/.config/certmaestro/certs').expanduser()

    def issue_cert(self, csr: CsrBuilder) -> (PrivateKey, Cert):
        public_key, private_key = asymmetric.generate_pair('rsa', bit_size=4096)
        builder = CertificateBuilder(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            public_key
        )
        builder.self_signed = True
        cert = builder.build(private_key)
        serial = SerialNumber.from_int(cert.serial_number).as_hex()

        keypath = self._cert_dir / (serial + '.key')
        with keypath.open('wb') as f:
            f.write(asymmetric.dump_private_key(private_key, 'password'))

        certpath = self._cert_dir / (serial + '.pem')
        with certpath.open('wb') as f:
            f.write(pem_armor_certificate(cert))
