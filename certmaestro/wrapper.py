"""
    Wrapper around oscrypto and asn1crypto modules for a nicer API.
"""

from oscrypto.keys import parse_certificate
from asn1crypto.x509 import Certificate, NameType
from asn1crypto.keys import PublicKeyInfo


class SerialNumber:

    def __init__(self, serial_str: str):
        # might have 0x prefix, and/or colons
        serial_str = serial_str.lower()
        if serial_str.startswith('0x'):
            serial_str = serial_str[2:]
        if ':' in serial_str:
            serial_str = self._decolonize(serial_str)
        serial_str = self._zero_prefix(serial_str)
        serial_str = self.colonize(serial_str)
        self._value = serial_str

    @classmethod
    def from_int(cls, serial_int: int):
        return cls(hex(serial_int))

    def __str__(self):
        return self._value

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self._value}>'

    def as_hex(self, prefix=False):
        serial_hex = self._decolonize(self._value)
        return '0x' + serial_hex if prefix else serial_hex

    @staticmethod
    def _zero_prefix(serial_hex):
        if len(serial_hex) % 2 == 1:
            serial_hex = '0' + serial_hex
        return serial_hex

    @staticmethod
    def colonize(serial_hex: str):
        return ':'.join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))

    def _decolonize(self, serial_str):
        return serial_str.replace(':', '')


class Name:

    def __init__(self, name):
        self._name = name

    @property
    def formatted_lines(self):
        field_names = [NameType(field).human_friendly for field in self._name.native.keys()]
        max_length = max(len(field) for field in field_names)
        field_names = [f'{field}:'.ljust(max_length + 3) for field in field_names]
        return (field + val for field, val in zip(field_names, self._name.native.values()))


class Cert:

    def __init__(self, pem_data: str):
        self._pem_data = pem_data
        self._cert: Certificate = parse_certificate(pem_data.encode('utf8'))

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls(f.read())

    def __str__(self):
        return self._pem_data

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._cert.serial_number)

    @property
    def validity(self):
        return self._cert['tbs_certificate'].native['validity']

    @property
    def version(self):
        return self._cert['tbs_certificate'].native['version']

    @property
    def issuer(self):
        return Name(self._cert.issuer)

    @property
    def subject(self):
        return Name(self._cert.subject)

    @property
    def ca(self):
        return self._cert.ca

    @property
    def max_path_length(self):
        return self._cert.max_path_length

    @property
    def key_usages(self):
        yield from self._convert_values(self._cert.key_usage_value.native)

    @property
    def extended_key_usages(self):
        yield from self._convert_values(self._cert.extended_key_usage_value.native)

    def _convert_values(self, values):
        """Reformat the words as defined in RFC5280. E.g. keyEncipherment."""
        for usage in values:
            words = usage.split('_')
            yield ''.join(words[0:1] + [w.title() for w in words[1:]])

    @property
    def public_key(self):
        return PublicKey(self._cert.public_key)

    @property
    def signature(self):
        return ':'.join(hex(i)[2:].zfill(2) for i in self._cert.signature)

    @property
    def signature_algorithm(self):
        return self._cert['signature_algorithm'].native['algorithm']


class PrivateKey:

    def __init__(self, pem_data: str):
        self._pem_data = pem_data

    def __str__(self):
        return self._pem_data


class PublicKey:
    def __init__(self, public_key: PublicKeyInfo):
        self._public_key = public_key

    @property
    def modulus(self):
        hex_modulus = hex(self._public_key.native['public_key']['modulus'])[2:]
        # http://stackoverflow.com/questions/15953631/rsa-modulus-prefaced-by-0x00
        return '00:' + SerialNumber.colonize(hex_modulus)

    @property
    def bit_size(self):
        return self._public_key.bit_size

    @property
    def algorithm(self):
        return self._public_key.algorithm

    @property
    def exponent(self):
        return self._public_key.native['public_key']['public_exponent']

    @property
    def hex_exponent(self):
        return hex(self._public_key.native['public_key']['public_exponent'])


class RevokedCert:
    ...


class Crl:
    ...
