"""
    Wrapper around oscrypto and asn1crypto modules for a nicer API.
"""
import re
from pathlib import Path
from oscrypto.keys import parse_certificate
from asn1crypto import x509 as asn1x509, keys as asn1keys, pem as asn1pem, crl as asn1crl


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

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._value == other._value

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
    _map = {
        'C': 'country_name',
        'O': 'organization_name',
        'OU': 'organizational_unit_name',
        'CN': 'common_name',
        'L': 'locality_name',
        'ST': 'state_or_province_name',
        'emailAddress': 'email_address',
    }
    _name_re = re.compile(r'/([A-Z]+)=([^/]*)')

    def __init__(self, name: asn1x509.Name):
        self._name = name

    @classmethod
    def from_dict(cls, values):
        return cls(asn1x509.Name.build(values))

    @classmethod
    def from_str(cls, name_str):
        raw_values = dict(cls._name_re.findall(name_str))
        values = {cls._map[k]: v for k, v in raw_values.items()}
        return cls.from_dict(values)

    @property
    def common_name(self):
        return self._name.native.get('common_name')

    @property
    def formatted_lines(self):
        field_names = [asn1x509.NameType(field).human_friendly for field in self._name.native.keys()]
        max_length = max(len(field) for field in field_names)
        field_names = [f'{field}:'.ljust(max_length + 3) for field in field_names]
        return (field + val for field, val in zip(field_names, self._name.native.values()))


class FromFileMixin:
    @classmethod
    def from_file(cls, path):
        return cls(Path(path).read_text())


class Cert(FromFileMixin):

    def __init__(self, pem_data: str):
        # OpenSSL have an option to write readable text into the same file with PEM data
        start = self._find_start(pem_data)
        pem_data = pem_data[start:]
        self._cert: asn1x509.Certificate = parse_certificate(pem_data.encode())
        self._pem_data = pem_data

    def __str__(self):
        return self._pem_data

    @staticmethod
    def _find_start(pem_data):
        start = pem_data.find('-----BEGIN')
        if start == -1:
            start = pem_data.find('---- BEGIN')
            if start == -1:
                raise ValueError(f"This doesn't seem like a valid X509 Certificate: {pem_data}")
        return start

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._cert.serial_number)

    @property
    def not_valid_before(self):
        return self._cert['tbs_certificate']['validity']['not_before'].native

    @property
    def not_valid_after(self):
        return self._cert['tbs_certificate']['validity']['not_after'].native

    @property
    def version(self):
        return self._cert['tbs_certificate']['version'].native

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
        yield from self._convert_values(self._cert.key_usage_value)

    @property
    def extended_key_usages(self):
        yield from self._convert_values(self._cert.extended_key_usage_value)

    def _convert_values(self, asn1type):
        """Reformat the words as defined in RFC5280. E.g. keyEncipherment."""
        if asn1type is None:
            return None
        values = asn1type.native
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
        return self._cert['signature_algorithm']['algorithm'].native


class PrivateKey(FromFileMixin):

    def __init__(self, pem_data: str):
        self._pem_data = pem_data

    def __str__(self):
        return self._pem_data


class PublicKey:
    def __init__(self, public_key: asn1keys.PublicKeyInfo):
        self._public_key = public_key

    @property
    def modulus(self):
        hex_modulus = hex(self._public_key['public_key'].native['modulus'])[2:]
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
        return self._public_key['public_key'].native['public_exponent']

    @property
    def hex_exponent(self):
        return hex(self._public_key['public_key'].native['public_exponent'])


class RevokedCert:

    def __init__(self, revoked_cert: asn1crl.RevokedCertificate):
        self._rev_cert = revoked_cert

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._rev_cert['user_certificate'].native)

    @property
    def revocation_date(self):
        return self._rev_cert['revocation_date'].native

    @property
    def invalidity_date(self):
        return self._rev_cert.invalidity_date_value

    @property
    def reason(self):
        return self._rev_cert.crl_reason_value


class Crl(FromFileMixin):

    def __init__(self, crl_pem: str):
        type_name, headers, der_bytes = asn1pem.unarmor(crl_pem.encode())
        if type_name != 'X509 CRL':
            raise ValueError('This not seem like a Certificate Revocation List.')

        self._crl = asn1crl.CertificateList.load(der_bytes)

    def __iter__(self):
        return iter(RevokedCert(c) for c in self._crl['tbs_cert_list']['revoked_certificates'])

    @property
    def this_update(self):
        return self._crl['tbs_cert_list']['this_update'].native

    @property
    def next_update(self):
        return self._crl['tbs_cert_list']['next_update'].native

    @property
    def issuer(self):
        return Name(self._crl['tbs_cert_list']['issuer'])
