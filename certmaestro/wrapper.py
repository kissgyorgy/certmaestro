"""
    Wrapper around cryptography.x509 module for a nicer API.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


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


class Identity:

    def __init__(self, val):
        self._val = val

    @property
    def common_name(self):
        return self._get_attr(x509.OID_COMMON_NAME)

    @property
    def country(self):
        return self._get_attr(x509.OID_COUNTRY_NAME)

    @property
    def state(self):
        return self._get_attr(x509.OID_STATE_OR_PROVINCE_NAME)

    @property
    def locality(self):
        return self._get_attr(x509.OID_LOCALITY_NAME)

    @property
    def org_name(self):
        return self._get_attr(x509.OID_ORGANIZATION_NAME)

    @property
    def org_unit(self):
        return self._get_attr(x509.OID_ORGANIZATIONAL_UNIT_NAME)

    @property
    def email(self):
        return self._get_attr(x509.OID_EMAIL_ADDRESS)

    def _get_attr(self, oid):
        attributes = self._val.get_attributes_for_oid(oid)
        return attributes[0].value if attributes else None


class Cert:

    def __init__(self, pem_data: str):
        self._pem_data = pem_data
        self._cert = x509.load_pem_x509_certificate(pem_data.encode('utf8'), default_backend())

    def __str__(self):
        return self._pem_data

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls(f.read())

    @property
    def issuer(self):
        return Identity(self._cert.issuer)

    @property
    def subject(self):
        return Identity(self._cert.subject)

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._cert.serial_number)

    @property
    def public_key(self):
        return PublicKey(self._cert.public_key())

    @property
    def not_before(self):
        return self._cert.not_valid_before

    @property
    def not_after(self):
        return self._cert.not_valid_after

    @property
    def version(self):
        return self._cert.version.value + 1

    @property
    def hex_version(self):
        return hex(self._cert.version.value)

    @property
    def signature_algorithm(self):
        return self._cert.signature_algorithm_oid._name

    @property
    def signature(self):
        return ':'.join(hex(i)[2:].zfill(2) for i in self._cert.signature)

    @property
    def extensions(self):
        return Extensions(self._cert.extensions)


class Extensions:

    def __init__(self, extensions):
        self._val = extensions

    @property
    def basic_constraints_ca(self):
        constr = self._val.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        return constr.value.ca

    @property
    def basic_constraints_path_length(self):
        constr = self._val.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        return constr.value.path_length

    @property
    def key_usages(self):
        try:
            usages = self._val.get_extension_for_oid(x509.OID_KEY_USAGE).value
        except x509.extensions.ExtensionNotFound:
            return []

        return [
            usages.digital_signature,
            usages.content_commitment,
            usages.key_encipherment,
            usages.data_encipherment,
            usages.key_agreement,
            usages.cert_sign,
            usages.crl_sign,
        ]

    @property
    def extended_key_usages(self):
        try:
            return self._val.get_extension_for_oid(x509.OID_EXTENDED_KEY_USAGE).value
        except x509.extensions.ExtensionNotFound:
            return []


class PrivateKey:

    def __init__(self, pem_data: str):
        self._pem_data = pem_data

    def __str__(self):
        return self._pem_data


class PublicKey:

    def __init__(self, key):
        self._key = key

    def __str__(self):
        return self._key

    @property
    def size(self):
        return self._key.key_size

    @property
    def modulus(self):
        return self._key.public_numbers().n

    @property
    def coloned_modulus(self):
        hex_modulus = hex(self.modulus)[2:]
        # http://stackoverflow.com/questions/15953631/rsa-modulus-prefaced-by-0x00
        return '00:' + SerialNumber.colonize(hex_modulus)

    @property
    def exponent(self):
        return self._key.public_numbers().e

    @property
    def hex_exponent(self):
        return hex(self._key.public_numbers().e)

    @property
    def algorithm(self):
        if isinstance(self._key, RSAPublicKey):
            return 'RSA'
        elif isinstance(self._key, DSAPublicKey):
            return 'DSA'
        elif isinstance(self._key, EllipticCurvePublicKey):
            return 'Elliptic Curve'


class RevokedCert:

    def __init__(self, cert):
        self._cert = cert

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._cert.serial_number)

    @property
    def revocation_date(self):
        return self._cert.revocation_date

    @property
    def reason(self):
        try:
            return self._cert.extensions.get_extension_for_oid(x509.OID_CRL_REASON)
        except x509.ExtensionNotFound:
            return None

    @property
    def invalidity_date(self):
        try:
            return self._cert.extensions.get_extension_for_oid(x509.OID_INVALIDITY_DATE)
        except x509.ExtensionNotFound:
            return None


class Crl:

    def __init__(self, pem_data):
        self._crl = x509.load_pem_x509_crl(pem_data.encode('utf8'), default_backend())

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls(f.read())

    def __iter__(self):
        return iter(RevokedCert(r) for r in self._crl)

    @property
    def last_update(self):
        return self._crl.last_update

    @property
    def next_update(self):
        return self._crl.next_update

    @property
    def issuer(self):
        name_attr = self._crl.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)
        return name_attr[0].value
