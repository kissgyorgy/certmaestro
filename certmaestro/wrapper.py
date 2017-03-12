"""
    Wrapper around cryptography.x509 module for a nicer API.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SerialNumber:

    def __init__(self, serial_str: str):
        # might have 0x prefix, and/or colons
        serial_str = serial_str.lower()
        if serial_str.startswith('0x'):
            serial_str = serial_str[2:]
        if ':' in serial_str:
            serial_str = self._decolonize(serial_str)
        serial_str = self._zero_prefix(serial_str)
        serial_str = self._colonize(serial_str)
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
    def _colonize(serial_hex: str):
        return ':'.join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))

    def _decolonize(self, serial_str):
        return serial_str.replace(':', '')


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
    def common_name(self):
        attributes = self._cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
        return attributes[0].value if attributes else None

    @property
    def serial_number(self):
        return SerialNumber.from_int(self._cert.serial_number)

    @property
    def not_valid_before(self):
        return self._cert.not_valid_before

    @property
    def not_valid_after(self):
        return self._cert.not_valid_after


class Key:

    def __init__(self, pem_data: str):
        self._pem_data = pem_data

    def __str__(self):
        return self._pem_data


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
