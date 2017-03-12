"""
    Wrapper around cryptography.x509 module for a nicer API.
"""

import datetime as dt
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def hexify(serial_number: int):
    """Convert an integer to a colon separated hexadecimal value."""
    serial = hex(serial_number)[2:]
    if len(serial) % 2 == 1:
        serial = '0' + serial
    return ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))


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
        return hexify(self._cert.serial_number)

    @property
    def expires(self):
        return self._cert.not_valid_before


class RevokedCert:

    def __init__(self, cert):
        self._cert = cert

    @property
    def serial_number(self):
        return hexify(self._cert.serial_number)

    @property
    def revocation_date(self):
        try:
            return self._cert.revocation_date
        except ValueError as e:
            error_message = e.args[0]
            # Fix for bug in Vault, # see: https://github.com/hashicorp/vault/issues/1727
            # and https://github.com/pyca/cryptography/issues/3086
            invalid_date_str = error_message[11:30]
            local_date = dt.datetime.strptime(invalid_date_str, '%Y%m%d%H%M%S%z')
            return local_date.astimezone(dt.timezone.utc).replace(tzinfo=None)

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
