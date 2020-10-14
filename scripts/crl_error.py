from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend


pem_data = open('only_one.crl').read().encode('ascii')
crl = x509.load_pem_x509_crl(pem_data, openssl_backend)

for cert in crl:
    print(cert.revocation_date)
