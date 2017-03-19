import ssl
import socket
import certifi
from oscrypto.tls import TLSSocket
from urllib3.connection import VerifiedHTTPSConnection


CERTIFI_CA_FILE = certifi.where()
ALL_BADSSL_SUBDOMAINS = (
    # 🎫Certificate
    ('expired', '❌'),
    ('wrong.host', '❌'),
    ('self-signed', '❌'),
    ('untrusted-root', '❌'),
    ('revoked', '❌'),
    ('incomplete-chain', '⚠'),
    ('sha256', '✅'),
    ('1000-sans', '✅'),
    ('10000-sans', '✅'),
    ('ecc256', '✅'),
    ('ecc384', '✅'),
    ('rsa8192', '⚠'),

    # 🖼Mixed Content
    ('mixed-script', '❌'),
    ('very', '❌'),
    ('mixed', '⚠'),
    ('mixed-favicon', '⚠'),

    # ✏️HTTP Input
    ('http-password', '❌'),
    ('http-login', '❌'),
    ('http-dynamic-login', '❌'),
    ('http-credit-card', '❌'),

    # 🔀Cipher Suite
    ('cbc', '⚠'),
    ('rc4-md5', '❌'),
    ('rc4', '❌'),
    ('3des', '❌'),
    ('null', '❌'),
    ('mozilla-old', '❌'),
    ('mozilla-intermediate', '⚠'),
    ('mozilla-modern', '✅'),

    # 🔑Key Exchange
    ('dh480', '❌'),
    ('dh512', '❌'),
    ('dh1024', '⚠'),
    ('dh2048', '✅'),
    ('dh-small-subgroup', '❌'),
    ('dh-composite', '❌'),
    ('static-rsa', '⚠'),

    # ⬆️Upgrade
    ('hsts', '✅'),
    ('upgrade', '✅'),
    ('preloaded-hsts', '✅'),
    ('subdomain.preloaded-hsts', '❌'),
    ('https-everywhere', '✅'),

    # 💬Miscellaneous
    ('http', '⚠'),
    ('spoofed-favicon', '⚠'),
    ('pinning-test', '❌'),
    ('long-extended-subdomain-name-containing-many-letters-and-dashes', '✅'),
    ('longextendedsubdomainnamewithoutdashesinordertotestwordwrapping', '✅'),

    # ❌Known Bad
    ('superfish', '❌'),
    ('edellroot', '❌'),
    ('dsdtestprovider', '❌'),

    # ☠️Defunct
    ('sha1-2016', '❌'),
    ('sha1-2017', '❌'),
)

OTHER_DOMAINS = (
    ('badssl.com', '✅'),
    ('officecontrol.hu', '✅'),
    ('google.com', '✅'),
    ('facebook.com', '✅'),
    ('twitter.com', '✅'),
    ('instagram.com', '✅'),
    ('anteus.hu', '❌'),
)


def with_openssl(domain):
    # this was always good: ssl.get_server_certificate((domain, 443))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    ssl_sock = context.wrap_socket(sock, server_hostname=domain)
    ssl_sock.connect((domain, 443))


def with_openssl_certifi(domain):
    # this was always bad: ssl.get_server_certificate((domain, 443), ca_certs=CERTIFI_CA_FILE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(cafile=CERTIFI_CA_FILE)
    ssl_sock = context.wrap_socket(sock, server_hostname=domain)
    ssl_sock.connect((domain, 443))


def with_oscrypto(domain):
    TLSSocket(domain, 443)


def with_urllib3(domain):
    conn = VerifiedHTTPSConnection(domain)
    conn.set_cert(cert_reqs='CERT_REQUIRED')
    conn.connect()


# def with_urllib3_certifi(domain):


def run_and_catch(func, domain):
    try:
        func(domain)
        return '✅'
    except Exception:
        return '❌'


def print_matrix_line(format_str, domain, marked_as):
    print(format_str.format(domain[:38],
                            marked_as,
                            run_and_catch(with_openssl, domain),
                            run_and_catch(with_openssl_certifi, domain),
                            run_and_catch(with_oscrypto, domain),
                            run_and_catch(with_urllib3, domain)))


def main():
    format_str = '{:<40}{:<10}{:<10}{:<20}{:<15}{}'
    print(format_str.format('Subdomain', 'Marked', 'OpenSSL', 'OpenSSL Certifi',
                            'OSCrypto', 'urllib3'))

    BADSSL_DOMAINS = map(lambda s: (s[0] + '.badssl.com', s[1]), ALL_BADSSL_SUBDOMAINS)
    for domain, marked_as in tuple(BADSSL_DOMAINS) + OTHER_DOMAINS:
        print_matrix_line(format_str, domain, marked_as)


if __name__ == '__main__':
    main()
