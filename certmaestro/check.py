import ssl
import enum
import socket
import asyncio
import certifi
import attr
from .url import parse_url


async def check_hostname(hostname):
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    try:
        # server_hostname is not needed, because by default,
        # hostname is used for the server cert verification
        _, writer = await asyncio.open_connection(hostname, 443, ssl=ssl_context)
        writer.close()
        await writer.wait_closed()
    except socket.timeout as e:
        return 'Timed out'
    except OSError as e:
        return parse_socket_error_message(e.args[1])
    except ssl.CertificateError as e:
        return str(e)
    else:
        return None


def parse_socket_error_message(message):
    """Cut off brackets from the message, make it human readable."""
    # example: "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:749)"
    start_ind = message.find(']')
    if start_ind != -1:
        start = start_ind + 2
        end = message.find('(_ssl') - 1
        message = message[start:end]
    return message


class CheckSiteManager:
    def __init__(self, redirect, timeout, retries, max_threads):
        self.redirect = redirect
        self.timeout = timeout
        self.retries = retries
        self.skipped = []
        self.succeeded = []
        self.failed = []

    @property
    def success_count(self):
        return len(self.succeeded)

    @property
    def skip_count(self):
        return len(self.skipped)

    @property
    def fail_count(self):
        return len(self.failed)

    async def check_sites(self, urls):
        self.skipped, skipped_urls = self._skip_urls(urls)
        # we deduplicate hostnames, because they are fed in the form of URLs
        hostnames = {parse_url(url).host for url in urls if url not in skipped_urls}
        # we enforce task so they will be started right away, so we can yield from skipped
        check_coros = [self._check_hostname(hostname) for hostname in hostnames]
        # we start yielding after starting requests, so the perceived speed might be better
        # if the client does something with the return values
        for skipped in self.skipped:
            yield skipped

        for future in asyncio.as_completed(check_coros):
            result = await future
            if result.succeeded:
                self.succeeded.append(result)
            elif result.failed:
                self.failed.append(result)
            yield result

    def _skip_urls(self, urls):
        skipped_sites, skipped_urls = [], set()

        for url in urls:
            parsed = parse_url(url)
            if parsed.host is None or not parsed.host.strip():
                checked = CheckedSite(url, CheckResult.SKIPPED, 'invalid_hostname')
            # any other protocoll will be None and as we cannot make a difference,
            # we will check those. Maybe we shouldn't?
            elif parsed.scheme == 'http':
                checked = CheckedSite(url, CheckResult.SKIPPED, 'not https://')
            else:
                continue

            skipped_sites.append(checked)
            skipped_urls.add(url)

        return skipped_sites, skipped_urls

    async def _check_hostname(self, hostname):
        # OpenSSL is more strict about misconfigured servers, e.g. it recognizes missing chains
        openssl_error = await check_hostname(hostname)
        result = CheckResult.FAILED if openssl_error else CheckResult.SUCCEEDED
        return CheckedSite(hostname, result, openssl_error)


class CheckResult(enum.Enum):
    SUCCEEDED = 'SUCCEEDED'
    SKIPPED = 'SKIPPED'
    FAILED = 'FAILED'


@attr.s(slots=True, cmp=False)
class CheckedSite:
    url = attr.ib()
    result = attr.ib(convert=CheckResult)
    message = attr.ib(default=None)

    succeeded = attr.ib(init=False)
    skipped = attr.ib(init=False)
    failed = attr.ib(init=False)

    def __attrs_post_init__(self):
        self.succeeded = (self.result == CheckResult.SUCCEEDED)
        self.skipped = (self.result == CheckResult.SKIPPED)
        self.failed = (self.result == CheckResult.FAILED)
