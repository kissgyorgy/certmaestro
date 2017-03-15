from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3 import exceptions as u3exc
import certifi
import urllib3


class CheckSiteManager:
    def __init__(self, urls, redirect, timeout, retries):
        self.redirect = redirect
        self.timeout = timeout
        self.retries = retries
        self.urls = urls
        self.skipped = []
        self.succeeded = []
        self.failed = []

    def check_sites(self):
        # enable certificate verification with certifi (Mozilla CA bundle)
        self.http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where(),
                                        num_pools=len(self.urls), timeout=self.timeout, maxsize=2,
                                        retries=self.retries)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_url = {executor.submit(self._check, url) for url in self.urls}
            for future in as_completed(future_to_url):
                result = future.result()
                if result.succeeded:
                    self.succeeded.append(result)
                elif result.skipped:
                    self.skipped.append(result)
                elif result.failed:
                    self.failed.append(result)
                yield result

    @property
    def success_count(self):
        return len(self.succeeded)

    @property
    def skip_count(self):
        return len(self.skipped)

    @property
    def fail_count(self):
        return len(self.failed)

    def _check(self, url):
        if url.startswith('https://'):
            pass
        elif '://' in url:
            return CheckSiteResult(url, CheckSiteResult.SKIPPED, 'not https://')
        else:
            url = 'https://' + url

        try:
            self.http.request('HEAD', url, redirect=self.redirect)

        except u3exc.SSLError as e:
            # example: "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:749)"
            message = e.args[0].args[-1]
            start_ind = message.find(']')
            if start_ind > -1:
                start = start_ind + 2
                end = message.find('(_ssl') - 1
                message = message[start:end]
            return CheckSiteResult(url, CheckSiteResult.FAILED, message)

        except (u3exc.MaxRetryError, u3exc.NewConnectionError) as e:
            message = e.reason.args[0]
            start_ind = message.find(': ')
            if start_ind > -1:
                cut_error_type = slice(start_ind + 2, None)
                message = message[cut_error_type]
            return CheckSiteResult(url, CheckSiteResult.FAILED, message)

        else:
            return CheckSiteResult(url, CheckSiteResult.SUCCEEDED)


class CheckSiteResult:
    SUCCEEDED = 'SUCCEEDED'
    SKIPPED = 'SKIPPED'
    FAILED = 'FAILED'

    def __init__(self, url, status, message=None):
        self.url = url
        self.status = status
        self.message = message
        self.succeeded = status == self.SUCCEEDED
        self.skipped = status == self.SKIPPED
        self.failed = status == self.FAILED
