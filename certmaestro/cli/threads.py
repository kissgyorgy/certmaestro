from threading import Thread
from urllib3 import exceptions as u3exc
import click


class CheckSiteThread(Thread):
    def __init__(self, http, redirect, url):
        super().__init__(daemon=True)
        self.http = http
        self.redirect = redirect
        self.url = url
        self.succeeded = False
        self.skipped = False
        self.failed = False

    def run(self):
        url = self.url
        if url.startswith('https://'):
            pass
        elif '://' in url:
            click.echo(f'Skipped:   {url} (not https://)')
            self.skipped = True
            return
        else:
            url = 'https://' + url

        try:
            self.http.request('HEAD', url, redirect=self.redirect)
            click.secho(f'Valid:     {url}', fg='green')
            self.succeeded = True

        except u3exc.SSLError as e:
            # example: "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:749)"
            message = e.args[0].args[-1]
            start_ind = message.find(']')
            if start_ind > -1:
                start = start_ind + 2
                end = message.find('(_ssl') - 1
                message = message[start:end]
            click.secho(f'Failed:    {url} ({message})', fg='red')
            self.failed = True

        except (u3exc.MaxRetryError, u3exc.NewConnectionError) as e:
            message = e.reason.args[0]
            start_ind = message.find(': ')
            if start_ind > -1:
                cut_error_type = slice(start_ind + 2, None)
                message = message[cut_error_type]
            click.secho(f'Failed:    {url} ({message})', fg='red')
            self.failed = True

