import click
import requests
from tabulate import tabulate
from certmaestro import Config, BackendConfigurationError, get_backend
from certmaestro.backends import BACKENDS


class Obj:

    def __init__(self):
        ctx = click.get_current_context()
        self.config = self._get_config(ctx)
        self.backend = self._get_backend(ctx)
        if self.config.is_reconfigured:
            self._save_config(ctx)

    def _get_config(self, ctx):
        root_ctx = ctx.find_root()

        try:
            return Config(root_ctx.params['config_path'])
        except FileNotFoundError:
            if click.confirm('This command needs configuration and an initialized backend!\n'
                             'Do you want to initialize one now?'):
                ctx.invoke(init_backend)
            else:
                ctx.abort()

    def _get_backend(self, ctx):
        while True:
            try:
                return get_backend(self.config)
            except BackendConfigurationError as bce:
                self.config.is_reconfigured = True
                click.echo('Something is wrong with the {} backend configuration:\n  * {}'
                           .format(bce.backend_name, bce.message))
                if not click.confirm('Would you like to reconfigure it?'):
                    ctx.abort()

                for param_name, question in bce.required:
                    value = click.prompt(question, default=bce.defaults.get(param_name))
                    self.config.backend_config[param_name] = str(value)
                click.echo()

    def _save_config(self, ctx):
        self.config.save()
        click.echo('Configuration saved successfully.')
        if not click.confirm('Do you want to run the %s command now?' % ctx.command.name):
            ctx.abort()


needs_config = click.make_pass_decorator(Obj, ensure=True)


@click.group()
@click.option('--config', 'config_path', default=Config.DEFAULT_PATH,
              help='Default: ' + Config.DEFAULT_PATH,
              type=click.Path(dir_okay=False, writable=True, resolve_path=True))
def main(config_path):
    """Certmaestro command line interface."""


backend_choices = """\
@main.command('setup-backend')
1. Vault (https://www.vaultproject.io)
2. Letsencrypt (Behave as an ACME client)
3. OpenSSL (OpenSSL command line tools with openssl.cnf, https://www.openssl.org)
4. PostgreSQL (Storing certificates in a PostgreSQL database)
5. MySQL (Storing certificates in a MySQL database)
6. File\
"""
backend_names = ['vault', 'letsencrypt', 'openssl', 'postgres', 'mysql', 'file']


@click.pass_obj
def setup_backend(obj):
    """Initializes backend storage, settings roles, and generate CA."""
    click.echo(backend_choices)
    backend_num = click.prompt('Please choose a backend [1-6]', type=click.IntRange(1, 6))
    backend_name = backend_names[backend_num - 1]

    params = dict()
    Backend = BACKENDS[backend_name]
    defaults = Backend.get_defaults()
    for param_name, question in Backend.required:
        default = defaults.get(param_name)
        default = str(default) if default is not None else None
        params[param_name] = click.prompt(question, default=default)
    backend = Backend(**params)
    backend.connect()
    backend.init_config()
    click.echo('Successfully initialized backend. You can issue certificates now!')


@main.command('show-config')
@click.pass_obj
@needs_config
def show_config(obj):
    """Shows saved configuration options."""
    click.echo(obj.config)
    click.echo(obj.backend.config)


@main.command('issue-cert')
@click.pass_obj
@needs_config
def issue_cert(obj):
    """Issue a new certificate."""
    common_name = click.prompt('Common name')
    result = obj.backend.issue_cert(common_name)
    click.echo(result)


@main.command('show-cert')
@click.argument('serial_number')
@click.pass_obj
@needs_config
def show_cert(obj, serial_number):
    """View certificate details."""
    cert = obj.backend.get_cert(serial_number)
    click.echo('Serial number:     %s' % cert.coloned_serial)
    click.echo('Common Name:       %s' % cert.common_name)
    click.echo('Expires:           %s' % cert.expiration)


@main.command('list-certs')
@click.pass_obj
@needs_config
def list_certs(obj):
    """List issued certificates."""
    cert_list = obj.backend.get_cert_list()
    cert_table = ((c.common_name, c.expires, c.serial_number,) for c in cert_list)
    click.echo(tabulate(cert_table, headers=['Common Name', 'Expires', 'Serial Number']))


@main.command('revoke-cert')
@click.argument('serial_number')
@click.pass_obj
@needs_config
def revoke_cert(obj, serial_number):
    """Revoke a certificate."""
    result = obj.backend.revoke_cert(serial_number)
    click.echo(result)


@main.command('update-crl')
@click.pass_obj
@needs_config
def update_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@main.command('show-crl')
@click.pass_obj
@needs_config
def show_crl(obj):
    """Show the Certificate Revocation List."""
    crl = obj.backend.get_crl()
    click.echo('Issuer Common Name:    %s' % crl.issuer)
    click.echo('Last update:           %s' % crl.last_update)
    click.echo('Next update:           %s' % crl.next_update)
    click.echo()
    headers = ['Revocation Date', 'Invalidity Date', 'Reason', 'Serial Number']
    revoked_certs = ((rc.revocation_date, rc.invalidity_date, rc.reason, rc.serial_number)
                     for rc in crl)
    click.echo(tabulate(revoked_certs, headers=headers))


@main.command('deploy-cert')
@click.pass_obj
@needs_config
def deploy_cert(obj):
    """Copy the certificate via SSH to the given host."""


def _validate_https(ctx, param, url):
    if url.startswith('http://'):
        raise click.BadParameter('Sorry, you need to provide an https:// website!')
    return url


@main.command('check-site')
@click.argument('url', callback=_validate_https)
@click.pass_context
def check_site(ctx, url):
    """Simple check if the website has a valid certificate."""
    if not url.startswith('https://'):
        url = 'https://' + url

    click.echo('Checking %s ...' % url)

    try:
        requests.head(url)  # noqa
    except requests.exceptions.SSLError as e:
        click.echo(str(e))
        ctx.exit(1)

    click.echo('Certificate is valid!')
