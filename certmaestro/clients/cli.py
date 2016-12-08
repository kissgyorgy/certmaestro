from os.path import exists
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
            click.confirm('This command needs configuration and an initialized backend!\n'
                          'Do you want to initialize one now?', abort=True)
            ctx.invoke(setup_backend)

    def _get_backend(self, ctx):
        while True:
            try:
                return get_backend(self.config)
            except BackendConfigurationError as bce:
                self.config.is_reconfigured = True
                click.echo('Something is wrong with the {} backend configuration:\n  * {}'
                           .format(bce.backend_name, bce.message))
                click.confirm('Would you like to reconfigure it?', abort=True)

                for param_name, question in bce.required:
                    value = click.prompt(question, default=bce.defaults.get(param_name))
                    self.config.backend_config[param_name] = str(value)
                click.echo()

    def _save_config(self, ctx):
        self.config.save()
        click.echo('Configuration saved successfully.')
        click.confirm('Do you want to run the %s command now?' % ctx.command.name, abort=True)


ensure_config = click.make_pass_decorator(Obj, ensure=True)


@click.group()
@click.option('--config', 'config_path', default=Config.DEFAULT_PATH,
              help='Default: ' + Config.DEFAULT_PATH,
              type=click.Path(dir_okay=False, writable=True, resolve_path=True))
def main(config_path):
    """Certmaestro command line interface."""


@main.command('setup-backend')
@click.pass_context
def setup_backend(ctx):
    """Initializes backend storage, settings roles, and generate CA."""
    config_path = ctx.parent.params['config_path']
    if exists(config_path):
        click.confirm('Configuration file already exists: %s'
                      '\nDo you want to replace it?' % config_path, abort=True)

    builder = BackendBuilder(VaultBackend)

    while True:
        for param_name, question, default in builder:
            value = click.prompt(question, default=default)
            builder[param_name] = value
        try:
            builder.validate()
            break
        except ValueError as e:
            click.echo('\nSomething is wrong with the configuration: %s' % e)

    backend = builder.setup_backend()
    config = Config.make_new(config_path)
    config.backend_name = backend.name
    str_values = {k: str(v) for k, v in builder.init_params.items()}
    config.backend_config.update(str_values)
    config.save()
    click.echo('Saved configuration to %s' % config_path)
    click.echo('Successfully initialized backend. You can issue certificates now!')


@main.command('show-config')
@ensure_config
def show_config(obj):
    """Shows saved configuration options."""


@main.command('issue-cert')
@ensure_config
def issue_cert(obj):
    """Issue a new certificate."""
    common_name = click.prompt('Common name')
    result = obj.backend.issue_cert(common_name)
    click.echo(result)


@main.command('show-cert')
@click.argument('serial_number')
@ensure_config
def show_cert(obj, serial_number):
    """View certificate details."""
    cert = obj.backend.get_cert(serial_number)
    click.echo('Serial number:     %s' % cert.serial_number)
    click.echo('Common Name:       %s' % cert.common_name)
    click.echo('Expires:           %s' % cert.expires)


@main.command('list-certs')
@ensure_config
def list_certs(obj):
    """List issued certificates."""
    cert_list = obj.backend.get_cert_list()
    cert_table = ((c.common_name, c.expires, c.serial_number,) for c in cert_list)
    click.echo(tabulate(cert_table, headers=['Common Name', 'Expires', 'Serial Number']))


@main.command('revoke-cert')
@click.argument('serial_number')
@ensure_config
def revoke_cert(obj, serial_number):
    """Revoke a certificate."""
    result = obj.backend.revoke_cert(serial_number)
    click.echo(result)


@main.command('update-crl')
@ensure_config
def update_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@main.command('show-crl')
@ensure_config
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
@ensure_config
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
