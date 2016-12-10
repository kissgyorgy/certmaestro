from os.path import exists
import click
import requests
import pkg_resources
from tabulate import tabulate
from certmaestro import Config
from certmaestro.backends import get_backend, get_backend_cls, enumerate_backends
from certmaestro.config import BackendBuilder
from certmaestro.exceptions import BackendError


class Obj:

    def __init__(self):
        self.ctx = click.get_current_context()
        self.config = self._get_config()
        self.backend = self._get_backend()

    def _get_config(self):
        root_ctx = self.ctx.find_root()
        try:
            return Config(root_ctx.params['config_path'])
        except FileNotFoundError:
            click.confirm('This command needs configuration and an initialized backend!\n'
                          'Do you want to initialize one now?', abort=True)
            self.ctx.invoke(setup_backend)
            if not click.confirm(f'\nDo you want to run the "{self.ctx.info_name}" command now?'):
                self.ctx.exit()
            return Config(root_ctx.params['config_path'])

    def _get_backend(self):
        while True:
            try:
                return get_backend(self.config)
            except BackendError as exc:
                click.echo(f'Something is wrong with the {self.config.backend_name} '
                           f'backend configuration:\n  * {exc}')
                click.confirm('Would you like to reconfigure it?', abort=True)
                self.ctx.invoke(setup_backend)
                if not click.confirm(f'\nDo you want to run the "{self.ctx.info_name}" command now?'):
                    self.ctx.exit()


ensure_config = click.make_pass_decorator(Obj, ensure=True)


@click.group(invoke_without_command=True)
@click.option('--config', 'config_path', default=Config.DEFAULT_PATH,
              help='Default: ' + Config.DEFAULT_PATH,
              type=click.Path(dir_okay=False, writable=True, resolve_path=True))
@click.option('-V', '--version', 'show_version', is_flag=True, is_eager=True,
              help='Show Certmaestro and backend versions.')
@click.pass_context
def main(ctx, config_path, show_version):
    """Certmaestro command line interface."""
    # Only way to get backend, because we need config_path. With a callback,
    # it would run before the main method so there would be no config_path
    if show_version:
        ctx.invoke(version)
        ctx.exit()
    elif not ctx.invoked_subcommand:
        help_text = ctx.command.get_help(ctx)
        click.echo(help_text)


@main.command('setup-backend')
@click.pass_context
def setup_backend(ctx):
    """Initializes backend storage, settings roles, and generate CA."""
    config_path = ctx.find_root().params['config_path']
    if exists(config_path):
        click.confirm(f'Configuration file already exists: {config_path}\n'
                      'Do you want to replace it?', abort=True)
        click.echo()

    click.echo('Backend choices:')
    for choice, name, description in enumerate_backends():
        click.echo(f'{choice}. {name} - {description}')

    backend_choice = click.prompt('Which backend do you want to set up (1-5)?', default=1)
    click.echo()
    BackendCls = get_backend_cls(backend_choice)
    builder = BackendBuilder(BackendCls)

    while True:
        for param_name, question, default in builder:
            value = click.prompt(question, default=default)
            builder[param_name] = value
        try:
            builder.validate()
            break
        except ValueError as exc:
            click.echo(f'\nSomething is wrong with the configuration:\n  * {exc}')

    backend = builder.setup_backend()
    config = Config.make_new(config_path)
    config.backend_name = backend.name
    str_values = {k: str(v) for k, v in builder.init_params.items()}
    config.backend_config.update(str_values)
    config.save()
    click.echo(f'Saved configuration to {config_path}')
    click.echo(f'Successfully initialized {backend.name}. You can issue certificates now!')


@main.command('show-config')
@ensure_config
def show_config(obj):
    """Show saved configuration options."""


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
    """Show certificate details."""
    cert = obj.backend.get_cert(serial_number.lower())
    click.echo(f'Serial number:     {cert.serial_number}')
    click.echo(f'Common Name:       {cert.common_name}')
    click.echo(f'Expires:           {cert.expires}')


@main.command('show-ca-cert')
@ensure_config
def show_ca_cert(obj):
    """Show CA certificate details."""
    cert = obj.backend.get_ca_cert()
    click.echo(f'Serial number:     {cert.serial_number}')
    click.echo(f'Common Name:       {cert.common_name}')
    click.echo(f'Expires:           {cert.expires}')


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
    click.echo(f'Issuer Common Name:    {crl.issuer}')
    click.echo(f'Last update:           {crl.last_update}')
    click.echo(f'Next update:           {crl.next_update}')
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

    click.echo(f'Checking {url} ...')

    try:
        requests.head(url)  # noqa
    except requests.exceptions.SSLError as e:
        click.echo(str(e))
        ctx.exit(1)

    click.echo('Certificate is valid!')


@main.command()
@click.pass_context
def version(ctx):
    """Same as --version."""
    certmaestro_version = pkg_resources.get_distribution('certmaestro').version
    click.echo(f'Certmaestro version:   {certmaestro_version}')

    root_ctx = ctx.find_root()
    try:
        config = Config(root_ctx.params['config_path'])
        is_configured = True
    except FileNotFoundError:
        is_configured = False

    if is_configured:
        backend = get_backend(config)
        click.echo(f'Backend version:       {backend.version}')
    else:
        click.echo(f'Backend is not configured yet or invalid config path')
