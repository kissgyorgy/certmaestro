import ssl
import click
import pkg_resources
from certmaestro import Config
from certmaestro.exceptions import BackendError
from certmaestro.backends import get_backend
from ..utils import get_config_path


class Obj:

    def __init__(self):
        self.ctx = click.get_current_context()
        self.config = self._get_config()
        self.backend = self._get_backend()

    def _get_config(self):
        config_path = get_config_path(self.ctx)
        try:
            return Config(config_path)
        except FileNotFoundError:
            click.confirm('This command needs configuration and an initialized backend!\n'
                          'Do you want to initialize one now?', abort=True)
            self.ctx.invoke(config.setup_backend)
            self._ask_run_command()
            return Config(config_path)

    def _get_backend(self):
        while True:
            try:
                return get_backend(self.config)
            except BackendError as exc:
                click.echo(f'Something is wrong with the {self.config.backend_name} '
                           f'backend configuration:\n  * {exc}')
                click.confirm('Would you like to reconfigure it?', abort=True)
                self.ctx.invoke(config.setup_backend)
                self._ask_run_command()

    def _ask_run_command(self):
        if not click.confirm(f'\nDo you want to run the "{self.ctx.info_name}" command now?'):
            self.ctx.exit()


ensure_config = click.make_pass_decorator(Obj, ensure=True)


@click.group(invoke_without_command=True)
@click.option('-c', '--config', 'config_path', default=Config.DEFAULT_PATH,
              help=f'Default: {Config.DEFAULT_PATH}',
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


@main.command()
@click.pass_context
def version(ctx):
    """Same as --version."""
    certmaestro_version = pkg_resources.get_distribution('certmaestro').version
    click.echo('Certmaestro ' + certmaestro_version)
    try:
        config = Config(get_config_path(ctx))
    except FileNotFoundError:
        click.echo('Backend is not configured or invalid config path')
    else:
        backend = get_backend(config)
        click.echo('Backend: ' + backend.version)


# import for the side effect
from . import config
from . import cert
from . import crl
from . import site
