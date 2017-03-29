import ssl
import click
import pkg_resources
from certmaestro import Config
from certmaestro.backends import get_backend
from ..utils import get_config_path


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
