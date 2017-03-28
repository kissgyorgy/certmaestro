import click
from certmaestro.backends import BACKENDS, BackendBuilder
from certmaestro import Config
from . import main, ensure_config
from ..utils import get_config_path


@main.group()
def config():
    """Manage Certmaestro configuration."""


@config.command('setup-backend')
@click.pass_context
def setup_backend(ctx):
    """Initializes backend storage, settings roles, and generate CA."""
    config_path = get_config_path(ctx)
    _check_config_path(config_path)
    BackendCls = _select_backend()
    builder = _ask_backend_params(BackendCls)
    _make_new_config(builder, config_path)
    click.echo(f'Saved configuration to {config_path}')
    click.echo(f'Successfully initialized {backend.name}. You can issue certificates now!')


def _check_config_path(config_path):
    if config_path.exists():
        click.confirm(f'Configuration file already exists: {config_path}\n'
                      'Do you want to replace it?', abort=True)
        click.echo()


def _select_backend():
    click.echo('Backend choices:')
    for choice, Backend in enumerate(BACKENDS):
        click.echo(f'{choice + 1}. {Backend.name} - {Backend.description}')

    backend_choice = click.prompt(f'Which backend do you want to set up (1-{len(BACKENDS)})?',
                                  default=1)
    click.echo()
    BackendCls = BACKENDS[backend_choice - 1]
    return BackendCls


def _ask_backend_params(BackendCls):
    builder = BackendBuilder(BackendCls)

    while True:
        for param in builder:
            value = click.prompt(param.help, default=param.default)
            builder[param.name] = value

        if builder.is_valid():
            break
        else:
            click.echo(f'\nSomething is wrong with the configuration:\n  * {exc}')

    return builder


def _make_new_config(builder, config_path):
    backend = builder.setup_backend()
    config = Config.make_new(config_path)
    config.backend_name = backend.name
    str_values = {k: str(v) for k, v in builder.init_params.items()}
    config.backend_config.update(str_values)
    config.save()


@config.command('show-config')
@ensure_config
def show_config(obj):
    """Show saved configuration options."""
