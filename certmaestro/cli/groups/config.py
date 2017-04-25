import click
from certmaestro.backends import BackendBuilder, get_backend, load_all_backends
from certmaestro.exceptions import BackendError
from certmaestro import Config
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
            self.ctx.invoke(setup)
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
                self.ctx.invoke(setup)
                self._ask_run_command()

    def _ask_run_command(self):
        if not click.confirm(f'\nDo you want to run the "{self.ctx.info_name}" command now?'):
            self.ctx.exit()


ensure_config = click.make_pass_decorator(Obj, ensure=True)


@click.group()
def config():
    """Manage Certmaestro configuration."""


@config.command()
@click.pass_context
def setup(ctx):
    """Initializes backend storage, settings roles, and generate CA."""
    all_backends = load_all_backends()
    config_path = get_config_path(ctx)
    _check_config_path(config_path)
    BackendCls = _select_backend(all_backends)
    builder = _ask_backend_params(BackendCls)
    backend = builder.setup_backend()
    _make_new_config(builder, config_path)
    click.echo(f'Saved configuration to {config_path}')
    click.secho(f'Successfully initialized {backend.name}. You can issue certificates now!',
                fg='green')


def _check_config_path(config_path):
    if config_path.exists():
        click.secho(f'Configuration file already exists: {config_path}', fg='yellow')
        click.confirm('Do you want to replace it?', abort=True)
        click.echo()


def _select_backend(all_backends):
    click.echo('Backend choices:')
    for choice, Backend in enumerate(all_backends):
        click.echo(f'{choice + 1}. {Backend.name} - {Backend.description}')

    backend_choice = click.prompt(f'Which backend do you want to set up (1-{len(all_backends)})?',
                                  default=1)
    click.echo()
    BackendCls = all_backends[backend_choice - 1]
    return BackendCls


def _ask_backend_params(BackendCls):
    builder = BackendBuilder(BackendCls)

    while True:
        for param in builder:
            value = click.prompt(param.help, default=param.default)
            builder[param.name] = value

        try:
            builder.validate()
        except ValueError as exc:
            click.secho(f'\nSomething is wrong with the configuration:\n  * {exc}\n', fg='red')
        else:
            break

    return builder


def _make_new_config(builder, config_path):
    config = Config.make_new(config_path)
    config.backend_name = builder.backend_name
    str_values = {k: str(v) for k, v in builder.init_params.items()}
    config.backend_config.update(str_values)
    config.save()


@config.command()
@ensure_config
def show(obj):
    """Show saved configuration options."""


@config.command()
def switch():
    """Switch to an already configured backend and use that from now on."""
