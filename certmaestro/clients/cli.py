from collections import namedtuple
import click
from certmaestro import Config, get_backend


Obj = namedtuple('Obj', 'config, backend')


@click.group()
@click.pass_context
def main(ctx):
    """Certmaestro command line interface."""
    config = Config('certmaestro.ini')
    backend = get_backend(config)
    while not backend.check_config():
        click.echo('Invalid Configuration parameters!')
        for param_name, question in backend.config.check_config_requires:
            value = click.prompt(question, default=getattr(backend.config, param_name))
            setattr(backend.config, param_name, value)
    ctx.obj = Obj(config, backend)


@main.command('init-backend')
@click.pass_obj
def init_backend(obj):
    """Initializes backend storage, settings roles, and generate CA."""
    required_params = dict()
    for param_name, question in obj.backend.config.init_requires:
        default = getattr(obj.backend.config, param_name)
        required_params[param_name] = click.prompt(question, default=default)
    obj.backend.init(**required_params)
    obj.config.save()
    click.echo('Initialized backend. You can issue certificates now!')


@main.command('show-config')
@click.pass_obj
def show_config(obj):
    """Shows saved configuration options."""
    click.echo(obj.config)
    click.echo(obj.backend.config)


@main.command('issue-cert')
@click.pass_obj
def issue_cert(obj):
    """Issue a new certificate."""
    common_name = click.prompt('Common name')
    result = obj.backend.issue_cert(common_name)
    click.echo(result)


@main.command('view-cert')
@click.argument('serial')
@click.pass_obj
def show_cert(obj, serial):
    """View certificate details."""
    cert = obj.backend.get_cert(serial)
    click.echo(cert)


@main.command('list-certs')
@click.pass_obj
def list_certs(obj):
    """List issued certificates."""
    certs = obj.backend.get_cert_list()
    click.echo(certs)


@main.command('revoke-cert')
@click.pass_obj
def revoke_cert(obj):
    """Revoke a certificate."""


@main.command('update-crl')
@click.pass_obj
def update_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@main.command('view-crl')
@click.pass_obj
def show_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@main.command('deploy-cert')
@click.pass_obj
def deploy_cert(obj):
    """Copy the certificate via SSH to the given host."""
