from collections import namedtuple
import click
from certmaestro import Config, get_backend
from tabulate import tabulate


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


@main.command('show-cert')
@click.argument('serial_number')
@click.pass_obj
def show_cert(obj, serial_number):
    """View certificate details."""
    cert = obj.backend.get_cert(serial_number)
    click.echo('Serial number:     %s' % cert.coloned_serial)
    click.echo('Common Name:       %s' % cert.common_name)
    click.echo('Expires:           %s' % cert.expiration)


@main.command('list-certs')
@click.pass_obj
def list_certs(obj):
    """List issued certificates."""
    cert_list = obj.backend.get_cert_list()
    cert_table = ((c.common_name, c.expires, c.serial_number,) for c in cert_list)
    click.echo(tabulate(cert_table, headers=['Common Name', 'Expires', 'Serial Number']))


@main.command('revoke-cert')
@click.argument('serial_number')
@click.pass_obj
def revoke_cert(obj, serial_number):
    """Revoke a certificate."""
    result = obj.backend.revoke_cert(serial_number)
    click.echo(result)


@main.command('update-crl')
@click.pass_obj
def update_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@main.command('show-crl')
@click.pass_obj
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
def deploy_cert(obj):
    """Copy the certificate via SSH to the given host."""
