import click
from tabulate import tabulate
from . import main, ensure_config


@main.group()
def crl():
    """Handle Certification revocation list."""


@crl.command('update-crl')
@ensure_config
def update_crl(obj):
    """Update the Certificate Revocation List (CRL)."""


@crl.command('show-crl')
@ensure_config
def show_crl(obj):
    """Show the Certificate Revocation List."""
    crl = obj.backend.get_crl()
    click.echo(f'Issuer Common Name:    {crl.issuer.common_name}')
    click.echo(f'This update:           {crl.this_update}')
    click.echo(f'Next update:           {crl.next_update}')
    click.echo()
    headers = ['Revocation Date', 'Invalidity Date', 'Reason', 'Serial Number']
    revoked_certs = [(rc.revocation_date, rc.invalidity_date, rc.reason, rc.serial_number)
                     for rc in crl]
    click.echo(tabulate(revoked_certs, headers=headers))
    if not revoked_certs:
        click.echo('No certificates has been revoked yet!')
