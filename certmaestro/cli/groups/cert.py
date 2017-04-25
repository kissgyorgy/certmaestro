import click
from .config import ensure_config


@click.group()
def cert():
    """Issue, sign, revoke and view certificates."""


@cert.command()
@ensure_config
def issue(obj):
    """Issue a new certificate."""
    from certmaestro.csr import CsrPolicy, CsrBuilder
    from certmaestro.config import CERT_FIELDS

    policy = obj.backend.get_csr_policy()
    defaults = obj.backend.get_csr_defaults()
    csr = CsrBuilder(policy, defaults)
    for field, description in CERT_FIELDS:
        if csr.policy[field] == CsrPolicy.REQUIRED:
            csr[field] = click.prompt(description, default=csr[field])
    key, cert = obj.backend.issue_cert(csr)


@cert.command()
@click.argument('serial_number')
@ensure_config
def show(obj, serial_number):
    """Show certificate details."""
    from ..formatter import env

    template = env.get_template('certmaestro_format.jinja2')
    cert = obj.backend.get_cert(serial_number.lower())
    click.echo(template.render(cert=cert))


@cert.command('show-ca')
@ensure_config
def show_ca(obj):
    """Show CA certificate details."""
    from ..formatter import env

    cert = obj.backend.get_ca_cert()
    template = env.get_template('certmaestro_format.jinja2')
    click.echo(template.render(cert=cert))


@cert.command('list')
@ensure_config
def list_certs(obj):
    """List issued certificates."""
    from tabulate import tabulate

    cert_list = obj.backend.list_certs()
    cert_table = ((c.subject.common_name, c.not_valid_before, c.not_valid_after, c.serial_number)
                  for c in cert_list)
    headers = ['Common Name', 'Not valid before', 'Not valid after', 'Serial Number']
    click.echo(tabulate(cert_table, headers=headers, numalign='left'))


@cert.command()
@click.argument('serial_number')
@ensure_config
def revoke(obj, serial_number):
    """Revoke a certificate."""
    result = obj.backend.revoke_cert(serial_number)
    click.echo(result)


@cert.command()
@ensure_config
def deploy(obj):
    """Copy the certificate via SSH to the given host."""


@cert.command()
@click.argument('email_address')
@ensure_config
def send(obj, email_address):
    """Send certificate in email."""
