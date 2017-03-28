import click
from tabulate import tabulate
from certmaestro.csr import CsrPolicy, CsrBuilder
from certmaestro.config import CERT_FIELDS
from ..formatter import env
from .config import ensure_config
from . import main


@main.group()
def cert():
    """Issue, sign, revoke and view certificates."""


@cert.command('issue')
@ensure_config
def issue_cert(obj):
    """Issue a new certificate."""
    policy = obj.backend.get_csr_policy()
    defaults = obj.backend.get_csr_defaults()
    csr = CsrBuilder(policy, defaults)
    for field, description in CERT_FIELDS:
        if csr.policy[field] == CsrPolicy.REQUIRED:
            csr[field] = click.prompt(description, default=csr[field])
    key, cert = obj.backend.issue_cert(csr)


@cert.command('show-cert')
@click.argument('serial_number')
@ensure_config
def show_cert(obj, serial_number):
    """Show certificate details."""
    template = env.get_template('certmaestro_format.jinja2')
    cert = obj.backend.get_cert(serial_number.lower())
    click.echo(template.render(cert=cert))


@cert.command('show-ca-cert')
@ensure_config
def show_ca_cert(obj):
    """Show CA certificate details."""
    cert = obj.backend.get_ca_cert()
    template = env.get_template('certmaestro_format.jinja2')
    click.echo(template.render(cert=cert))


@cert.command('list-certs')
@ensure_config
def list_certs(obj):
    """List issued certificates."""
    cert_list = obj.backend.get_cert_list()
    cert_table = ((c.subject.common_name, c.not_valid_before, c.not_valid_after, c.serial_number)
                  for c in cert_list)
    headers = ['Common Name', 'Not valid before', 'Not valid after', 'Serial Number']
    click.echo(tabulate(cert_table, headers=headers, numalign='left'))


@cert.command('revoke-cert')
@click.argument('serial_number')
@ensure_config
def revoke_cert(obj, serial_number):
    """Revoke a certificate."""
    result = obj.backend.revoke_cert(serial_number)
    click.echo(result)


@cert.command('deploy-cert')
@ensure_config
def deploy_cert(obj):
    """Copy the certificate via SSH to the given host."""
