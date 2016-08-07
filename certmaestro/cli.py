import click


@click.group()
def main():
    """Certmaestro."""


@main.command('init-config')
def init_config():
    """Initializes backend storage and settings."""


@main.command('issue-cert')
def issue_cert():
    """Issue a new certificate."""


@main.command('view-cert')
def show_cert():
    """View certificate details."""


@main.command('revoke-cert')
def revoke_cert():
    """Revoke a certificate."""


@main.command('update-crl')
def update_crl():
    """Update the Certificate Revocation List (CRL)."""


@main.command('view-crl')
def show_crl():
    """Update the Certificate Revocation List (CRL)."""
