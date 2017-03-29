import ssl
import click
from certmaestro.wrapper import Cert
from certmaestro.check import CheckSiteManager
from ..formatter import env
from . import main


@main.group()
def site():
    """Live website certificate checks."""


@site.command('show-cert')
@click.argument('hostname')
def show_cert(hostname, port):
    """Download the certificate from a website and show information about it."""
    cert_pem = ssl.get_server_certificate((hostname, port))
    template = env.get_template('certmaestro_format.jinja2')
    click.echo(template.render(cert=Cert(cert_pem)))
@click.argument('port', default=443, required=False, metavar='[PORT:443]')


@site.command(short_help='Check website(s) certificate(s).')
@click.argument('urls', metavar='[SITE1] [SITE2] [...]', nargs=-1)
@click.option('-t', '--timeout', default=3.0,
              help='HTTP request timeout in seconds for individual requests.')
@click.option('-r', '--retries', default=3)
@click.option('-f', '--follow-redirects', 'redirect', is_flag=True,
              help='Follow redirects (disabled by default).')
@click.pass_context
def check(ctx, urls, timeout, retries, redirect):
    """Checks if all of the websites have a valid certificate.
    Accepts multiple urls or hostnames. URLs with invalid protocols will be skipped.
    This doesn't say anything about your whole webserver configuration, only check
    the certificate. Use it as a quick check!

    \b
    Shell exitcode will be:
        - 0 if every check succeeded
        - 1 if there was an unknown protocol (not https://)
        - 2 if at least one failed
    """
    if not urls:
        raise click.UsageError('You need to provide at least one site to check!')

    click.echo('Checking certificates...')
    manager = CheckSiteManager(urls, redirect, timeout, retries)
    for check_result in manager.check_sites():
        if check_result.succeeded:
            click.secho(f'Valid:     {check_result.url}', fg='green')
        elif check_result.skipped:
            click.echo(f'Skipped:   {check_result.url} ({check_result.message})')
        elif check_result.failed:
            click.secho(f'Failed:    {check_result.url} ({check_result.message})', fg='red')

    total_message = click.style(f'Total: {len(urls)}', fg='blue')
    success_message = click.style(f'success: {manager.success_count}', fg='green')
    failed_message = click.style(f'failed: {manager.fail_count}.', fg='red')
    click.echo(f'{total_message}, {success_message}, skipped: {manager.skip_count}, {failed_message}')

    if manager.fail_count > 0:
        exitcode = 2
    elif manager.skip_count > 0:
        exitcode = 1
    else:
        exitcode = 0

    ctx.exit(exitcode)
