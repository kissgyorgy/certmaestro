import click


@click.group()
def site():
    """Live website certificate checks."""


@site.command('show-cert')
@click.argument('hostname')
@click.argument('port', default=443, required=False, metavar='[PORT:443]')
@click.pass_context
def show_cert(ctx, hostname, port):
    """Download the certificate from a website and show information about it.
    \b
    You can optionally give a port number which is 443 by default.
    """
    import ssl
    from certmaestro.wrapper import Cert
    from certmaestro.check import parse_socket_error_message
    from ..formatter import env

    try:
        cert_pem = ssl.get_server_certificate((hostname, port))
    except ssl.SSLError as e:
        click.echo('Error: ' + parse_socket_error_message(e.args[1]))
        ctx.abort()
    else:
        template = env.get_template('certmaestro_format.jinja2')
        click.echo(template.render(cert=Cert(cert_pem)))


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
    from certmaestro.check import CheckSiteManager

    if not urls:
        raise click.UsageError('You need to provide at least one site to check!')

    click.echo('Checking certificates...')
    manager = CheckSiteManager(urls, redirect, timeout, retries)
    for checked_site in manager.check_sites():
        if checked_site.succeeded:
            click.secho(f'Valid:     {checked_site.url}', fg='green')
        elif checked_site.skipped:
            click.echo(f'Skipped:   {checked_site.url} ({checked_site.message})')
        elif checked_site.failed:
            click.secho(f'Failed:    {checked_site.url} ({checked_site.message})', fg='red')

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
