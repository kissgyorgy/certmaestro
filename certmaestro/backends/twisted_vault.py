import json
from twisted.internet import reactor, defer
from twisted.web.client import Agent, RedirectAgent, readBody
from twisted.web.http_headers import Headers
from .interfaces import IBackend
from .vault import _VaultCommon
from . import register_backend


@register_backend
class TwistedVaultClient:
    def __init__(self, url, token):
        self._url = url[:-1] if url.endswith('/') else url
        self._agent = RedirectAgent(Agent(reactor))
        self._token = token

    def write(self, path, **kwargs):
        full_url = self._url + '/v1/' + path
        d = self._agent.request(b'PUT', full_url.encode(),
                                Headers({b'X-Vault-Token': [self._token]}), None)
        d.addCallback(readBody)
        d.addCallback(print)
        return d

    def read(self, path, **kwargs):
        full_url = self._url + '/v1/' + path
        d = self._agent.request(b'GET', full_url.encode(),
                                Headers({b'X-Vault-Token': [self._token]}), None)
        d.addCallback(self._getBody)
        d.addErrback(print)
        return d

    def _getBody(self, response):
        print('Reading body')
        d = readBody(response)
        d.addCallback(lambda b: json.loads(b))
        return d


class Backend(_VaultCommon, IBackend):
    _client_class = TwistedVaultClient
    name = 'Twisted Vault'
