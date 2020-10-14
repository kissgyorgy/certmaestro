from __future__ import print_function

import json
from pprint import pformat

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers

TOKEN = 'aa0a48f5-b307-b7e4-bfe2-d1df0733d806'

agent = Agent(reactor)
d = agent.request(b'GET', b'http://127.0.0.1:8200/v1/sys/init',
                  Headers({b'X-Vault-Token': [TOKEN]}), None)


def cbRequest(response):
    print('Response version:', response.version)
    print('Response code:', response.code)
    print('Response phrase:', response.phrase)
    print('Response headers:')
    print(pformat(list(response.headers.getAllRawHeaders())))
    d = readBody(response)
    d.addCallback(lambda b: print(b))
    return d
d.addCallback(cbRequest)


def cbShutdown(ignored):
    reactor.stop()
d.addBoth(cbShutdown)

reactor.run()
