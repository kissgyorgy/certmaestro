from __future__ import print_function

import json
from pprint import pformat

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

TOKEN = 'aa0a48f5-b307-b7e4-bfe2-d1df0733d806'

class BeginningPrinter(Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.remaining = 1024 * 10

    def dataReceived(self, bytes):
        if self.remaining:
            display = bytes[:self.remaining]
            print('Some data received:')
            print(json.loads(display))
            self.remaining -= len(display)

    def connectionLost(self, reason):
        print('Finished receiving body:', reason.getErrorMessage())
        self.finished.callback(None)


agent = Agent(reactor)
d = agent.request(b'GET', b'http://127.0.0.1:8200/v1/sys/init',
                  Headers({b'X-Vault-Token': [TOKEN]}), None)


def cbRequest(response):
    print('Response version:', response.version)
    print('Response code:', response.code)
    print('Response phrase:', response.phrase)
    print('Response headers:')
    print(pformat(list(response.headers.getAllRawHeaders())))
    finished = Deferred()
    response.deliverBody(BeginningPrinter(finished))
    return finished
d.addCallback(cbRequest)

def cbShutdown(ignored):
    reactor.stop()
d.addBoth(cbShutdown)

reactor.run()
