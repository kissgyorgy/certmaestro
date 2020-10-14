from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

TOKEN = 'f4c2d5e1-c2cf-16bf-c338-9f5da8d0af9e'

agent = Agent(reactor)

d = agent.request(b'GET', b'http://127.0.0.1:8200/sys/init',
                  Headers({b'X-Vault-Token': [TOKEN]}), None)

def cbResponse(response):
    print('Response received')
    print(response.content)
d.addCallback(cbResponse)

def cbShutdown(error):
    print('Error', error)
    reactor.stop()
d.addBoth(cbShutdown)

print('Start reactor')
reactor.run()
