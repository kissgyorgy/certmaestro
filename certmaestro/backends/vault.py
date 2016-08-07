import hvac


class VaultBackend:
    def __init__(self, connection, token):
        self.client = hvac.Client(connection, token)

    def init(self):
        self.client.enable_secret_backend('pki')
