class ConnectTo:
    def __init__(self, connected_interface, config):
        self.interface = connected_interface
        self.config = config

    def __enter__(self):
        self.connection = self.interface(self.config)
        return self.connection

    def __exit__(self, *args):
        self.connection.shutdown()
