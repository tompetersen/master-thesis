from proxy.AbstractPlugin import AbstractPlugin


class Pseudonymize(AbstractPlugin):

    def handle_data(self, data: str, **kwargs):
        return "PSEUDONYM(" + data + ")"