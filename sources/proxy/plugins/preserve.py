from proxy.plugin import AbstractPlugin


class Preserve(AbstractPlugin):

    def handle_data(self, data: str, **kwargs) -> str:
        return data
