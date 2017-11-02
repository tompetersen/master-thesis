from AbstractPlugin import AbstractPlugin


class MissingSubstituteError(Exception):
    pass


class Substitute(AbstractPlugin):

    def handle_data(self, data: str, **kwargs) -> str:
        if 'substitute' in kwargs:
            return kwargs['substitute']
        else:
            raise MissingSubstituteError
