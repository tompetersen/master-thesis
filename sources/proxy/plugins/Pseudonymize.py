import requests

from proxy.plugin import AbstractPlugin


class Pseudonymize(AbstractPlugin):

    SERVICE_URL = 'http://127.0.0.1:8000/store/pseudonym'
    TIMEOUT = 1.0

    def handle_data(self, data: str, **kwargs):
        try:
            request_data = {'content': data}
            r = requests.post(self.SERVICE_URL, data=request_data, timeout=self.TIMEOUT)
            r.raise_for_status()
            result = r.json()
            return result['pseudonym']
        except Exception as e:
            # TODO: what to do here?
            raise
