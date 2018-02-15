import requests
from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto.threshold_crypto import KeyShare


class ClientApiError(Exception):
    pass


class ClientApiCaller:

    @staticmethod
    def send_share(client_address: str, client_port: int, share: KeyShare):
        route = 'share'
        ClientApiCaller._call_client_api(client_address, client_port, route, share.to_dict())

    @staticmethod
    def _call_client_api(client_address: str, client_port: int, route: str, data: dict=None) -> Response:
        try:
            url = 'http://' + client_address + ':' + str(client_port) + '/' + route

            if data:
                print('Sending with data: ' + str(data))
                result = requests.post(url, json=data)
            else:
                result = requests.get(url)
            result.raise_for_status()

            return result
        except RequestException as e:
            raise ClientApiError(str(e))
