import json

import requests
from requests.exceptions import RequestException
from threshold_crypto.threshold_crypto import KeyShare


class ClientApiError(Exception):
    pass


class ClientApiCaller:

    @staticmethod
    def send_share(client_address: str, client_port: int, share: KeyShare):
        route='share'
        ClientApiCaller._call_client_api(client_address, client_port, route, share.to_json())

    @staticmethod
    def _call_client_api(client_address: str, client_port: int, route:str, data) -> str:
        try:
            if not isinstance(data, str):
                data = json.dumps(data)

            url = 'http://' + client_address + ':' + str(client_port) + '/' + route
            result = requests.post(url, json=data)
            if result.status_code >= 400:
                raise ClientApiError(result.text())

            return result
        except RequestException as e:
            raise ClientApiError(str(e))
