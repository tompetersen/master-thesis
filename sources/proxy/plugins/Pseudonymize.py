import json
import requests
import hashlib

from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto import PublicKey, ThresholdCrypto

from proxy.plugin import AbstractPlugin


class Pseudonymize(AbstractPlugin):

    SERVICE_URL = '127.0.0.1'
    SERVICE_PORT = 8000

    def handle_data(self, data: str, **kwargs):
        try:
            pk = ServiceApiCaller.get_public_key(self.SERVICE_URL, self.SERVICE_PORT)
            search_token = hashlib.sha256(bytes(data, 'utf-8')).hexdigest()  # TODO: Replace with MAC
            encrypted_content = ThresholdCrypto.encrypt_message(data, pk).to_json()
            pseudonym = ServiceApiCaller.get_pseudonym_for_data(self.SERVICE_URL, self.SERVICE_PORT, encrypted_content, search_token)

            return pseudonym
        except Exception as e:
            # TODO: what to do here?
            raise


class ServiceApiError(Exception):
    pass


class ServiceApiCaller:

    @staticmethod
    def get_public_key(address: str, port: int) -> PublicKey:
        route = 'threshold/api/publickey/'
        response = ServiceApiCaller._call_service_api(address, port, route)
        return PublicKey.from_dict(response.json())

    @staticmethod
    def get_pseudonym_for_data(address: str, port: int, encrypted_content: str, search_token: str) -> str:
        route = 'store/pseudonym/'

        request_data = {'content': encrypted_content, 'search_token': search_token}
        response = ServiceApiCaller._call_service_api(address, port, route, request_data)
        result = response.json()

        return result['pseudonym']

    @staticmethod
    def _call_service_api(address: str, port: int, route: str, data=None) -> Response:
        try:
            url = 'http://' + address + ':' + str(port) + '/' + route

            if data:
                result = requests.post(url, data=data)
            else:
                result = requests.get(url)
            result.raise_for_status()

            return result
        except RequestException as e:
            raise ServiceApiError(str(e))
