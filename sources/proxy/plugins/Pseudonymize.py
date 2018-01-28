import datetime

import requests
import hashlib
from nacl import utils, hash

from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto import PublicKey, ThresholdCrypto

from proxy.plugin import AbstractPlugin


class Pseudonymize(AbstractPlugin):

    SERVICE_URL = '127.0.0.1'
    SERVICE_PORT = 8000

    def __init__(self):
        try:
            self.mac_key = None
            self.pk, self.pseudonym_update_interval = ServiceApiCaller.get_config(self.SERVICE_URL, self.SERVICE_PORT)
            print('\tReceived service public key: ' + str(self.pk.g_a))
            print('\tReceived service pseudonym_update_interval: ' + str(self.pseudonym_update_interval))
        except Exception:
            raise Exception('Could not receive required public encryption key from pseudonym service! Make sure service is reachable!')

        self._generate_new_mac_key_if_required()

    def handle_data(self, data: str, **kwargs):
        self._generate_new_mac_key_if_required()

        search_token = hash.blake2b(data.encode(), key=self.mac_key)
        encrypted_content = ThresholdCrypto.encrypt_message(data, self.pk).to_json()
        pseudonym = ServiceApiCaller.get_pseudonym_for_data(self.SERVICE_URL, self.SERVICE_PORT, encrypted_content, search_token)

        return pseudonym

    def _generate_new_mac_key_if_required(self):
        """
        Generate a new mac key if no key is present or it has been created at least [pseudoynm_update_interval]
        minutes before.
        """
        create_new = True
        if self.mac_key:
            now = datetime.datetime.now()
            gen_plus_update_interval = self.mac_key_generation_time + datetime.timedelta(minutes=self.pseudonym_update_interval)
            create_new = (gen_plus_update_interval < now)

        if create_new:
            self.mac_key = utils.random(size=64)
            self.mac_key_generation_time = datetime.datetime.now()


class ServiceApiError(Exception):
    pass


class ServiceApiCaller:

    @staticmethod
    def get_config(address: str, port: int) -> (PublicKey, int):
        route = 'api/config/'
        response = ServiceApiCaller._call_service_api(address, port, route)
        response_dict = response.json()
        pk = response_dict['public_key']
        pseudonym_update_interval = response_dict['pseudonym_update_interval']

        return PublicKey.from_dict(pk), int(pseudonym_update_interval)

    @staticmethod
    def get_pseudonym_for_data(address: str, port: int, encrypted_content: str, search_token: str) -> str:
        route = 'api/pseudonym/'

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
