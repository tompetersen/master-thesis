import datetime

import requests
import hashlib
from nacl import utils, hash
from requests.auth import HTTPBasicAuth

from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto import PublicKey, ThresholdCrypto

from proxy.plugin import AbstractPlugin


class Pseudonymize(AbstractPlugin):

    SERVICE_URL = '127.0.0.1'
    SERVICE_PORT = 8000
    USERNAME = 'store'
    PASSWORD = 'test1234'

    def __init__(self):
        try:
            self._apicaller = ServiceApiCaller(self.SERVICE_URL, self.SERVICE_PORT, self.USERNAME, self.PASSWORD)
            self.mac_key = None
            self.pk, self.pseudonym_update_interval = self._apicaller.get_config()
            print('\tReceived service public key: ' + str(self.pk.g_a))
            print('\tReceived service pseudonym_update_interval: ' + str(self.pseudonym_update_interval))
        except Exception:
            raise Exception('Could not receive required public encryption key from pseudonym service! Make sure service is reachable!')

        self._generate_new_mac_key_if_required()

    def handle_data(self, data: str, **kwargs):
        self._generate_new_mac_key_if_required()

        search_token = hash.blake2b(data.encode(), key=self.mac_key)
        encrypted_content = ThresholdCrypto.encrypt_message(data, self.pk).to_json()
        pseudonym = self._apicaller.get_pseudonym_for_data(encrypted_content, search_token)

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

    def __init__(self, address, port, username, password):
        self._address = address
        self._port = port
        self._username = username
        self._password = password

    def get_config(self) -> (PublicKey, int):
        route = 'api/config/'
        response = self._call_service_api(route)
        response_dict = response.json()
        pk = response_dict['public_key']
        pseudonym_update_interval = response_dict['pseudonym_update_interval']

        return PublicKey.from_dict(pk), int(pseudonym_update_interval)

    def get_pseudonym_for_data(self, encrypted_content: str, search_token: str) -> str:
        route = 'api/pseudonym/'

        request_data = {'content': encrypted_content, 'search_token': search_token}
        response = self._call_service_api(route, request_data)
        result = response.json()

        return result['pseudonym']

    def _call_service_api(self, route: str, data=None) -> Response:
        try:
            url = 'http://' + self._address + ':' + str(self._port) + '/' + route

            if data:
                result = requests.post(url, data=data, auth=HTTPBasicAuth(self._username, self._password))
            else:
                result = requests.get(url, auth=HTTPBasicAuth(self._username, self._password))
            result.raise_for_status()

            return result
        except RequestException as e:
            raise ServiceApiError(str(e))
