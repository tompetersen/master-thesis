"""
Client application for ElGamal-based threshold decryption.

This application uses Bottle as local webserver to enable server -> client and client -> client calls.
"""
import argparse
import getpass
import json
import os
import threading

import bottle
import requests
from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto import KeyShare
from nacl import secret, utils, pwhash, exceptions
from threshold_crypto.threshold_crypto import PartialDecryption, EncryptedMessage, ThresholdCrypto

DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
DEFAULT_LOCAL_PORT = 1111
SERVICE_ADDRESS = '127.0.0.1'
SERVICE_PORT = 8000
DEFAULT_CONFIG_PATH = './config.txt'


class Config:

    def __init__(self, address: str, port: int, service_username: str, service_password: str, key_share: KeyShare=None):
        self.client_address = address
        self.client_port = port
        self.service_username = service_username
        self.service_password = service_password
        self.key_share = key_share

    @staticmethod
    def from_json(json_string):
        dict = json.loads(json_string)
        key_share = KeyShare.from_dict(dict['key_share']) if len(dict['key_share']) > 0 else None
        return Config(dict['address'], dict['port'], dict['service_username'], dict['service_password'], key_share)

    def to_json(self):
        return json.dumps({
            'address': self.client_address,
            'port': self.client_port,
            'service_username': self.service_username,
            'service_password': self.service_password,
            'key_share': self.key_share.to_dict() if self.key_share else ''
        })

    def save_config(self, local_password: str, filepath: str):
        encoded_message = self.to_json().encode()
        key, salt = Config._key_from_password(local_password)
        box = secret.SecretBox(key)
        encrypted = box.encrypt(encoded_message)

        with open(filepath, 'w') as file:
            file.write(salt.hex() + '\n')
            file.write(encrypted.hex() + '\n')

    @staticmethod
    def load_config(local_password: str, filepath: str):
        with open(filepath) as file:
            salt = file.readline().strip('\n ')
            salt = bytes.fromhex(salt)
            encrypted = file.readline().strip('\n ')
            encrypted = bytes.fromhex(encrypted)

        key, _ = Config._key_from_password(local_password, salt)
        box = secret.SecretBox(key)
        decrypted = box.decrypt(encrypted).decode()

        return Config.from_json(decrypted)

    @staticmethod
    def _key_from_password(password: str, salt: bytes=None) -> (bytes, bytes):
        """
        Generates key bytes from a password and an optional salt

        :param password: the password
        :param salt: a random salt. If not set, a random salt is generated.
        :return: (key bytes, salt bytes)
        """
        if not salt:
            salt = utils.random(pwhash.argon2i.SALTBYTES)
        password_encoded = password.encode()

        key = pwhash.argon2i.kdf(size=secret.SecretBox.KEY_SIZE,
                                 password=password_encoded,
                                 salt=salt,
                                 opslimit=pwhash.argon2i.OPSLIMIT_MODERATE,
                                 memlimit=pwhash.argon2i.MEMLIMIT_MODERATE)

        return key, salt


class ThresholdClient:

    def __init__(self, client_address: str, client_port: int, config_path: str):
        self.client_address = client_address
        self.client_port = client_port
        self.config_path = config_path

        if os.path.exists(config_path):
            p = getpass.getpass('Please enter your local password: ')
            try:
                self.config = Config.load_config(p, config_path)
            except exceptions.CryptoError as e:
                print('Could not decrypt required client data. Exiting...')
                exit(-1)
            print('Loaded config.')
            self.service_api_caller = ServiceApiCaller(self.config.service_username, self.config.service_password)

            self.start_request_process()
        else:
            service_username = input('Please enter your service username: ')
            service_password = getpass.getpass('Please enter your service password: ')

            self.config = Config(client_address, client_port, service_username, service_password)
            self.service_api_caller = ServiceApiCaller(self.config.service_username, self.config.service_password)
            print('Created config.')

            try:
                self.service_api_caller.send_client_data(client_address, client_port)
            except ServiceApiError as e:
                print('Could not send initial client data. Please check that server is reachable and credentials are valid.')
                exit(-1)

            print('Sent client data.')
            print('Please wait for server to create shares and respond. This may take some time...')

    def create_api_caller_from_config(self):
        c = self.config
        self.service_api_caller = ServiceApiCaller(c.service_username, c.service_password)

    def store_share(self, received: dict):
        print('Received share.')
        key_share = KeyShare.from_dict(received)
        self.config.key_share = key_share

        p = ''
        while not self._is_valid_pw(p):
            p = getpass.getpass('Please enter a valid password used to store your config and share: ')

        self.config.save_config(p, self.config_path)
        print('Stored config with share.')

        # TODO: Wait for server OK after finishing generation process?

        self.start_request_process()

    def _is_valid_pw(self, p: str):
        return p and len(p) >= 8

    def start_request_process(self):
        while True:
            input('\nPress a key to ask for new decryption requests requiring your choice...')
            store_entry_requests = self.service_api_caller.get_store_entry_requests()
            if len(store_entry_requests) == 0:
                print('No action required.')
            else:
                for r in store_entry_requests:
                    self.handle_request(r)
                print('All decryption requests handled.')

    def handle_request(self, request):
        req_id = request['request_id']
        req_by = request['requested_by']
        pseudonym = request['pseudonym']
        encrypted_message = EncryptedMessage(request['em_v'], request['em_c'], '')

        print('New decryption request for pseudonym ' + pseudonym + ' by ' + req_by)
        print('(A)ccept - (D)ecline - (P)ostpone')
        choice = ''
        while choice not in ['A', 'D', 'P']:
            choice = input('Choose your action: ')

        try:
            if choice == 'A':
                partial_decryption = ThresholdCrypto.compute_partial_decryption(encrypted_message, self.config.key_share)
                self.service_api_caller.send_partial_decryption(req_id, True, partial_decryption)
                print('Accepted pseudonym decryption request.')
            elif choice == 'D':
                self.service_api_caller.send_partial_decryption(req_id, False)
                print('Declined pseudonym decryption request.')
            elif choice == 'P':
                print('Choosing action postponed.')
        except ServiceApiError as e:
            print('Could not perform action: ' + str(e))
        print('--------')


class ServiceApiError(Exception):
    pass


class ServiceApiCaller:

    def __init__(self, username: str, password: str, service_address: str=SERVICE_ADDRESS, service_port: int=SERVICE_PORT):
        self._address = service_address
        self._port = service_port
        self._username = username
        self._password = password

    def get_store_entry_requests(self) -> [dict]:
        route = 'api/requests/'

        response = self._call_service_api(route)
        return response.json()

    def send_client_data(self, client_address: str, client_port: int):
        route = 'api/clientconnect/'
        data = {
            'client_address': client_address,
            'client_port': client_port,
        }

        response = self._call_service_api(route, data)

    def send_partial_decryption(self, request_id: int, accepted: bool, partial_decryption: PartialDecryption=None):
        route = 'api/partial_decryption/'
        data = {
            'request': request_id,
            'accepted': accepted,
            'partial_decryption': partial_decryption.to_json() if partial_decryption else ''
        }

        response = self._call_service_api(route, data)

    def _call_service_api(self, route: str, data=None) -> Response:
        result = None
        try:
            url = 'http://' + self._address + ':' + str(self._port) + '/' + route

            if data:
                result = requests.post(url, data=data)
            else:
                result = requests.get(url)
            result.raise_for_status()

            return result
        except RequestException as e:
            error_dict = result.json()
            raise ServiceApiError(error_dict['detail'] if 'detail' in error_dict else 'Unknown reason.')


def main():
    parser = argparse.ArgumentParser(description='Run the threshold crypto client.')
    parser.add_argument('--localaddress', '-a', default=DEFAULT_LOCAL_ADDRESS, required=False, help='the local address')
    parser.add_argument('--localport', '-p', default=DEFAULT_LOCAL_PORT, required=False, type=int, help='the local port')
    parser.add_argument('--configfile', '-c', default=DEFAULT_CONFIG_PATH, required=False, help='the config file path')
    args = parser.parse_args()
    localport = args.localport
    localaddress = args.localaddress
    configfile_path = args.configfile

    client = ThresholdClient(localaddress, localport, configfile_path)
    app = create_bottle_app(client)
    bottle.run(app, host=localaddress, port=localport, debug=False, quiet=True)


def create_bottle_app(client: ThresholdClient) -> bottle.Bottle:
    app = bottle.Bottle()

    @app.post('/share')
    def store_share():
        received = bottle.request.json
        t = threading.Thread(target=ThresholdClient.store_share, args=(client, json.loads(received)))
        t.start()

        return "SUCCESS"

    return app


if __name__ == "__main__":
    main()