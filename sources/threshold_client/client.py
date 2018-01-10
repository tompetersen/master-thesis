"""
Client application for ElGamal-based threshold decryption.

This application uses Bottle as local webserver to enable server -> client and client -> client calls.
"""
import argparse
import json
import os
import threading

import bottle
import requests
from requests.exceptions import RequestException
from requests.models import Response
from threshold_crypto import KeyShare
from nacl import secret, utils, pwhash, encoding

DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
DEFAULT_LOCAL_PORT = 1111
SERVICE_ADDRESS = '127.0.0.1'
SERVICE_PORT = 8000
DEFAULT_CONFIG_PATH = './config.txt'


class Config:

    def __init__(self, address: str, port: int, name: str, key_share: KeyShare=None):
        self.address = address
        self.port = port
        self.name = name
        self.key_share = key_share

    @staticmethod
    def from_json(json_string):
        dict = json.loads(json_string)
        key_share = KeyShare.from_dict(dict['key_share']) if len(dict['key_share']) > 0 else None
        return Config(dict['address'], dict['port'], dict['name'], key_share)

    def to_json(self):
        return json.dumps({
            'address': self.address,
            'port': self.port,
            'name': self.name,
            'key_share': self.key_share.to_dict() if self.key_share else ''
        })

    def save_config(self, password: str, filepath: str):
        encoded_message = self.to_json().encode()
        key, salt = Config._key_from_password(password)
        box = secret.SecretBox(key)
        encrypted = box.encrypt(encoded_message)

        with open(filepath, 'w') as file:
            file.write(salt.hex() + '\n')
            file.write(encrypted.hex() + '\n')

    @staticmethod
    def load_config(password: str, filepath: str):
        with open(filepath) as file:
            salt = file.readline().strip('\n ')
            salt = bytes.fromhex(salt)
            encrypted = file.readline().strip('\n ')
            encrypted = bytes.fromhex(encrypted)

        key, _ = Config._key_from_password(password, salt)
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
            p = input('Please enter your password: ')
            self.config = Config.load_config(p, config_path)
            print('Loaded config.')
        else:
            name = input('Please enter your name: ')
            self.config = Config(client_address, client_port, name)
            print('Created config.')
            ServiceApiCaller.send_client_data(client_address, client_port, name)
            print('Sent client data.')
            print('Please wait for server to create shares and respond. This may take some time...')

    def store_share(self, received: dict):
        print('Received share.')
        key_share = KeyShare.from_dict(received)
        self.config.key_share = key_share

        p = ''
        while not self._is_valid_pw(p):
            p = input('Please enter a valid password: ')

        self.config.save_config(p, self.config_path)
        print('Stored config with share.')

    def _is_valid_pw(self, p: str):
        return p and len(p) >= 8

    def get_requests(self):
        pass # TODO: TBD



class ServiceApiError(Exception):
    pass


class ServiceApiCaller:

    @staticmethod
    def get_store_entry_requests(name: str, service_address: str=SERVICE_ADDRESS, service_port: int=SERVICE_PORT):
        route = 'TBD'
        data = {
            'name': name
        }

        response = ServiceApiCaller._call_service_api(service_address, service_port, route, data)

    @staticmethod
    def send_client_data(client_address: str, client_port: int, name: str, service_address: str=SERVICE_ADDRESS, service_port: int=SERVICE_PORT):
        route = 'threshold/api/clientconnect/'
        data = {
            'name': name,
            'client_address': client_address,
            'client_port': client_port,
        }

        response = ServiceApiCaller._call_service_api(service_address, service_port, route, data)

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
    bottle.run(app, host=localaddress, port=localport, debug=True)


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