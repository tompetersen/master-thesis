"""
Client application for ElGamal-based threshold decryption.

This application uses Bottle as local webserver to enable server -> client and client -> client calls.
"""
import argparse
import bottle
import requests


DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
DEFAULT_LOCAL_PORT = 1111
DEFAULT_SERVICE_ADDRESS = '127.0.0.1'
DEFAULT_SERVICE_PORT = 8000


class ThresholdClient:

    def __init__(self):
        pass

    def store_share(self, received):
        print('RECEIVED share: ' + str(received))


def main():
    parser = argparse.ArgumentParser(description='Run the threshold crypto client.')
    parser.add_argument('--localaddress', '-a', default=DEFAULT_LOCAL_ADDRESS, required=False, help='the local address')
    parser.add_argument('--localport', '-p', default=DEFAULT_LOCAL_PORT, required=False, type=int, help='the local port')
    parser.add_argument('name', help='your name')
    args = parser.parse_args()
    localport = args.localport
    localaddress = args.localaddress
    name = args.name

    send_client_data(localaddress, localport, name)

    client = ThresholdClient()

    app = create_bottle_app(client)
    bottle.run(app, host=localaddress, port=localport, debug=True)


def send_client_data(localaddress, localport, name):
    data = {
        'name': name,
        'client_address': localaddress,
        'client_port': localport,
    }
    response = requests.post('http://' + DEFAULT_SERVICE_ADDRESS + ':' + str(DEFAULT_SERVICE_PORT) + '/threshold/api/clientconnect/', json=data)
    if response.status_code != 201:
        print('Sending own address failed [%d]:' % response.status_code)
        print(response.json())
        exit(-1)

def create_bottle_app(client: ThresholdClient) -> bottle.Bottle:
    app = bottle.Bottle()

    @app.route('/test')
    def test():
        return {'key': 'testvalue'}

    @app.route('/error')
    def error():
        bottle.abort(542, 'Some error')

    @app.post('/share')
    def store_share():
        received = bottle.request.json
        client.store_share(received)

        return "SUCCESS"

    return app


if __name__ == "__main__":
    main()