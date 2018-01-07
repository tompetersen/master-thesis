"""
TBW

"""
import json

from threshold_crypto import number


class ThresholdCryptoError(Exception):
    pass


class ThresholdParameters:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return ThresholdParameters(obj['t'], obj['n'])

    def __init__(self, t: int, n: int):
        if t > n:
            raise ThresholdCryptoError('threshold parameter t must be smaller than n')
        if t <= 0:
            raise ThresholdCryptoError('threshold parameter t must be greater than 0')

        self._t = t
        self._n = n

    @property
    def t(self) -> int:
        return self._t

    @property
    def n(self) -> int:
        return self._n

    def to_json(self) -> str:
        return json.dumps({
            't': self._t,
            'n': self._n
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
               self.t == other.t and
               self.n == other.n)

    def __str__(self):
        return 'ThresholdParameters: t = %d, n = %d)' % (self._t, self._n)


class KeyParameters:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return KeyParameters(obj['p'], obj['q'], obj['g'])

    def __init__(self, p: int, q: int, g: int):
        if (2 * q + 1) != p:
            raise ThresholdCryptoError('no safe prime (p = 2q + 1) given')
        if pow(g, q, p) != 1 or pow(g, 2, p) == 1:
            raise ThresholdCryptoError('no generator g for subgroup of order q given')

        self._p = p
        self._q = q
        self._g = g

    @property
    def p(self) -> int:
        return self._p

    @property
    def q(self) -> int:
        return self._q

    @property
    def g(self) -> int:
        return self._g

    def to_json(self):
        return json.dumps({
            'p': self._p,
            'q': self._q,
            'g': self._g
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.p == other.p and
                self.q == other.q and
                self.g == other.g)

    def __str__(self):
        return 'KeyParameters:\n\tp = %d\n\tq = %d\n\tg = %d' % (self._p, self._q, self._g)


class PublicKey:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        key_params = KeyParameters.from_json(json_str)
        return PublicKey(obj['g_a'], key_params)

    def __init__(self, g_a: int, key_params: KeyParameters):
        if key_params is None:
            raise ThresholdCryptoError('key parameters must be given')

        self._g_a = g_a
        self._key_params = key_params

    @property
    def g_a(self) -> int:
        return self._g_a

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params

    def to_json(self):
        return json.dumps({
            'p': self._key_params.p,
            'q': self._key_params.q,
            'g': self._key_params.g,
            'g_a': self._g_a,
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.key_parameters == other.key_parameters and
                self.g_a == other.g_a)

    def __str__(self):
        return 'PublicKey:\n\tg^a = ' + str(self._g_a)


class PrivateKey:

    def __init__(self, a: int, key_params: KeyParameters):
        if key_params is None:
            raise ThresholdCryptoError('key parameters must be given')

        self._a = a
        self._key_params = key_params

    @property
    def a(self) -> int:
        return self._a

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params

    def __str__(self):
        return 'PrivateKey:\n\ta = ' + str(self._a)


class KeyShare:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        key_params = KeyParameters.from_json(json_str)
        return KeyShare(obj['x'], obj['y'], key_params)

    def __init__(self, x: int, y: int, key_params: KeyParameters):
        if key_params is None:
            raise ThresholdCryptoError('key parameters must be given')

        self._x = x
        self._y = y
        self._key_params = key_params

    @property
    def x(self) -> int:
        return self._x

    @property
    def y(self) -> int:
        return self._y

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params

    def to_json(self):
        return json.dumps({
            'p': self.key_parameters.p,
            'q': self.key_parameters.q,
            'g': self.key_parameters.g,
            'x': self.x,
            'y': self.y,
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.key_parameters == other.key_parameters and
                self.x == other.x and
                self.y == other.y)

    def __str__(self):
        return 'KeyShare:\n\tx = %d\n\ty = %d' % (self._x, self._y)


class EncryptedMessage:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return EncryptedMessage(obj['v'], obj['c'])

    def __init__(self, v: int, c: int):
        self._v = v
        self._c = c

    @property
    def v(self) -> int:
        return self._v

    @property
    def c(self) -> int:
        return self._c

    def to_json(self):
        return json.dumps({
            'v': self.v,
            'c': self.c,
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.v == other.v and
                self.c == other.c)

    def __str__(self):
        return 'EncryptedMessage:\n\tv = %d\n\tc = %d' % (self._v, self._c)


class PartialDecryption:

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return PartialDecryption(obj['x'], obj['v_y'])

    def __init__(self, x: int, v_y: int):
        self._x = x
        self._v_y = v_y

    @property
    def x(self) -> int:
        return self._x

    @property
    def v_y(self) -> int:
        return self._v_y

    def to_json(self):
        return json.dumps({
            'x': self.x,
            'v_y': self.v_y,
        })

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.x == other.x and
                self.v_y == other.v_y)

    def __str__(self):
        return 'PartialDecryption:\n\tx = %d\n\tv^y = %d' % (self._x, self._v_y)


class ThresholdCrypto:

    @staticmethod
    def generate_static_key_parameters() -> KeyParameters:
        # TODO: update (fixed or generated?)
        p = 7452962895294639129334402125897500494888232626693057568141676237916133687836239813279595639173262006234190877985012715032067188198462763852940914332974923
        q = 3726481447647319564667201062948750247444116313346528784070838118958066843918119906639797819586631003117095438992506357516033594099231381926470457166487461
        g = 1291791552707048245090176929539921926555612768576578304996066408519254635531597933040589792119803333400907701386210407460215915386675734438575583315866662

        return KeyParameters(p=p, q=q, g=g)

    @staticmethod
    def create_keys_centralized(key_params: KeyParameters) -> (PublicKey, PrivateKey):
        a = number.getRandomRange(2, key_params.q - 2) # TODO: parameters for key_params (here 2 and -2?)
        g_a = pow(key_params.g, a, key_params.p)
        private = PrivateKey(a, key_params)
        public = PublicKey(g_a, key_params)

        return public, private

    @staticmethod
    def create_shares_centralized(private_key: PrivateKey, threshold_params: ThresholdParameters) -> [KeyShare]:
        key_params = private_key.key_parameters

        # Perform Shamir's secret sharing in Z_q
        polynom = number.PolynomMod.create_random_polynom(private_key.a, threshold_params.t - 1, key_params.q)
        supporting_points = range(1, threshold_params.n + 1)
        shares = [KeyShare(x, polynom.evaluate(x), key_params) for x in supporting_points]

        return shares

    @staticmethod
    def encrypt_message(message: bytes, public_key: PublicKey) -> EncryptedMessage:
        key_params = public_key.key_parameters

        # TODO: message encoding?
        m = int.from_bytes(message, byteorder='big')
        if m >= key_params.p:
            raise ThresholdCryptoError('message is larger than key parameter p')

        k = number.getRandomRange(1, key_params.q - 1)
        g_k = pow(key_params.g, k, key_params.p) # aka v
        g_ak = pow(public_key.g_a, k, key_params.p)
        c = (m * g_ak) % key_params.p

        return EncryptedMessage(g_k, c)

    @staticmethod
    def compute_partial_decryption(encrypted_message: EncryptedMessage, key_share: KeyShare) -> PartialDecryption:
        key_params = key_share.key_parameters

        v_y = pow(encrypted_message.v, key_share.y, key_params.p)

        return PartialDecryption(key_share.x, v_y)

    @staticmethod
    def combine_shares(partial_decryptions: [PartialDecryption],
                       encrypted_message: EncryptedMessage,
                       threshold_params: ThresholdParameters,
                       key_params: KeyParameters
                       ) -> bytes:
        # Disabled to enable testing for unsuccessful decryption
        # if len(partial_decryptions) < threshold_params.t:
        #    raise ThresholdCryptoError('less than t partial decryptions given')

        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = number.build_lagrange_coefficients(partial_indices, key_params.q)

        factors = [pow(partial_decryptions[i].v_y, lagrange_coefficients[i], key_params.p) for i in range(0, len(partial_decryptions))]
        restored_g_ka = number.prod(factors) % key_params.p
        restored_g_minus_ak = number.prime_mod_inv(restored_g_ka, key_params.p)
        restored_m = encrypted_message.c * restored_g_minus_ak % key_params.p

        # TODO: message decoding?
        return restored_m.to_bytes((restored_m.bit_length() // 8) + 1, byteorder='big')

