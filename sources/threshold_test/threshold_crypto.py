import number_test as number


class ThresholdParameters:

    def __init__(self, t: int, n: int):
        assert t < n, 'threshold parameter t must be smaller than n'
        assert t > 0, 'threshold parameter t must be greater than 0'

        self._t = t
        self._n = n

    @property
    def t(self) -> int:
        return self._t

    @property
    def n(self) -> int:
        return self._n


class KeyParameters:

    def __init__(self, p: int, q: int, g: int):
        assert (2 * q + 1) == p, 'no safe prime (p = 2q + 1) given'
        assert pow(g, q, p) == 1, 'no generator g for subgroup of order q given'
        assert pow(g, 2, p) != 1, 'no generator g for subgroup of order q given'

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


class PublicKey:

    def __init__(self, g_a: int, key_params: KeyParameters):
        assert key_params is not None, 'key parameters must be given'

        self._g_a = g_a
        self._key_params = key_params

    @property
    def g_a(self) -> int:
        return self._g_a

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params


class PrivateKey:

    def __init__(self, a: int, key_params: KeyParameters):
        assert key_params is not None, 'key parameters must be given'

        self._a = a
        self._key_params = key_params

    @property
    def a(self) -> int:
        return self._a

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params


class KeyShare:

    def __init__(self, x: int, y: int, key_params: KeyParameters):
        assert key_params is not None, 'key parameters must be given'

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


class EncryptedMessage:

    def __init__(self, v: int, c: int):
        self._v = v
        self._c = c

    @property
    def v(self) -> int:
        return self._v

    @property
    def c(self) -> int:
        return self._c


class PartialDecryption:

    def __init__(self, x: int, v_y: int):
        self._x = x
        self._v_y = v_y

    @property
    def x(self) -> int:
        return self._x

    @property
    def v_y(self) -> int:
        return self._v_y


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
        a = number.getRandomRange(2, key_params.q - 2) # TODO: parameters for key_params
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
        assert m < key_params.p, 'message is larger than key parameter p'

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
        assert len(partial_decryptions) >= threshold_params.t

        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = number.build_lagrange_coefficients(partial_indices, key_params.q)

        factors = [pow(partial_decryptions[i].v_y, lagrange_coefficients[i], key_params.p) for i in range(0, len(partial_decryptions))]
        restored_g_ka = number.prod(factors) % key_params.p
        restored_g_minus_ak = number.prime_mod_inv(restored_g_ka, key_params.p)
        restored_m = encrypted_message.c * restored_g_minus_ak % key_params.p

        # TODO: message decoding?
        return restored_m.to_bytes((restored_m.bit_length() // 8) + 1, byteorder='big')

