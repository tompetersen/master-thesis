import unittest
from threshold_crypto import ThresholdCrypto, ThresholdParameters, KeyParameters


class TCTestCase(unittest.TestCase):

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = ThresholdCrypto.generate_static_key_parameters()
        self.pk, self.sk = ThresholdCrypto.create_keys_centralized(self.kp)

    def tearDown(self):
        pass

    def test_valid_threshold_parameters(self):
        t = ThresholdParameters(3,5)

    @unittest.expectedFailure
    def test_invalid_threshold_parameters(self):
        t = ThresholdParameters(5,3)

    def test_valid_key_parameters(self):
        k = KeyParameters(7, 3, 2) # 2 generates 3-order subgroup {1,2,4}

    @unittest.expectedFailure
    def test_invalid_key_parameters_whole_group(self):
        k = KeyParameters(7, 3, 3) # 3 generates 6-order group Z_7*

    @unittest.expectedFailure
    def test_invalid_key_parameters_no_safe_prime(self):
        k = KeyParameters(7, 4, 3)

    def test_static_key_parameter_generation(self):
        kp = ThresholdCrypto.generate_static_key_parameters()

        self.assertEqual(self.kp.p, 2*self.kp.q + 1) # safe prime
        self.assertEqual(pow(self.kp.g, self.kp.q, self.kp.p), 1) # g generates q order subgroup
        self.assertNotEqual(pow(self.kp.g, 2, self.kp.p), 1)

    def test_central_key_generation(self):
        pk, sk = ThresholdCrypto.create_keys_centralized(self.kp)

        self.assertEqual(pk.key_parameters, self.kp)
        self.assertEqual(sk.key_parameters, self.kp)
        self.assertEqual(pk.g_a, pow(self.kp.g, sk.a, self.kp.p))
        
    def test_central_share_generation(self):
        shares = ThresholdCrypto.create_shares_centralized(self.sk, self.tp)

        self.assertEqual(len(shares), self.tp.n)

    def test_message_encryption(self):
        em = ThresholdCrypto.encrypt_message(b'1234', self.pk)

        self.assertTrue(em.c >= 0)
        self.assertTrue(em.v >= 0)

    # TBD: further tests

    def test_complete_process(self):
        key_params = ThresholdCrypto.generate_static_key_parameters()
        thresh_params = ThresholdParameters(2,3)

        pub_key, priv_key = ThresholdCrypto.create_keys_centralized(key_params)
        key_shares = ThresholdCrypto.create_shares_centralized(priv_key, thresh_params)

        message = b'1337'
        encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in key_shares]
        decrypted_message = ThresholdCrypto.combine_shares(partial_decryptions, encrypted_message, thresh_params, key_params)

        self.assertEqual(message, decrypted_message)
