import unittest

import nacl.utils
import nacl.secret

from threshold_crypto import (ThresholdCrypto,
                              ThresholdParameters,
                              KeyParameters,
                              PolynomMod,
                              ThresholdCryptoError,
                              PublicKey,
                              KeyShare,
                              EncryptedMessage,
                              PartialDecryption,
                              )


class TCTestCase(unittest.TestCase):

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = ThresholdCrypto.generate_static_key_parameters()
        self.pk, self.sk = ThresholdCrypto.create_keys_centralized(self.kp)
        self.shares = ThresholdCrypto.create_shares_centralized(self.sk, self.tp)
        self.em = ThresholdCrypto.encrypt_message('Some secret message', self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [ThresholdCrypto.compute_partial_decryption(self.em, share) for share in self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_valid_threshold_parameters(self):
        t = ThresholdParameters(3,5)

    def test_invalid_threshold_parameters(self):
        with self.assertRaises(ThresholdCryptoError):
            t = ThresholdParameters(5,3)

    def test_threshold_parameter_json(self):
        t = ThresholdParameters(3, 5)
        t_j = ThresholdParameters.from_json(t.to_json())

        self.assertEqual(t, t_j)

    def test_valid_key_parameters(self):
        k = KeyParameters(7, 3, 2) # 2 generates 3-order subgroup {1,2,4}

    def test_invalid_key_parameters_whole_group(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 3, 3) # 3 generates 6-order group Z_7*

    def test_invalid_key_parameters_no_safe_prime(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 4, 3)

    def test_key_parameter_json(self):
        k_j = KeyParameters.from_json(self.kp.to_json())

        self.assertEqual(self.kp, k_j)

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

    def test_public_key_json(self):
        pk_j = PublicKey.from_json(self.pk.to_json())

        self.assertEqual(self.pk, pk_j)
        
    def test_central_share_generation(self):
        shares = ThresholdCrypto.create_shares_centralized(self.sk, self.tp)

        self.assertEqual(len(shares), self.tp.n)

    def test_key_share_json(self):
        share = self.shares[0]
        share_j = KeyShare.from_json(share.to_json())

        self.assertEqual(share, share_j)

    def test_message_encryption(self):
        em = ThresholdCrypto.encrypt_message('Some secret message', self.pk)

        self.assertTrue(em.c >= 0)
        self.assertTrue(em.v >= 0)

    def test_message_json(self):
        m_j = EncryptedMessage.from_json(self.em.to_json())

        self.assertEqual(self.em, m_j)

    def test_partial_decryption_json(self):
        pd = self.partial_decryptions[0]
        pd_j = PartialDecryption.from_json(pd.to_json())

        self.assertEqual(pd, pd_j)

    # TBD: further tests

    def test_polynom_creation(self):
        p = PolynomMod.create_random_polynom(17, 5, 41)

        self.assertTrue(p.degree == 5)
        self.assertTrue(p.evaluate(0) == 17)

    def test_key_encryption_decryption_with_enough_shares(self):
        testkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        g_k, c = ThresholdCrypto._encrypt_key(testkey, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey = ThresholdCrypto._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertEqual(testkey, rec_testkey)

    def test_key_encryption_decryption_without_enough_shares(self):
        testkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        g_k, c = ThresholdCrypto._encrypt_key(testkey, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey = ThresholdCrypto._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertNotEqual(testkey, rec_testkey)

    def test_complete_process_with_enough_shares(self):
        key_params = ThresholdCrypto.generate_static_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, priv_key = ThresholdCrypto.create_keys_centralized(key_params)
        key_shares = ThresholdCrypto.create_shares_centralized(priv_key, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [0, 2, 4]] # choose 3 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]
        decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)

        self.assertEqual(message, decrypted_message)

    def test_complete_process_without_enough_shares(self):
        key_params = ThresholdCrypto.generate_static_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, priv_key = ThresholdCrypto.create_keys_centralized(key_params)
        key_shares = ThresholdCrypto.create_shares_centralized(priv_key, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [3, 4]] # choose 2 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

        with self.assertRaises(ThresholdCryptoError):
            decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)
