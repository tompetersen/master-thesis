import os
import shutil
import tempfile
import unittest

from threshold_crypto.threshold_crypto import KeyShare, KeyParameters

from client import Config


class ThresholdClientTest(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        print(self.test_dir)

    def tearDown(self):
        # Remove the directory after the test
        # shutil.rmtree(self.test_dir)
        pass

    def test_config_storage(self):
        path = os.path.join(self.test_dir, 'test.txt')

        key_share = KeyShare(1, 2, KeyParameters(7, 3, 2))
        c = Config('address', 42, 'name', key_share)

        c.save_config('password', path)
        c_load = Config.load_config('password', path)

        self.assertEqual(c.client_address, c_load.address)


if __name__ == '__main__':
    unittest.main()
