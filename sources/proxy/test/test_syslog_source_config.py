import os
import re
from unittest import TestCase, main
from unittest.mock import Mock

from proxy.SyslogSourceConfig import SyslogSourceConfig, InvalidSyslogSourceConfigError, ConfigAction, InvalidConfigActionError


class TestSyslogSourceConfig(TestCase):

    def setUp(self):
        attrs = {'has_plugin_with_name.return_value': True}
        self.mock_plugin_registry = Mock(**attrs)

    def file_path_for_test_config(self, test_config: str) -> str:
        return os.path.join('test', 'test_configs', test_config)

    def test_valid_config_general_section(self):
        config_path = self.file_path_for_test_config('test_config.cfg')
        config = SyslogSourceConfig(config_path, self.mock_plugin_registry)

        self.assertTrue(config)
        self.assertEqual(config.pattern, '^(?P<time>\w+ *\d{1,2} \d{2}:\d{2}:\d{2}) (?P<device>[^:]+): Testing my device USER=(?P<user>.+)$')
        self.assertTrue(config.active)

    def test_valid_config_actions_section(self):
        config_path = self.file_path_for_test_config('test_config.cfg')
        config = SyslogSourceConfig(config_path, self.mock_plugin_registry)

        action1 = config.action_for_key('time')
        action2 = config.action_for_key('user')

        self.assertEqual(action1.plugin_name, 'Substitute')
        self.assertEqual(len(action1.parameters), 1)
        self.assertEqual(action1.parameters['substitute'], 'somevalue_time')
        self.assertEqual(action2.plugin_name, 'Pseudonymize')
        self.assertEqual(len(action2.parameters), 0)

    def test_bad_config_1(self):
        config_path = self.file_path_for_test_config('bad_config_1.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('Config file must contain [general] and [actions] sections.' in str(context.exception))

    def test_bad_config_2(self):
        config_path = self.file_path_for_test_config('bad_config_2.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('Config file must contain [general] and [actions] sections.' in str(context.exception))

    def test_bad_config_3(self):
        config_path = self.file_path_for_test_config('bad_config_3.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('Config file must contain [general] and [actions] sections.' in str(context.exception))

    def test_bad_config_4(self):
        config_path = self.file_path_for_test_config('bad_config_4.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('active field in [general] section has to be a bool value.' in str(context.exception))

    def test_bad_config_5(self):
        config_path = self.file_path_for_test_config('bad_config_5.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('Invalid pattern: ' in str(context.exception))

    def test_bad_config_6(self):
        config_path = self.file_path_for_test_config('bad_config_6.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('No action found for pattern group ' in str(context.exception))

    def test_bad_config_7(self):
        config_path = self.file_path_for_test_config('bad_config_7.cfg')

        attrs = {'has_plugin_with_name.return_value': False}
        tmp_mock_plugin_registry = Mock(**attrs)

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, tmp_mock_plugin_registry)
            self.assertTrue(re.match('Used plugin .* in group .* not found.', str(context.exception)))

    def test_bad_config_8(self):
        config_path = self.file_path_for_test_config('bad_config_8.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('[general] section must contain pattern and active values.' in str(context.exception))

    def test_bad_config_9(self):
        config_path = self.file_path_for_test_config('bad_config_9.cfg')

        with self.assertRaises(InvalidSyslogSourceConfigError) as context:
            SyslogSourceConfig(config_path, self.mock_plugin_registry)
        self.assertTrue('Invalid action given: ' in str(context.exception))


class TestConfigAction(TestCase):

    def test_valid_action_strings(self):
        self.assertTrue(ConfigAction.is_valid_action_string('A()'))
        self.assertTrue(ConfigAction.is_valid_action_string('A(b=3)'))
        self.assertTrue(ConfigAction.is_valid_action_string('A(b="23486gsfdjbg89z&//$%?=(")'))
        self.assertTrue(ConfigAction.is_valid_action_string('A(b=\'23486gsfdjbg89z&//$%?=(\')'))
        self.assertTrue(ConfigAction.is_valid_action_string('A(b=3,c=\'\',d="")'))
        self.assertTrue(ConfigAction.is_valid_action_string('A( b = 3   , c     =\'\',d=     ""    )'))

    def test_invalid_action_strings(self):
        self.assertFalse(ConfigAction.is_valid_action_string(''))
        self.assertFalse(ConfigAction.is_valid_action_string('()'))
        self.assertFalse(ConfigAction.is_valid_action_string('A'))
        self.assertFalse(ConfigAction.is_valid_action_string('A(b=\'")'))
        self.assertFalse(ConfigAction.is_valid_action_string('A(b)'))
        self.assertFalse(ConfigAction.is_valid_action_string('A(b=())'))


if __name__ == '__main__':
    main()