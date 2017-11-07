import configparser
import re

from proxy.PluginRegistry import PluginRegistry


class InvalidSyslogSourceConfigError(Exception):
    pass


class ActionForKeyNotFoundError(Exception):
    pass


class InvalidConfigActionError(Exception):
    pass


class ConfigAction:

    def __init__(self, action_str: str):
        if ConfigAction.is_valid_action_string(action_str):
            self._plugin_name, parameters = action_str.split('(', 1)

            self._parameters = {}
            params = [p.strip() for p in parameters[:-1].split(',')]
            for p in params:
                if len(p) > 0:
                    key, value = [s.strip() for s in p.split('=')]
                    if value.startswith('\'') or value.startswith('"'):
                        value = value[1:-1] # Remove possible quotes
                    self._parameters[key] = value.strip()
        else:
            raise InvalidConfigActionError('Invalid action given: ' + action_str)

    @property
    def plugin_name(self):
        return self._plugin_name

    @property
    def parameters(self):
        return self._parameters

    @classmethod
    def is_valid_action_string(cls, action_str: str) -> bool:
        """
        Allow the following format:
        PLUGINNAME(ARG1 = 123, ARG2='StringThis%&/)', ARG3 = "")

        Simply beautiful and easy to read!
        """
        pattern = '^\w+\(( *\w+ *= *((\'[^\']*\'*)|("[^"]*")|\d+) *, *)*( *\w+ *= *((\'[^\']*\')|("[^"]*")|\d+) *)?\)$'
        return bool(re.match(pattern, action_str))

    def __str__(self):
        parameters = [k + "=" + self.parameters[k] for k in self.parameters]
        return "Config action: plugin_name=" + self.plugin_name +  " parameters=[" + ", ".join(parameters) + "]"


class SyslogSourceConfig:

    def __init__(self, config_file_path: str, plugin_registry: PluginRegistry):
        config = configparser.ConfigParser()
        try:
            read_config = config.read(config_file_path)
        except configparser.Error as e:
            raise InvalidSyslogSourceConfigError('Parsing of syslog source config [%s] failed: %s' % (config_file_path,
                                                                                                      str(e)))

        if len(read_config) < 1:
            raise InvalidSyslogSourceConfigError('Syslog source config [%s] could not be read.' % config_file_path)

        valid_file_format, error_message = self._check_config_file_format(config)
        if not valid_file_format:
            raise InvalidSyslogSourceConfigError("Syslog source config [%s] has invalid format: %s" % (config_file_path,
                                                 error_message))

        try:
            self._parse_config_values(config)
        except Exception as e:
            raise InvalidSyslogSourceConfigError("Syslog source config [%s] has invalid format: %s" % (config_file_path,
                                                 str(e)))

        has_actions_for_groups, error_message = self._check_pattern_groups_have_actions()
        if not has_actions_for_groups:
            raise InvalidSyslogSourceConfigError("Syslog source config [%s] has invalid format: %s" % (config_file_path,
                                                 error_message))

        uses_existing_plugins, error_message = self._check_used_plugins(plugin_registry)
        if not uses_existing_plugins:
            raise InvalidSyslogSourceConfigError("Syslog source config [%s] has invalid format: %s" % (config_file_path,
                                                 error_message))

    def _check_config_file_format(self, config: configparser.ConfigParser) -> (bool, str):
        if not(('general' in config) and ('actions' in config)):
            return False, "Config file must contain [general] and [actions] sections."

        if not (('pattern' in config['general']) and ('active' in config['general'])):
            return False, "[general] section must contain pattern and active values."

        try:
            re.compile(config['general']['pattern'])
        except Exception as e:
            return False, "Invalid pattern: %s." % str(e)

        try:
            config['general'].getboolean('active')
        except Exception:
            return False, "active field in [general] section has to be a bool value."

        return True, None

    def _check_pattern_groups_have_actions(self) -> (bool, str):
        pattern = re.compile(self.pattern)
        for groupname in pattern.groupindex:
            if not groupname in self._actions:
                return False, "No action found for pattern group (%s)." % groupname

        return True, None

    def _check_used_plugins(self, plugin_registry: PluginRegistry) -> (bool, str):
        for group in self._actions:
            action = self._actions[group]
            if not plugin_registry.has_plugin_with_name(action.plugin_name):
                return False, "Used plugin '%s' for group (%s) not found." % (action.plugin_name, group)
        return True, None

    def _parse_config_values(self, config: configparser.ConfigParser):
        general_section = config['general']
        action_section = config['actions']

        self._pattern = general_section['pattern']
        self._active = general_section.getboolean('active')

        self._actions = {}
        for key in action_section:
            action = ConfigAction(action_section[key])
            self._actions[key] = action

    @property
    def pattern(self):
        return self._pattern

    @property
    def active(self):
        return self._active

    def action_for_key(self, key: str) -> ConfigAction:
        if key in self._actions:
            action = self._actions.get(key)
            return action
        else:
            raise ActionForKeyNotFoundError('Config contains no action for ' + key)