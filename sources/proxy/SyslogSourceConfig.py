import configparser
import re


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
                key, value = p.split('=')
                self._parameters[key.strip()] = value.strip()
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
        """
        pattern = '^\w+\((\w+ *= *((\'[^\']+\'*)|("[^"]+")|\d+) *, *)*(\w+ *= *((\'[^\']+\'*)|("[^"]+")|\d+))?\)$'
        return bool(re.match(pattern, action_str))

    def __str__(self):
        parameters = [k + "=" + self.parameters[k] for k in self.parameters]
        return "Config action: plugin_name=" + self.plugin_name +  " parameters=[" + ", ".join(parameters) + "]"


class SyslogSourceConfig:

    def __init__(self, config_file_path: str):
        config = configparser.ConfigParser()
        try:
            read_config = config.read(config_file_path)
        except configparser.Error as e:
            raise InvalidSyslogSourceConfigError('Parsing of syslog source config [%s] failed: %s' % (config_file_path, str(e)))

        if len(read_config) < 1:
            raise InvalidSyslogSourceConfigError('Syslog source config [%s] could not be read.' % config_file_path)

        if self._config_file_has_valid_format(config):
            self._parse_config_values(config)
        else:
            raise InvalidSyslogSourceConfigError("Syslog source config [%s] has wrong format." % config_file_path)

    def _config_file_has_valid_format(self, config: configparser.ConfigParser):
        # TODO: return failed reason?
        valid_general_section = ('general' in config) and ('pattern' in config['general']) and ('pattern' in config['general']) # Valid regex and valid boolean
        valid_actions_section = ('actions' in config) # TODO: action for each named pattern group

        return valid_actions_section and valid_general_section

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