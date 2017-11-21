import configparser
import re

from proxy import plugin


class InvalidSyslogSourceConfigError(Exception):
    pass


class ActionNotFoundError(Exception):
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

    @classmethod
    def is_valid_action_string(cls, action_str: str) -> bool:
        """
        Allow the following format:
        PLUGINNAME(ARG1 = 123, ARG2='StringThis%&/)', ARG3 = "")

        Simply beautiful and easy to read!
        """
        pattern = '^\w+\(( *\w+ *= *((\'[^\']*\'*)|("[^"]*")|\d+) *, *)*( *\w+ *= *((\'[^\']*\')|("[^"]*")|\d+) *)?\)$'
        return bool(re.match(pattern, action_str))

    @property
    def plugin_name(self):
        return self._plugin_name

    @property
    def parameters(self):
        return self._parameters

    def __str__(self):
        parameters = [k + '=' + self.parameters[k] for k in self.parameters]
        return 'Config action: plugin_name=%s parameters=[%s]' % (self.plugin_name, ", ".join(parameters))


class PatternSection:

    def __init__(self, pattern: str, actions: {str: ConfigAction}):
        try:
            self._pattern = re.compile(pattern)
        except Exception as e:
            raise Exception("Invalid pattern: %s." % str(e))
        self._actions = actions
        self._check_section_contains_actions()

    def _check_section_contains_actions(self):
        for groupname in self._pattern.groupindex:
            if not groupname in self._actions:
                raise Exception('No action found for pattern group (%s).' % groupname)

    @property
    def pattern(self) -> any:
        """ Returns compiled regex for pattern to prevent multiple compile/match calls."""
        return self._pattern

    @property
    def actions(self) -> {str: ConfigAction}:
        return self._actions

    def action_for_field(self, field: str) -> ConfigAction:
        if field in self.actions:
            action = self.actions[field]
            return action
        else:
            raise ActionNotFoundError('Section contains no action %s' % field)


class SyslogSourceConfig:

    def __init__(self, config_file_path: str, plugin_registry: plugin.PluginRegistry):
        config = configparser.ConfigParser()
        try:
            read_config = config.read(config_file_path)
        except configparser.Error as e:
            raise InvalidSyslogSourceConfigError('Parsing of syslog source config [%s] failed: %s' % (config_file_path,
                                                                                                      str(e)))
        if len(read_config) < 1:
            raise InvalidSyslogSourceConfigError('Syslog source config [%s] could not be read.' % config_file_path)

        try:
            self._parse_general_section(config)
            self._parse_pattern_sections(config)
            self._check_used_plugins(plugin_registry)
        except Exception as e:
            raise InvalidSyslogSourceConfigError('Syslog source config [%s] has invalid format: %s' % (config_file_path,
                                                                                                       str(e)))

    def _parse_general_section(self, config: configparser.ConfigParser):
        if not('general' in config):
            raise Exception('Config file must contain [general] section.')

        if not ('active' in config['general']):
            raise Exception('[general] section must contain active value.')

        try:
            self._active = config['general'].getboolean('active')
        except Exception:
            raise Exception('active field in [general] section has to be a bool value.')

    def _parse_pattern_sections(self, config: configparser.ConfigParser):
        self._sections = {}
        for key in [k for k in config.keys() if (k != 'general' and k != 'DEFAULT')]:
            config_section = config[key]

        # Pattern
            if not ('pattern' in config_section):
                raise Exception('Section [%s] must contain pattern field.' % key)

            pattern = config_section['pattern']

        # Actions
            config_actions = {}
            for action in [a for a in config_section if a != 'pattern']:
                value = config_section[action]

                try:
                    config_actions[action] = ConfigAction(value)
                except InvalidConfigActionError as e:
                    raise Exception('Invalid action %s in section [%s]: %s' % (action, key, str(e)))

            try:
                section = PatternSection(pattern, config_actions)
            except Exception as e:
                raise Exception('Invalid section [%s]: %s' % (key, str(e)))
            self._sections[key] = section

    def _check_used_plugins(self, plugin_registry: plugin.PluginRegistry):
        for section_key, section in self.sections.items():
            for action_key, action in section.actions.items():
                if not plugin_registry.has_plugin_with_name(action.plugin_name):
                    raise Exception("Plugin '%s' for entry %s in section [%s] not found." % (action.plugin_name, action_key, section_key))

    @property
    def active(self) -> bool:
        return self._active

    @property
    def sections(self) -> {str: PatternSection}:
        return self._sections
