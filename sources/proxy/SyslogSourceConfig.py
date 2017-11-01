import configparser


class InvalidSyslogSourceConfigError(Exception):
    pass


class SyslogSourceConfig:

    pattern = None
    active = None
    actions = []

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

        self.pattern = general_section['pattern']
        self.active = general_section.getboolean('active')

        for key in action_section:
            self.actions.append((key, action_section[key]))