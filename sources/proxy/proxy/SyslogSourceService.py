import os

from proxy.PluginRegistry import PluginRegistry
from proxy.SyslogMessage import SyslogMessage
from proxy.SyslogSourceConfig import InvalidSyslogSourceConfigError
from proxy.SyslogSourceHandler import SyslogSourceHandler


class ApplicableConfigMissingError(Exception):
    pass


class SyslogSourceService:

    def __init__(self, configs_dir: str, plugin_registry: PluginRegistry):
        self._plugin_registry = plugin_registry
        self._init_handlers(configs_dir)

    def _init_handlers(self, configs_dir: str):
        print('Creating handlers for source config files from [%s]...' % configs_dir)

        self._handlers = []
        for file in self.get_config_files(configs_dir):
            try:
                self._handlers.append(SyslogSourceHandler(file, self._plugin_registry))
                print('\tCreated handler for source config file: ' + os.path.basename(file))
            except InvalidSyslogSourceConfigError as e:
                print('\tCould not create handler for source config file: %s\n%s\n' % (os.path.basename(file), str(e)))
        print('')

    def get_config_files(self, configs_dir: str) -> [str]:
        return [os.path.join(configs_dir, f) for f in os.listdir(configs_dir) if os.path.isfile(os.path.join(configs_dir, f)) and f.endswith(".cfg")]

    def handle_syslog_message(self, message: SyslogMessage) -> SyslogMessage:
        for handler in self._handlers:
            if handler.can_handle_syslog_message(message):
                altered_message = handler.handle_syslog_message(message)
                return altered_message

        raise ApplicableConfigMissingError
