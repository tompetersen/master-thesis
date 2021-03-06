import os

from proxy.plugin import PluginRegistry
from proxy.syslog.message import SyslogMessage
from proxy.syslog.sourceconfig import InvalidSyslogSourceConfigError
from proxy.syslog.sourcehandler import SyslogSourceHandler, CannotHandleSyslogMessageError


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
                handler = SyslogSourceHandler(file, self._plugin_registry)
                if handler.is_active():
                    self._handlers.append(handler)
                    print('\t+ %s: Created handler' % os.path.basename(file))
                else:
                    print('\t- %s: Inactive' % os.path.basename(file))
            except InvalidSyslogSourceConfigError as e:
                print('\t- %s: Could not create handler\n\t\t%s\n' % (os.path.basename(file), str(e)))
        print('')

    def get_config_files(self, configs_dir: str) -> [str]:
        return [os.path.join(configs_dir, f) for f in os.listdir(configs_dir) if os.path.isfile(os.path.join(configs_dir, f)) and f.endswith(".cfg")]

    def handle_syslog_message(self, message: SyslogMessage) -> SyslogMessage:
        for handler in self._handlers:
            try:
                altered_message = handler.handle_syslog_message(message)
                return altered_message
            except CannotHandleSyslogMessageError:
                pass

        raise ApplicableConfigMissingError
