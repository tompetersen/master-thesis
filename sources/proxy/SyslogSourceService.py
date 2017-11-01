import SyslogMessage
from SyslogSourceHandler import SyslogSourceHandler


class ApplicableConfigMissingError(Exception):
    pass


class SyslogSourceService:

    _handlers = []

    def __init__(self):
        self._init_handlers()

    def _init_handlers(self):
        self._handlers.append(SyslogSourceHandler('./syslog_source_config/test_config.cfg'))

    def handle_syslog_message(self, message: SyslogMessage):
        for handler in self._handlers:
            if handler.can_handle_syslog_message(message):
                altered_message = handler.handle_syslog_message(message)
                return altered_message

        raise ApplicableConfigMissingError
