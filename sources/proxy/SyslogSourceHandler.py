import re

from SyslogMessage import SyslogMessage
from SyslogSourceConfig import SyslogSourceConfig


class CannotHandleSyslogMessageError(Exception):
    pass


class SyslogSourceHandler:

    _pattern = None
    _config = None

    def __init__(self, config_file_path: str):
        self._config = SyslogSourceConfig(config_file_path)

    def can_handle_syslog_message(self, message: SyslogMessage) -> bool:
        """ TBD """
        return bool(re.match(self._config.pattern, message.get_message()))

    def handle_syslog_message(self, message: SyslogMessage) -> SyslogMessage:
        """ TBD """
        m = re.match(self._config.pattern, message.get_message())

        if m:
            orig_message = m.group(0)

            # Build update list from match groups.
            update_list = [(key, m.group(key), m.start(key), m.end(key)) for key in m.groupdict()]
            update_list.sort(key=lambda group: group[2])

            altered_message = self._get_altered_message(orig_message, update_list)
            return SyslogMessage(message.priority, message.facility, altered_message)
        else:
            raise CannotHandleSyslogMessageError('Handler can not handle syslog message: pattern not matching.')

    def _get_altered_message(self, orig_message: str, update_list:[]) -> str:
        result = []
        last_idx = 0

        for update in update_list:
            name = update[0]
            group = update[1]
            start = update[2]
            end = update[3]

            if last_idx <= start:
                result.append(orig_message[last_idx:start])
            result.append(self._alter_group(name, group))
            last_idx = end

        return "".join(result)

    def _alter_group(self, name: str, group: str) -> str:
        return "ALTERED[" + group + "]"