import re

from proxy.PluginRegistry import PluginRegistry
from proxy.SyslogMessage import SyslogMessage
from proxy.SyslogSourceConfig import SyslogSourceConfig


class CannotHandleSyslogMessageError(Exception):
    pass


class SyslogSourceHandler:

    def __init__(self, config_file_path: str, plugin_registry: PluginRegistry):
        self._plugin_registry = plugin_registry
        self._config = SyslogSourceConfig(config_file_path, plugin_registry)

    def can_handle_syslog_message(self, message: SyslogMessage) -> bool:
        """ TBW """
        return bool(re.match(self._config.pattern, message.message_content))

    def handle_syslog_message(self, message: SyslogMessage) -> SyslogMessage:
        """ TBW """
        m = re.match(self._config.pattern, message.message_content)

        if m:
            orig_message = m.group(0)
            altered_message = self._get_altered_message(orig_message, m)
            return SyslogMessage(message.priority, message.facility, altered_message)
        else:
            raise CannotHandleSyslogMessageError('Handler can not handle syslog message: pattern not matching.')

    def _get_altered_message(self, orig_message: str, m) -> str:
        # Build update list from match groups and sort it by start position
        update_list = [(key, m.group(key), m.start(key), m.end(key)) for key in m.groupdict()]
        update_list.sort(key=lambda group: group[2])

        # Build altered message by joining parts of the original message with substituted groups
        result = []
        last_idx = 0

        for update in update_list:
            key = update[0]
            group = update[1]
            start = update[2]
            end = update[3]

            # Parts of original message must be included
            if last_idx <= start:
                result.append(orig_message[last_idx:start])

            # group content must be substituted according to the config
            result.append(self._alter_group(key, group))
            last_idx = end

        return "".join(result)

    def _alter_group(self, key: str, group: str) -> str:
        config_action = self._config.action_for_key(key)
        plugin_name = config_action.plugin_name
        parameters = config_action.parameters

        altered_data = self._plugin_registry.alter_data(plugin_name, group, **parameters)

        return altered_data