import re

from proxy.plugin import PluginRegistry
from proxy.syslog.message import SyslogMessage
from proxy.syslog.sourceconfig import SyslogSourceConfig, PatternSection, ConfigAction


class CannotHandleSyslogMessageError(Exception):
    pass


class SyslogSourceHandler:

    def __init__(self, config_file_path: str, plugin_registry: PluginRegistry):
        self._plugin_registry = plugin_registry
        self._config = SyslogSourceConfig(config_file_path, plugin_registry)

    def can_handle_syslog_message(self, message: SyslogMessage) -> bool:
        """ TBW """
        return self._config_section_for_message(message.message_content) is not None

    def _config_section_for_message(self, message: str) -> (str, PatternSection):
        for key, section in self.config.sections.items():
            if section.can_handle_message(message):
                return key, section
        return None

    @property
    def config(self):
        return self._config

    def handle_syslog_message(self, message: SyslogMessage) -> SyslogMessage:
        """ TBW """
        section_key, section = self._config_section_for_message(message.message_content)
        match = re.match(section.pattern, message.message_content)

        if match:
            orig_message = match.group(0)
            altered_message = self._get_altered_message(orig_message, match, section)
            return SyslogMessage(message.priority, message.facility, altered_message)
        else:
            raise CannotHandleSyslogMessageError('Handler can not handle syslog message: pattern not matching.')

    def _get_altered_message(self, orig_message: str, match, section: PatternSection) -> str:
        # Build update list from match groups and sort it by start position
        update_list = [(key, match.group(key), match.start(key), match.end(key)) for key in match.groupdict()]
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
            result.append(self._alter_group(key, group, section))
            last_idx = end

        return "".join(result)

    def _alter_group(self, field: str, group_content: str, section: PatternSection) -> str:
        config_action = section.action_for_field(field)
        plugin_name = config_action.plugin_name
        parameters = config_action.parameters

        altered_data = self._plugin_registry.alter_data(plugin_name, group_content, **parameters)

        return altered_data