import re
from logging.handlers import SysLogHandler


class InvalidSyslogMessageException(Exception):
    pass


class SyslogMessage:
    """ A class representing syslog messages. """
    facility = None
    priority = None
    message = None

    @classmethod
    def from_logdata(cls, logdata:str):
        if re.match('<\d+>.+', logdata):
            facility_priority_str, message = logdata.split('>', 1)

            facility_priority = int(facility_priority_str[1:])
            priority = facility_priority & 0x7 # lowest 3 bits
            facility = facility_priority >> 3 # upper 28 bits

            return cls(priority, facility, message)
        else:
            raise InvalidSyslogMessageException("Invalid syslog message format")

    def __init__(self, priority: int, facility: int, message: str):
        self.facility = facility
        self.priority = priority
        self.message = message

    def _dict_key_for_value(self, dict, search_value):
        for key, value in dict.items():
            if value == search_value:
                return key
        return None

    def get_facility_name(self)->str:
        return self._dict_key_for_value(SysLogHandler.facility_names, self.facility)

    def get_priority_name(self)->str:
        return self._dict_key_for_value(SysLogHandler.priority_names, self.priority)

    def get_message(self)->str:
        return self.message

    def __str__(self):
        return "Syslog message [%s,%s]: %s", (self.get_facility_name(), self.get_priority_name(), self.message)