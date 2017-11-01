"""
Python based Syslog proxy.

Based on: https://gist.github.com/marcelom/4218010
"""

from socketserver import BaseRequestHandler, ThreadingUDPServer
from logging.handlers import SysLogHandler
import re

from SyslogSourceConfig import SyslogSourceConfig
from SyslogMessage import SyslogMessage, InvalidSyslogMessageException
from SyslogSourceService import SyslogSourceService

HOST = '169.254.65.208' #VMNET 1
PORT = 514


class SyslogUdpHandler(BaseRequestHandler):

    def handle(self):
        client_address_ip = self.client_address[0]
        logdata = bytes.decode(self.request[0].strip())

        print("Client: %s" % str(client_address_ip))

        syslog_message = None
        try:
            syslog_message = SyslogMessage.from_logdata(logdata)

            print("Message: " + syslog_message.message)
            print("Facility: %d %s" % (syslog_message.facility, str(syslog_message.get_facility_name())))
            print("Priority: %d %s" % (syslog_message.priority, str(syslog_message.get_priority_name())))

            altered_message = SyslogSourceService().handle_syslog_message(syslog_message)
            print("Altered_message: " + altered_message.get_message())

        except InvalidSyslogMessageException:
            print("Invalid syslog message: %s" % logdata)

def main():
    try:
        print("Starting syslog proxy...")
        server = ThreadingUDPServer((HOST, PORT), SyslogUdpHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        print("Syslog proxy encountered error!")
        raise
    except KeyboardInterrupt:
        print("Crtl+C Pressed. Shutting down.")


if __name__ == "__main__":
    main()