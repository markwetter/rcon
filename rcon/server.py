"""
    rcon.server

    :copyright: (c) 2014 Mark Wetter
    :license: MIT, see LICENSE for more details
"""

from . import (
    SERVERDATA_AUTH, SERVERDATA_AUTH_RESPONSE, SERVERDATA_EXECCOMMAND,
    SERVERDATA_RESPONSE_VALUE, RconServerError
)
from .packet import RconPacket
import threading
import inspect
try:
    import socketserver
except ImportError:
    import SocketServer as socketserver


class RconServerHandler(socketserver.BaseRequestHandler):
    """Extended request handler to be passed to an RCON socketserver instance.

    Extends `socketserver.BaseRequestHandler` to provide a `handle` method
    appropriate for processing RCON queries. Functionality has been split
    out into two methods, `authenticate` and `exec_command` which are
    invoked by `handle`.
    """

    def handle(self):
        """Handles incoming RCON requests.

        Holds TCP connection open until client disconnects. Each loop
        will call `self.authenticate` until a valid password is recieved.
        Once authenticated, client is allowed to send commands."""

        auth = False
        while True:
            request_packet = RconPacket().recieve_from_socket(self.request)
            if not request_packet:
                break
            if auth:
                response = self.exec_command(request_packet)
                RconPacket(request_packet.packet_id, SERVERDATA_RESPONSE_VALUE, response).send_to_socket(self.request)
            else:
                auth = self.authenticate(request_packet)

    def authenticate(self, request_packet):
        """Authenticates client sessions.

        Check to see if incoming request is an authentication packet
        containing the correct password. If not, return a -1 (auth failure)
        to the client. If the server password isn't set, then authentication
        will always fail.
        """

        if (self.server.password and
                request_packet.packet_type == SERVERDATA_AUTH and
                request_packet.body == self.server.password):
            RconPacket(request_packet.packet_id, SERVERDATA_RESPONSE_VALUE, '').send_to_socket(self.request)
            RconPacket(request_packet.packet_id, SERVERDATA_AUTH_RESPONSE, '').send_to_socket(self.request)
            return True
        else:
            RconPacket(-1, SERVERDATA_AUTH_RESPONSE, '').send_to_socket(self.request)
            return False

    def exec_command(self, request_packet):
        """Execute commands submitted by client.

        Split incoming request body into an array, treating the first
        element as a function name and the remaining elements as arguments
        """

        request = request_packet.body.split()
        if not request:
            return ""
        function = request.pop(0)
        if not function in self.server.funcs.keys():
            return "Unknown command: %s" % function
        args = inspect.getargspec(self.server.funcs[function])[0]
        if not len(args) == len(request):
            return "Command %s requires %s arguments: %s arguments given" % (function, len(args), len(request))
        return str(self.server.funcs[function](*request))


class RconServer(socketserver.ThreadingTCPServer):
    """A server implementation for the Source RCON Protocol.

    Extends `socketserver.ThreadingTCPServer` to provide a password string and
    funcs hash for `RconServerHandler`. Also provides the `register_function`
    method for adding new elements to `self.funcs`
    """

    def __init__(self, server_address=("localhost", 27015), password=''):
        socketserver.ThreadingTCPServer.__init__(self, server_address, RconServerHandler)
        self.password = password
        self.funcs = {}
        self.server_thread = None

    def start(self):
        """Launches seperate thread to hold server loop"""
        self.server_thread = threading.Thread(target=self.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        """Instructs server thread to terminate itself"""
        self.shutdown()

    def register_function(self, function):
        """Writes a function to `self.funcs` using its name as a key"""
        name = function.__name__
        self.funcs[name] = function
