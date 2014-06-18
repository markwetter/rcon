# Copyright (c) 2014 Mark Wetter

from . import RconServerError
from .packet import RconPacket
from .constants import (
    SERVERDATA_AUTH, SERVERDATA_AUTH_RESPONSE,
    SERVERDATA_RESPONSE_VALUE
)
import socketserver
import threading
import inspect


class RconServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
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
        request = request_packet.body.split()
        if not request:
            return ""
        function = request.pop(0)
        if not function in self.server.funcs.keys():
            return "Unknown command: %s" % function
        (args, varargs, keywords, default) = inspect.getargspec(self.server.funcs[function])
        if not len(args) == len(request):
            return "Command %s requires %s arguments: %s arguments given" % (function, len(args), len(request))
        return str(self.server.funcs[function](*request))


class RconServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address=("localhost",27015), password=''):
        socketserver.ThreadingTCPServer.__init__(self, server_address, RconServerHandler)
        self.password = password
        self.funcs = {}

    def start(self):
        self.server_thread = threading.Thread(target=self.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.shutdown()

    def register_function(self, function):
        name = function.__name__
        self.funcs[name] = function
