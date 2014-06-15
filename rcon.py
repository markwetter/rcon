# Copyright (c) 2014 Mark Wetter

import socket
import socketserver
import threading
import inspect
import struct
import itertools

SERVERDATA_AUTH             = 3
SERVERDATA_AUTH_RESPONSE    = 2
SERVERDATA_EXECCOMMAND      = 2
SERVERDATA_RESPONSE_VALUE   = 0


class RconError(Exception):
    pass

class RconAuthenticationError(Exception):
    pass


class RconPacket(object):
    def __init__(self, packet_id=0, packet_type=0, body=''):
        self.packet_id = packet_id
        self.packet_type = packet_type
        self.body = body

    def __str__(self):
        return self.body

    def size(self):
        return len(self.body)+10

    def serialize(self):
        header = struct.pack('<3i', self.size(), self.packet_id, self.packet_type)
        return b"".join([header, self.body.encode('utf-8'), b"\x00\x00"])

    def send_to_socket(self, socket):
        if self.size() > 4096:
            raise RconError('Packet size cannot exceed 4096 bytes')
        socket.send(self.serialize())

    def recieve_from_socket(self, socket):
        header = socket.recv(struct.calcsize('<3i'))
        if not header:
            return False
        (content_length, self.packet_id, self.packet_type) = struct.unpack('<3i', header)
        content_length = content_length - struct.calcsize('<2i')
        response_buffer = b''
        while len(response_buffer) < content_length:
            response_buffer += socket.recv(content_length - len(response_buffer))
        self.body = response_buffer.decode('utf-8').rstrip('\x00')

        return self


class RconClient(object):
    def __init__(self, host, port, password='', timeout=1.0):
        self.host = host
        self.port = port
        self.packet_id = itertools.count(1)
        self.socket = socket.create_connection((host, port), timeout)
        self.authenticate(password)

    def send(self, packet):
        packet.send_to_socket(self.socket)

    def recieve(self):
        response_packet = RconPacket().recieve_from_socket(self.socket)
        if not response_packet:
            raise RconError("Remote server disconnected")
        return response_packet

    def authenticate(self, password):
        auth_packet = RconPacket(next(self.packet_id), SERVERDATA_AUTH, password)
        self.send(auth_packet)
        auth_response = self.recieve()
        if auth_response.packet_type == SERVERDATA_RESPONSE_VALUE:
            auth_response = self.recieve()
        if auth_response.packet_type != SERVERDATA_AUTH_RESPONSE:
            raise RconError('Invalid authentication response type: %s' % auth_response.packet_type)
        if auth_response.packet_id == -1:
            raise RconAuthenticationError('Server Response: Invalid Password')

    def exec_command(self, command):
        command_packet = RconPacket(next(self.packet_id), SERVERDATA_EXECCOMMAND, command)
        check_packet = RconPacket(next(self.packet_id), SERVERDATA_EXECCOMMAND, "")
        self.send(command_packet)
        self.send(check_packet)
        response_buffer = ""
        while True:
            response = self.recieve()
            if response.packet_id == command_packet.packet_id:
                response_buffer += response.body
            elif response.packet_id == check_packet.packet_id:
                break
            else:
                raise RconError('Packet response ID: %s does not match request ID: %s' % (response.packet_id, command_packet.packet_id))
        return response_buffer


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
