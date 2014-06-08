# Copyright (c) 2014 Mark Wetter

import socket, struct, itertools

SERVERDATA_AUTH             = 3
SERVERDATA_AUTH_RESPONSE    = 2
SERVERDATA_EXECCOMMAND      = 2
SERVERDATA_RESPONSE_VALUE   = 0


class RconError(Exception):
    pass

class RconAuthenticationError(Exception):
    pass


class RconConnection(object):
    def __init__(self, host, port, password='', timeout=1.0):
        self.host = host
        self.port = port
        self.packet_id = itertools.count(1)
        self.socket = socket.create_connection((host, port), timeout)
        self.authenticate(password)

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

    def send(self, packet):
        if packet.size() > 4096:
            raise RconError('Packet Size > 4096 bytes')
        self.socket.send(packet.serialize())

    def recieve(self):
        header = self.socket.recv(struct.calcsize('<3i'))
        (response_size, response_id, response_type) = struct.unpack('<3i', header)
        response_size = response_size - struct.calcsize('<2i')
        response_buffer = b''
        while len(response_buffer) < response_size:
            response_buffer += self.socket.recv(response_size - len(response_buffer))
        response_body = response_buffer.decode('utf-8').rstrip('\x00')

        return RconPacket(response_id, response_type, response_body)

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


class RconPacket(object):
    def __init__(self, packet_id, packet_type, body):
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