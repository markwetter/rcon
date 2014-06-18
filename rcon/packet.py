# Copyright (c) 2014 Mark Wetter

from . import RconPacketError
import socket
import struct


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
            raise RconPacketError('Packet size cannot exceed 4096 bytes')
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
