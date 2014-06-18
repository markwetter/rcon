# Copyright (c) 2014 Mark Wetter

from . import RconClientError
from .packet import RconPacket
from .constants import (
    SERVERDATA_AUTH, SERVERDATA_AUTH_RESPONSE,
    SERVERDATA_EXECCOMMAND, SERVERDATA_RESPONSE_VALUE
)
import socket
import itertools


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
            raise RconClientError("Remote server disconnected")
        return response_packet

    def authenticate(self, password):
        auth_packet = RconPacket(next(self.packet_id), SERVERDATA_AUTH, password)
        self.send(auth_packet)
        auth_response = self.recieve()
        if auth_response.packet_type == SERVERDATA_RESPONSE_VALUE:
            auth_response = self.recieve()
        if auth_response.packet_type != SERVERDATA_AUTH_RESPONSE:
            raise RconClientError('Invalid authentication response type: %s' % auth_response.packet_type)
        if auth_response.packet_id == -1:
            raise RconClientError('Server Response: Invalid Password')

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
                raise RconClientError('Packet response ID: %s does not match request ID: %s' % (response.packet_id, command_packet.packet_id))
        return response_buffer