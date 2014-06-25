"""
    rcon.client

    :copyright: (c) 2014 Mark Wetter
    :license: MIT, see LICENSE for more details
"""

from . import (
    SERVERDATA_AUTH, SERVERDATA_AUTH_RESPONSE, SERVERDATA_EXECCOMMAND,
    SERVERDATA_RESPONSE_VALUE, RconClientError
)
from .packet import RconPacket
import socket
import itertools


class RconClient(object):
    """A client implementation for the Source RCON Protocol."""

    def __init__(self, host, port, timeout=1.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.packet_id = itertools.count(1)
        self.socket = None

    def connect(self):
        """Create TCP connection"""
        self.socket = socket.create_connection((self.host, self.port), self.timeout)

    def disconnect(self):
        """Close TCP connection"""
        self.socket.close()

    def send(self, packet):
        """Send packet using `self.socket`."""
        packet.send_to_socket(self.socket)

    def recieve(self):
        """Recieve packet from `self.socket`."""
        response_packet = RconPacket().recieve_from_socket(self.socket)
        if not response_packet:
            raise RconClientError("Remote server disconnected")
        return response_packet

    def authenticate(self, password):
        """Attempt to authenticate against RCON server."""
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
        """Send command to RCON server and return response as a string."""
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


def create_connection(host, port, password, timeout):
    client = RconClient(host, port, timeout)
    client.connect()
    client.authenticate(password)
    return client
