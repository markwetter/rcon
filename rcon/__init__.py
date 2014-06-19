"""
    rcon

    :copyright: (c) 2014 Mark Wetter
    :license: MIT, see LICENSE for more details
"""

__version__ = "0.0.1"

SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

class RconError(Exception):
    pass

class RconClientError(RconError):
    pass

class RconServerError(RconError):
    pass

class RconPacketError(RconError):
    pass
