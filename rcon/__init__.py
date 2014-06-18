# Copyright (c) 2014 Mark Wetter

__version__ = "0.0.1"


class RconError(Exception):
    pass

class RconClientError(RconError):
    pass

class RconServerError(RconError):
    pass

class RconPacketError(RconError):
    pass
