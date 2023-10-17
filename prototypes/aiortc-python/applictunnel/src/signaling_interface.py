import abc
from aiortc import RTCIceCandidate, RTCSessionDescription


class SignalingInterface(metaclass=abc.ABCMeta):
    """
    A signaling interface
    """
    @abc.abstractmethod
    async def connect(self):
        """
        Connect signaling method
        """
        raise not NotImplemented

    @abc.abstractmethod
    async def close(self, sig_id: str):
        """
        Close signaling method
        :param id: Signaling ID
        """
        raise not NotImplemented

    @abc.abstractmethod
    async def receive(self) -> [object, str]:
        # RTCSessionDescription | RTCIceCandidate | object --> supported on python 3.10 upwards
        """
        Receive signaling method
        :return:  [RTCSessionDescription | RTCIceCandidate | object, signaling ID]
        """
        raise not NotImplemented

    @abc.abstractmethod
    async def send(self, sig_id: str, descr: object):
        # RTCSessionDescription | RTCIceCandidate | object --> supported on python 3.10 upwards
        """
        Send signaling method
        :param sig_id: Signaling ID
        :param descr: Description of candidates
        """
        raise not NotImplemented

    @abc.abstractmethod
    async def disconnect(self):
        """
        Disconnect signaling
        """
        raise not NotImplemented