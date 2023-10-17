# signaling prototype based on https://github.com/aiortc/aiortc/blob/main/src/aiortc/contrib/signaling.py
import binascii
import json
import sys
import uuid
import ssl
import warnings
import cryptography
import asyncio_mqtt.error
import certifi
import nacl.encoding
import nacl.exceptions
from paho.mqtt.client import MQTTMessage

from applic_tunnel_utilities import *
from nacl.public import Box, PrivateKey, PublicKey
from asyncio_mqtt import Client
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
from signaling_interface import *

logger = logging.getLogger(__name__)
BYE = object()

warnings.filterwarnings("ignore", category=cryptography.CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)


def object_from_string(message_str: str) -> object:
    # RTCSessionDescription | RTCIceCandidate | object --> supported on pyhton 3.10 upwards
    """
    Parse a signaling message string to a signaling object
    :param message_str: signaling message as string
    :return: signaling messages as object
    """
    message = json.loads(message_str)
    if message["type"] in ["answer", "offer"]:
        return RTCSessionDescription(**message)
    elif message["type"] == "candidate" and message["candidate"]:
        candidate = candidate_from_sdp(message["candidate"].split(":", 1)[1])
        candidate.sdpMid = message["id"]
        candidate.sdpMLineIndex = message["label"]
        return candidate
    elif message["type"] == "bye":
        return BYE


def object_to_string(obj: object) -> str:
    # RTCSessionDescription | RTCIceCandidate | object --> supported on pyhton 3.10 upwards
    """
    Parse a signaling object to a signaling message string
    :param obj: Signaling message as object
    :return: Signaling message string
    """
    if isinstance(obj, RTCSessionDescription):
        message = {"sdp": obj.sdp, "type": obj.type}
    elif isinstance(obj, RTCIceCandidate):
        message = {
            "candidate": "candidate:" + candidate_to_sdp(obj),
            "id": obj.sdpMid,
            "label": obj.sdpMLineIndex,
            "type": "candidate",
        }
    else:
        assert obj is BYE
        message = {"type": "bye"}
    return json.dumps(message, sort_keys=True)


class MqttSecureSignalingBase(SignalingInterface, metaclass=abc.ABCMeta):
    """
    A base class which provide signaling functions for a WebRTC connection via aiortc. The signaling is based
    on encrypted messages over MQTT.
    """
    def __init__(self, broker_host: str, broker_port: int, user: str, pw: str, main_topic: str, tunnel_name: str,
                 private_key: str, no_tls: bool, unsafe: bool):
        """
        Constructor
        :param broker_host: Signaling broker hostname or ip address
        :param broker_port: Signaling broker port
        :param user: Username on broker (leave empty to use anonymous access)
        :param pw: Password on broker (leave empty to use anonymous access)
        :param main_topic: Main signaling topic
        :param tunnel_name: Tunnel name
        :param private_key: Private key for signaling
        :param unsafe: Set to true to use unsafe mode (not recommended, messages won't be encrypted)
        """
        self._read_pipe = sys.stdin
        self._read_transport = None
        self._write_pipe = sys.stdout
        self._unsafe = unsafe
        self._main_topic = main_topic
        self._tunnel_name = tunnel_name
        self._subtopic = ''
        self._privatekey = private_key

        if no_tls:
            # create mqtt client
            self._client = Client(
                hostname=broker_host,
                port=broker_port,
                username=user,
                password=pw,
                clean_session=True
            )
        else:
            # create tls settings
            sslsettings = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            sslsettings.verify_mode = ssl.CERT_OPTIONAL
            sslsettings.load_verify_locations(
                cafile=certifi.where(),  # create a client certificate
                capath=None,
                cadata=None)
            # create mqtt client
            self._client = Client(
                hostname=broker_host,
                port=broker_port,
                username=user,
                password=pw,
                clean_session=True,
                tls_context=sslsettings
            )
        # create client id from hardware
        self._clientid = tunnel_name + '-' + str(uuid.UUID(int=uuid.getnode()))
        self._user = user
        self._pw = pw

    async def connect(self):
        """
        Connect signaling method
        """
        logger.debug("wait on client connect")
        try:
            await self._client.connect()
            logger.debug("client connected, wait on subscribe to topic: " + self._subtopic)
            await self._client.subscribe(self._subtopic)
            logger.debug("subscribe done")
        except (asyncio_mqtt.error.MqttError, asyncio_mqtt.error.MqttConnectError, asyncio_mqtt.error.MqttCodeError):
            print("Connect to signaling broker failed")
            exit(0)

    @abc.abstractmethod
    async def close(self, sig_id: str):
        """
        Close signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        """

    async def disconnect(self):
        """
        Disconnect signaling
        """
        try:
            await self._client.disconnect()
            logger.debug("client disconnected")
        except (asyncio_mqtt.error.MqttError, asyncio_mqtt.error.MqttConnectError, asyncio_mqtt.error.MqttCodeError):
            print("Close signaling failed")
            exit(0)

    @abc.abstractmethod
    async def receive(self) -> [object, str]:
        # RTCSessionDescription | RTCIceCandidate | object --> supported on python 3.10 upwards
        """
        Receive signaling method
        :return:  [RTCSessionDescription | RTCIceCandidate | object, signaling ID]
        """

    @abc.abstractmethod
    async def send(self, sig_id: str, descr: object):
        # RTCSessionDescription | RTCIceCandidate | object --> supported on pyhton 3.10 upwards
        """
        Send signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        :param descr: Description of candidates
        """

    def _generate_crypto_box(self, remote_pub_key: str) -> Box:
        """
        Populate crypto box
        :param remote_pub_key: Remote public key
        """
        return Box(
                PrivateKey(self._privatekey.encode("utf-8"), encoder=nacl.encoding.Base32Encoder),
                PublicKey(remote_pub_key.encode("utf-8"), encoder=nacl.encoding.Base32Encoder))

    async def _publish(self, remote_pub_key: str, topic: str, message: str):
        """
        Publish a message on signaling channel
        :param: remote_pub_key: Public key of remote party
        :param topic: Topic to publish to
        :param message: Message to publish
        """
        logger.debug("wait on publish message:\n " + str(message) + "\n")

        # do not encrypt on unsafe mode
        if not self._unsafe:
            box = self._generate_crypto_box(remote_pub_key)
            message = box.encrypt(message.encode("utf-8"))

        await self._client.publish(topic, message)
        logger.debug("publish message done")

    def _encrypt_msg(self, remote_pub_key: str, message: MQTTMessage) -> object:
        # MQTTMessage | None
        """
        Encrypt the payload of a MQTT message. Return None if encryption failed
        :param remote_pub_key: Public key of remote party
        :param message: MQTT message
        :return: MQTT message with encrypted payload
        """
        try:
            # generate box if not already existing
            box = self._generate_crypto_box(remote_pub_key)
            message.payload = box.decrypt(message.payload)
            return message
        except nacl.exceptions.ValueError:
            logging.warning("Message can not be decrypted (ValueError)")
            return None
        except nacl.exceptions.TypeError:
            logging.warning("Message can not be decrypted (TypeError)")
            return None
        except nacl.exceptions.CryptoError:
            logging.warning("Message can not be decrypted (CryptoError)")
            return None
        except binascii.Error:
            logging.warning("decrypt error occurred")
            return None


class MqttSecureSignalingInitiator(MqttSecureSignalingBase):
    """
    A class which provide signaling functions of an initiator for a WebRTC connection via aiortc. The signaling is based
    on encrypted messages over MQTT.
    """
    # constructor
    def __init__(self, broker_host: str, broker_port: int, user: str, pw: str, main_topic: str, tunnel_name: str,
                 private_key: str, no_tls: bool, unsafe: bool, remote_pub_key: str):
        """
        Constructor
        :param broker_host: Signaling broker hostname or ip address
        :param broker_port: Signaling broker port
        :param user: Username on broker (leave empty to use anonymous access)
        :param pw: Password on broker (leave empty to use anonymous access)
        :param main_topic: Main signaling topic
        :param tunnel_name: Tunnel name
        :param private_key: Private key for signaling
        :param remote_pub_key: Public key for signaling of remote party
        :param unsafe: Set to true to use unsafe mode (not recommended, messages won't be encrypted)
        """

        super().__init__(broker_host, broker_port, user, pw, main_topic, tunnel_name, private_key, no_tls, unsafe)

        self._remote_pub_key = remote_pub_key

        # create a private key if handover key is None
        if private_key == '':
            key = PrivateKey.generate()
            self._privatekey = str(key.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")
            self._publickey = str(key.public_key.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")
        else:
            self._privatekey = private_key
            # generate public key from private key
            self._publickey = str(PrivateKey(self._privatekey.encode("utf-8"),
                                     encoder=nacl.encoding.Base32Encoder).public_key.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")

        self._pubtopic = concat_topics(
            [self._main_topic, self._remote_pub_key, self._publickey, self._tunnel_name, 'o'])
        self._subtopic = concat_topics(
            [self._main_topic, self._remote_pub_key, self._publickey, self._tunnel_name, 'a'])

    async def close(self, sig_id: str):
        """
        Close signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        """
        try:
            logger.debug('publish BYE')
            await self._publish(self._remote_pub_key, self._pubtopic, object_to_string(BYE))
            logger.debug("wait on unsubscribe")
            await self._client.unsubscribe(self._subtopic)
            logger.debug("unsubscribe done, wait on client disconnect")
        except (asyncio_mqtt.error.MqttError, asyncio_mqtt.error.MqttConnectError, asyncio_mqtt.error.MqttCodeError):
            print("Close signaling failed")
            exit(0)

    async def receive(self) -> [object, str]:
        # RTCSessionDescription | RTCIceCandidate | object --> supported on python 3.10 upwards
        """
        Receive signaling method
        :return:  [RTCSessionDescription | RTCIceCandidate | object, signaling ID]
        """
        logger.debug("wait on message")
        async with self._client.messages() as messages:
            async for message in messages:
                if message != '':

                    # do not decrypt on unsafe mode
                    if not self._unsafe:
                        message = self._encrypt_msg(self._remote_pub_key, message)
                        if message is None:
                            return [None, None]

                    data = message.payload.decode("utf-8")
                    logger.debug("got message from {}:\n{}\n".format(data, self._remote_pub_key))
                    return [object_from_string(data), self._remote_pub_key]

    async def send(self, sig_id: str, descr: object):
        # RTCSessionDescription | RTCIceCandidate | object --> supported on pyhton 3.10 upwards
        """
        Send signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        :param descr: Description of candidates
        """
        message = object_to_string(descr)

        logging.info("send message as initiator to topic {}".format(self._pubtopic))
        await self._publish(self._remote_pub_key, self._pubtopic, message)


class MqttSecureSignalingListener(MqttSecureSignalingBase):
    """
    A class which provide signaling functions of a listener for a WebRTC connection via aiortc. The signaling is based
    on encrypted messages over MQTT.
    """
    # constructor
    def __init__(self, broker_host: str, broker_port: int, user: str, pw: str, main_topic: str, tunnel_name: str,
                 private_key: str, no_tls: bool, unsafe: bool, initiator_keys: [str]):
        """
        Constructor
        :param broker_host: Signaling broker hostname or ip address
        :param broker_port: Signaling broker port
        :param user: Username on broker (leave empty to use anonymous access)
        :param pw: Password on broker (leave empty to use anonymous access)
        :param main_topic: Main signaling topic
        :param tunnel_name: Tunnel name
        :param private_key: Private key for signaling
        :param unsafe: Set to true to use unsafe mode (not recommended, messages won't be encrypted)
        :param initiator_keys: List of trusted initiator public keys
        """

        super().__init__(broker_host, broker_port, user, pw, main_topic, tunnel_name, private_key, no_tls, unsafe)

        self._read_pipe = sys.stdin
        self._read_transport = None
        self._write_pipe = sys.stdout
        self._unsafe = unsafe
        self._remote_pub_key = None     # only used as initiator
        self._main_topic = main_topic
        self._tunnel_name = tunnel_name
        self._initiator_keys = initiator_keys


        self._privatekey = private_key
        # generate public key from private key
        self._publickey = str(PrivateKey(self._privatekey.encode("utf-8"),
            encoder=nacl.encoding.Base32Encoder).public_key.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")

        # define subscribe topics
        self._subtopic = concat_topics(
            [self._main_topic, self._publickey, "+", self._tunnel_name, 'o'])

    async def close(self, sig_id: str):
        """
        Close signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        """
        try:
            logger.debug('publish BYE')
            await self._publish(sig_id, self._get_listener_pub_topic(sig_id), object_to_string(BYE))
            logger.debug("wait on unsubscribe")
            await self._client.unsubscribe(self._subtopic)
            logger.debug("unsubscribe done, wait on client disconnect")
        except (asyncio_mqtt.error.MqttError, asyncio_mqtt.error.MqttConnectError, asyncio_mqtt.error.MqttCodeError):
            print("Close signaling failed")
            exit(0)

    async def receive(self) -> [object, str]:
        # RTCSessionDescription | RTCIceCandidate | object --> supported on python 3.10 upwards
        """
        Receive signaling method
        :return:  [RTCSessionDescription | RTCIceCandidate | object, signaling ID]
        """
        logger.debug("wait on message")
        async with self._client.messages() as messages:
            async for message in messages:
                if message != '':
                    topics = str(message.topic).split("/")

                    # exit if topic structure is not valid
                    if len(topics) < 3:
                        logging.warning("Invalid topic length")
                        return [None, None]
                    remote_pub_key = topics[-3]

                    # check initiator is trusted
                    if self._initiator_keys:
                        if remote_pub_key not in self._initiator_keys:
                            logging.info('Untrusted initiator %s, abort signaling', remote_pub_key)
                            return [BYE, remote_pub_key]

                    # do not decrypt on unsafe mode
                    if not self._unsafe:
                        message = self._encrypt_msg(remote_pub_key, message)
                        if message is None:
                            return [None, None]

                    data = message.payload.decode("utf-8")
                    logger.debug("got message from {}:\n{}\n".format(data, remote_pub_key))
                    return [object_from_string(data), remote_pub_key]

    async def send(self, sig_id: str, descr: object):
        # RTCSessionDescription | RTCIceCandidate | object --> supported on pyhton 3.10 upwards
        """
        Send signaling method
        :param sig_id: Signaling ID (only relevant for listener)
        :param descr: Description of candidates
        """
        message = object_to_string(descr)

        logging.info("send message as listener to {}".format(sig_id))
        await self._publish(sig_id, self._get_listener_pub_topic(sig_id), message)

    def _get_listener_pub_topic(self, remote_key: str) -> str:
        """
        Get listener public topic from remote key
        :param remote_key: Key of initiator
        :return:
        """
        return concat_topics([self._main_topic, self._publickey, remote_key, self._tunnel_name, 'a'])

