import asyncio
import copy
import logging

import asyncio_mqtt.error
from mqtt_secure_signaling import *

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel, RTCConfiguration


MAX_BYTES_READ = 250
"""
Maximum bytes to read from TCP
"""


class ApplicTunnelBase(metaclass=abc.ABCMeta):
    """
    A base class to inherit basic methods of an applic tunnel instance class
    """
    def __init__(self, rtcconf: RTCConfiguration, signaling: SignalingInterface, ip: str, port: int):
        """
        Constructor
        :param rtcconf: RTC configuration
        :param signaling: Signaling interface
        :param ip: IP address of local socket
        :param port: Port number of local socket
        """
        self._signaling = signaling
        self._ip = ip
        self._port = port
        self._rtcconf = rtcconf

        # is set to applic tunnel
        self._stop = False

    async def _close_socket(self, writer: asyncio.StreamWriter):
        """
        Close a socket as coroutine
        :param writer: Writer of socket
        """
        await asyncio.sleep(1)
        writer.close()
        await writer.wait_closed()
        logger.debug('socket closed')

    @abc.abstractmethod
    async def run(self) -> None:
        """
        Run the applic tunnel as coroutine.
        """

    @abc.abstractmethod
    async def stop(self) -> None:
        """
        Stop the applic tunnel as coroutine.
        """

class ApplicTunnelInitiator(ApplicTunnelBase):
    """
    An applic tunnel initiator
    """

    def __init__(self, rtcconf: RTCConfiguration, signaling: SignalingInterface, ip: str, port: int):
        """
        Constructor
        :param rtcconf: RTC configuration
        :param signaling: Signaling interface
        :param ip: IP address of local socket
        :param port: Port number of local socket
        """
        super().__init__(rtcconf, signaling, ip, port)

        self._pc = RTCPeerConnection(configuration=self._rtcconf)
        # Channel number to identify multiple open channels / sockets
        self._channel_number: int = 0

    async def _wait_on_end(self) -> None:
        """
        Wait on signaling end
        """
        try:
            while not self._stop:
                obj, sig_id = await self._signaling.receive()
                if obj is BYE:
                    logger.info("Exiting")
                    break
        except asyncio_mqtt.MqttError:
            logger.info('MQTT error occurred, exit anyway')

    async def _consume_signaling(self) -> bool:
        """
        Consume signaling coroutine
        :param pc: RTC peer connection
        :return: True if signaling was successful
        """
        obj, sig_id = await self._signaling.receive()

        if isinstance(obj, RTCSessionDescription):
            await self._pc.setRemoteDescription(obj)

            if obj.type == "offer":
                # send answer
                await self._pc.setLocalDescription(await self._pc.createAnswer())
                await self._signaling.send(sig_id, self._pc.localDescription)
            return True
        elif obj is BYE:
            logger.info("Exiting")
            return False
        else:
            logger.error("Unknown signaling message")
            return False


    async def _listen_to_socket(self, channel: RTCDataChannel, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter):
        """
        listen to a specific socket and datachannel
        :param channel: WebRTC data channel
        :param reader: Socket reader
        :param writer: Socket writer
        """
        # endless loop until end of file (connection closed) detected
        while not reader.at_eof():
            # get data from tcp socket
            data = await reader.read(MAX_BYTES_READ)
            logger.debug("Data from client: %s", data)
            # send via rtc
            if channel.readyState == "open":
                channel.send(data)
            else:
                logger.debug("Data not sent, channel state: " + channel.readyState)

        # close socket
        logger.info('Closing client side socket and channel')
        await self._close_socket(writer)

        # wait
        channel.close()
        logger.info(channel.label + ": channel closed")

    async def _connect_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Callback on TCP client connect
        :param reader: Socket reader
        :param writer: Socket writer
        """
        logger.debug('data channel established')
        # Create a rtc datachannel

        self._channel_number += 1
        channel = self._pc.createDataChannel("channel" + str(self._channel_number))

        logger.info('client connected %s', reader._transport.get_extra_info('socket').getpeername())

        # Callback on datachannel open
        @channel.on("open")
        def on_open():
            logger.info(channel.label + ': open')
            # Start listen to socket
            asyncio.ensure_future(self._listen_to_socket(channel, reader, writer))

        # Callback on datachannel message
        @channel.on("message")
        def on_message(message):
            logger.debug("Data to broker: %s" % message)
            # Send message via tcp to mqtt client
            asyncio.ensure_future(self._send_tcp(reader, writer, message))

    async def _send_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, message: bytes):
        """
        Send a message over TCP.
        :param reader: Socket reader
        :param writer: Socket writer
        :param message: Message to send
        """
        if not reader.at_eof():
            writer.write(message)
            await writer.drain()
        else:
            logger.debug('do not send over tcp, socket closed')

    async def run(self) -> None:
        """
        Run the applic tunnel initiator as coroutine.
        """
        self._pc.createDataChannel('dummy')

        # start and wait on signaling finished
        await self._signaling.connect()

        # Start tcp server socket
        try:
            await asyncio.start_server(self._connect_client, self._ip, self._port)
            logger.info('tcp socket open (%s:%s)', self._ip, self._port)
        except OSError as err:
            logging.error("Open socket failed (%s)", err.with_traceback(None))
            print("Open socket failed ({})".format(err.with_traceback(None)))
            exit(0)

        # send offer
        await self._pc.setLocalDescription(await self._pc.createOffer())
        await self._signaling.send('not relevant', self._pc.localDescription)

        try:
            if await asyncio.wait_for(self._consume_signaling(), SIG_TIMEOUT):
                await self._wait_on_end()
            else:
                print("Exiting")
        except asyncio.TimeoutError:
            print("Signaling timeout")

    async def stop(self) -> None:
        """
        Stop the applic tunnel initator as coroutine.
        """
        self._stop = True
        await self._pc.close()
        logging.info('Peer connection closed')
        await self._signaling.close('not relevant')
        logging.info('Signaling closed')
        await self._signaling.disconnect()
        logging.info('Signaling disconnected')


class ApplicTunnelListener(ApplicTunnelBase):
    """
    An applic tunnel listener
    """

    def __init__(self, rtcconf: RTCConfiguration, signaling: SignalingInterface, ip: str, port: int):
        """
        Constructor
        :param rtcconf: RTC configuration
        :param signaling: Signaling interface
        :param ip: IP address of local socket
        :param port: Port number of local socket
        """
        super().__init__(rtcconf, signaling, ip, port)

        self._pcs: {RTCPeerConnection} = {}

        # Reader / writer dictionaries
        self._readers: {asyncio.StreamReader} = {}
        self._writers: {asyncio.StreamWriter} = {}

    async def _listen_to_socket(self, socket_id: str, channel: RTCDataChannel):
        """
        Listen to a socket and data channel
        :param socket_id: Socket ID
        :param channel: WebRTC data channel
        """
        # endless loop until end of file (connection closed) detected
        while True:
            if socket_id in self._readers.keys():
                break
            else:
                logger.debug('key not yet available')
                await asyncio.sleep(5)
        while not self._readers[socket_id].at_eof():
            # Read from tcp socket
            data = await self._readers[socket_id].read(MAX_BYTES_READ)
            logger.debug("Data from server: %s" % data)
            # Send data to rtc datachannel
            if channel.readyState == "open":
                channel.send(data)
            else:
                logger.debug("do not send, channel %s has state %s", channel.label, channel.readyState)

                # close socket
                logger.info('Closing listener socket')
                await self._close_socket(self._writers[socket_id])
                return

    async def _open_socket(self, socket_id: str, channel: RTCDataChannel):
        """
        Open a socket linked to a data channel and add it to the socket lists
        :param socket_id: Socket ID
        :param channel: WebRTC data channel
        """
        try:
            # tcp connect to server (broker)
            reader, writer = await asyncio.open_connection(self._ip, self._port)
            self._readers[socket_id] = reader
            self._writers[socket_id] = writer
            logger.info('tcp connection to server established (%s:%s)', self._ip, self._port)
            # Start listen to tcp socket
            asyncio.ensure_future(self._listen_to_socket(socket_id, channel))
        except OSError:
            logging.warning('open tcp connection to server failed (%s:%s)', self._ip, self._port)
            channel.close()

    async def _send_tcp(self, socket_id: str, message: bytes):
        """
        Send a message over TCP. Wait if data channel not yet open.
        :param socket_id: Socket ID
        :param message: Message
        """
        while True:
            if socket_id in self._readers.keys():
                break
            else:
                # wait until channel is valid
                await asyncio.sleep(0.005)
        if not self._readers[socket_id].at_eof():
            self._writers[socket_id].write(message)
            await self._writers[socket_id].drain()
        else:
            logger.debug('Socket %s: do not send message over tcp, socket closed', socket_id)

    async def _consume_signaling(self):
        """
        Consume signaling coroutine
        :param pc: RTC peer connection
        :return: True if signaling was successful
        """
        try:
            obj, sig_id = await self._signaling.receive()

            # create a new peer connection if it does not exist already
            if sig_id not in self._pcs and obj is not BYE:
                self._pcs[sig_id] = RTCPeerConnection(configuration=self._rtcconf)
                logging.info('Create new peer connection {}'.format(sig_id))

                # Called after datachannel establishment
                @self._pcs[sig_id].on("datachannel")
                def on_datachannel(channel: RTCDataChannel):

                    socket_id = sig_id + '-' + channel.label

                    logger.info(socket_id + ": open data channel")
                    # Start tunneling runnable
                    if channel.label != "dummy":
                        asyncio.ensure_future(self._open_socket(socket_id, channel))

                    # Callback on rtc datachannel message
                    @channel.on("message")
                    def on_message(message: bytes):
                        logger.debug(socket_id + ": Data to client: %s" % message)
                        # Async send message rtc datachannel --> tcp
                        asyncio.ensure_future(self._send_tcp(socket_id, message))

                    @channel.on("close")
                    def on_close():
                        logger.info(socket_id + ": Data channel close")
                        if channel.label != "dummy":
                            try:
                                asyncio.ensure_future(self._close_socket(self._writers[socket_id]))
                            except KeyError:
                                logging.info('Socket of channel %s is already closed', channel.label)

            if isinstance(obj, RTCSessionDescription):
                await self._pcs[sig_id].setRemoteDescription(obj)

                if obj.type == "offer":
                    # send answer
                    await self._pcs[sig_id].setLocalDescription(await self._pcs[sig_id].createAnswer())
                    await self._signaling.send(sig_id, self._pcs[sig_id].localDescription)
            elif obj is BYE:
                if not self._stop and sig_id in self._pcs:
                    logger.info("Closing pc {}".format(sig_id))
                    self._pcs.pop(sig_id)
            else:
                logger.error("Unknown signaling message on id {}".format(sig_id))

        except asyncio_mqtt.MqttError:
            logging.info('MQTT error occurred, return')

    async def run(self):
        """
        Run the applic tunnel listener as coroutine
        """
        # wait for data channel
        await self._signaling.connect()

        # Consume signaling
        while not self._stop:
            await self._consume_signaling()

    async def stop(self) -> None:
        """
        Stop the applic tunnel initator as coroutine.
        """
        self._stop = True

        for sig_id, pc in self._pcs.items():
            await pc.close()
            logging.info('peer connection closed'.format(sig_id))
            await self._signaling.close(sig_id)
            logging.info('signaling close {}'.format(sig_id))

        await self._signaling.disconnect()
        logging.info('Signaling disconnected')







