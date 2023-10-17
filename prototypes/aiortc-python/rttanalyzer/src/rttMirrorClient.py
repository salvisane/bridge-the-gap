# sources: https://github.com/sbtinstruments/asyncio-mqtt/blob/master/examples/EXAMPLES.md 
# Subscriber for testing performance differences between tunnel and bridge
# procedure:
# 1. subscribes to test topic
# 2. returns message to evaluation topic

# Usage:
# see -h of program call
# example call with file: python3 rttMirrorClient.py 147.87.118.29 8883 tunnelBridge/RTTRelay tunnelBridge/RTTEvaluation --user cedalo --password test

import argparse
import asyncio
import json
import ssl
import certifi
import logging

from asyncio_mqtt import Client, MqttError

# fix to make it work on windows: https://stackoverflow.com/questions/63860576/asyncio-event-loop-is-closed-when-using-asyncio-run
import sys

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)


async def main():
    parser = argparse.ArgumentParser(
        prog="RTT Mirror client",
        description="Round Trip Time evaluation mirror client")
    parser.add_argument("brokername", help="hostname or ip of broker")
    parser.add_argument("brokerport", help="port on broker", type=int)
    parser.add_argument("s_topic", help="topic to subscribe to")
    parser.add_argument("p_topic", help="topic to publish to")
    parser.add_argument("-u", "--user", help="broker user name", type=str)
    parser.add_argument("-p", "--password", help="broker password", type=str)
    parser.add_argument("--notls", help="do not use TLS", action="count")
    parser.add_argument("-v", "--verbose", action="count")
    parser.add_argument("-l", "--logfile", help="enable log to file", action="count")
    args = parser.parse_args()

    if args.logfile:
        filename = "mirror_log.log"
    else:
        filename = None

    # set logging level; for file add argument filename="log.log"
    if args.verbose:
        logging.basicConfig(
            format='%(process)d-%(levelname)s-%(message)s',
            level=logging.DEBUG,
            filename=filename)
    else:
        logging.basicConfig(
            format='%(process)d-%(levelname)s-%(message)s',
            level=logging.WARNING,
            filename=filename)

    reconnect_interval = 5  # in seconds
    # create tls settings
    if args.notls:
        sslsettings = None
    else:
        sslsettings = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sslsettings.verify_mode = ssl.CERT_OPTIONAL
        sslsettings.load_verify_locations(
            cafile=certifi.where(),  # create a client certificate
            capath=None,
            cadata=None)

    while True:
        try:
            async with Client(hostname=args.brokername, port=args.brokerport, username=args.user,
                              password=args.password, tls_context=sslsettings) as client:
                logger.info("mirror client connected")
                async with client.messages() as messages:
                    # subscribe is done afterwards so that we just start receiving messages
                    # from this point on
                    await client.subscribe(args.s_topic)
                    logger.info("mirror client subscribed")
                    async for message in messages:
                        logger.debug("message topic: " + str(message.topic))
                        logger.debug("message payload: " + str(json.loads(message.payload)))

                        await client.publish(args.p_topic,
                                             payload=message.payload)

        except MqttError as error:
            logger.info(f'Error "{error}". Reconnecting in {reconnect_interval} seconds.')
            await asyncio.sleep(reconnect_interval)


asyncio.run(main())
