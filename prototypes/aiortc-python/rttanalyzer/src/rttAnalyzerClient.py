# Client for testing performance differences between tunnel and bridge
# procedure:
# 1. send message with timpestamp to subscriber
# 2. subscriber (rttMirrorClient) returns message to evaluation topic (client subscribes to that)
# 3. client compares timestamp with current time

# source:   https://pypi.org/project/asyncio-mqtt/

# Usage:
# see -h of program call
# example call with file: python3 rttAnalyzerClient.py 147.87.118.29 8883 tunnelBridge/RTTEvaluation tunnelBridge/RTTRelay --user cedalo --password test

import argparse
import time
import json
import asyncio
import ssl
import certifi
import logging

from contextlib import AsyncExitStack
from asyncio_mqtt import Client, MqttError

# fix to make it work on windows: https://stackoverflow.com/questions/63860576/asyncio-event-loop-is-closed-when-using-asyncio-run
import sys

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# store RTTs
OUTPUT_FILE = "round-trip-times.txt"

logger = logging.getLogger(__name__)


# payload with timestamp:
def create_message():
    """
    Creates the message to measure RTT
    :return: RTT message string
    """
    logger.debug("create_message() called")
    # time in seconds since the epoch as a floating point number
    timestamp = time.time()
    # JSON payload containing timestamp
    message = {"timestamp": timestamp}
    return json.dumps(message)  # encode object to JSON


async def publish_test_message(client, interval, p_topic):
    """
    Publishes the message to measure RTT
    :param client: MQTT client
    :param interval: interval for sending messages (in seconds)
    :param p_topic: topic to publish to
    :return:
    """
    logger.debug("publish_test_message() called")
    while True:
        message = create_message()
        await client.publish(p_topic, payload=message)
        await asyncio.sleep(interval)


async def measure_rtt(messages, output_file):
    """
    Calculates RTT of received messages
    :param messages: MQTT messages
    :param output_file: Textfile to write measured RTT to
    :return:
    """

    logger.debug("measure_rtt() called")

    async for message in messages:
        payload_json = json.loads(message.payload)
        logger.debug("message payload: " + str(payload_json))
        time_sent = payload_json["timestamp"]
        logger.debug("time_sent: " + str(time_sent))
        time_now = time.time()
        logger.debug("time_now: " + str(time_now))
        round_trip_time = time_now - time_sent
        logger.debug("RTT: " + str(round_trip_time))
        output_file.write(str(round_trip_time) + "\n")


async def cancel_tasks(tasks):
    """
    Helper for canceling tasks on exit
    :param tasks: Tasks
    :return:
    """
    for task in tasks:
        if task.done():
            continue
        try:
            task.cancel()
            await task
        except asyncio.CancelledError:
            pass


async def run_evaluation(client, s_topic, p_topic, output_file, message_interval):
    """
    Runs the evaluation loop
    :param client MQTT Client
    :param s_topic: topic to subscribe
    :param p_topic: topic to publish to
    :param output_file: Filestream
    :param message_interval: interval messages are sent (in seconds)
    :return:
    """
    # create a stack to help manage context manager.
    async with AsyncExitStack() as stack:
        # Keep track of the asyncio tasks that we create, so that
        # we can cancel them on exit
        tasks = set()
        stack.push_async_callback(cancel_tasks, tasks)

        await stack.enter_async_context(client)

        # handle messages
        manager = client.unfiltered_messages()
        messages = await stack.enter_async_context(manager)
        task = asyncio.create_task(measure_rtt(messages, output_file))
        tasks.add(task)

        # Publish to topic
        task = asyncio.create_task(publish_test_message(client, message_interval, p_topic))
        tasks.add(task)

        # Subscribe to topic
        await client.subscribe(s_topic)
        logger.info("analyzer client subscribed")
        logger.info("subscribed topic: " + s_topic)

        # Wait for everything to complete (or fail due to, e.g., network
        # errors)
        await asyncio.gather(*tasks)


# Main program
async def main():
    parser = argparse.ArgumentParser(
        prog="RTT Analyzer Client",
        description="Round Trip Time evaluation analyzer client")
    parser.add_argument("brokername", help="hostname or ip of broker")
    parser.add_argument("brokerport", help="port on broker", type=int)
    parser.add_argument("s_topic", help="topic to subscribe to")
    parser.add_argument("p_topic", help="topic to publish to")
    parser.add_argument("-u", "--user", help="broker user name", type=str)
    parser.add_argument("-p", "--password", help="broker password", type=str)
    parser.add_argument("--message_interval", help="interval messages are sent (in seconds), default is 1 second",
                        default=1, type=int)
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

    reconnect_interval = 5  # in seconds
    logger.info("reconnect_interval set to " + str(reconnect_interval))

    output_file = open(OUTPUT_FILE, "w")
    logger.info("output_file " + output_file.name + " opened")

    while True:
        try:
            async with Client(hostname=args.brokername, port=args.brokerport, username=args.user,
                              password=args.password, tls_context=sslsettings) as client:
                logger.info("analyzer client connected")
                await run_evaluation(client, args.s_topic, args.p_topic, output_file, args.message_interval)

        except MqttError as error:
            logger.info(f'Error "{error}". Reconnecting in {reconnect_interval} seconds.')
            await asyncio.sleep(reconnect_interval)

        finally:
            output_file.close()
            logger.info("output_file closed")


asyncio.run(main())
