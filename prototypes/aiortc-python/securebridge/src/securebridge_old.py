# Secure Bridge - MQTT message payload encryption and decryption tool

# code example/base:
#   https://github.com/sbtinstruments/asyncio-mqtt
#   https://pynacl.readthedocs.io/en/latest/secret/

# Usage:
# see -h of program call
# example call: python3 mqttPayloadCryptool.py encrypt 147.87.118.29 8883 cedalo test secret_key.bin --s_topics topics/a/# topics/b/# topics/c/# --p_topic encrypted -v


import argparse
import asyncio
import logging
import os.path
import ssl
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import certifi
import nacl.secret
import nacl.utils
from asyncio_mqtt import Client, MqttError

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)


def generate_key_file(file):
    """
    write key into file for encryption
    :param file: path to file
    """
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    try:
        with open(file, 'wb') as f:
            f.write(key)
    except FileNotFoundError:
        print("No valid path passed")


def get_key_from_file(file):
    """
    Retrieve key from file
    :param file: path to file where key is stored
    :return: secret key
    """
    try:
        with open(file, 'rb') as f:
            key = f.read()
        return key
    except FileNotFoundError:
        print("No valid path passed")


def change_base_topic(current_topic_string, new_base_topic):
    """
    Change first level of topic or remove it if empty string is passed
    :param current_topic_string: Current topic string
    :param new_base_topic: First level of new topic string
    :return: new topic string
    """
    subtopics = current_topic_string.split("/")
    base_topic = subtopics[0]

    if new_base_topic == "":
        new_topic_string = '/'.join(subtopics[1:])
    else:
        new_topic_string = current_topic_string.replace(base_topic, new_base_topic)

    return new_topic_string


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


def encrypt_payload(payload, key):
    """
    :param payload: payload of MQTTmessage object
    :param key: secret key for encryption
    :return: encrypted message payload
    """
    logger.info("encrypt_payload() called")
    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)
    encrypted_payload = box.encrypt(payload)
    logger.debug("encrypted_payload: ")
    logger.debug(encrypted_payload)
    return encrypted_payload


def decrypt_payload(payload, key):
    """
    Decrypts message payload
    :param payload: Message payload
    :param key: Secret key for decryption
    :return: Decrypted payload
    """
    logger.info("decrypt_payload() called")
    box = nacl.secret.SecretBox(key)
    decrypted_payload = box.decrypt(payload)
    logger.debug("decrypted_payload: ")
    logger.debug(decrypted_payload)
    return decrypted_payload


async def decrypt_and_publish(messages, key, publish_topic_base, client):
    """
    Decrypts and publishes messages
    :param messages: MQTT messages
    :param key: Secret key for decryption
    :param publish_topic_base: First level of topic string to publish message to,
            removes first level of message topic if empty
    :param client: MQTT client
    :return:
    """
    logger.info("decrypt_and_publish() called")
    async for message in messages:
        decrypted_payload = decrypt_payload(message.payload, key)
        destination_topic = change_base_topic(message.topic, publish_topic_base)
        await client.publish(
            destination_topic,
            payload=decrypted_payload
        )


async def encrypt_and_publish(messages, key, publish_topic_base, client):
    """

    :param messages:
    :param key: secret key for encryption
    :param publish_topic_base: First level of topic string to publish message to
    :param client: MQTT client
    :return:
    """

    logger.info("encrypt_and_publish() called")
    async for message in messages:
        logger.debug("message.payload.decode(): ")
        logger.debug(message.payload.decode())
        encrypted_payload = encrypt_payload(message.payload, key)
        destination_topic = publish_topic_base + "/" + message.topic
        logger.debug("destination_topic: ")
        logger.debug(destination_topic)
        await client.publish(
            destination_topic,
            payload=encrypted_payload
        )


async def run_payload_crypto(role, client, key, subscribed_topics, publish_topic_base):
    """
    Creates and handles tasks to encryp or decrypt MQTT messages and publish them
    :param role: Parsed argument to decide mode
    :param client: MQTT client
    :param key: Secret key
    :param subscribed_topics: Subscribed MQTT topics
    :param publish_topic_base: First level of topic string to publish message to
    :return:
    """

    # create a stack to help manage context manager.
    async with AsyncExitStack() as stack:
        # Keep track of the asyncio tasks that we create, so that
        # we can cancel them on exit
        tasks = set()
        stack.push_async_callback(cancel_tasks, tasks)

        await stack.enter_async_context(client)

        # set topic filters
        topic_filters = tuple(subscribed_topics)
        logger.info("topic_filters: ")
        logger.info(topic_filters)

        # set mode
        if role == "encrypt":
            run = encrypt_and_publish
            logger.info("encryption mode")
        else:
            run = decrypt_and_publish
            logger.info("encryption mode")

        # handle filtered messages
        for topic_filter in topic_filters:
            logger.debug("topic filter: ")
            logger.debug(topic_filter)
            manager = client.filtered_messages(topic_filter)
            messages = await stack.enter_async_context(manager)
            task = asyncio.create_task(run(messages, key, publish_topic_base, client))
            tasks.add(task)

        # subscribe to topic
        await client.subscribe("#")
        logger.info("client subscribed")

        # Wait for everything to complete (or fail due to, e.g., network
        # errors)
        await asyncio.gather(*tasks)


# Main program
async def main():
    # create parser for cli arguments
    parser = argparse.ArgumentParser(description='MQTT message encryption or decryption')
    # role
    parser.add_argument("role", choices=["encrypt", "decrypt"])
    # broker
    parser.add_argument("brokername", help="hostname or ip of broker")
    parser.add_argument("brokerport", help="port on broker", type=int)
    parser.add_argument("--user", help="user name")
    parser.add_argument("--user_pw", help="user password for broker")
    # path to key file
    parser.add_argument("--keyfile", type=Path, help="Path to key-file")
    # topics to encrypt or decrypt as lists
    parser.add_argument(
        "--s_topics",  # name on the CLI; `-<letter>` or `--<word>` for positional/required parameters
        nargs="*",  # 0 or more values expected => creates a list
        type=str,  # any type/callable can be used here
        default=[],  # default if nothing is provided
        help="pass a list of topics to subscribe to"
    )
    # base topic level
    parser.add_argument(
        "--p_topic",
        type=str,
        default="",
        help="base topic level to publish messages to"
    )
    # no TLS option
    parser.add_argument("--notls", help="do not use TLS", action="count")
    # verbose mode for debugging
    parser.add_argument("-v", "--verbose", action="count")

    # parse arguments
    args = parser.parse_args()

    # logger settings
    if args.verbose:
        logging.basicConfig(
            format='%(process)d-%(levelname)s-%(message)s',
            level=logging.DEBUG,
            filename="cryptool_log.log")
    else:
        logging.basicConfig(
            format='%(process)d-%(levelname)s-%(message)s',
            level=logging.WARNING,
            filename="cryptool_log.log")

    role = args.role

    # topics
    logger.info("subscribe topics: %r" % args.s_topics)
    logger.info("publish topics: %r" % args.p_topic)
    subscribed_topics = args.s_topics
    publish_topics = args.p_topic

    # tls
    if args.notls:
        # create mqtt client without tls
        client = Client(
            hostname=args.brokername,
            port=args.brokerport,
            username=args.user,
            password=args.user_pw,
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
        # create mqtt client with tls
        client = Client(
            hostname=args.brokername,
            port=args.brokerport,
            username=args.user,
            password=args.user_pw,
            tls_context=sslsettings,
            clean_session=True
        )

    # check if keyfile exists
    key = None
    if args.keyfile.exists() and type(args.keyfile == Path):
        key = get_key_from_file(args.keyfile)
        logger.info("file path: ")
        logger.info(args.keyfile)
    else:
        logger.error(FileNotFoundError)

    # Run indefinitely. Reconnect automatically if the connection is lost.
    reconnect_interval = 3  # [seconds]

    while True:
        try:
            # connect client
            async with client:
                logger.info("client connected")

                await run_payload_crypto(role, client, key, subscribed_topics, publish_topics)

        except MqttError as error:
            logger.error(f'Error "{error}". Reconnecting in {reconnect_interval} seconds.')
        finally:
            await asyncio.sleep(reconnect_interval)


asyncio.run(main())
