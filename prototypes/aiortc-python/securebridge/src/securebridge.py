# Secure Bridge - MQTT message payload encryption and decryption tool

# code example/base:
#   https://pypi.org/project/asyncio-mqtt/0.13.0/
#   https://pynacl.readthedocs.io/en/latest/secret/
#   https://pynacl.readthedocs.io/en/latest/password_hashing/

# Usage:
# see -h of program call
# example call with file: python3 securebridge.py encrypt 147.87.118.29 8883 --user cedalo --keyfile test secret_key.bin --s_topics topics/a/# topics/b/# topics/c/# --p_topic encrypted -v
# example call with password: python3 securebridge.py encrypt 147.87.118.29 8883 --user cedalo --user_pw test --password test1234 --s_topics topics/a/# topics/b/# topics/c/# --p_topic encrypted -v


import argparse
import ast
import asyncio
import json
import logging
import ssl
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import certifi
import nacl.secret
import nacl.utils
from asyncio_mqtt import Client, MqttError
from nacl import pwhash, secret, utils

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)


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
        logger.error("No valid path passed")


def handle_publish_topic(role, current_topic_string, new_base_topic):
    """
    Change first level of topic string or remove use default values
    :param role: Role of client to decide default first level topic
    :param current_topic_string: Current topic string
    :param new_base_topic: First level of new topic string
    :return: new topic string
    """
    subtopics = current_topic_string.split("/")
    base_topic = subtopics[0]

    if role == "decrypt":
        # default behaviour, remove current first level of topic
        if new_base_topic == "":
            new_topic_string = '/'.join(subtopics[1:])
        # replace first level of topic with given string
        else:
            new_topic_string = current_topic_string.replace(base_topic, new_base_topic)
    else:  # role == "encrypt"
        # default behaviour, add "encrypted" as new first level
        if new_base_topic == "":
            new_topic_string = "encrypted" + "/" + str(current_topic_string)
        # prepend given string as new first level of topic
        else:
            new_topic_string = str(new_base_topic) + "/" + str(current_topic_string)

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


def encrypt_payload(mode, payload, key):
    """
    Encrypts message payload
    :param mode: password or file as key
    :param payload: payload of MQTTmessage object
    :param key: secret key for encryption
    :return: encrypted message payload
    """
    logger.info("encrypt_payload() called")

    # encryption with file as key
    if mode == "file":
        logger.info("file mode")
        # like safe, used to encrypt or decrypt messages
        box = nacl.secret.SecretBox(key)
        encrypted_payload = box.encrypt(payload)
        logger.debug("encrypted_payload: ")
        logger.debug(encrypted_payload)
        return encrypted_payload

    # encryption with password as key
    elif mode == "password":
        logger.info("password mode")
        # key derivation function from pynacl, use standard values for ops and mem
        # has to be the same in the decryption function
        kdf = pwhash.argon2i.kdf
        salt = utils.random(pwhash.argon2i.SALTBYTES)
        # password must be bytes
        key = bytes(key, 'utf-8')
        derived_key = kdf(secret.SecretBox.KEY_SIZE, key, salt)
        box = secret.SecretBox(derived_key)
        encrypted_message = box.encrypt(payload)
        # must send both the encrypted message and the salt for decryption
        encrypted_payload = {"message": encrypted_message,
                             "salt": salt
                             }
        # encrypted_payload must be converted to string, otherwise it's not serializable
        return json.dumps(str(encrypted_payload))

    else:
        logger.error("no mode chosen for encryption")
        exit(0)


def decrypt_payload(mode, payload, key):
    """
    Decrypts message payload
    :param mode: password or file as key
    :param payload: Message payload
    :param key: Secret key for decryption
    :return: Decrypted payload
    """
    logger.info("decrypt_payload() called")
    decrypted_payload = None

    # encrypt with keyfile
    if mode == "file":
        box = nacl.secret.SecretBox(key)
        decrypted_payload = box.decrypt(payload)
        logger.debug("decrypted_payload: ")
        logger.debug(decrypted_payload)

    # encrypt with password
    elif mode == "password":
        logger.info("decryption password mode")

        # JSON to string
        payload = json.loads(payload)

        # convert string to dictionary
        payload = ast.literal_eval(payload)

        # get necessary values for decryption
        salt = payload["salt"]
        message = payload["message"]
        key = bytes(key, 'utf-8')

        # key derivation function from pynacl, use standard values for ops and mem
        # has to be the same in the encryption function
        kdf = pwhash.argon2i.kdf
        derived_key = kdf(secret.SecretBox.KEY_SIZE, key, salt)
        box = secret.SecretBox(derived_key)
        decrypted_payload = box.decrypt(message)

    else:
        logger.error("no mode chosen for decryption")
        exit(0)

    return decrypted_payload


async def publish_message(role, mode, messages, key, publish_topic_base, client):
    """
    Publishes messages
    :param role: Role of client, encrypt or decrypt
    :param mode: password or file as key
    :param messages: MQTT messages
    :param key: Secret key for decryption
    :param publish_topic_base: First level of topic string to publish message to
    :param client: MQTT client
    :return:
    """
    logger.info("publish_messages() called")

    async for message in messages:
        # cryptographic functions according to role
        if role == "decrypt":
            payload = decrypt_payload(mode, message.payload, key)

        else:
            payload = encrypt_payload(mode, message.payload, key)

        # destination topic
        destination_topic = handle_publish_topic(role, message.topic, publish_topic_base)
        logger.debug("destination_topic: ")
        logger.debug(destination_topic)

        # publish
        await client.publish(
            destination_topic,
            payload=payload,
            qos=1
        )


async def run_payload_crypto(role, mode, client, key, subscribed_topics, publish_topic_base):
    """
    Creates and handles tasks to encrypt or decrypt MQTT messages and publish them
    :param role: Role of client, encrypt or decrypt
    :param mode: password or file as key
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

        manager = client.unfiltered_messages()
        messages = await stack.enter_async_context(manager)
        task = asyncio.create_task(publish_message(role, mode, messages, key, publish_topic_base, client))
        tasks.add(task)

        # subscribe to topics (subscribe after starting message handling to not miss retained messages)
        for topic in subscribed_topics:
            await client.subscribe(topic)
            logger.info("client subscribed" + topic)

        # Wait for everything to complete (or fail due to, e.g., network
        # errors)
        await asyncio.gather(*tasks)


# Main program
async def main():
    # create parser for cli arguments
    parser = argparse.ArgumentParser(
        prog="Encryption Client",
        description="MQTT message encryption or decryption")
    # role
    parser.add_argument("role", choices=["encrypt", "decrypt"], help="'encrypt': encrypts and publishes messages"
                                                                     " from and to specified topics. "
                                                                     "'decrypt': decrypts and publishes messages"
                                                                     " from and to specified topics")
    # broker
    parser.add_argument("brokername", help="hostname or ip of broker")
    parser.add_argument("brokerport", help="port on broker", type=int)
    parser.add_argument("--user", default=None, help="user name")
    parser.add_argument("--user_pw", default=None, help="user password for broker")
    # path to key file
    parser.add_argument("--keyfile", type=Path, default=None, help="Path to key-file")
    parser.add_argument("--password", default="", help="secret password for encryption")
    # topic lists
    parser.add_argument(
        "--s_topics",  # name on the CLI; `-<letter>` or `--<word>` for positional/required parameters
        nargs="*",  # 0 or more values expected => creates a list
        type=str,  # any type/callable can be used here
        default=[""],  # default if nothing is provided
        help="pass a list of topics to subscribe to; "
             "role 'decrypt': default value is encrypted/#"
             "role 'encrypt': default value is 'securebridge/#"
             "subscribe to '#' is not possible (creates loop, kills broker)"
    )
    # base topic level
    parser.add_argument(
        "--p_topic",
        type=str,
        default="",
        help="Change first level of topic to publish messages to "
             "default behaviour if nothing entered: "
             "'encrypt' role: add 'encrypted' as first level topic"
             "'decrypt' role: remove current first level topic"
    )
    # no TLS option
    parser.add_argument("--notls", help="do not use TLS", action="count")
    # verbose mode for debugging
    parser.add_argument("-v", "--verbose", action="count")

    # parse arguments
    args = parser.parse_args()

    role = args.role

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

    # subscribe topics
    logger.info("subscribe topics: %r" % args.s_topics)

    # handle subscribe to everything ("#")
    for topic in args.s_topics:
        if topic == "#":
            logger.error("subscribe to '#' is not possible")
            exit(0)

    # default cases subscribe
    if args.s_topics == [""] and role == "encrypt":
        subscribed_topics = ["securebridge/#"]
    elif args.s_topics == [""] and role == "decrypt":
        subscribed_topics = ["encrypted/#"]
    else:
        subscribed_topics = args.s_topics

    # publish topics
    logger.info("publish topics: %r" % args.p_topic)
    publish_topic = args.p_topic

    # instantiate client
    # no tls
    if args.notls:
        # create mqtt client without tls
        client = Client(
            hostname=args.brokername,
            port=args.brokerport,
            username=args.user,
            password=args.user_pw,
            clean_session=True
        )
    # with tls
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

    # check for keyfile or password
    key = None  # will be either password or file
    mode = None  # needed for the corresponding encryption function and message creation

    # password not file
    if args.password != "" and args.keyfile is None:
        key = args.password
        mode = "password"
        logger.info("password mode")

    # file not password
    elif args.keyfile is not None and type(args.keyfile == Path) and args.password == "":
        key = get_key_from_file(args.keyfile)
        mode = "file"
        logger.info("file mode")
        logger.info("file path: ")
        logger.info(args.keyfile)

    # neither password nor file
    elif args.password == "" and args.keyfile is None:
        logger.error("No password or path to key file given")
        logger.error(FileNotFoundError)
        exit(0)

    # something else went wrong
    else:
        logger.error("missing resources for password or keyfile")
        exit(0)

    # Run indefinitely. Reconnect automatically if the connection is lost.
    reconnect_interval = 3  # [seconds]

    while True:
        try:
            # connect client
            async with client:
                logger.info("client connected")
                # run crypto tasks
                await run_payload_crypto(role, mode, client, key, subscribed_topics, publish_topic)
        except MqttError as error:
            logger.error(f'Error "{error}". Reconnecting in {reconnect_interval} seconds.')
        finally:
            await asyncio.sleep(reconnect_interval)


asyncio.run(main())
