# code example/base socket: https://docs.python.org/3/library/asyncio-stream.html#examples
# code example/base aiortc: https://github.com/aiortc/aiortc/blob/main/examples/datachannel-cli/cli.py
import argparse
import base64
import os.path
from applic_tunnel import *
from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer

logger = logging.getLogger(__name__)

# Main program
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Application layer tunnel",
        description="A program to tunnel a TCP application layer by a RTC data channel. "
                 "The signaling protocol is based on MQTT with message based end to end "
                 "encryption. "
                 "A listener instance is waiting for initiators, which can be optionally "
                 "approved by a list of public keys.")

    # create subparser to start the applic tunnel as intitiator or listener
    subparsers = parser.add_subparsers(required=True, dest="role")
    parserInitiator = subparsers.add_parser("initiator", help="run applic tunnel as initiator")
    parserListener = subparsers.add_parser("listener", help="run applic tunnel as listener")

    subparserList: list = [parserInitiator, parserListener]

    for p in subparserList:
        p.add_argument("sigbrokername", help="hostname or ip of signaling broker")
        p.add_argument("sigbrokerport", help="port on signaling broker", type=int)
        p.add_argument("connectionip", help="connection ip")
        p.add_argument("connectionport", help="connection port", type=int)
        p.add_argument("-u", "--siguser", help="signaling user name", type=str)
        p.add_argument("-p", "--sigpassword", help="signaling password", type=str)
        p.add_argument("-t", "--sigtopic", help="signaling topic")
        p.add_argument("-n", "--tunnelname", help="tunnel name")
        p.add_argument("--notls", help="do not use TLS", action="count")
        p.add_argument("--unsecure",
                       help="use no application encryption mode (not recommended). Activate on both sides.",
                       action="count")
        p.add_argument("-v", "--verbose", action="count")

    parserInitiator.add_argument("listenerpubkey", help="Public key of listener as Base32 string", type=str)
    parserInitiator.add_argument("-pk", "--privatekey", help="Path to private key of initiator. Use random key if not set.", type=open)

    parserListener.add_argument("privatekey", help="Path to private key", type=open)
    parserListener.add_argument("-i", "--initiators", help="Path to file with trusted initators, trust every initiator if not set", type=open)

    # create subparser to start the key generator
    parserKeygen = subparsers.add_parser("keygen", help="generate a key pair")
    parserKeygen.add_argument("-p", "--path", help="path to save the keys")
    parserKeygen.add_argument("-v", "--verbose", action="count")

    args = None

    try:
        args = parser.parse_args()
    except FileNotFoundError as err:
        logging.error('Invalid path to file %s', err.filename)
        print('Invalid path to file {}'.format(err.filename))
        exit(0)

    if args.verbose:
        logging.basicConfig(
            format='%(process)d-%(levelname)s-%(message)s',
            level=logging.INFO)
    else:
        logging.disable(sys.maxsize)

    # generate key pair
    if args.role == "keygen":

        logging.info("generate private key")
        privateKey = PrivateKey.generate()
        privateKeyString = str(privateKey.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")

        publicKey = privateKey.public_key
        publicKeyString = str(publicKey.encode(encoder=nacl.encoding.Base32Encoder), "utf-8")

        # check keys can be used as topic
        if not check_valid_topic(privateKeyString) or not check_valid_topic(publicKeyString):
            logging.error("No keys for topics: " + privateKeyString + ", " + publicKeyString)

        # generate key path
        priPath = "key.private"
        pubPath = "key.public"

        if args.path:
            priPath = os.path.join(args.path, priPath)
            pubPath = os.path.join(args.path, pubPath)
        else:
            priPath = os.path.join(os.path.curdir, priPath)
            pubPath = os.path.join(os.path.curdir, pubPath)

        try:

            fpri = open(priPath, "x")
            fpub = open(pubPath, "x")

            fpri.write(privateKeyString)
            fpri.close()
            logging.info("Private key stored")

            fpub.write(publicKeyString)
            fpub.close()
            logging.info("Public key stored")

            print('Keys stored ("{}", "{}")'.format(priPath, pubPath))

        except FileExistsError:
            print('File(s) does already exit ("{}", "{}")'.format(priPath, pubPath))
            exit(0)
        except FileNotFoundError:
            print('Path not found ("{}")'.format(args.path))
            exit(0)
    # start applic tunnel
    else:

        # check private key
        if args.privatekey:
            private_key = args.privatekey.readline().strip().strip('\n')
            try:
                base64.b32decode(private_key)
            except Exception as err:
                logging.error("Invalid private key encoding (%s)", err.with_traceback(None))
                print("Invalid private key encoding".format(err.with_traceback(None)))
                exit(0)
        else:
            private_key = ''

        if args.tunnelname:
            tunnelname = args.tunnelname
        else:
            tunnelname = SIG_DEFAULT_CHANNEL

        if args.sigtopic:
            sigtopic = args.sigtopic
        else:
            sigtopic = SIG_DEFAULT_TOPIC

        if args.role == "initiator":

            # check private key
            listenerpubkey = args.listenerpubkey.strip().strip('\n')
            try:
                base64.b32decode(listenerpubkey)
            except Exception as err:
                logging.error("Invalid listener public key encoding (%s)", err.with_traceback(None))
                print("Invalid listener public key encoding ({})".format(err.with_traceback(None)))
                exit(0)

            signaling = MqttSecureSignalingInitiator(
                args.sigbrokername,
                args.sigbrokerport,
                args.siguser,
                args.sigpassword,
                sigtopic,
                tunnelname,
                private_key,
                args.notls,
                args.unsecure,
                listenerpubkey)

        else:
            if args.initiators:
                trusted_initiators = args.initiators.readlines()
                # remove empty entries
                for idx, entry in enumerate(trusted_initiators):
                    if entry.strip().startswith('#'):
                        trusted_initiators[idx] = ''
                    else:
                        trusted_initiators[idx] = entry.strip('\n').strip()
                trusted_initiators = list(filter(None, trusted_initiators))
            else:
                trusted_initiators = None

            signaling = MqttSecureSignalingListener(
                args.sigbrokername,
                args.sigbrokerport,
                args.siguser,
                args.sigpassword,
                sigtopic,
                tunnelname,
                private_key,
                args.notls,
                args.unsecure,
                trusted_initiators)

        rtcconfig = RTCConfiguration([
                RTCIceServer("stun:stun.l.google.com:19302")
            ])

        if args.role == "initiator":
            applic_tunnel = ApplicTunnelInitiator(rtcconfig, signaling, args.connectionip, args.connectionport)
        else:
            applic_tunnel = ApplicTunnelListener(rtcconfig, signaling, args.connectionip, args.connectionport)

        # run event loop
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(applic_tunnel.run())
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(applic_tunnel.stop())
            logging.info('stopped')
