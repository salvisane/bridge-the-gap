import argparse

import nacl.secret
import nacl.utils
from pathlib import Path


def generate_key_file(file):
    """
    Write key into file for encryption
    :param file: path to file
    """
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    try:
        with open(file, 'wb') as f:
            f.write(key)
            print("key created")
    except FileNotFoundError:
        print("No valid path passed")


if __name__ == "__main__":

    # create parser for cli arguments
    parser = argparse.ArgumentParser(
        prog="Symmetric key generator",
        description='Generate a symmetric key for encrypting MQTT payload')
    parser.add_argument("path", type=Path, default=None, help="Path to store keyfile to")

    # parse arguments
    args = parser.parse_args()

    print(args.path)

    if args.path is not None and type(args.path == Path):
        generate_key_file(args.path)

