import argparse
import sys

from keys import generate_keypair
from box import encrypt_file, decrypt_file


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("genkeys")
    gen.add_argument("--name", required=True)
    gen.add_argument("--passphrase", required=True)

    enc = sub.add_parser("encrypt")
    enc.add_argument("--to", required=True)
    enc.add_argument("--file", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--key", required=True)
    dec.add_argument("--passphrase", required=True)
    dec.add_argument("--file", required=True)

    args = parser.parse_args()

    if args.command == "genkeys":
        generate_keypair(args.name, args.passphrase)
    elif args.command == "encrypt":
        encrypt_file(getattr(args, "to"), args.file)
    elif args.command == "decrypt":
        decrypt_file(args.key, args.passphrase, args.file)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
