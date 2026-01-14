#!/usr/bin/env python3
import sys
import time
import jwt
import argparse
import os

def main():
    parser = argparse.ArgumentParser(description='Generate GitHub App JWT')

    parser.add_argument(
        '--pem', '-p',
        required=True,
        help='Path of private PEM file',
    )

    parser.add_argument(
        '--client-id', '-c',
        required=False,
        default=os.environ.get('CLIENT_ID'),
        help='GitHub Client ID (can also be set via CLIENT_ID env var)',
    )

    args = parser.parse_args()

    if not args.client_id:
        parser.error("Client ID is required. Please provide --client-id flag or set CLIENT_ID environment variable.")

    # Проверка существования файла
    if not os.path.exists(args.pem):
        print(f"Error: File not found: {args.pem}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.pem, 'rb') as pem_file:
            signing_key = pem_file.read()
    except Exception as e:
        print(f"Error reading PEM file: {e}", file=sys.stderr)
        sys.exit(1)

    payload = {
        # Issued at time
        'iat': int(time.time()),
        # JWT expiration time (10 minutes maximum)
        'exp': int(time.time()) + 600,
        # GitHub App's Client ID
        'iss': args.client_id
    }

    try:
        encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')

        if isinstance(encoded_jwt, bytes):
            encoded_jwt = encoded_jwt.decode('utf-8')

        print(encoded_jwt)

    except Exception as e:
        print(f"Error encoding JWT: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()