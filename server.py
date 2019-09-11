#!/usr/bin/env python3
"""Server application for the SecureCommunications demo project.

Format of the request accepted by the server::

    <?xml version="1.0" ?>
    <request>
        <enckey>base64(RSAEncrypt(AES_KEY))</enckey>
        <message>base64(AES(msg,AES_KEY))</message>
        <signature>base64(RSASign(AES(msg,AES_KEY), "SHA-1"))</signature>
    </request>

Format of the response produced by the server::

    <response>base64(AES(back,AES_KEY))</response>
"""

import logging
import rsa
import sys
import xmltodict
import uuid

from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from flask import abort, current_app, Flask, request

RESPONSE_TEMPLATE = """<response>{0}</response>"""
PRIVATE_KEY_FILE = "server_priv.pem"
PUBLIC_KEY_FILE = "server_pub.pem"
CLIENT_PUBLIC_KEY_FILE = "client_pub.pem"
PORT_NUMBER = 9999

#############################################################################


class KeyPair(object):
    """Represents a private-public key pair.

    Attributes:
        public (str): the public key
        private (Optional[str]): the private key; may be `None` if not known
    """

    def __init__(self, public=None, private=None):
        self.public = public
        self.private = private

    def __repr__(self):
        return (
            "{0.__class__.__name__!r}"
            "(public={0.public!r}, private={0.private!r})"
        ).format(self)


def aes_encrypt(msg, key, iv):
    """Encrypts a message with AES encryption.

    Parameters:
        msg (bytes): the message to encrypt as a byte array. It will be padded
            with spaces to a length divisible with 16.
        key (bytes): the AES encryption / decryption key
        iv (bytes): the AES initiaization vector

    Returns:
        bytes: the padded and encrypted message
    """
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad_pkcs7(msg)
    return aes.encrypt(padded_msg)


def aes_decrypt(msg, key, iv):
    """Decrypts a message previously encrypted with AES encryption.

    Parameters:
        msg (bytes): the message to decrypt as a byte array. Its length must be
            divisible with 16. The underlying message is assumed to have been
            padded with PKCS#7 and it will be unpadded before returning it to
            the caller.
        key (bytes): the AES encryption / decryption key
        iv (bytes): the AES initiaization vector

    Returns:
        bytes: the decrypted and unpadded message
    """
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_msg = aes.decrypt(msg)
    return unpad_pkcs7(decrypted_msg)


def load_pem_key(filename, private=False):
    """Loads a PEM formatted private or public key from the file with the
    given name.

    Parameters:
        filename (str): the name of the file
        private (bool): whether the file contains a private key

    Returns:
        Union[rsa.PrivateKey, rsa.PublicKey]: the loaded private or public key
    """
    key_class = rsa.PrivateKey if private else rsa.PublicKey
    with open(filename, mode="rb") as fp:
        data = fp.read()
    return key_class.load_pkcs1(data, format="PEM")


def pad_pkcs7(b, block_size=16):
    """Applies PKCS#7 padding to the end of the given byte array such that its
    length becomes divisible with the given block size, in bytes.

    Parameters:
        b (bytes): the input array
        block_size (int): the block size to pad to
    """
    extra = block_size - (len(b) % block_size)
    padding = bytes([extra]) * extra
    return b + padding


def unpad_pkcs7(b):
    """Strips PKCS#7 padding from the end of the given byte array and returns
    the stripped byte array.

    Parameters:
        b (bytes): the input array

    Returns:
        bytes: the input array without the trailing PKCS#7 padding
    """
    return b[:-b[len(b)-1]]


def verify_rsa_signature(msg, signature, public_key):
    """Verifies the RSA signature on the given message.

    It is assumed that the signature was created on the SHA1 hash of the
    input message.

    Parameters:
        msg (bytes): the encrypted message
        signature (bytes): the signature of the input message, created from the
            SHA1 hash of the encrypted message
        public_key (bytes): the public key to verify the signature with

    Returns:
        bool: whether the message passed the signature validation
    """
    try:
        rsa.verify(msg, signature, public_key)
        return True
    except rsa.VerificationError as ex:
        logging.exception(ex)
        return False


#############################################################################
# Flask application setup

app = Flask(__name__)


@app.route("/")
def index():
    """Handler for the root URL so we have some content there."""
    return "Hello World!"


@app.route("/request", methods=["POST"])
def process_request():
    """Handles POST requests sent to the `/request` URL."""
    client_keys = current_app.client_keys
    server_keys = current_app.server_keys

    try:
        payload = xmltodict.parse(request.data)
        encrypted_aes_key = b64decode(payload["request"]["enckey"])
        message = b64decode(payload["request"]["message"])
        signature = b64decode(payload["request"]["signature"])
    except RuntimeError:
        return abort(400)          # return an HTTP 400 error (Bad Request)

    if not verify_rsa_signature(message, signature, client_keys.public):
        logging.error("Signature validation failed")
        return abort(400)          # return an HTTP 400 error (Bad Request)

    aes_key_data = rsa.decrypt(encrypted_aes_key, server_keys.private)

    aes_key, aes_iv = aes_key_data.split(b"|")

    plain_msg = aes_decrypt(message, aes_key, aes_iv)

    response = b' '.join([b'<status>success</status><transaction>',uuid.uuid4().hex,b'</transaction>'])
    encrypted_response = aes_encrypt(response, aes_key, aes_iv)
    return RESPONSE_TEMPLATE.format(
        b64encode(encrypted_response).decode('ascii')
    )


@app.before_first_request
def load_keys():
    """Loads the RSA keys to be used by the application before the first
    request is processed, and registers them in the current Flask context.

    Returns:
        (KeyPair, KeyPair): the public and private key pair of the server and
            the public key of the client
    """
    client_keys = KeyPair()
    server_keys = KeyPair()

    server_keys.private = load_pem_key(PRIVATE_KEY_FILE, private=True)
    server_keys.public = load_pem_key(PUBLIC_KEY_FILE)
    client_keys.public = load_pem_key(CLIENT_PUBLIC_KEY_FILE)

    with app.app_context():
        current_app.server_keys = server_keys
        current_app.client_keys = client_keys


#############################################################################
# Main application code

def main(debug=True):
    """Main application entry point.

    Configures logging and then launches the Flask web application in
    debug or production mode.

    Parameters:
        debug (bool): whether to run in debug mode

    Returns:
        int: exit code to return to the OS
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(format="%(message)s", level=level)
    app.run(host="127.0.0.1", port=PORT_NUMBER, debug=debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
