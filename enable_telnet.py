#!/usr/bin/env python

import argparse
import ctypes
import socket
import hashlib
import logging
from Crypto.Util.Padding import pad
import re

"""
Netgear RAX30
Payload Structure:
    signature   : size = 16 bytes (0x10)
    mac         : size = 16 bytes (0x10)
    username    : size = 16 bytes (0x10)
    password    : size = 65 bytes (0x41)
    reserved    : size = 15 bytes (0xF)
    Total Payload size = 128 bytes (0x80)
signature = MD5(mac + username + SHA256(password) + reserved)
payload = signature + mac + username + SHA256(password) + reserved
encryption = Blowfish(payload)
"""
libBlowfish = ctypes.CDLL('../blowfish/libblowfish.so')

# Constants for sizes
MAC_SIZE = 16
USERNAME_SIZE = 16
PASSWORD_SIZE = 65
SIGNATURE_SIZE = 16
RESERVED_SIZE = 15
PAYLOAD_SIZE = 128
BLOWFISH_KEY_SIZE = 54
BLOCK_SIZE = 8
HALF_BLOCK_SIZE = 4
RESERVED_BYTES = b'\x00' * RESERVED_SIZE
logging.basicConfig(level=logging.INFO)


def validate_mac(mac_cleaned):
    # MAC must be 12 characters long and valid hex)
    if not re.match(r"[A-F0-9]{12}", mac_cleaned):
        raise ValueError("MAC address is invalid.")


def validate_password(password):
    if not password:
        raise ValueError("Password must not be empty.")
    if len(password) > PASSWORD_SIZE:
        raise ValueError(f"Password must not exceed {PASSWORD_SIZE} character.")


def validate_username(username):
    if not username:
        raise ValueError("Username must not be empty.")
    if len(username) > USERNAME_SIZE:
        raise ValueError(f"Username must not exceed {USERNAME_SIZE} characters.")


class PayloadBuilder:
    """
    Builder class for creating a payload based on MAC address, username, and password.
    """
    def __init__(self, mac, username, password):
        self.mac = mac
        self.username = username
        self.password = password

    def format_mac_address(self):
        """
        Format the MAC address to a 16-byte string.
        The MAC address will be cleaned (colons removed), validated, and padded to 16 bytes.

        Returns:
            bytes: 16-byte formatted MAC address.
        """
        mac_cleaned = self.mac.replace(":", "").upper()
        validate_mac(mac_cleaned)
        mac_padded = mac_cleaned.encode('ascii').ljust(MAC_SIZE, b'\x00')

        return mac_padded

    def format_username(self):
        """
        Format the username to a 16-byte string, ensuring it is valid, cleaned, and padded.

        Returns:
            bytes: 16-byte formatted username.
        """
        validate_username(self.username)
        username_cleaned = username.encode('ascii').ljust(USERNAME_SIZE, b'\x00')

        return username_cleaned

    def format_password(self):
        """
        Format the password to a 65-byte string, similar to the behavior of the other code for MAC and username.
        The password will be hashed (SHA256), cleaned, validated, and padded.

        Returns:
            bytes: 65-byte formatted password.
        """
        validate_password(self.password)
        sha256_hash = hashlib.sha256(password.encode('ascii')).hexdigest()
        password_cleaned = sha256_hash.encode('ascii').ljust(PASSWORD_SIZE, b'\x00')

        return password_cleaned

    def calculate_signature(self):
        """
        Calculate the MD5 signature for the payload.

        Returns:
            bytes: The MD5 hash of the concatenated input as bytes.
        """
        formatted_mac = self.format_mac_address()
        formatted_username = self.format_username()
        sha256_password = self.format_password()
        text = formatted_mac + formatted_username + sha256_password + RESERVED_BYTES
        if len(text) != 112:
            raise ValueError(f"Text length is {len(text)}, expected 112")
        signature = hashlib.md5(text).digest()

        return signature

    def create_payload(self):
        """
        Construct the full payload including signature, mac, username, password, and reserved bytes.

        Returns:
            bytes: The complete payload of 128 bytes.
        """
        signature = self.calculate_signature()
        mac = self.format_mac_address()
        username = self.format_username()
        password = self.format_password()
        payload = signature + mac + username + password + RESERVED_BYTES
        if len(payload) != PAYLOAD_SIZE:
            raise ValueError(f"Text length is {len(payload)}, expected {PAYLOAD_SIZE}")

        return payload

    def blowfish_encrypt(self):
        """
        Encrypt the payload using the Blowfish algorithm via the C library.

        Returns:
            bytes: Encrypted payload.
        """
        sha256_password = hashlib.sha256(self.password.encode('ascii')).hexdigest()
        key = b"AMBIT_TELNET_ENABLE+" + sha256_password.encode('ascii')
        payload = self.create_payload()
        # Blowfish block size is multiple of 8 bytes
        padded_payload = pad(payload, BLOCK_SIZE)

        logging.info(f"Blowfish context initialization...")
        ctx = ctypes.create_string_buffer(256)
        try:
            libBlowfish.Blowfish_Init(ctx, key, len(key))
        except Exception as e:
            logging.error(f"Blowfish encryption initialization failed: {e}")
            raise

        num_blocks = len(padded_payload) // BLOCK_SIZE
        encrypted_data = bytearray()

        # Encrypt each 8-byte block of the padded payload
        for i in range(num_blocks):
            block = padded_payload[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            # Convert the 8-byte block into two 32-bit integers (xl, xr)
            xl = ctypes.c_uint32(int.from_bytes(block[:HALF_BLOCK_SIZE], byteorder='little'))
            xr = ctypes.c_uint32(int.from_bytes(block[HALF_BLOCK_SIZE:], byteorder='little'))
            libBlowfish.Blowfish_Encrypt(ctx, ctypes.byref(xl), ctypes.byref(xr))
            encrypted_block = xl.value.to_bytes(HALF_BLOCK_SIZE, byteorder='little') + xr.value.to_bytes(HALF_BLOCK_SIZE, byteorder='little')
            encrypted_data.extend(encrypted_block)

        return bytes(encrypted_data)


def udp_send(payload, ip, port):
    """
    Send the payload over UDP.

    Args:
        payload (bytes): The payload to be sent.
        ip (str): The target IP address.
        port (int): The target port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.sendto(payload, (ip, port))
    logging.info(f"Sending Magic Packet to {ip}:{port} over UDP")


def tcp_send(payload, ip, port):
    """
    Send the payload over TCP.

    Args:
        payload (bytes): The payload to be sent.
        ip (str): The target IP address.
        port (int): The target port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.sendall(payload)
    sock.close()
    logging.info(f"Sending Magic Packet to {ip}:{port} over TCP")


def get_argument():
    parser = argparse.ArgumentParser(description="Netgear RAX30 Magic Packet")
    parser.add_argument('-ip',
                        dest='ip',
                        default='192.168.1.1',
                        required=False,
                        type=str,
                        help='IP address of the Netgear router. Default: 192.168.1.1')
    parser.add_argument('-p',
                        dest='port',
                        default=23,
                        required=False,
                        type=int,
                        help='Telnet Port Number. Default: 23')
    parser.add_argument('-u',
                        dest='username',
                        default='admin',
                        required=False,
                        type=str,
                        help='Useername. Default: admin')
    parser.add_argument('-w',
                        dest='password',
                        default='password',
                        required=False,
                        type=str,
                        help='User Account Password. Default: password')
    parser.add_argument('-m',
                        dest='mac',
                        required=True,
                        type=str,
                        help='Netgear Router MAC address.')

    return parser.parse_args()


if __name__ == '__main__':
    args = get_argument()
    ip = args.ip
    port = args.port
    mac = args.mac
    username = args.username
    password = args.password

    builder = PayloadBuilder(mac, username, password)
    payload = builder.create_payload()
    logging.info(f"Generating signature = MD5(mac + username + password)")
    logging.info(f"Generated payload of size: {len(payload)} bytes")
    enc_payload = builder.blowfish_encrypt()
    logging.info(f"Magic Packet: {enc_payload.hex()}")
    udp_send(enc_payload, ip, port)
