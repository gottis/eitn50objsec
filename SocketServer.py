import time
import socket
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# Generates private key from elliptic curve
private_key = ec.generate_private_key(ec.SECP384R1, default_backend())

#   Retrieves public key from private key
public_key = private_key.public_key()

#   Convert to byte for transfer
#   X962 is encoding for elliptic curve publickey,
#   and together with CompressedPoint we can achieve sufficiently small packages
public_key_in_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


nonceList = [0]
stateHandshake = 1
realNonce = 0
inputString = "mul"
keySlot = None

UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 10000

serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))


# Create nonce
def nonce_creation():
    time.sleep(1)
    return int(time.time())


# Struct package
def struct_package(inputstring, statehandshake, realnonce, keyslot):
    return struct.pack(">3sii49s", inputstring, statehandshake, realnonce, keyslot)


# Struct unpack
def struct_unpack(recdata):
    return struct.unpack(">3sii49s", recdata)


while True:

    recData, address = serverSock.recvfrom(1024)
    try:

        # struct_unpack
        inputString, stateHandshake, realNonce, keySlot = struct_unpack(recData)
        print("hej")
        print(keySlot)
        print("hej")
        # inputString = inputString.decode('ascii')

        # if nonce in list, close socket (replay attack)
        if realNonce in nonceList:
            print("REPLAY attacko")
            serverSock.close()

        # else, add to list of nonces
        nonceList.append(realNonce)

        # Stage 1 in the handshake
        if stateHandshake == 1:
            if keySlot:
                print("Stage 1")
                # Change the state of the handshake
                print(keySlot)
                shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), keySlot))
                print(shared_key)
                print('Computed shared key with {}:\n {}'.format(address, shared_key))
                keySlot = str(public_key_in_bytes)
                stateHandshake = 2
                realNonce = nonce_creation()
                binary = struct_package(inputString, stateHandshake, realNonce, keySlot)
                serverSock.sendto(binary, address)

        # Stage 2 in the handshake
        if stateHandshake == 2:
            print("part two")
            # serverSharedSecret = (A**serverSecret) % sharedPrime
            # print(serverSharedSecret)

        # Stage 3 receive protected input from server
        if stateHandshake == 3:
            print("third part")

    except struct.error:
        # Handle the case where we receive a malformed packet
        print("Unable to unpack packet")
