# from cryptography.fernet import Fernet
import socket
import struct
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# nonce = str(int(time.time() * 1000))

clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 10000

#   private key does not need to generate new. Could use same everytime, but elliptic curves are fast so I didnt
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


def nonce_creation():
    time.sleep(1)
    return int(time.time())


def struct_package(inputstring, statehandshake, realnonce, keyslot):
    return struct.pack(">3sii49s", inputstring, statehandshake, realnonce, keyslot)


def struct_unpack(recdata):
    return struct.unpack(">3sii49s", recdata)

try:

    # Stage 1: nonce, struct_package, send_to_server
    print("Stage 1")
    realNonce = nonce_creation()
    keySlot = str(public_key_in_bytes)
    print(len(keySlot))
    print(keySlot)
    print(bytes(keySlot))
    binary = struct_package(inputString, stateHandshake, realNonce, keySlot)
    inputString, stateHandshake, realNonce, keySlot = struct_unpack(binary)
    print(keySlot)
    clientSock.sendto(binary, (UDP_IP_ADDRESS, UDP_PORT_NO))

    # Stage 2: Rec from server, struct_unpack, add_servernonce_to_list
    print("Stage 2")
    recData, server = clientSock.recvfrom(4096)
    inputString, stateHandshake, realNonce, keySlot = struct_unpack(recData)
    shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), keySlot))
    print(shared_key)
    print('Computed shared key:\n {}'.format(shared_key))
    nonceList.append(realNonce)

    # Stage 3: nonce, struct_package, send_to_server
    print("Stage 3")
    realNonce = nonce_creation()
    binary = struct_package(inputString, stateHandshake, realNonce, keySlot)
    clientSock.sendto(binary, (UDP_IP_ADDRESS, UDP_PORT_NO))

    # clientSharedSecret = (dataFromServer[0] ** clientSecret) % sharedPrime

    # print("part two")
    # print(clientSharedSecret)

    # data[1] = 3
    # clientSock.setblocking(0)
    # print "Transmitting"
    # while True:

    # NONCE CREATION
    # nonce = str(int(time.time() * 1000))
    # try:
    # clientInput = raw_input("WRITE: ")
    # data[2] = clientInput
    # data[3] = data[3] + 1
    # clientSock.sendto(bytearray(data), (UDP_IP_ADDRESS, UDP_PORT_NO))

    # data, server = clientSock.recvfrom(1024)
    # print "RX: " + str(data)

    # except socket.error, msg:
    # pass
    # except KeyboardInterrupt:
    # exit = True
    # print "Received Ctrl+C... initiating exit"
    # break

finally:
    clientSock.close()

# finally:
#  print "Done"
# clientSock.close()


# firstShared = (sharedBase**clientSecret) % sharedPrime
# data[1] = firstShared

# data, addr = clientSock.recvfrom(1024)


# while True:
# data, addr = serverSock.recvfrom(1024)
# f.decrypt(data)
# if data == "Respond 1":
#   print "Message: ", data
#  A = (sharedBase ** data) % sharedPrime
# clientSock.sendto(A, (UDP_IP_ADDRESS, UDP_PORT_NO))
# elif data == "Request 2":
#  print "data"
# clientSharedSecret = (data ** clientSecret) % sharedPrime
# clientSock.sendto(data, UDP_IP_ADDRESS)

# Message = "Hello, Server"
# A = (sharedBase**clientSecret) % sharedPrime
# B = (sharedBase ** bobSecret) % sharedPrime

# clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# clientSock.sendto(Message, (UDP_IP_ADDRESS, UDP_PORT_NO))


# INNAN
# recData, server = clientSock.recvfrom(4096)  # type: (str, object)

# if recData == "Respond 1":

# INNAN
# print "Message: ", recData


# A = (sharedBase ** data) % sharedPrime

# INNAN
# clientSock.sendto(, (UDP_IP_ADDRESS, UDP_PORT_NO))
# recData, server = clientSock.recvfrom(4096)  # type: (str, object)


# elif recData == "Respond 2":

# INNAN
# print "Message: ", recData

# clientSharedSecret = (data ** clientSecret) % sharedPrime

# INNAN
# clientSock.sendto("Request 3", (UDP_IP_ADDRESS, UDP_PORT_NO))
# recData, server = clientSock.recvfrom(4096)  # type: (str, object)
# print "Message: " , recData

# key = Fernet.generate_key()
# f = Fernet(key)
# token = f.encrypt(b"A really secret message. Not for prying eyes.")
# print token
# '...'
# print f.decrypt(token)

# Variables

# p
# sharedPrime = 23
# g
# sharedBase = 5
# clientSecret
# clientSecret = 6
# array

# Calculation of (clientKey)
# A = (sharedBase ** clientSecret) % sharedPrime

# nonce = 2
# dataToSend = 1

# data = [A, 1, dataToSend, nonce]

# byteArr = bytes(data)
# byteArr2 = bytearray(data)


# clientSock.sendto(byteArr2, (UDP_IP_ADDRESS, UDP_PORT_NO))
# print(byteArr)
# data2 = list(bytearray(byteArr2))
# print(byteArr2)
# print(data2)

# SEND DATA
