import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

serveraddress = ('127.0.0.1', 10000)

# Writes message in bytes
message = b'VARSTRANGFARINTEVARALANGREAN64BYTES_____________________________'

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#   private key does not need to generate new. Could use same everytime, but elliptic curves are fast so I didnt
private_key = ec.generate_private_key(ec.SECP384R1, default_backend())

#   Retrieves public key from private key
public_key = private_key.public_key()
#   Convert to byte for transfer
#   X962 is encoding for elliptic curve publickey,
#   and together with CompressedPoint we can achieve sufficiently small packages
public_key_in_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


try:
    # Send client public key to server
    print ('sending public key')
    print('_______________________________________')
    sent = clientsocket.sendto(public_key_in_bytes, serveraddress)

    # Receive server public key
    print ('waiting to receive')
    print('_______________________________________')
    server_public_key, server = clientsocket.recvfrom(512)
    print ('received public key from server')
    print('_______________________________________')
    # Prints public key neatly
    print('Server public key {}'.format(server_public_key))
    print('_______________________________________')
    # New exchange must be done for each new session to achieve forward secrecy
    #shared_key = private_key.exchange(ec.ECDH(), server_public_key)
    shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_public_key))
    print('Computed shared key:\n {}'.format(shared_key))
    print('_______________________________________')

finally:
    print ("closing socket")
    clientsocket.close()