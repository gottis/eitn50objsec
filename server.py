import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


serveraddress = ("127.0.0.1", 10000)

serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print( 'starting on {} port {}'.format( *serveraddress))
serversocket.bind(serveraddress)


# Generates private key from elliptic curve

private_key = ec.generate_private_key(ec.SECP384R1, default_backend())

public_key = private_key.public_key()
#   Convert to byte for transfer
#   X962 is encoding for elliptic curve publickey,
#   and together with CompressedPoint we can achieve sufficiently small packages
public_key_in_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

#shared_key = private_key.exchange(ec.ECDH(), peer_public_key)


while True:
    print('_______________________________________')
    print ('\nwaiting to receive')
    client_public_key, address = serversocket.recvfrom(512)

    print('received {} bytes from {}'.format(len(client_public_key), address))
    print('_______________________________________')

    if client_public_key:
        print('Client public key {}'.format(client_public_key))
        print('_______________________________________')
        shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_public_key))
        print('_______________________________________')
        print('Computed shared key with {}:\n {}'.format(address, shared_key))
        sent = serversocket.sendto(public_key_in_bytes, address)
        print('_______________________________________')
        print('sent {} bytes back to {}'.format( sent, address))
