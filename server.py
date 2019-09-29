import socket
import select
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#TODO
# Implement authentication/verification using PSK.
# Implement nounce to stop replay attacks.

serveraddress = ("127.0.0.1", 10000)
serveraddress2 = ("127.0.0.1", 10001)

serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serversocket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#PSK = b'd7xmxmydueRaiHTiEaS0pa8gsGnhgNJXMR82NWE_cbo='

storage = []


print( 'starting on {} port {}'.format( *serveraddress))
serversocket.bind(serveraddress)
serversocket2.bind(serveraddress2)


# Generates private key from elliptic curve

private_key = ec.generate_private_key(ec.SECP384R1, default_backend())

public_key = private_key.public_key()
#   Convert to byte for transfer
#   X962 is encoding for elliptic curve publickey,
#   and together with CompressedPoint we can achieve sufficiently small packages
public_key_in_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def handleclient(socket):
    client_public_key, address = socket.recvfrom(100)
    print('_______________________________________')
    print('received {} bytes from {}'.format(len(client_public_key), address))
    print('_______________________________________')
    sent = socket.sendto(public_key_in_bytes, address)
    print('sent {} bytes back to {}'.format(sent, address))

    if client_public_key:
        print('Client public key {}\n'.format(client_public_key))
        shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(),
                                                                                                  client_public_key))
        print('_______________________________________')
        print('Computed shared key with {}:\n {}'.format(address, shared_key))
        print('_______________________________________')
        # We want to derive a keys from our shared key, this will destroy any structure that may be present in shared key
        # We set the keylength to be 32bytes to be able to use Fernet to encrypt/decrypt later
        # HKDF = HMAC key derivation function
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption key',
            backend=default_backend()
        ).derive(shared_key)
        f = Fernet(base64.urlsafe_b64encode(derived_key))
        print('Derived key: \n {}'.format(derived_key))
        return f


def sendstored(socket, f):
    client2_data, client2_address = socket.recvfrom(100)
    print(f"recieved {client2_data} from {client2_address}")
    print(f"{len(storage)} packets stored")
    socket.sendto(f.encrypt(str(len(storage)).encode()), client2_address)
    for data in storage:
        print(f"trying to send {data} to {client2_address}")
        socket.sendto(f.encrypt(data.encode()), client2_address)


def storedata(socket, f):
    # Verification should be here
    if True:
        print('Verification OK, receiving package')
        print('_______________________________________')
        encrypted_data, address = socket.recvfrom(100)
        print('Encrypted data: \n {}'.format(encrypted_data))
        print('_______________________________________')
        print('Size of encrypted data:\n {}'.format(len(encrypted_data)))
        print('_______________________________________')
        plaintext = f.decrypt(encrypted_data)
        print('Received data from client: {}'.format(plaintext))
        storage.append(plaintext)


while True:
    print('_______________________________________')
    print('\nwaiting to receive')
    readable, writeable, errors = select.select([serversocket, serversocket2], [], [])
    for s in readable:
        if s == serversocket:
            print("Awoken by socket1")
            fernet = handleclient(s)
            print("Handshake with client1 finished")
            storedata(s, fernet)
            print(f"Stored recieved data {storage}")
        else:
            print("Awoken by socket2")
            fernet = handleclient(s)
            print("Handshake with client2 finished")
            sendstored(s, fernet)
            print(f"Sent stored data {storage}")

