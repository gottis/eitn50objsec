import socket
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
# Make sure data transfer does not exceed 64bytes per package

serveraddress = ('127.0.0.1', 10001)

#PSK = b'd7xmxmydueRaiHTiEaS0pa8gsGnhgNJXMR82NWE_cbo='


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
    print('_______________________________________')
    print ('sending public key')
    print('_______________________________________')
    sent = clientsocket.sendto(public_key_in_bytes, serveraddress)

    # Receive server public key
    print ('waiting to receive')
    print('_______________________________________')
    server_public_key, server = clientsocket.recvfrom(100)
    print ('received public key from server')
    print('_______________________________________')
    # Prints public key neatly
    print('Server public key {}\n'.format(server_public_key))
    print('_______________________________________')
    # New exchange must be done for each new session to achieve forward secrecy
    shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_public_key))
    print('Computed shared key:\n {}'.format(shared_key))
    print('_______________________________________')
    # We want to derive a key from our shared key to destroy any structure that may be present
    # We set the keylength to be 32bytes to be able to use Fernet to encrypt/decrypt later
    # HKDF = HMAC key derivation function
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption key',
        backend=default_backend()
    ).derive(shared_key)

    print('Derived key: \n {}'.format(derived_key))
    print('_______________________________________')

    f = Fernet(base64.urlsafe_b64encode(derived_key))

finally:
    print("Sending request for data")
    clientsocket.sendto("gif data please".encode(), serveraddress)
    print("waiting to recieve")
    data = clientsocket.recvfrom(100)[0]
    data = int(f.decrypt(data).decode())
    print(f"Server has {data} packets in storage")

    for i in range(data):
        control = 0
        encrypted_data_total = b''
        while control == 0:
            packet = clientsocket.recvfrom(100)[0]
            head_list = [x for x in packet[0:4]]
            encrypted_data_total = encrypted_data_total + packet[4:]

            if len(packet) < 64:
                control = 1
        plaintext = f.decrypt(encrypted_data_total)
        print('Received data from client: {}'.format(plaintext.decode()))


        # print(f"Packet {i}: {packet}")

    print("closing socket")
    clientsocket.close()
