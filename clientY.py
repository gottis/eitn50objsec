import socket
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# TODO
# Implement authentication/verification using PSK.
# Implement nounce to stop replay attacks.
# Make sure data transfer does not exceed 64bytes per package

serveraddress = ('127.0.0.1', 10000)

# PSK = b'd7xmxmydueRaiHTiEaS0pa8gsGnhgNJXMR82NWE_cbo='


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

sequence_number = 1
segment_count = 1
segment_number = 1
state_code = 1


def current_head_list(seq_num, seg_count, seg_num, code):
    head_list = [seq_num, seg_count, seg_num, code]
    return head_list


def send_package(head, slot):
    return bytearray(head) + slot


def int_from_bytes(bytes_value):
    return int.from_bytes(bytes_value, byteorder='big', signed=False)


try:
    # Send client public key to server
    print('_______________________________________')
    print('sending public key')
    print('_______________________________________')

    head_list = current_head_list(sequence_number, segment_count, segment_number, state_code)
    send_pack = send_package(head_list, public_key_in_bytes)
    sent = clientsocket.sendto(send_pack, serveraddress)

    # Receive server public key
    print('waiting to receive')
    print('_______________________________________')
    received_package, server = clientsocket.recvfrom(100)
    head_list = current_head_list(int_from_bytes(received_package[0:1]),
                                  int_from_bytes(received_package[1:2]),
                                  int_from_bytes(received_package[2:3]),
                                  int_from_bytes(received_package[3:4]))

    print(head_list)
    print('received public key from server')
    print('_______________________________________')
    # Prints public key neatly
    print('Server public key {}\n'.format(received_package[4:]))
    print('_______________________________________')
    # New exchange must be done for each new session to achieve forward secrecy
    shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(),
                                                                                              received_package[4:]))
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

    plaintext = input().encode()
    f = Fernet(base64.urlsafe_b64encode(derived_key))
    ciphertext = f.encrypt(plaintext)
    cipherSize = len(ciphertext)
    value = 0

    for value in range(0, len(ciphertext), 60):
        print(head_list[1])
        head_list = current_head_list(head_list[0], head_list[1], head_list[2],
                                      head_list[3])
        send_pack = send_package(head_list, ciphertext[value:value + 60])
        clientsocket.sendto(send_pack, serveraddress)
        head_list[1] = head_list[1] + 1
        head_list[2] = head_list[2] + 1
        print('Sending package of size {} : \n {}'.format(len(send_pack), send_pack))
        print('_______________________________________')


finally:
    print("closing socket")
    clientsocket.close()
