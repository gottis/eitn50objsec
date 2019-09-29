import socket
import select
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

serveraddress = ("127.0.0.1", 10000)
serveraddress2 = ("127.0.0.1", 10001)

serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serversocket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# PSK = b'd7xmxmydueRaiHTiEaS0pa8gsGnhgNJXMR82NWE_cbo='

storage = []

print('starting on {} port {}'.format(*serveraddress))
serversocket.bind(serveraddress)
serversocket2.bind(serveraddress2)

# Generates private key from elliptic curve

private_key = ec.generate_private_key(ec.SECP384R1, default_backend())

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


def get_session_text(session):
    encrypted_data_total = b''
    for i in session:
        for value in range(4, len(i), 64):
            encrypted_data_total = encrypted_data_total + i[value:value + 60]
    return encrypted_data_total


def handleclient(socket):
    received_package, address = socket.recvfrom(100)
    print('_______________________________________')
    print('received {} bytes from {}'.format(len(received_package), address))
    print('_______________________________________')

    head_list = current_head_list(int_from_bytes(received_package[0:1]),
                                  int_from_bytes(received_package[1:2]),
                                  int_from_bytes(received_package[2:3]),
                                  int_from_bytes(received_package[3:4]))

    if head_list[3] == 1:

        head_list[3] = 2

        send_pack = send_package(head_list, public_key_in_bytes)
        sent = serversocket.sendto(send_pack, address)
        print('sent {} bytes back to {}'.format(sent, address))
        if received_package[4:]:

            print('Client public key {}\n'.format(received_package[4:]))
            shared_key = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(),
                                                                                                      received_package[
                                                                                                      4:]))
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

            # Verification should be here
            if True:
                session = []
                encrypted_data_total = b''

                print('Verification OK, receiving package')
                print('_______________________________________')
                control = 0
                while control == 0:

                    encrypted_data, address = serversocket.recvfrom(100)
                    print('Encrypted data: \n {}'.format(encrypted_data))
                    print('_______________________________________')
                    print('Size of encrypted data:\n {}'.format(len(encrypted_data)))
                    print('_______________________________________')

                    head_list = current_head_list(int_from_bytes(encrypted_data[0:1]),
                                                  int_from_bytes(encrypted_data[1:2]),
                                                  int_from_bytes(encrypted_data[2:3]),
                                                  int_from_bytes(encrypted_data[3:4]))
                    print(head_list[2])

                    if head_list[3] == 2:
                        # plaintext = f.decrypt(encrypted_data)
                        # timestamp = f.extract_timestamp(encrypted_data)
                        text = encrypted_data[4:]
                        print(encrypted_data[4:])
                        data = send_package(head_list, text)

                        session.insert(head_list[2], data)
                        if len(data) < 64:
                            control = 1

                plaintext = f.decrypt(get_session_text(session))
                print('Received data from client: {}'.format(plaintext))

                # storage.insert(session, session[0])


def sendstored(socket):
    client2_data, client2_address = socket.recvfrom(100)
    print(f"recieved {client2_data} from {client2_address}")
    for data in storage:
        print(f"trying to send {data} to {client2_address}")
        socket.sendto(data, client2_address)


while True:
    print('_______________________________________')
    print('\nwaiting to receive')
    readable, writeable, errors = select.select([serversocket, serversocket2], [], [])
    for s in readable:
        if s == serversocket:
            print("Awoken by socket1")
            handleclient(s)
        else:
            print("Awoken by socket2")
            sendstored(s)
