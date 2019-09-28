import socket

serveraddress = ('127.0.0.1', 10001)
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

input()

clientsocket.sendto("gif data please".encode(), serveraddress)
print("waiting to recieve")
data, server = clientsocket.recvfrom(100)
print("recieved:")

print(data)

