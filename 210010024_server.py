import socket 
from threading import Thread 
import time
import sys
import json
import os
import cv2
# from subprocess import check_output
from datetime import datetime
# import threading
# import msgpack
import _thread
# import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 
from base64 import b64decode,b64encode

# lock = threading.Lock()
lock = _thread.allocate_lock()

hostIP = "127.0.0.1"
PORT = 8888
Addrs = (hostIP, PORT)

clients_pubkey = {}
clients_socket = {}

# def encrypt_data(data, pubkey):
#     try:
#         rsa_public_key = RSA.importKey(pubkey)
#         rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
#         encrypted_text = rsa_public_key.encrypt(data)
#         return encrypted_text
#         # key = RSA.import_key(pubkey)
#         # cipher = PKCS1_v1_5.new(key)
#         # encrypted_data = cipher.encrypt(data.encode())
#         # return b64encode(encrypted_data).decode('utf-8')
#     except Exception as e:
#         print("Error encrypting data:", e)
#         return None

def encrypt_data(data, pubkey):
    try:
        rsa_public_key = RSA.importKey(pubkey)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_text = rsa_public_key.encrypt(data.encode())
        return b64encode(encrypted_text)
    except Exception as e:
        print("Error encrypting data:", e)
        return None
    
# def issueDict(clients_socket, clients_pubkey,json_data):
def issueDict(clients_socket, clients_pubkey):
    # lock.acquire()
    for x in clients_socket:
        clients_socket[x].send("TABLE".encode('utf-8'))
        # clients_socket[x].send(encrypt_data(clients_pubkey,clients_pubkey[x]))
        # clients_socket[x].send(clients_pubkey)
        print(clients_pubkey)
        # clients_socket[x].send(len(clients_pubkey))
        for y in clients_pubkey:
            clients_socket[x].send(y.encode())
            time.sleep(0.2)
            # clients_socket[x].recv(1024).decode()
            clients_socket[x].send(clients_pubkey[y])
            # clients_socket[x].recv(1024).decode()
        # serialized_data = msgpack.packb(clients_pubkey)
        # clients_socket[x].send(serialized_data)
            # print("k")
        time.sleep(0.2)
        clients_socket[x].send("Complete".encode())
    # lock.release()

def sendVideo(clientsocket,clientName,pubkey):
    lock.acquire()
    contents = os.listdir("./videos/fish")
    # contents = ['video'] + contents
    # print("q")
    clientsocket.send("VIDEO".encode())
    time.sleep(0.1)
    # print("w")
    for x in contents:
        clientsocket.send(x.encode())
    time.sleep(0.5)
    clientsocket.sendall("END".encode())
    # print("e")
    received_data = clientsocket.recv(1024).decode()
    # received_list = pickle.loads(received_data)
    # msg = received_list[0]
    print("client requested for video: " + received_data)

    print("./videos/" + received_data +"240.mp4")
    video240 = cv2.VideoCapture("./videos/fish/"+received_data +"240.mp4")
    video720 = cv2.VideoCapture("./videos/fish/"+received_data +"720.mp4")
    video1440 = cv2.VideoCapture("./videos/fish/"+received_data +"1440.mp4")
    size = int(video240.get(cv2.CAP_PROP_FRAME_COUNT))
    clientsocket.sendall(size.to_bytes(4, byteorder='big'))
    # print(".fcgvhbjnkdeos/240.mp4")
    for i in range(size//3):
        ret, frame = video720.read()
        ret, frame = video1440.read()
    for i in range(size//3):
        ret, frame = video1440.read()
    index = 0
    while 1:
        index += 1
        if index < size//3:
            ret, frame = video240.read()
        elif size//3 <= index < 2*(size // 3):
            ret, frame = video720.read()
        else:
            ret, frame = video1440.read()
        if not ret:
            break
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 90]
        result, encoded_frame = cv2.imencode('.jpg', frame, encode_param)
        if not result:
            continue
        frame_size = len(encoded_frame)
        clientsocket.send(frame_size.to_bytes(4, byteorder='big'))
        clientsocket.send(encoded_frame)
    print("frame index: ", index)

    lock.release()
    print("LOCK RLE broWatch")

def broadcastMsg(clients_socket,  clients_pubkey, msg):
    lock.acquire()
    for x in clients_socket:
        clients_socket[x].send("server".encode('utf-8'))
        clients_socket[x].send(encrypt_data(msg, clients_pubkey[x]))
    lock.release()

def broadcastInteract( clients_socket,namecli,interactMsg):
    # lock.acquire()
    for x in clients_socket:
        # print("start")
        clients_socket[x].send("INTERACT".encode())
        clients_socket[x].send(namecli)
        clients_socket[x].send(interactMsg)
        # print("end")
    # lock.release()

def getNameAndKey(clientSocket, ):
    # lock.acquire()
    askName = "ENTER YOUR NAME: "
    clientSocket.send(askName.encode())
    clientName = clientSocket.recv(1024).decode()
    print("GETTING CLIENT's NAME <<"+clientName)

    askpubkey = "ENTER YOUR PUBLIC KEY: "
    clientSocket.send(askpubkey.encode())
    pubkey = clientSocket.recv(1024)
    print("GETTING PUBLIC KEY <<" )
    print(pubkey)
    return [clientName,pubkey]
    # lock.release()

def clientLeft(clientSocket,clientName,pubkey):
    lock.acquire()
    # clientSocket.send(encrypt_data("QUIT",pubkey))
    clientSocket.send("QUIT".encode())
    del clients_socket[clientName]
    del clients_pubkey[clientName]
    # json_data = json.dumps(clients_pubkey)
    issueDict(clients_socket, clients_pubkey)
    lock.release()

def clientsHandler(clientSocket, addr):
    # print("inch")
    try:
        lock.acquire()
        print(f"[NEW CONNECTION] {addr} connected.")
        clientName, pubkey = getNameAndKey(clientSocket)
        clients_pubkey[clientName] = pubkey
        clients_socket[clientName] = clientSocket
        # print("PUBLIC KEY:/n ", pubkey)
        # json_data = json.dumps(clients_pubkey)
        # issueDict(clients_socket, clients_pubkey, json_data)
        # print("o")
        issueDict(clients_socket, clients_pubkey)
        lock.release()
        # print("pi")
        connected = True
        while connected:
            # print("ki")
            request = clientSocket.recv(1024).decode("utf-8")
            # print(request)
            if request.upper() == "QUIT":
                # print("li")
                clientLeft(clientSocket,clientName,pubkey)
                print("QUITTING CONNECTION WITH "+clientName)
                break

            elif request.upper() == "INTERACT":
                lock.acquire()
                # print("1")
                namecli = clientSocket.recv(1024)
                # print(namecli)
                interactMsg = clientSocket.recv(1024)
                # print(interactMsg)
                broadcastInteract( clients_socket, namecli,interactMsg )
                # print("4")
                lock.release()

            elif request.upper() == "VIDEO":
                # header = "VIDEO".encode()
                # clientSocket.send(header)
                # clientSocket.send(encrypt_data(video,pubkey))
                # vidReq = clientSocket.recv(1024).decode("utf-8")
                # if vidReq in video:
                sendVideo(clientSocket,clientName,pubkey)

    except Exception as e:
        print(f"Error when hanlding client: {e}")
    finally:
        clientSocket.close()
        print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

def main():
    print("[STARTING] Server is starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(Addrs)
    server.listen()
    print(f"[LISTENING] Server is listening on {hostIP}:{PORT}")
    try:
        while True:
            # print("inM")
            conn, addr = server.accept()
            # print("inM2")
            # thread = threading.Thread(target=clientsHandler, args=(conn, addr))
            # print("inM3")
            # thread.start()
            _thread.start_new_thread(clientsHandler,(conn,addr))
            # print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()