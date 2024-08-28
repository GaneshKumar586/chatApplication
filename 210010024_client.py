import socket
import math
import json
import numpy as np
import random
import time
from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode,b64encode
import cv2
# import threading
import _thread
# lock = threading.Lock()
lock = _thread.allocate_lock()
clientDict = {} 
pwd = b'secret'


def encrypt_data(data, pubkey):
    try:
        # print("z")
        rsa_public_key = RSA.importKey(pubkey)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_text = rsa_public_key.encrypt(data.encode())
        # print("x")
        return b64encode(encrypted_text)

    except Exception as e:
        print("Error encrypting data:", e)
        return None
def decrypt_msg(data, privkey):
    try:
        rsa_private_key = RSA.importKey(privkey)
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        
        ciphertext = b''
        while True:
            ciphertext += data
            # Try to decrypt with current data
            try:
                decrypted_text = rsa_private_key.decrypt(b64decode(ciphertext))
                return decrypted_text.decode()
            except (ValueError, TypeError):
                # data = client.recv(1024)
                print("error decrypt cipher")
    except Exception as e:
        print("Error decrypting data:", e)
        return None

def decrypt_data(data, privkey):
    try:
        # print("r")
        rsa_private_key = RSA.importKey(privkey)
        # print("q")
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        # print("w")
        decrypted_text = rsa_private_key.decrypt(b64decode(data))
        # print("e")
        return decrypted_text.decode()        
    except Exception as e:
        print("Error decrypting data:", e)
        return None

def HandleserverMsgs(client):

    try:
        while True:
            serverReq = client.recv(1024).decode('utf-8')
            print(serverReq)
            if(serverReq.upper() == 'QUIT' ):
                break
            if(serverReq == 'INTERACT' ):
                try:
                    namecli = decrypt_data(client.recv(1024), privkey)
                    # print(namecli)
                    msg_rec = decrypt_data(client.recv(1024), privkey)
                    print("\n-------------------------------------------------------------------------------------------------------")
                    print(namecli," SENT YOU A MESSAGE >> ", msg_rec)
                    print("-------------------------------------------------------------------------------------------------------")

                except Exception as er:
                    continue
            elif(serverReq == 'TABLE'):
                while True:
                    # print("l")
                    name = client.recv(1024).decode()
                    print(name)
                    if name == "Complete":
                        # print("oh")
                        break
                    key = client.recv(1024)
                    # print(name + " client's key added")
                    # print(key)
                    clientDict[name] = key 
            elif(serverReq == 'VIDEO'):
                # print("entered video recv")
                vidList = []
                while True:
                    vidname = client.recv(1024).decode()
                    print(vidname)
                    if vidname == 'END':
                        # print("Ending")
                        break
                    # print("l")
                    vidList.append(vidname)
                # print("la")
                print("CHOOSE THE VIDEO FROM THE LIST: [")
                for x in vidList:
                    print(x+ ", ")
                print("]")
                print("----------------------------------------------------------")
                pop = input("ENTER THE VIDEO NAME: ")
                print("----------------------------------------------------------")
                client.send(pop.encode())
                scrapevid = client.recv(4)
                vidSize = int.from_bytes(scrapevid, byteorder ='big')
                print("size of video:" )
                print(vidSize)
                index = 0
                while index < vidSize-1:
                    index += 1
                    print(index)
                    vid_Frame_byteSize = client.recv(4)
                    if not vid_Frame_byteSize:
                        break
                    frame_Size = int.from_bytes(vid_Frame_byteSize, byteorder='big')
                    frame_Data = b''
                    while len(frame_Data) < frame_Size:
                        chunk = client.recv(min(frame_Size - len(frame_Data), 4096))
                        if not chunk:
                            break
                        frame_Data += chunk
                    if len(frame_Data) == frame_Size:
                        frame = cv2.imdecode(np.frombuffer(frame_Data, dtype=np.uint8), cv2.IMREAD_COLOR)
                        cv2.imshow('Received Frame', frame)
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            break
                cv2.destroyAllWindows()
                lock.release()
            # else:
                # print("NOTA")
    except Exception as e:
        print(f"Error last: {e}")
    finally:
        client.close()
        print("Connection to server closed")




client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_ip = "127.0.0.1"  # replace with the server's IP address
# print("1")
server_port = 8888  # replace with the server's port number
# establish connection with server
# print("2")
client.connect((server_ip, server_port))
# print("3")
# clientDict = {}
try:

    # (pubkey, privkey) = RSA.newkeys(512,accurate=False)
    key = RSA.generate(2048)
    privkey = key.export_key('PEM')
    pubkey = key.publickey().exportKey('PEM')
    # print("31")
    # clientName = "ferrari"
    # client.sendall(clientName.encode("utf-8")[:1024])
    # print("23")
    nameReq = client.recv(1024).decode("utf-8")
    # print("33")
    print("REQUEST RECEIVED FROM SERVER: ", nameReq)
    clientName = input()
    client.sendall(clientName.encode())
    
    keyReq = client.recv(1024).decode("utf-8")
    print("REQUEST RECEIVED FROM SERVER: ", keyReq)

    client.send(pubkey)
    # print("sdfghjkl")
    # thread = threading.Thread(target=HandleserverMsgs, args=(client,))
    _thread.start_new_thread(HandleserverMsgs,(client,))

    # thread.start()

    while True:
        # Create threads for each task
        # message_thread = threading.Thread(target=check_messages, args=(conn, addr))
        # table_thread = threading.Thread(target=receive_table, args=(conn, addr))
        # video_thread = threading.Thread(target=process_video_frames, args=(conn, addr))

        # message_thread.start()
        # table_thread.start()
        # video_thread.start()
        lock.acquire()
        lock.release()
        print("--------------------------------------------------------------------------------------------------------")
        choice = input("ENTER 'Q' TO CLOSE THE CONNECTION   | ENTER 'I' TO INTERACT WITH A CLIENT   | ENTER 'V' TO WATCH VIDEO | ENTER 'P' TO PASS ")
        print("--------------------------------------------------------------------------------------------------------")
        if(choice.upper() == 'P'):
            time.sleep(0.1)
            continue
        elif(choice.upper() == 'Q'):
            print("QUITTING CLIENT SERVER CONNECTION !!")
            client.sendall(("QUIT").encode())
            print("THREAD-1's ")
            break
        elif(choice.upper() == 'I'):
            # while True:
            try:
                client.sendall(("INTERACT").encode())
                print("CHOOSE THE CLIENT YOU WANT TO CHAT WITH FROM GIVEN LIST:")
                print("CLIENTS LISt: [\n")
                for x in clientDict:
                    print(x+", ")
                print("\n]\n")
                print("--------------------------------------------------------------------------------------------------------")
                friend = input("ENTER CLIENT NAME :\t")
                chatMsg = input("ENTER THE MESSAGE :\t")
                print("--------------------------------------------------------------------------------------------------------")
                # print(friend )
                client.send( encrypt_data( clientName, clientDict[friend] ) )
                # print("g ")
                client.send( encrypt_data( chatMsg, clientDict[friend] ) )
                # print("h")
            except Exception as e:
                print(f"ERROR: {e}")
        elif(choice.upper() == 'V'):
            # client.sendall(("VIDEO").encode())
            lock.acquire()
            # print("1")
            client.send("VIDEO".encode())
            # listVideos = client.recv()
            # listVideos = decrypt_data(listVideos,privkey)
            # x = input("CHOOSE TEH VIDEO FROM THE LIST", listVideos)
            # if x in listVideos:
            #     client.send(x.encode())
            #     resVideo = client.recv()
            #     decVideo =  decrypt_data(resVideo,privkey)
            #     cv2.imshow(decVideo)
            # else:
            #     print("REQUESTED VIDEO NOT AVAILABLE AT SERVER..")

        else:
            continue
except Exception as e:
    print(f"ERROR: {e}")
finally:
    # thread.join()
    client.close()
    print("CONNECTION TO SERVER CLOSED")

