import json
import os
import traceback
import socket
import threading
import pickle
import hashlib
import secrets
import random
import base64

from TCP_AES import Encrypt_AES, Decrypt_AES
from tcp_by_size import send_with_size, recv_by_size
from AsyncMessages import AsyncMessages
from RSA import RSA_CLASS


users = {}
connected = []
AMessages = AsyncMessages()
all_to_die = False

def logtcp(direction, tid, byte_data):
    if direction == 'sent':
        print(f'{tid} S LOG: Sent     >>> {byte_data}')
    else:
        print(f'{tid} S LOG: Received <<< {byte_data}')

def load_users():
    global users
    try:
        with open('user.pkl', 'rb') as f:
            users = pickle.load(f)
    except Exception as e:
        print(f'Error loading users.pkl: {e}')
        users = {}

def save_users():
    try:
        with open('user.pkl', 'wb') as f:
            pickle.dump(users, f)
    except Exception as e:
        print(f'Error saving users.pkl: {e}')

def hash_password(password, salt):
    if salt == None:
        salt = secrets.token_hex(16)
    combined = password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return hashed, salt

def sign_up(username, password):
    load_users()
    if username in users:
        return 'SUP@Username already exists', False
    hashed_pass, salt = hash_password(password, None)
    users[username] = (hashed_pass, salt)
    save_users()
    return 'SUP@Success', True

def login(username, password, sock):
    try:
        global AMessages
        load_users()
        if username not in users:
            return "LOG@User not found", False
        if username in connected:
            return "LOG@User alrady in", False
        user_data = users[username]
        stored_hashed_pass = user_data[0]
        salt = user_data[1]
        hashed_input_pass, salt1 = hash_password(password, salt)
        if hashed_input_pass == stored_hashed_pass:
            AMessages.sock_by_user[username] = sock
            connected.append(username)
            return "LOG@Login Successful", True
        return "LOG@Login Unsuccessful", False
    except Exception as err:
        print(err)

def hash_key(key):
    key = hashlib.sha256(str(key).encode()).hexdigest()
    key = key[:16]
    return key

def dp_key_get(G, P, x):
    b = random.randint(0, 100)
    y = pow(G, b, P)
    key = pow(x, b, P)
    key = hash_key(key)
    print(f'key= {key}')
    return y, key

def rsa_key(public_key,rsa_obj):
    key = os.urandom(16)
    print(key)
    other_key = public_key
    rsa_obj.set_other_public(other_key)
    key_enc = rsa_obj.encrypt_RSA(key)
    return key_enc,key

def protocol_build_reply(request, sock, user_name1, finish, key,rsa_obj):
    global connected
    global AMessages
    try:
        reply = ''
        request_code = request[:3].decode()
        if request_code != 'LGN' and request_code != 'SNU':
            request = request.decode("utf8").split('@')

        if request_code == 'LGN':
            request = request.split(b'@')
            iv = base64.b64decode(request[3])
            user_name = Decrypt_AES(key, iv, base64.b64decode(request[1])).decode()
            password1 = Decrypt_AES(key, iv, base64.b64decode(request[2])).decode()
            reply, login1 = login(user_name, password1, sock)
            return reply, login1, user_name, key

        if request_code == 'SGU':
            reply, suc = sign_up(request[1], request[2])
            return reply, None, None, key

        elif request_code == 'SNU':
            request = request.split(b'@')
            iv = base64.b64decode(request[3])
            msg = request[1]
            user_to = Decrypt_AES(key, iv, base64.b64decode(request[2])).decode()
            iv_encoded = base64.b64encode(iv)
            AMessages.put_msg_by_user(b'SNU@' + user_name1.encode() + b'@' + msg + b'@' + iv_encoded, user_to)
            reply = b'SNU@Message sent to@' + request[2] + b'@' + iv_encoded

        elif request_code == 'SNA':
            AMessages.put_msg_to_all('SNA@' + user_name1 + '@' + request[1])
            reply = 'SNM@Message sent to ALL '

        elif request_code == 'BYE':
            connected.remove(user_name1)
            finish = True
            return '', None

        elif request_code == 'GNS':
            msg, key = dp_key_get(int(request[1]), int(request[2]), int(request[3]))
            reply = f'FKS@{msg}'
            return reply, None, None, key

        elif request_code == 'GSR':
            public_key_b64 = request[1]
            public_key = base64.b64decode(public_key_b64.encode())
            msg, key = rsa_key(public_key, rsa_obj)
            msg_64=base64.b64encode(msg).decode()
            reply = f'FRS@{msg_64}'
            return reply, None, None, key

        elif request_code == 'GEN':
            enc_user = Decrypt_AES(key, base64.b64decode(request[5]), base64.b64decode(request[4])).decode()
            if enc_user in connected:
                AMessages.put_msg_by_user('SKB@' + f'{request[1]}@{request[2]}@{request[3]}@{user_name1}', enc_user)
                reply = f'SNK@key requst sent to {enc_user}'
            else:
                reply = f'SNK@user not connected {enc_user}'

        elif request_code == 'GNR':
            public_key1=request[1]
            user_enc = request[2]
            iv = request[3]
            enc_user = Decrypt_AES(key, base64.b64decode(request[3]), base64.b64decode(request[2])).decode()
            if enc_user in connected:
                AMessages.put_msg_by_user(f'SKR@{request[1]}@{user_name1}', enc_user)
                reply = f'SNK@key requst sent to {enc_user}'
            else:
                reply = f'SNK@user not connected {enc_user}'

        elif request_code == 'KYR':
            key1 = request[1]
            user_enc = request[2]
            iv = request[3]
            enc_user = Decrypt_AES(key, base64.b64decode(request[3]), base64.b64decode(request[2])).decode()
            if enc_user in connected:
                AMessages.put_msg_by_user('FYR@' + f'{request[1]}@{user_name1}', enc_user)
                reply = f'SNK@key requst sent to {enc_user}'
            else:
                reply = f'SNK@user not connected {enc_user}'


        elif request_code == 'KEY':
            if request[2] in connected:
                AMessages.put_msg_by_user(f'FKY@{request[1]}@' + user_name1, request[2])
                reply = f'SNK@key requst sent to {request[2]}'
            else:
                reply = f'SNK@user not connected {request[2]}'

        elif request_code == 'CON':
            conected_users = json.dumps(connected)
            reply = 'COS@' + conected_users
            return reply, None, None, key

        return reply, None
    except Exception as err:
        print(err)
        return 'ERR@' + str(err), None

def handle_client(sock, tid, addr):
    global all_to_die
    global AMessages
    global connected
    sucseec = False
    user_name1 = ''
    key = None
    rsa_obj=RSA_CLASS()

    AMessages.add_new_socket(sock)
    finish = False
    print(f'New Client number {tid} from {addr}')
    while True:
        try:
            byte_data = recv_by_size(sock)
            if byte_data == b'':
                print('Seems client disconnected')
                break

            try:
                to_send, sucseec, user_name1, key = protocol_build_reply(byte_data, sock, user_name1, finish, key,rsa_obj)
            except Exception as err:
                print(to_send)
                print(err)
                to_send = ''
                finish = False

            if to_send != '':
                send_with_size(sock, to_send.encode())

            if sucseec:
                AMessages.put_msg_to_all(('SNA@' + user_name1 + '@logged in'))
                to_send = AMessages.get_async_messages_to_send(sock)
                break

        except Exception as err:
            print(f'General Error: {err} - exiting client loop')
            print(traceback.format_exc())
            break

    sock.settimeout(0.1)
    while not finish:
        if all_to_die:
            print('Will close due to main server issue')
            break

        try:
            byte_data = recv_by_size(sock)
            if byte_data == b'':
                print('Seems client disconnected')
                break

            try:
                to_send, som = protocol_build_reply(byte_data, sock, user_name1, finish, key,rsa_obj)
            except Exception as err:
                print(err)
                if user_name1 in connected:
                    connected.remove(user_name1)
                to_send = ''
                finish = True

            if to_send != '':
                if not isinstance(to_send, bytes):
                    send_with_size(sock, to_send.encode())
                else:
                    send_with_size(sock, to_send)

        except socket.timeout:
            if sucseec:
                to_send = AMessages.get_async_messages_to_send(sock)
                for m in to_send:
                    send_with_size(sock, m)
            continue

        except Exception as err:
            print(f'General Error: {err} - exiting client loop')
            print(traceback.format_exc())
            break
    AMessages.put_msg_to_all(('SNA@' + user_name1 + '@disconnected'))
    print(f'Client {tid} Exit')
    sock.close()

def main():
    global all_to_die
    global AMessages

    AMessages = AsyncMessages()

    threads = []
    srv_sock = socket.socket()
    srv_sock.bind(('0.0.0.0', 3001))
    srv_sock.listen(20)

    async_messages = AsyncMessages()

    i = 0
    while True:
        cli_sock, addr = srv_sock.accept()
        async_messages.add_new_socket(cli_sock)
        t = threading.Thread(target=handle_client, args=(cli_sock, str(i), addr))
        t.start()
        i += 1
        threads.append(t)

    srv_sock.close()
    print('Bye ..')

if __name__ == '__main__':
    main()
