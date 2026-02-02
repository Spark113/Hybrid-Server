import hashlib
import json
import os
from errno import ECHILD
from random import random

from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QGridLayout, QWidget, QLineEdit, \
    QRadioButton, QTextBrowser, QListWidget, QListWidgetItem
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import QObject, pyqtSignal
import socket

from numpy.lib.format import magic
from urllib3 import request
from RSA import RSA_CLASS
from tcp_by_size import send_with_size, recv_by_size
from TCP_AES import Encrypt_AES, Decrypt_AES
import threading
import math
import random
import hashlib
import base64


class MyWindow(QObject):
    update_text_signal = pyqtSignal(str)
    update_err_signal = pyqtSignal(str)
    update_exit = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.rsa_object= RSA_CLASS()
        self.debug = True
        self.disconect = False
        self.conected = False
        self.users_connected = []
        self.login_suc = 'no'
        self.see_pas = False
        self.sock = socket.socket()
        self.listener = threading.Thread(target=self.listen)
        self.keys = {}
        self.key_finish = False
        self.key_server = None
        self.B = 0
        self.A = 0
        self.G = 0
        self.P = 0
        self.dp=True
        self.rsa=False

        self.app = QApplication([])
        self.window = QMainWindow()
        self.window.setFixedSize(600, 400)
        self.window.setWindowTitle('gui cli')

        self.window.setStyleSheet("background-color: lightblue;")

        self.layout = QGridLayout()

        self.server_ip = QLineEdit('127.0.0.1')
        self.server_ip.setPlaceholderText('server ip')
        self.server_ip.setFixedSize(100, 50)
        self.server_ip.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.server_ip, 0, 0)

        self.user_name = QLineEdit('')
        self.user_name.setPlaceholderText('user name')
        self.user_name.setFixedSize(100, 50)
        self.user_name.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.user_name, 0, 1)
        self.user_name.hide()

        self.dp_keys_bool = QRadioButton('dp')
        self.dp_keys_bool.setFixedSize(70, 30)
        self.dp_keys_bool.clicked.connect(self.set_dp_key)
        self.layout.addWidget(self.dp_keys_bool, 1, 3)
        self.dp_keys_bool.show()

        self.rsa_keys_bool = QRadioButton('rsa')
        self.rsa_keys_bool.setFixedSize(70, 30)
        self.rsa_keys_bool.clicked.connect(self.set_rsa_key)
        self.layout.addWidget(self.rsa_keys_bool, 1, 4)
        self.rsa_keys_bool.show()

        self.paswword = QLineEdit('')
        self.paswword.setPlaceholderText('paswword')
        self.paswword.setFixedSize(100, 50)
        self.paswword.setEchoMode(QLineEdit.EchoMode.Password)
        self.paswword.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.paswword, 0, 2)
        self.paswword.hide()

        self.login_botten = QPushButton('login')
        self.login_botten.setFixedSize(100, 50)
        self.login_botten.clicked.connect(self.login)
        self.login_botten.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.login_botten, 2, 1)
        self.login_botten.hide()

        self.sign_up_bot = QPushButton('sign up')
        self.sign_up_bot.setFixedSize(100, 50)
        self.sign_up_bot.clicked.connect(self.sign_up)
        self.sign_up_bot.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.sign_up_bot, 3, 1)
        self.sign_up_bot.hide()

        self.connect_srv = QPushButton('connect')
        self.connect_srv.setFixedSize(100, 50)
        self.connect_srv.clicked.connect(self.connect_to_srv)
        self.connect_srv.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.connect_srv, 2, 0)

        self.close_all = QPushButton('exit')
        self.close_all.setFixedSize(100, 50)
        self.close_all.clicked.connect(self.exit)
        self.close_all.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.close_all, 2, 2)

        self.show_pas = QRadioButton('show pas')
        self.show_pas.setFixedSize(70, 30)
        self.show_pas.clicked.connect(self.pas_visibale)
        self.layout.addWidget(self.show_pas, 0, 3)
        self.show_pas.hide()

        self.listUsers = QListWidget()
        self.listUsers.setFixedSize(100, 300)
        self.listUsers.setStyleSheet("background-color: gray;")
        self.listUsers.itemClicked.connect(self.user_clicked)
        self.layout.addWidget(self.listUsers, 0, 0)
        self.listUsers.hide()

        self.back_list_botten = QPushButton('back to list')
        self.back_list_botten.setFixedSize(100, 50)
        self.back_list_botten.clicked.connect(self.main_ui)
        self.back_list_botten.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.back_list_botten, 3, 2)
        self.back_list_botten.hide()



        self.user_to_send = QLabel('')
        #self.user_to_send.setPlaceholderText('user_to_send')
        self.user_to_send.setFixedSize(200, 50)
        self.user_to_send.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.user_to_send, 0, 0)
        self.user_to_send.hide()

        self.text_to_send = QLineEdit('')
        self.text_to_send.setPlaceholderText('text_to_send')
        self.text_to_send.setFixedSize(100, 50)
        self.text_to_send.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.text_to_send, 1, 2)
        self.text_to_send.hide()

        self.send = QPushButton('send to user')
        self.send.setFixedSize(100, 50)
        self.send.clicked.connect(self.send_msg)
        self.send.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.send, 2, 1)
        self.send.hide()

        self.send_to_all = QPushButton('send to all')
        self.send_to_all.setFixedSize(100, 50)
        self.send_to_all.clicked.connect(self.send_all)
        self.send_to_all.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.send_to_all, 2, 0)
        self.send_to_all.hide()

        self.text_box = QTextBrowser()
        self.text_box.setPlaceholderText('text_box')
        self.text_box.setFixedSize(150, 100)
        self.text_box.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.text_box, 1, 3)
        self.text_box.hide()

        self.err_box = QTextBrowser()
        self.err_box.setPlaceholderText('err_box')
        self.err_box.setFixedSize(150, 100)
        self.err_box.setStyleSheet("background-color: gray;")
        self.layout.addWidget(self.err_box, 2, 3)

        #all object on the screen
        # all ui things
        # self.err_box
        # self.text_box
        # self.user_to_send
        # self.show_pas
        # self.close_all
        # self.connect_srv
        # self.sign_up_bot
        # self.paswword
        # self.login_botten
        # self.user_name
        # self.server_ip
        # self.text_to_send
        # self.send
        # self.send_to_all
        # self.listUsers
        # self.back_list_botten
        # self.rsa_keys_bool
        # self.dp_keys_bool

        self.center = QWidget()
        self.center.setLayout(self.layout)
        self.window.setCentralWidget(self.center)

        self.update_text_signal.connect(self.update_text)
        self.update_err_signal.connect(self.update_err)
        self.update_exit.connect(self.exit)

        self.window.show()
        self.app.exec()

    def login_ui(self):
        self.err_box.show()
        self.text_box.hide()
        self.user_to_send.hide()
        self.show_pas.show()
        self.close_all.show()
        self.connect_srv.hide()
        self.sign_up_bot.show()
        self.paswword.show()
        self.login_botten.show()
        self.user_name.show()
        self.server_ip.hide()
        self.text_to_send.hide()
        self.send.hide()
        self.send_to_all.hide()
        self.back_list_botten.hide()
        self.dp_keys_bool.show()
        self.rsa_keys_bool.show()

    def main_ui(self):
        self.err_box.show()
        self.text_box.show()
        self.user_to_send.hide()
        self.show_pas.hide()
        self.close_all.show()
        self.connect_srv.hide()
        self.sign_up_bot.hide()
        self.paswword.hide()
        self.login_botten.hide()
        self.user_name.hide()
        self.server_ip.hide()
        self.text_to_send.hide()
        self.send.hide()
        self.send_to_all.hide()
        self.listUsers.show()
        self.back_list_botten.hide()
        self.dp_keys_bool.hide()
        self.rsa_keys_bool.hide()

    def user_clicked(self,item):
        clicked_user = item.text()
        self.user_to_send.setText(f'you are sending to: {clicked_user}')

        self.err_box.show()
        self.text_box.show()
        self.user_to_send.show()
        self.show_pas.hide()
        self.close_all.show()
        self.connect_srv.hide()
        self.sign_up_bot.hide()
        self.paswword.hide()
        self.login_botten.hide()
        self.user_name.hide()
        self.server_ip.hide()
        self.text_to_send.show()
        self.send.show()
        self.send_to_all.show()
        self.listUsers.hide()
        self.back_list_botten.show()
        self.dp_keys_bool.hide()
        self.rsa_keys_bool.hide()

    def set_dp_key(self):
        self.dp=True
        self.rsa=False
        self.err_box.setText('key set to dp')

    def set_rsa_key(self):
        self.rsa=True
        self.dp=False
        self.err_box.setText('key set to rsa')

    def dp_keys_gen(self):
        rnd = random.randint(10, 100)
        P = self.get_prime_num(rnd)
        if self.debug:
            print('--------------------------------------------------')
            print("The value of P:", P)
            print('--------------------------------------------------')

        rnd1 = random.randint(10, 100)
        G = self.get_primitive_root(P)
        if self.debug:
            print('--------------------------------------------------')
            print("The value of G:", G)
            print('--------------------------------------------------')
        self.A = random.randint(10, 100)
        if self.debug:
            print('--------------------------------------------------')
            print("The value of A:", self.A)
            print('--------------------------------------------------')
        X = pow(G, self.A, P)
        return G, P, X

    def get_prime_num(self, cnt):
        num = 1
        num_gen = 0
        while True:
            num += 1
            if (self.is_prime_num(num)):
                num_gen += 1
                if cnt == num_gen:
                    return num

    def is_prime_num(self, num):
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                return False
        return True

    def get_primitive_root(self, p):
        if not self.is_prime_num(p):
            return None

        required_set = set(range(1, p))  # {1, 2, ..., p-1}
        for g in range(2, p):
            generated_set = {pow(g, exp, p) for exp in range(1, p)}
            if generated_set == required_set:
                return g
        return None

    def final_key(self, Y, user):
        key = pow(Y, self.A, self.P)
        key = self.hash_key(key)
        if self.debug:
            print('--------------------------------------------------')
            print(f'key= {key}')
            print(len(key))
            print('--------------------------------------------------')
        self.keys[user] = key
        self.key_finish = True

    def final_key_rsa(self,key,user):
        key=base64.b64decode(key)
        key=self.rsa_object.decrypt_RSA(key)
        if self.debug:
            print('--------------------------------------------------')
            print(f'key= {key}')
            print(len(key))
            print('--------------------------------------------------')
        self.keys[user] = key
        self.key_finish = True

    def hash_key(self, key):
        key = hashlib.sha256(str(key).encode()).hexdigest()
        key = key[:16]
        return key

    def dp_key_get(self, G, P, x, user):
        b = random.randint(0, 100)
        y = pow(G, b, P)
        key = pow(x, b, P)
        key = self.hash_key(key)
        if self.debug:
            print('--------------------------------------------------')
            print(f'key= {key}')
            print(len(key))
            print('--------------------------------------------------')
        self.keys[user] = key
        self.key_finish = True
        return y

    def final_key_server(self, Y):
        key = pow(Y, self.A, self.P)
        key = self.hash_key(key)
        if self.debug:
            print('--------------------------------------------------')
            print(f'key= {key}')
            print(len(key))
            print('--------------------------------------------------')
        self.key_server = key

    def final_key_rsa_server(self,key):
        key = self.rsa_object.decrypt_RSA(key)
        if self.debug:
            print('--------------------------------------------------')
            print(f'key= {key}')
            print(len(key))
            print('--------------------------------------------------')
        self.key_server = key

    def update_text(self, text):
        self.text_box.setText(text)

    def update_err(self, text):
        self.err_box.setText(text)
        if text == 'Login successful':
            self.main_ui()


    def key_dp(self,user_to_not_en):
        self.G, self.P, self.X = self.dp_keys_gen()
        iv = os.urandom(16)
        enc_user = Encrypt_AES(user_to_not_en, self.key_server, iv)
        enc_user_b64 = base64.b64encode(enc_user).decode()
        iv_b64 = base64.b64encode(iv).decode()

        msg = f'GEN@{self.G}@{self.P}@{self.X}@{enc_user_b64}@{iv_b64}'
        send_with_size(self.sock, msg.encode())
        if self.debug:
            print('--------------------------------------------------')
            print(msg)
            print('--------------------------------------------------')


    def key_rsa(self,user_to_not_en):
        public_key=self.rsa_object.public_key
        public_key_b64=base64.b64encode(public_key).decode()

        iv = os.urandom(16)
        enc_user = Encrypt_AES(user_to_not_en, self.key_server, iv)
        enc_user_b64 = base64.b64encode(enc_user).decode()
        iv_b64 = base64.b64encode(iv).decode()

        msg = f'GNR@{public_key_b64}@{enc_user_b64}@{iv_b64}'
        if self.debug:
            print('--------------------------------------------------')
            print(msg)
            print(public_key_b64)
            print(enc_user_b64)
            print(iv_b64)
            print('--------------------------------------------------')
        send_with_size(self.sock, msg.encode())
        if self.debug:
            print('--------------------------------------------------')
            print(msg)
            print('--------------------------------------------------')

    def send_msg(self):
        try:
            user_to = self.user_to_send.text().split(':')[1]
            user_to=user_to[1:]
            user_to_not_en = user_to
            if self.debug:
                print('--------------------------------------------------')
                print(str(self.users_connected))
                print('--------------------------------------------------')
            if user_to in self.users_connected:

                if (user_to not in self.keys) or (self.keys[user_to]==None):
                    if self.dp:
                        self.key_dp(user_to_not_en)
                    elif self.rsa:
                        self.key_rsa(user_to_not_en)
                    self.key_finish = False
                    while not self.key_finish:
                        continue
                    self.key_finish = False
                    if not user_to in self.users_connected:
                        self.err_box.setText('user disconected')
                        return

                iv = os.urandom(16)
                msg = self.text_to_send.text()
                msg = Encrypt_AES(msg, self.keys[user_to], iv)
                msg = base64.b64encode(msg)
                user_to = Encrypt_AES(user_to, self.key_server, iv)
                user_to = base64.b64encode(user_to)
                iv = base64.b64encode(iv)

                if self.debug:
                    print('--------------------------------------------------')
                    print('user to: ',user_to_not_en)
                    print('key: ',self.keys[user_to_not_en])
                    print('--------------------------------------------------')
                send_str = b'SNU@' + msg + b'@' + user_to + b'@' + iv
                send_with_size(self.sock, send_str)
                self.err_box.setText(f'sent {self.text_to_send.text()} to {user_to}')
            else:
                self.err_box.setText('user not connected')
        except Exception as err:
            if self.debug:
                print('--------------------------------------------------')
                print(err)
                print('--------------------------------------------------')
            self.err_box.setText(err)

    def send_all(self):
        try:
            msg = self.text_to_send.text()
            send_str = f'SNA@{msg}'
            send_with_size(self.sock, send_str.encode())
            self.err_box.setText(f'sent {msg} to all')
        except Exception as err:
            self.err_box.setText(err)

    def exit(self):
        try:
            self.disconect = True
            self.err_box.setText('shoting down')
            if self.conected:
                self.listener.join()
                send_with_size(self.sock, b'BYE')
                self.sock.close()
            self.app.quit()
        except Exception as err:
            if self.debug:
                print('--------------------------------------------------')
                print(err)
                print('--------------------------------------------------')

    def login(self):
        try:
            if self.conected:
                if self.key_server == None:
                    if self.dp:
                        self.G, self.P, self.X = self.dp_keys_gen()
                        msg = f'GNS@{self.G}@{self.P}@{self.X}'
                        send_with_size(self.sock, msg.encode())
                    elif self.rsa:
                        public_key = self.rsa_object.public_key
                        public_key_b64 = base64.b64encode(public_key).decode()
                        if self.debug:
                            print('--------------------------------------------------')
                            print('public_key=',public_key)
                            print('--------------------------------------------------')
                        msg = f'GSR@{public_key_b64}'
                        send_with_size(self.sock, msg.encode())

                while self.key_server == None:
                    continue
                if self.debug:
                    print('--------------------------------------------------')
                    print('srv key= ' + str(self.key_server))
                    print('--------------------------------------------------')
                iv = os.urandom(16)
                user_name1 = Encrypt_AES(f'{self.user_name.text()}', self.key_server, iv)
                user_name = base64.b64encode(user_name1)
                password = Encrypt_AES(f'{self.paswword.text()}', self.key_server, iv)
                password = base64.b64encode(password)
                iv = base64.b64encode(iv)
                login_str = b'LGN@' + user_name + b'@' + password + b'@' + iv
                if self.debug:
                    print('--------------------------------------------------')
                    print('user_name:', end='')
                    print(user_name)
                    print('password:', end='')
                    print(password)
                    print('iv:', end='')
                    print(iv)
                    print(login_str)
                    print('--------------------------------------------------')
                send_with_size(self.sock, login_str)
                self.err_box.setText('try to login')
            else:
                self.err_box.setText('need to conect')
        except Exception as err:
            self.err_box.setText(err)

    def sign_up(self):
        try:
            if self.conected:
                sigh_up_str = f'SGU@{self.user_name.text()}@{self.paswword.text()}'
                send_with_size(self.sock, sigh_up_str.encode())
                self.err_box.setText('try to sign up')
            else:
                self.err_box.setText('need to conect')
        except Exception as err:
            if self.debug:
                print('--------------------------------------------------')
                print(err)
                print('--------------------------------------------------')

    def pas_visibale(self):
        if self.see_pas:
            self.paswword.setEchoMode(QLineEdit.EchoMode.Password)
            self.see_pas = False
        else:
            self.paswword.setEchoMode(QLineEdit.EchoMode.Normal)
            self.see_pas = True

    def connect_to_srv(self):
        try:
            self.sock.connect((self.server_ip.text(), port))
            self.sock.settimeout(1)
            self.conected = True
            self.err_box.setText('conected')
            self.listener.start()
            self.login_ui()
            user_to = self.user_to_send.text()
            user_to_not_en = user_to
            send_with_size(self.sock, f'CON@{user_to}')
        except:
            self.conected = False
            self.err_box.setText('could not connect')

    def listen(self):
        while True:
            try:
                if self.disconect:
                    break
                data = recv_by_size(self.sock)
                if data == b'':
                    if self.debug:
                        print('--------------------------------------------------')
                        print('data=nothing')
                        print('--------------------------------------------------')
                    self.sock.close()
                    self.update_text_signal.emit('Server disconnected')
                    break
                else:
                    if self.debug:
                        print('--------------------------------------------------')
                        print(data)
                        print('--------------------------------------------------')
                    action = data[:3].decode()
                    if action != 'SNU':
                        data = data[4:].decode()
                        fields = data.split('@')

                    if action == 'SKB':
                        G, P, X, user = int(fields[0]), int(fields[1]), int(fields[2]), fields[3]
                        if self.debug:
                            print('--------------------------------------------------')
                            print(F'G= {G},P= {P},X={X}')
                            print('--------------------------------------------------')
                        y = self.dp_key_get(G, P, X, user)
                        print('got here')
                        msg = f'KEY@{y}@{user}'
                        send_with_size(self.sock, msg.encode())

                    if action == 'SKR':
                        user_to=fields[1]
                        iv = os.urandom(16)
                        enc_user = Encrypt_AES(user_to, self.key_server, iv)
                        enc_user_b64 = base64.b64encode(enc_user).decode()
                        iv_b64 = base64.b64encode(iv).decode()

                        key=os.urandom(16)
                        self.keys[user_to]=key
                        other_key=fields[0]
                        other_key=base64.b64decode(other_key)
                        self.rsa_object.set_other_public(other_key)
                        key_enc = self.rsa_object.encrypt_RSA(key)
                        key_enc_b64 = base64.b64encode(key_enc).decode()
                        msg = f'KYR@{key_enc_b64}@{enc_user_b64}@{iv_b64}'
                        send_with_size(self.sock,msg.encode())


                    if action=='FRS':
                        try:
                            rsa_encrypted_key = base64.b64decode(fields[0])
                            self.final_key_rsa_server(rsa_encrypted_key)
                        except Exception as err:
                            self.update_err_signal.emit(str(err))
                            if self.debug:
                                print('--------------------------------------------------')
                                print(err)
                                print('--------------------------------------------------')


                    if action == 'FYR':
                        try:
                            self.final_key_rsa(fields[0], fields[1])
                        except Exception as err:
                            self.update_err_signal.emit(str(err))
                            if self.debug:
                                print('--------------------------------------------------')
                                print(err)
                                print('--------------------------------------------------')


                    if action == 'FKY':
                        try:
                            self.final_key(int(fields[0]), fields[1])
                        except Exception as err:
                            self.update_err_signal.emit(str(err))
                            if self.debug:
                                print('--------------------------------------------------')
                                print(err)
                                print('--------------------------------------------------')

                    if action == 'FKS':
                        try:
                            self.final_key_server(int(fields[0]))
                        except Exception as err:
                            self.update_err_signal.emit(str(err))
                            if self.debug:
                                print('--------------------------------------------------')
                                print(err)
                                print('--------------------------------------------------')

                    if action == 'COS':
                        self.users_connected = json.loads(fields[0])
                        print('con=' + str(self.users_connected))
                        self.listUsers.clear()
                        for user in self.users_connected:
                            self.listUsers.addItem(QListWidgetItem(user))

                    if action == 'LOG':
                        if fields[0] == 'Login Successful':
                            self.login_suc = True
                            self.update_err_signal.emit('Login successful')
                        elif fields[0] == 'User not found':
                            self.update_err_signal.emit('User not found')
                        elif fields[0]=='User alrady in':
                            self.update_err_signal.emit('User alrady connected')
                        else:
                            self.update_err_signal.emit('Login failed')
                    if action == 'SUP':
                        if fields[0] == 'Success':
                            self.update_err_signal.emit('sign up successful')
                        elif fields[0] == 'Username already exists':
                            self.update_err_signal.emit('Username already exists')
                        else:
                            self.update_err_signal.emit('sign up failed')
                    if action == 'SNU':
                        data = data[4:]
                        fields = data.split(b'@')
                        if b'Message sent to' in fields[0]:
                            iv = base64.b64decode(fields[2])
                            user_to = base64.b64decode(fields[1])
                            user_to = Decrypt_AES(self.key_server, iv, user_to)
                            self.update_err_signal.emit('message sent to: ' + user_to.decode())
                        else:
                            iv = fields[2]
                            iv = base64.b64decode(iv)
                            msg = fields[1]
                            user_recv = fields[0].decode()
                            msg = base64.b64decode(msg)
                            if user_recv not in self.keys or self.keys[user_recv] is None:
                                self.update_err_signal.emit(f"no key to decrypt msg from {user_recv}")
                                if self.debug:
                                    print('--------------------------------------------------')
                                    print('keys',self.keys)
                                    print('--------------------------------------------------')
                                continue
                            msg = Decrypt_AES(self.keys[user_recv], iv, msg)
                            self.update_text_signal.emit(f'{user_recv} sent: you {msg.decode()}')

                    if action == 'SNK':
                        if fields[0] == 'user not connected':
                            self.key_finish = True
                            self.keys[fields[1]]=None
                            self.users_connected.remove(fields[1])
                        self.update_err_signal.emit(fields[0])

                    if action == 'SNA':
                        if fields[1] == 'logged in':
                            self.update_err_signal.emit(f'{fields[0]} has logged in')
                            self.users_connected.append(fields[0])
                            if self.debug:
                                print('--------------------------------------------------')
                                print('con lgn=' + str(self.users_connected))
                                print('--------------------------------------------------')
                            self.listUsers.clear()
                            for user in self.users_connected:
                                self.listUsers.addItem(QListWidgetItem(user))

                        elif fields[1] == 'disconnected':
                            self.update_err_signal.emit(f'{fields[0]} has disconnected')
                            if fields[0] in self.users_connected:
                                self.users_connected.remove(fields[0])
                                self.keys[fields[0]] = None
                                self.listUsers.clear()
                                for user in self.users_connected:
                                    self.listUsers.addItem(QListWidgetItem(user))
                            if self.debug:
                                print('--------------------------------------------------')
                                print('con dis=' + str(self.users_connected))
                                print('--------------------------------------------------')

                        else:
                            self.update_text_signal.emit(f'{fields[0]} told all {fields[1]}')


            except socket.timeout:
                continue

            except Exception as err:
                        self.update_err_signal.emit(str(err))
                        if self.debug:
                            print('--------------------------------------------------')
                            print(err)
                            print('--------------------------------------------------')
                        self.update_exit.emit()



if __name__ == '__main__':
    port = 3001
    try:
        a = MyWindow()
    except Exception as err:
        print(err)
