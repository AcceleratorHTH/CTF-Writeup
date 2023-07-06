import socket
from string import ascii_letters, digits
from random import choice
import threading
from _thread import *
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from math import gcd

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 2706        # Port to listen on (non-privileged ports are > 1023)

def generate_random_string(length):
    return "".join(choice(ascii_letters + digits) for _ in range(length))

def encrypt_flag(flag):
    flag = flag.encode() 
    key = "TRUNGPQ"

    res = []
    for i in range(len(flag)):
        res.append(flag[i] ^ ord(key[i % len(key)]))

    hex_flag = ''.join(format(c, '02x') for c in res)
    return hex_flag

def gen_params():
    while True:
        m = generate_random_string(16)
        p,q = getPrime(128), getPrime(128)
        n = p*q
        e = 65537
        phi = (p-1)*(q-1)
        if gcd(phi, e) == 1:
            d = inverse(e, phi)
            break
    return m,n,e,d

def threading(conn):
    m,n,e,d = gen_params()
    c = pow(bytes_to_long(m.encode()), e, n)

    msg_c = f'Chogath: {c}\n'.encode('utf-8')
    msg_d = f'Draven: {d}\n'.encode('utf-8')

    conn.sendall(msg_c)
    conn.sendall(msg_d)
    conn.sendall(b'Question: What did Malphite say?\n')
    conn.sendall(b'Enter your answer: ')
    try:
        answer = conn.recv(1024).decode().strip()
        if answer == m:
            conn.sendall(b'Nice! You got it right.\n')
            conn.sendall(b'Heres your reward: \n')
            with open("flag.txt") as f:
                reward = f.read().strip()
                flag = encrypt_flag(reward)
                conn.sendall(flag.encode('utf-8'))
        else:
            conn.sendall(b'Oops! Thats not the correct answer.\n')
            conn.sendall(b'Maybe next time?')  
    except UnicodeDecodeError:
        conn.sendall(b'Oops! Thats not the correct answer.\n')
        conn.sendall(b'Maybe next time?')  
    conn.close() 


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print(f'new connection: {addr}')
            start_new_thread(threading, (conn, ))
        s.close()