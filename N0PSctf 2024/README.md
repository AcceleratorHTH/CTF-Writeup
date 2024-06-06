# N0PSctf 2024

## **N0PSCTF 2024**

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

### Crypto Rookie

#### Description:

Hey Rookie, decode this and I'll give you a cookie!

`STSABEAOE OEIEALGSETRHNCOI MMFITTAK`

The flag's format is `N0PS{DECODEDMESSAGE}`.

#### Solution:

Đưa vào một trang [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier), ta sẽ ra được đây là **Rail-fence Cipher.**

Đưa vào [tool](https://www.dcode.fr/rail-fence-cipher) để decode và mình ra được flag.

<figure><img src="../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

Flag: _N0PS{SOMETIMESAFLAGISBETTERTHANACOOKIE}_

### Broken OTP

#### Description:

i heard OTP it the most secure encryption algorithm ever

`sc nopsctf-broken-otp.chals.io`

#### Attachments:

_main.py_

```python
import random

secret = 'XXXXXXXXXXXXXXXXXXXX'

PINK = 118
RED = 101
YELLOW = 97
GREEN = 108
BLACK = __builtins__
PURPLE = dir
e = getattr(BLACK, bytes([RED, PINK, YELLOW, GREEN]).decode())
g = e(''.__dir__()[4].strip('_')[:7])
b = g(BLACK, PURPLE(BLACK)[92])
i = g(BLACK, PURPLE(BLACK)[120])
t = ['74696d65', '72616e646f6d', '5f5f696d706f72745f5f', '726f756e64', '73656564']
d = lambda x: b.fromhex(x).decode()
fb = g(i, PURPLE(i)[-6])
_i = lambda x: e(d(t[2]))(x)
s = lambda: g(BLACK,d(t[3]))(g(_i(d(t[0])), d(t[0]))()) + fb(secret.encode())
r = g(_i(d(t[1])), d(t[4]))

def kg(l):
    return bytes([random.randint(0,255) for i in range(l)])

def c(p):
    k = kg(len(p))
    return bytes([k[i] ^ p[i] for i in range(len(p))]).hex()

if __name__ == '__main__':
    r(s())
    print("Welcome to our encryption service.")
    choice = input("Choose between:\n1. Encrypt your message.\n2. Get the encrypted secret.\nEnter your choice: ")
    match choice:
        case "1":
            message = input("Please enter the message you wish to encrypt: ")
            print(f"Your encrypted message is: {c(message.encode())}")
        case "2":
            print(f"The secret is: {c(secret.encode())}")
        case _:
            print("Invalid option!")
```

_Dockerfile_

```docker
FROM ubuntu:latest

WORKDIR /app

RUN apt-get update && apt-get install ncat python3.12 -y

COPY ./src/main.py ./main.py

EXPOSE 1234

CMD ncat -l -p 1234 --sh-exec "python3.12 /app/main.py" --keep-open
```

#### Recon:

Sau khi thử decode `e` bằng tay, mình ra được hàm `eval()`. Có vẻ đây là một chương trình bị obfuscate. Các bạn có thể deobfuscate bằng cách chạy từng dòng code để xem output (nhớ sử dụng python 3.12 vì kết quả sẽ khác nhau với mỗi phiên bản python, đây là lí do ta có Dockerfile)

Tuy nhiên, mình sẽ sử dụng GPT để deobfuscate hộ mình:

<figure><img src="../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

Bỏ qua vấn đề về chính tả các thứ thì GPT làm mọi thứ khá tốt. Ở đây mình thấy được chương trình dạng như sau

```python
import random
import time

# Define the secret key
secret = 'YourSecretKeyHere'

# Helper function to convert hex to string
def hex_to_str(hex_str):
    return bytes.fromhex(hex_str).decode()

# Function to generate random bytes
def kg(length):
    return bytes([random.randint(0, 255) for _ in range(length)])

# Function to perform XOR encryption
def encrypt(message, key):
    return bytes([message[i] ^ key[i] for i in range(len(message))]).hex()

# Main execution flow
if __name__ == '__main__':
    # Generate the seed using the current time
    seed = round(time.time()) + int(secret.encode().hex(), 16)
    random.seed(seed)
    
    print("Welcome to our encryption service.")
    choice = input("Choose between:\n1. Encrypt your message.\n2. Get the encrypted secret.\nEnter your choice: ")
    
    match choice:
        case "1":
            message = input("Please enter the message you wish to encrypt: ")
            key = kg(len(message))
            encrypted_message = encrypt(message.encode(), key)
            print(f"Your encrypted message is: {encrypted_message}")
        case "2":
            key = kg(len(secret))
            encrypted_secret = encrypt(secret.encode(), key)
            print(f"The secret is: {encrypted_secret}")
        case _:
            print("Invalid option!")

```

Ở đây ta chỉ nhìn vào logic của chương trình (vì đây là code gen minh họa nên chắc sẽ không chạy được). Có thể thấy đây chỉ đơn giản là chương trình mã hóa bằng cách gen ra một keystream bytes `random.randint(0, 255)` và xor với message tùy ý (option 1) hoặc secret (option 2). Xem chừng có vẻ khá là secure cho tới khi mình thấy dòng này:

```python
seed = round(time.time()) + int(secret.encode().hex(), 16)
random.seed(seed)
```

Seed của hàm `random` sẽ được set bằng cách lấy time hiện tại của hệ thống **tính theo giây** + secret ở dạng số nguyên. Do secret là không đổi và time là tính theo giây, nếu mình có thể kết nối tới 2 lần trong cùng 1 giây, cả 2 lần đó đều sẽ có cùng 1 seed.

Khi đó, mình sẽ dùng option số 1 với 1 message dài và lấy ra keystream đó bằng cách xor plaintext với ciphertext thu được. Vì cùng 1 seed nên keystream này sẽ có đoạn từ \[0:len(secret)] trùng với keystream tạo ra ở option 2. Cuối cùng, ta chỉ cần xor ciphertext của secret với đoạn keystream này là sẽ ra được flag.

```python
import threading # To make sure I can connect 2 times in 1 second
from pwn import *

def connect1(output, index):
    conn = remote("nopsctf-broken-otp.chals.io", 443, ssl=True)
    conn.recvline()
    conn.recvline()
    conn.recvline()
    conn.recvline()
    conn.sendline(b'1')
    plaintext = b'A' * 19 # I found it so I change to make it more beautiful only
    conn.sendline(plaintext)
    ciphertext = conn.recvline().decode().strip()[92:]
    output[index] = xor(plaintext, bytes.fromhex(ciphertext)).hex()

def connect2(output, index):
    conn = remote("nopsctf-broken-otp.chals.io", 443, ssl=True)
    conn.recvline()
    conn.recvline()
    conn.recvline()
    conn.recvline()
    conn.sendline(b'2')
    flag_encrypted = conn.recvline().decode().strip()[34:]
    output[index] = flag_encrypted

output = [None, None]

thread1 = threading.Thread(target=connect1, args=(output, 0))
thread2 = threading.Thread(target=connect2, args=(output, 1))

thread1.start()
thread2.start()

thread1.join()
thread2.join()

key = bytes.fromhex(output[0])
flag_encrypted = bytes.fromhex(output[1])

flag = xor(key, flag_encrypted)
print("Flag:", flag)

```

> Thật ra có thể gửi `\x00` thay vì `A`, khi đó ciphertext trả về sẽ chính là key luôn.

Flag: _N0PS{0tP\_k3Y\_r3u53}_

### Side Channel

#### Description:

Your goal is to extract the key used for the encryption of the captured data.

All blocks have been encrypted in Electronic Codebook (ECB) mode.\
All data blocks are in hexadecimal, byte 0 first, byte 15 last. First column: 128 bits input block, second column: 128 bits encrypted block, third column: encryption time.\
The key length is 128 bits.\
The format of the flag is `N0PS{key}` where key is the 32 digits hexadecimal representation of the secret key you found, byte 0 first, byte 15 last, with everything in capital letters.

If the correct key was 0102030405060708090A0B0C0D0E0F the following command would output the first ciphertext bloc in ta.dat: `printf "$(sed -n 's/ .*//;s/\(..\)/\\x\1/gp;q' ta.dat)" | openssl enc -aes-128-ecb -nosalt -nopad -K 0102030405060708090A0B0C0D0E0F | od -v -A none -tx1`

> Hint 1: [https://en.wikipedia.org/wiki/Timing\_attack](https://en.wikipedia.org/wiki/Timing\_attack)
>
> Hint 2: [http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl?num=42\&den=16\&f=m\&p=36\&d=1\&y=1\&m=1](http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl?num=42\&den=16\&f=m\&p=36\&d=1\&y=1\&m=1)

#### Attachments:

{% file src="../.gitbook/assets/ta.dat" %}

{% file src="../.gitbook/assets/aes.c" %}

{% file src="../.gitbook/assets/aes.h" %}

#### Solution:

\<Not Yet>
