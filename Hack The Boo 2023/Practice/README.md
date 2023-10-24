# **Hack The Boo 2023 - Practice**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving
### Hexoding
In order to be a successful ghost in the modern society, a ghost must fear nothing. Caspersky always loved scaring people, but he could not reach his maximum potential because he was fearful of cryptography. This is why he wants to join the Applied Cryptography Academy of Ghosts. To gain admission, the professors give you a challenge that you need to solve. They try to spook you with weird functions, but don't be scared; the challenge can be solved even without the source code. Can you help Caspersky pass the entrance exams?

Attachments: *source.py*
```python3
from secret import FLAG

HEX_CHARS = '0123456789abcdef'
B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def to_hex(data):
    data = int.from_bytes(data, 'big')
    encoded = ''
    while data:
        i = data % 16
        encoded = HEX_CHARS[i] + encoded
        data >>= 4
    return '0' * (len(encoded) % 2) + encoded


def to_base64(data):
    padding_length = 0

    if len(data) % 3 != 0:
        padding_length = (len(data) + 3 - len(data) % 3) - len(data)

    data += b'\x00' * padding_length
    bits = ''.join([bin(c)[2:].zfill(8) for c in data])
    blocks = [bits[i:i+6] for i in range(0, len(bits), 6)]

    encoded = ''
    for block in blocks:
        encoded += B64_CHARS[int(block, 2)]

    return encoded[:-padding_length] + '=' * padding_length


def main():
    first_half = FLAG[:len(FLAG)//2]
    second_half = FLAG[len(FLAG)//2:]

    hex_encoded = to_hex(first_half)
    base64_encoded = to_base64(second_half)

    with open('output.txt', 'w') as f:
        f.write(f'{hex_encoded}\n{base64_encoded}')

main()
```
*output.txt*
```
4854427b6b6e3077316e675f6830775f74305f3164336e743166795f336e633064316e675f736368336d33735f31735f6372756331346c5f6630725f615f
Y3J5cHQwZ3I0cGgzcl9fXzRsczBfZDBfbjB0X2MwbmZ1czNfZW5jMGQxbmdfdzF0aF9lbmNyeXA1MTBuIX0=
```

Đọc lướt qua thì output chỉ đơn giản là 1 dòng hex và 1 dòng base64 là 2 mảnh của flag. Đáp lên CyberChef là ra flag thoai.

Flag: *HTB{kn0w1ng_h0w_t0_1d3nt1fy_3nc0d1ng_sch3m3s_1s_cruc14l_f0r_a_crypt0gr4ph3r___4ls0_d0_n0t_c0nfus3_enc0d1ng_w1th_encryp510n!}*

### SPG
After successfully joining the academy, there is a process where you have to log in to eclass in order to access notes in each class and get the current updates for the ongoing prank labs. When you attempt to log in, though, your browser crashes, and all your files get encrypted. This is yet another prank for the newcomers. The only thing provided is the password generator script. Can you crack it, unlock your files, and log in to the spooky platform?

Attachments: *source.py*
```python3
from hashlib import sha256
import string, random
from secret import MASTER_KEY, FLAG
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

ALPHABET = string.ascii_letters + string.digits + '~!@#$%^&*'

def generate_password():
    master_key = int.from_bytes(MASTER_KEY, 'little')
    password = ''

    while master_key:
        bit = master_key & 1
        if bit:
            password += random.choice(ALPHABET[:len(ALPHABET)//2])
        else:
            password += random.choice(ALPHABET[len(ALPHABET)//2:])
        master_key >>= 1

    return password

def main():
    password = generate_password()
    encryption_key = sha256(MASTER_KEY).digest()
    cipher = AES.new(encryption_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(FLAG, 16))

    with open('output.txt', 'w') as f:
        f.write(f'Your Password : {password}\nEncrypted Flag : {b64encode(ciphertext).decode()}')

main()

```
*output.txt*
```
Your Password : gBv#3%DXMV*7oCN2M71Zfe0QY^dS3ji7DgHxx2bNRCSoRPlVRRX*bwLO5eM&0AIOa&#$@u
Encrypted Flag : tnP+MdNjHF1aMJVV/ciAYqQutsU8LyxVkJtVEf0J0T5j8Eu68AxcsKwd0NjY9CE+Be9e9FwSVF2xbK1GP53WSAaJuQaX/NC02D+v7S/yizQ=
```
Mấu chốt của bài này là tìm ra `MASTER_KEY` làm key cho vào AES_CBC để giải ra flag.

Ban đầu, `MASTER_KEY` được chuyển thành 1 số nguyên `master_key` theo Little-Endian. Password được tạo ra bằng cách chia `ALPHABET` ra làm 2 nửa. Nếu bit cuối cùng của `master_key` = 1 thì thêm vào password kí tự ngẫu nhiên ở nửa trái của `ALPHABET`, nếu là 0 thì ngược lại. Ta hoàn toàn có thể khôi phục từng bit của `master_key` bằng cách so sánh từng kí tự của password xem nó thuộc nửa nào của `ALPHABET`. Nếu nửa bên trái thì bit cuối cùng của `master_key` bằng 1, ngược lại thì là 0. 

Sau khi ra được `master_key`, ta chuyển nó sang dạng bytes và đảo ngược lại (vì là Little-Endian) sẽ ra được `MASTER_KEY` ban đầu.

Dưới đây là code thực thi:
```python3
from hashlib import sha256
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from base64 import b64decode

ALPHABET = string.ascii_letters + string.digits + '~!@#$%^&*'

left = ALPHABET[:len(ALPHABET)//2]
right = ALPHABET[len(ALPHABET)//2:]

password = "gBv#3%DXMV*7oCN2M71Zfe0QY^dS3ji7DgHxx2bNRCSoRPlVRRX*bwLO5eM&0AIOa&#$@u"
ciphertext = "tnP+MdNjHF1aMJVV/ciAYqQutsU8LyxVkJtVEf0J0T5j8Eu68AxcsKwd0NjY9CE+Be9e9FwSVF2xbK1GP53WSAaJuQaX/NC02D+v7S/yizQ="

ciphertext = b64decode(ciphertext)

key = []

for char in password:
    if(char in left):
        key.append(1)
    else:
        key.append(0)

master_key = key[::-1] # Đảo ngược

master_key = ''.join(map(str,master_key))
master_key = long_to_bytes(int(master_key, 2))[::-1] #Đảo ngược bytes do dùng Little Endian

encryption_key = sha256(master_key).digest()
cipher = AES.new(encryption_key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), 16)

print(plaintext)
```

Flag: *HTB{00ps___n0t_th4t_h4rd_t0_r3c0v3r_th3_m4st3r_k3y_0f_my_p4ssw0rd_g3n3r4t0r}*

### yence
During the pranking labs, the ghosts create a spooky encryption algorithm, and at midnight, they go outside to scare people by encrypting every device they own. To assess the situation at the end of the night, the professors have developed a spooky meter to measure how much people were spooked by the ransomware. The goal is to create irreversible ransomware that inflicts maximum damage. However, having interacted with humans over the past months, you've grown fond of them and don't want to harm them. You even managed to befriend a human who fell victim to such an attack. Can you help your friend unlock his files?

Attachments: *source.py*
```python3
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import os

with open('messages.txt') as f:
    MSG = eval(f.read())


class AdvancedEncryption:
    def __init__(self, block_size):
        self.KEYS = self.generate_encryption_keys()
        self.CTRs = [Counter.new(block_size, initial_value=i) for i in range(len(MSG))]

    def generate_encryption_keys(self):
        keys = [[b'\x00'] * 16] * len(MSG)

        for i in range(len(keys)):
            for j in range(16):
                keys[i][j] = os.urandom(1)

        return keys
    
    def encrypt(self, i, msg):
        key = b''.join(self.KEYS[i])
        ctr = self.CTRs[i]
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(pad(msg.encode(), 16))


def main():
    AE = AdvancedEncryption(128)
    with open('output.txt', 'w') as f:
        for i in range(len(MSG)):
            ct = AE.encrypt(i, MSG[i])
            f.write(ct.hex() + '\n')


if __name__ == '__main__':
    main()
```
*messages.txt*
```
[
    'Hm, I have heard that AES-CTR is a secure encryption mode!',
    'I think it is not possible to break it, right?',
    'HTB{?????????????????????????????????????????????}',
    'This is why I used it to encrypt my secret information above, hehe.',
]
```
*output.txt*
```
983641d252da35432cdd8aaa490b24bc5ac0583f5881adbe95c5b16d4309878a37c0d38d523f2b45390294e7ed7fe276a1ac966868a34e1284f6215389342b35
3394443645cf87dbaf9cd2506209809663818391442f37553047d1fde12df974b0a4922621ba0d5693be403dfb0d2f31
5ff5b1855a683504035184fbbd52e236a09ac86879ba10428de65d66d0065f412ed765fb2593aef817a6c59ed373ee8192ab659a30b06723ee9d363e00e2c7f7
81ad907568a7525696bf5e75c61258407fca36cd25dbe9c845f2cc95d555e9c1cbbb12b44ddb0a5f85e71859608aa68b271836560e3ecabde06ca9dddd35c9dd027436cf1facf536e9b7a51d5d09bbf5
```
Ở đây, tác giả sử dụng AES_CTR cho từng message một (mỗi lần encrypt là một lần gọi AES_CTR mới). Key của mỗi cái cũng là 16-bytes random, gần như không thể brute-force nổi. Có thể nói rằng thử thách này không thể khai thác bằng các lỗ hổng CTR thông thường. Vậy thử đọc kĩ code xem có điều gì vô tình tạo ra điểm yếu không?

Và mình tìm ra có điều bất thường ở đoạn code này:
```python3
self.CTRs = [Counter.new(block_size, initial_value=i) for i in range(len(MSG))]
```
`initial_value` =`i`, và `i` được chạy trong `range(len(MSG))`, ở đây là từ 0 tới 3. Điều này tạo ra nguy hiểm gì?

Để hiểu phần sau mình sẽ để lại sơ đồ AES_CTR ở đây:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/064c75f6-c501-456c-a156-220310916477)


Ở đây mình có tính được độ dài của 4 output lần lượt là 64, 48, 64 và 80-bytes. Dựa trên code trên, counter của từng cái sẽ đếm theo thứ tự như sau:
```
Msg1: 0, 1, 2, 3
Msg2: 1, 2, 3
Msg3: 2, 3, 4, 5
Msg4: 3, 4, 5, 6, 7
```
Ứng với 1 giá trị của `iv`, `block cypher encryption` sẽ luôn không đổi. Thứ ta cần tìm là message thứ 3 chứa flag, 3  message còn lại đã biết rõ. Vì vậy, ta có thể tính các block encrypt có iv = 2,3,4,5 từ các message đã biết để tìm ra flag. Để ví dụ:
- `block encryption iv = 2` = `block thứ 3 của msg1` XOR `block thứ 3 của cipher1`
- Khi đó, `block đầu tiên của msg3` =  `block encryption iv = 2` XOR `block đầu của cipher3`
- Tương tự với các block còn lại

Code thực thi:
```python3
from pwn import *
from Crypto.Util.Padding import pad, unpad

with open('./crypto_yesnce/messages.txt') as f:
    plaintext = eval(f.read())

plaintext = [i.encode() for i in plaintext]
cipher = ['983641d252da35432cdd8aaa490b24bc5ac0583f5881adbe95c5b16d4309878a37c0d38d523f2b45390294e7ed7fe276a1ac966868a34e1284f6215389342b35','3394443645cf87dbaf9cd2506209809663818391442f37553047d1fde12df974b0a4922621ba0d5693be403dfb0d2f31','5ff5b1855a683504035184fbbd52e236a09ac86879ba10428de65d66d0065f412ed765fb2593aef817a6c59ed373ee8192ab659a30b06723ee9d363e00e2c7f7','81ad907568a7525696bf5e75c61258407fca36cd25dbe9c845f2cc95d555e9c1cbbb12b44ddb0a5f85e71859608aa68b271836560e3ecabde06ca9dddd35c9dd027436cf1facf536e9b7a51d5d09bbf5']
ciphertext = [bytes.fromhex(i) for i in cipher]

def split_bytes_into_blocks(data):
    block_size = 16
    result = []
    for i in data:
        block = []
        for j in range(0, len(i), block_size):
            block.append(i[j:j + block_size])
        result.append(block)
    return result

plain_block = split_bytes_into_blocks(plaintext)
cipher_block = split_bytes_into_blocks(ciphertext)

counter1 = xor(plain_block[0][2], cipher_block[0][2])
flag1 = xor(cipher_block[2][0], counter1)

counter2 = xor(pad(plain_block[1][2], 16), cipher_block[1][2])
flag2 = xor(cipher_block[2][1], counter2)

counter3 = xor(plain_block[3][1], cipher_block[3][1])
flag3 = xor(cipher_block[2][2], counter3)

counter4 = xor(plain_block[3][2], cipher_block[3][2])
flag4 = xor(cipher_block[2][3], counter4)

flag = flag1 + flag2 + flag3 + flag4
print(unpad(flag, 16))
```

Flag: *HTB{m4k3_sur3_y0u_1n1t14l1z3_4rr4ys_th3_r1ght_w4y}*

**© 2023,Pham Quoc Trung. All rights reserved.**
