# Cyber Apocalypse 2024 Hacker Royale

## CYBER APOCALYPSE 2024 HACKER ROYALE

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

### Dynastic

#### Description:

You find yourself trapped inside a sealed gas chamber, and suddenly, the air is pierced by the sound of a distorted voice played through a pre-recorded tape. Through this eerie transmission, you discover that within the next 15 minutes, this very chamber will be inundated with lethal hydrogen cyanide. As the tape’s message concludes, a sudden mechanical whirring fills the chamber, followed by the ominous ticking of a clock. You realise that each beat is one step closer to death. Darkness envelops you, your right hand restrained by handcuffs, and the exit door is locked. Your situation deteriorates as you realise that both the door and the handcuffs demand the same passcode to unlock. Panic is a luxury you cannot afford; swift action is imperative. As you explore your surroundings, your trembling fingers encounter a torch. Instantly, upon flipping the switch, the chamber is bathed in a dim glow, unveiling cryptic letters etched into the walls and a disturbing image of a Roman emperor drawn in blood. Decrypting the letters will provide you the key required to unlock the locks. Use the torch wisely as its battery is almost drained out!

#### Attachments:

_source.py_

```python
from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))
```

_output.txt_

```
Make sure you wrap the decrypted text with the HTB flag format :-]
DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
```

#### Solution:

Cơ chế mã hóa của bài này khá đơn giản. Với mỗi kí tự là chữ cái trong flag, ta sẽ thực hiện lần lượt 2 việc:

* Tính ra giá trị `chi` bằng cách lấy giá trị ascii của chữ cái đó trừ đi 0x41 (65)
* Lấy ra giá trị char của `chi + i` bằng cách chia lấy dư cho 26 và cộng thêm 0x41, với `i` là index của chữ cái đó trong flag
* Các chữ cái lấy được sẽ tạo ra ciphertext.

<figure><img src="../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

Sau một hồi phân tích dựa trên bảng ASCII trên, mình nhận ra chỉ cần sửa đoạn `from_identity_map(chi + i)` thành `from_identity_map(chi - i)` là có thể lấy được flag ban đầu. Dưới đây là script giải mã:

```python
c = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
m = ''

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def decrypt(c):
    m = ''
    for i in range(len(c)):
        ch = c[i]
        if not ch.isalpha():
            dm = ch
        else:
            chi = to_identity_map(ch)
            dm = from_identity_map(chi - i)
        m += dm
    return m

print(decrypt(c))
```

Flag: _HTB{DID\_YOU\_KNOW\_ABOUT\_THE\_TRITHEMIUS\_CIPHER?!\_IT\_IS\_SIMILAR\_TO\_CAESAR\_CIPHER}_

### Makeshift

#### Description:

Weak and starved, you struggle to plod on. Food is a commodity at this stage, but you can’t lose your alertness - to do so would spell death. You realise that to survive you will need a weapon, both to kill and to hunt, but the field is bare of stones. As you drop your body to the floor, something sharp sticks out of the undergrowth and into your thigh. As you grab a hold and pull it out, you realise it’s a long stick; not the finest of weapons, but once sharpened could be the difference between dying of hunger and dying with honour in combat.

#### Attachments:

_source.py_

```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)
```

_output.txt_

```
!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB
```

#### Solution:

Bài này thì đầu tiên flag sẽ bị reverse, sau đó với mỗi cụm 3 ký tự của flag, ký tự đầu tiên sẽ bị đẩy xuống cuối. Vậy thì để giải, ta chỉ cần đẩy ký tự cuối của mỗi cụm 3 ký tự về đầu tiên và đảo ngược flag cuối cùng thu được.

```python
flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
ori_flag = ''

for i in range(0, len(flag), 3):
    ori_flag += flag[i+2]
    ori_flag += flag[i]
    ori_flag += flag[i+1]

print(ori_flag[::-1])
```

Flag: _HTB{4\_b3tTeR\_w3apOn\_i5\_n3edeD!?!}_

### Primary Knowledge

#### Description:

Surrounded by an untamed forest and the serene waters of the Primus river, your sole objective is surviving for 24 hours. Yet, survival is far from guaranteed as the area is full of Rattlesnakes, Spiders and Alligators and the weather fluctuates unpredictably, shifting from scorching heat to torrential downpours with each passing hour. Threat is compounded by the existence of a virtual circle which shrinks every minute that passes. Anything caught beyond its bounds, is consumed by flames, leaving only ashes in its wake. As the time sleeps away, you need to prioritise your actions secure your surviving tools. Every decision becomes a matter of life and death. Will you focus on securing a shelter to sleep, protect yourself against the dangers of the wilderness, or seek out means of navigating the Primus’ waters?

#### Attachments:

_source.py_

```python
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')
```

_output.txt_

```
n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215
```

#### Solution:

Đây là một bài về RSA đã biết sẵn `n`, `e` và `c`. Ở đây có thể thấy `n` là một số nguyên tố, áp dụng kiến thức về hàm phi Euler ta có thể dễ dàng tính ra `phi = n - 1`, từ đó tính ra `d` và lấy được flag.

```python
from Crypto.Util.number import *

n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215

phi = n - 1

d = inverse(e, phi)

print(long_to_bytes(pow(c, d, n)).decode())
```

Flag: _HTB{0h\_d4mn\_4ny7h1ng\_r41s3d\_t0\_0\_1s\_1!!!}_

### Iced TEA

#### Description:

Locked within a cabin crafted entirely from ice, you're enveloped in a chilling silence. Your eyes land upon an old notebook, its pages adorned with thousands of cryptic mathematical symbols. Tasked with deciphering these enigmatic glyphs to secure your escape, you set to work, your fingers tracing each intricate curve and line with determination. As you delve deeper into the mysterious symbols, you notice that patterns appear in several pages and a glimmer of hope begins to emerge. Time is flying and the temperature is dropping, will you make it before you become one with the cabin?

#### Attachments:

_source.py_

```python
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)



if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```

_output.txt:_

```
Key : 850c1413787c389e0b34437a6828a1b2
Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843
```

#### Solution:

Đây là một bài về **Tiny Encryption Algorithm (**[**https://en.wikipedia.org/wiki/Tiny\_Encryption\_Algorithm**](https://en.wikipedia.org/wiki/Tiny\_Encryption\_Algorithm)**)**. Có 2 mode là ECB và CBC, và nó sẽ được chọn dựa trên lúc khai báo object. Nhìn vào hàm main, ta thấy chỉ có giá trị `KEY` được truyền vào nên mode của bài này là ECB.

Đầu tiên, ta sẽ nhìn vào hàm `encrypt_block`:

```python
def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)
```

Có thể thấy, với mỗi block dài 8 bytes của flag, ta sẽ tiến hành mã hóa lần lượt như sau:

* Chia block thành 2 blocks 4 bytes `m0` và `m1`. Chuyển dữ liệu của 2 block này từ bytes thành long.
* Gán KEY vào biến `K` và khởi tạo mặt nạ `msk = (1 << (BLOCK_SIZE//2)) - 1`. Ở đây `BLOCK_SIZE = 64`, ta có:
  * 1 << 64 // 2 = 0b100000000000000000000000000000000 (33-bits)
  * 0b100000000000000000000000000000000 - 1 = 0b11111111111111111111111111111111 (32-bits) hay 0xFFFFFFFF
  * Mặt nạ này có tác dụng đảm bảo các block con sẽ có độ dài là 4 bytes ở đoạn sau
* `self.DELTA` là một hằng số, thường được chọn để đảm bảo việc phân phối đồng đều các giá trị trong quá trình mã hóa
* Quá trình mã hóa diễn ra qua 32 vòng lặp. Trong mỗi vòng lặp, giá trị của `m0` và `m1` được cập nhật dựa trên công thức tính có sử dụng phép cộng, phép XOR, và các phép dịch bit. Các phép toán này kết hợp giữa `m0` và `m1` với các khóa con (`K[0]`, `K[1]`, `K[2]`, `K[3]`) và giá trị đếm `s`, được tăng dần sau mỗi vòng lặp bằng cách cộng với `self.DELTA`. Mỗi lần cập nhật `m0` và `m1`, chúng được giới hạn bởi `msk` để đảm bảo kết quả nằm trong phạm vi kích thước khối.
* Gộp 2 giá trị thu được sau cùng của `m0` và `m1` với nhau. Sử dụng mặt nạ để đảm bảo kích thước là 64-bits. Kết quả trả về được chuyển lại về dạng bytes

Dựa vào phân tích, mình có thể tiến hành giải mã như sau:

* Chuyển cipher từ bytes về dạng long
* Tách số thu được ra làm 2 để lấy được `m1` và `m0`. Các giá trị mặt nạ và `s` vẫn giữ nguyên
* Quá trình giải mã diễn ra qua 32 vòng lặp. Ta chỉ đơn giản là làm ngược lại các bước của code mã hóa.
* Ghép 2 giá trị thu được của `m0` và `m1` lại với nhau về chuyển lại về dạng bytes.

Dưới đây là code giải mã block

```python
def decrypt_block(self, msg):
        m = b2l(msg)
        m0 = m >> (self.BLOCK_SIZE // 2)
        m1 = m & ((1 << (self.BLOCK_SIZE // 2)) - 1)
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        
        s = self.DELTA * 32
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        decrypted_msg = l2b(m0) + l2b(m1)
        return decrypted_msg[:self.BLOCK_SIZE//8] 
```

Về hàm `encrypt` thì chỉ đơn giản là chia message thành từng block 8 bytes và tiến hành mã hóa. Mode ECB và CBC có thể hình dung giống sơ đồ, với khối mã hóa chính là hàm `encrypt_block`

<figure><img src="../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

Cách giải mã:

<figure><img src="../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

Code giải mã:

```python
def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]

        msg = b''
        if self.mode == Mode.ECB:
            for block in blocks:
                msg += self.decrypt_block(block)
        elif self.mode == Mode.CBC:
            prev_ct = self.IV
            for block in blocks:
                decrypted_block = self.decrypt_block(block)
                decrypted_block = self._xor(decrypted_block, prev_ct)
                msg += decrypted_block
                prev_ct = block
        return msg
```

Dài dòng nãy giờ rồi, bài này đã cho ta biết `KEY` và cipher `c`. Mode sử dụng là ECB. Đơn giản là giải mã thôi

Final Script:

```python
import os
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)
    
    def decrypt_block(self, msg):
        m = b2l(msg)
        m0 = m >> (self.BLOCK_SIZE // 2)
        m1 = m & ((1 << (self.BLOCK_SIZE // 2)) - 1)
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        
        s = self.DELTA * 32
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        decrypted_msg = l2b(m0) + l2b(m1)
        return decrypted_msg[:self.BLOCK_SIZE//8] 
    
    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]

        msg = b''
        if self.mode == Mode.ECB:
            for block in blocks:
                msg += self.decrypt_block(block)
        elif self.mode == Mode.CBC:
            prev_ct = self.IV
            for block in blocks:
                decrypted_block = self.decrypt_block(block)
                decrypted_block = self._xor(decrypted_block, prev_ct)
                msg += decrypted_block
                prev_ct = block
        return msg


if __name__ == '__main__':
    KEY = bytes.fromhex('850c1413787c389e0b34437a6828a1b2')
    c = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"
    c = bytes.fromhex(c)
    cipher = Cipher(KEY)
    print(cipher.decrypt(c).decode())
```

Flag: _HTB{th1s\_1s\_th3\_t1ny\_3ncryp710n\_4lg0r1thm\_\_\_\_\_y0u\_m1ght\_h4v3\_4lr34dy\_s7umbl3d\_up0n\_1t\_1f\_y0u\_d0\_r3v3rs1ng}_

### Tsayaki

#### Description:

You find yourself in the middle of a deadly ancient maze. The maze sprawls before you, its secrets veiled in shadows, its gates locked tight against intruders. With thousands of keys shimmering under the harsh light, you steel yourself for the daunting challenge ahead. Each chamber of the maze presents a new puzzle to unravel, each gate a barrier to overcome. Armed with determination and resolve, you set forth into the labyrinth's depths, knowing that your survival hinges on unlocking the path forward by finding the proper key. With each new chamber you enter, you are greeted with a cup of tea—a brief respite from the perilous journey that lies ahead. But the tea is not the only gift bestowed upon you in these chambers. With each cup, you receive a hint that will guide you on how to move on. NOTE: 'tea.py' can be found in the challenge 'Iced Tea'

#### Attachments:

_source.py_

```python
from tea import Cipher as TEA
from secret import IV, FLAG
import os

ROUNDS = 10

def show_menu():
    print("""
============================================================================================
|| I made this decryption oracle in which I let users choose their own decryption keys.   ||
|| I think that it's secure as the tea cipher doesn't produce collisions (?) ... Right?   ||
|| If you manage to prove me wrong 10 times, you get a special gift.                      ||
============================================================================================
""")

def run():
    show_menu()

    server_message = os.urandom(20)
    print(f'Here is my special message: {server_message.hex()}')
    
    used_keys = []
    ciphertexts = []
    for i in range(ROUNDS):
        print(f'Round {i+1}/10')
        try:
            ct = bytes.fromhex(input('Enter your target ciphertext (in hex) : '))
            assert ct not in ciphertexts

            for j in range(4):
                key = bytes.fromhex(input(f'[{i+1}/{j+1}] Enter your encryption key (in hex) : '))
                assert len(key) == 16 and key not in used_keys
                used_keys.append(key)
                cipher = TEA(key, IV)
                enc = cipher.encrypt(server_message)
                if enc != ct:
                    print(f'Hmm ... close enough, but {enc.hex()} does not look like {ct.hex()} at all! Bye...')
                    exit()
        except:
            print('Nope.')
            exit()
            
        ciphertexts.append(ct)

    print(f'Wait, really? {FLAG}')


if __name__ == '__main__':
    run()
```

#### Solution:

Bài này import class TEA chính là class Cipher trong bài trước. Dựa vào dòng `cipher = TEA(key, IV)`, có thể thấy lần này mode được sử dụng là CBC.&#x20;

Về chương trình mà đoạn code này thực hiện, nó sẽ như sau:

* Server sẽ cung cấp cho chúng ta một message dạng hex
* Ta được yêu cầu gửi lên ciphertext và key của chúng ta tạo từ message trên. Nếu ciphertext của server cũng giống với ciphertext của ta thì sẽ là hợp lệ. Cái khó ở bước này là ta bị yêu cầu nhập 4 keys cho 1 message sao cho nó phải trả về cùng 1 ciphertext. Các keys không được trùng nhau.
* Lặp lại như thế 10 lần (các ciphertext cũng không được giống nhau), ta sẽ thu được flag

Trước hết, để có thể tạo ra ciphertext đúng thì ta phải tìm ra được IV. Nhìn vào code chương trình, có thể thấy với ciphertext và key đúng định dạng, nếu ciphertext không trùng với ciphertext của hệ thống thì ta sẽ có được ciphertext đúng.

```python
print(f'Hmm ... close enough, but {enc.hex()} does not look like {ct.hex()} at all! Bye...')
```

Từ đây, ta đã có plaintext, ciphertext tương ứng và đã biết thuật toán của khối mã hóa. Hãy nhìn vào sơ đồ mã hóa

<figure><img src="../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

Với 3 dữ kiện trên, ta có thể tính ra `IV = D(ct1) XOR pt1`, với ct1 là block đầu của ciphertext, pt1 là block đầu của plaintext. `IV` được import từ `secret`, nên giá trị này sẽ không đổi (và mình cũng đã test)

