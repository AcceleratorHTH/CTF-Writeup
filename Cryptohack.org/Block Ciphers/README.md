# **Cryptohack.org**

# **BLOCK CIPHERS WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### MODES OF OPERATION STARTER
The previous set of challenges showed how AES performs a keyed permutation on a block of data. In practice, we need to encrypt messages much longer than a single block. A mode of operation describes how to use a cipher like AES on longer messages.

All modes have serious weaknesses when used incorrectly. The challenges in this category take you to a different section of the website where you can interact with APIs and exploit those weaknesses. Get yourself acquainted with the interface and use it to take your next flag!

*source.py*
```python3
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/block_cipher_starter/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/block_cipher_starter/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

# ciphertext = 24e49b0a571db106b3392b0dc7b422b6d284081583603de51865f289806d855a
```
Encrypt => Decrypt => To_bytes

Flag: *crypto{bl0ck_c1ph3r5_4r3_f457_!}*

### PASSWORDS AS KEYS
It is essential that keys in symmetric-key algorithms are random bytes, instead of passwords or other predictable data. The random bytes should be generated using a cryptographically-secure pseudorandom number generator (CSPRNG). If the keys are predictable in any way, then the security level of the cipher is reduced and it may be possible for an attacker who gets access to the ciphertext to decrypt it.

Just because a key looks like it is formed of random bytes, does not mean that it necessarily is. In this case the key has been derived from a simple password using a hashing function, which makes the ciphertext crackable.

For this challenge you may script your HTTP requests to the endpoints, or alternatively attack the ciphertext offline. Good luck!

*source.py*
```python3
from Crypto.Cipher import AES
import hashlib
import random


# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]
keyword = random.choice(words)

KEY = hashlib.md5(keyword.encode()).digest()
FLAG = ?


@chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

# ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
```
Ở đây, key được lấy từ một file words khá dài và được lấy random. Vì vậy, mình sẽ thử với tất cả key trong đó luôn
```python3
from Crypto.Cipher import AES
import hashlib

ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

with open("words") as f:
    words = [w.strip() for w in f.readlines()]
for keyword in words:
    KEY = hashlib.md5(keyword.encode()).digest()

    def decrypt(ciphertext):
        ciphertext = bytes.fromhex(ciphertext)

        cipher = AES.new(KEY, AES.MODE_ECB)
        try:
            decrypted = cipher.decrypt(ciphertext)
        except ValueError as e:
            return {"error": str(e)}

        return decrypted.hex()
    flag = bytes.fromhex(decrypt(ciphertext))
    if(b'crypto{' in flag):
        print(flag)
```

Flag: *crypto{k3y5__r__n07__p455w0rdz?}*

### ECB CBC WTF
Here you can encrypt in CBC but only decrypt in ECB. That shouldn't be a weakness because they're different modes... right?

*source.py*
```python3
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

# ciphertext = "8433579e09ad33fa760c8f16a3a26d0ee043bcd3f8e5c1044d65564567624def0cb27dd49ed4688d202e94c3972b39f6"
```

Flag được mã hóa bằng AES_CBC, tuy nhiên giải mã lại là AES_ECB. Nghe có vẻ khá chuối.

Ở đây, mình để ý *ciphertext = iv.hex() + encrypted.hex()*, vì vậy 32 kí tự hex đầu chính là iv. Dựa vào iv đó, mình sẽ giải mã CBC với iv và phương thức decrypt là ECB. Dưới đây là code thực hiện:
```python3
from Crypto.Cipher import AES
import requests
from pwn import xor

ciphertext = "8433579e09ad33fa760c8f16a3a26d0ee043bcd3f8e5c1044d65564567624def0cb27dd49ed4688d202e94c3972b39f6"

iv = bytes.fromhex(ciphertext[0:32])

def decrypt(block):
	url = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/"
	url += block.hex() + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["plaintext"])

block1 = bytes.fromhex(ciphertext[32:64])
block2 = bytes.fromhex(ciphertext[64:96])

plain1 = xor(decrypt(block1), iv)
plain2 = xor(decrypt(block2), block1)

print(plain1 + plain2)
```
Flag: *crypto{3cb_5uck5_4v01d_17_!!!!!}*

### ECB Oracle
ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?

*source.py*
```python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}

```

Bài này thì đơn giản chỉ là ECB Oracle. Đấm thoi
```python3
from Crypto.Cipher import AES
import requests
from tqdm import tqdm

flag = 'crypto{'

def encrypt(string):
	url = "https://aes.cryptohack.org/ecb_oracle/encrypt/"
	url += str(string.encode().hex()) + "/"
	r = requests.get(url)
	js = r.json()
	return js["ciphertext"]

count = 15
for i in range(0,64,32):
    while(True):
        payload= "0" * (count-len(flag))
        res1 = encrypt(payload)
        for j in tqdm("abcdefghijklmnopqrstuvwxyz0123456789_{}"):
            res2 = encrypt(payload + flag + j)
            if(res1[i:i+32] == res2[i:i+32]):
                flag += j
                break
        if(len(flag) in [15, 31, 47]):
            count += 16
            break
        print(flag)

```

Flag: *crypto{p3n6u1n5_h473_3cb}*

### FLIPPING COOKIE
You can get a cookie for my website, but it won't help you read the flag... I think.

*source.py*
```python3
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta


KEY = ?
FLAG = ?


@chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}


@chal.route('/flipping_cookie/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}
```

Để ý *ciphertext = iv.hex() + encrypted.hex()* nên ta sẽ tìm ra được iv. VIệc đó tính sau, giờ hãy nhìn vào hàm *check_admin*. Sau khi giải mã, nếu trong cookie có *admin=True* thì mới trả về flag. Vậy phải làm như nào ta.

Do yếu tố liên quan tới admin nằm ở trong block đầu tiên, thứ mà mình có thể kiểm soát thông qua IV. Ở đây mình sẽ có như sau:
```
plaintext_1 = b'admin=False;expi' 
ciphertext_1 = enc(plaintext_1 ^ iv)
```
Nếu sử dụng iv tùy chỉnh, quá trình giải mã sẽ như này:
```
plaintext_1_new = dec(ciphertext_1) ^ iv_new
plaintext_1_new = plaintext_1 ^ iv ^ iv_new
```


chúng ta muốn plaintext_1_new có dạng *b'admin=True;expir'*, vậy phải làm mất đi *plaintext_1* và *iv*. Khi đó, *new_iv* sẽ phải như sau:
```
plaintext_1_new = plaintext_1 ^ iv ^ (plaintext_1 ^ iv ^ b'admin=True;expir')
=> plaintext_1_new = b'admin=True;expir'
```
Code thực thi như sau:
```python3
from pwn import *
import requests

plaintext_1 = b'admin=False;expi'
plaintext_1_new = b'admin=True;expir'

def check_admin(cookie, iv):
    url = "http://aes.cryptohack.org/flipping_cookie/check_admin/"
    url += cookie
    url += "/"
    url += iv.hex()
    url += "/"
    r = requests.get(url)
    js = r.json()
    return js['flag']

encrypt = "2fcf378b85cdf04cee54d489b2091b62ae514b08f75bf8f046c6d1faa905a0b866fbe95987ba8b42c4e8f70432c39c5a"

iv = encrypt[0:32]
cookie = encrypt[32:]

iv_new = xor(xor(plaintext_1, plaintext_1_new), bytes.fromhex(iv))

print(check_admin(cookie, iv_new))

```

Flag: *crypto{4u7h3n71c4710n_15_3553n714l}*

### LAZY CBC
I'm just a lazy dev and want my CBC encryption to work. What's all this talk about initialisations vectors? Doesn't sound important.

*source.py*
```python3
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/lazy_cbc/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


@chal.route('/lazy_cbc/get_flag/<key>/')
def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}


@chal.route('/lazy_cbc/receive/<ciphertext>/')
def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}
```
Với bài này, tác giả đã sử dụng chính KEY để làm IV. Điều này vô tình tạo ra lỗ hổng. Ở đây mình sẽ khai thác dựa vào hàm *receive*.

Ở đây, mình sẽ dựa trên bài viết [này](https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode)
![Screenshot 2023-10-03 161556](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/d969519e-e77d-4b30-8456-5b11631240d9)

Code:
```python3
from Crypto.Cipher import AES
import requests
from pwn import *

def encrypt(block):
	url = "https://aes.cryptohack.org/lazy_cbc/encrypt/"
	url += str(block.hex()) + "/"
	r = requests.get(url)
	js = r.json()
	return js["ciphertext"]

def get_flag(key):
	url = "https://aes.cryptohack.org/lazy_cbc/get_flag/"
	url += key.hex() + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js['plaintext'])

def receive(block):
	url = "https://aes.cryptohack.org/lazy_cbc/receive/"
	url += block + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["error"][len("Invalid plaintext: "):])

ciphertext = b'A' * 48
ciphertext = encrypt(ciphertext)
ciphertext = ciphertext[:32] + '0'*32 + ciphertext[:32]
recv = receive(ciphertext)
key = xor(recv[:16], recv[32:])
print(get_flag(key))

```
Flag: *crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}*

### Triple DES
Data Encryption Standard was the forerunner to AES, and is still widely used in some slow-moving areas like the Payment Card Industry. This challenge demonstrates a strange weakness of DES which a secure block cipher should not have.

*source.py*
```python3
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad


IV = os.urandom(8)
FLAG = ?


def xor(a, b):
    # xor 2 bytestrings, repeating the 2nd one if necessary
    return bytes(x ^ y for x,y in zip(a, b * (1 + len(a) // len(b))))



@chal.route('/triple_des/encrypt/<key>/<plaintext>/')
def encrypt(key, plaintext):
    try:
        key = bytes.fromhex(key)
        plaintext = bytes.fromhex(plaintext)
        plaintext = xor(plaintext, IV)

        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = xor(ciphertext, IV)

        return {"ciphertext": ciphertext.hex()}

    except ValueError as e:
        return {"error": str(e)}


@chal.route('/triple_des/encrypt_flag/<key>/')
def encrypt_flag(key):
    return encrypt(key, pad(FLAG.encode(), 8).hex())

```
Khái niệm Weak Key: https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES
![Screenshot 2023-10-04 140906](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/c9d903de-05fd-4bc6-87a1-e3848bf4f5dd)

Khi sử dụng Weak Key, điều này có thể xảy ra:
![Screenshot 2023-10-04 140748](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/42a8c5b2-caf5-427c-9781-51f858c2410b)

Nghĩa là chỉ cần mã hóa message 2 lần bằng Weak Key, ta sẽ nhận lại chính message.

Áp dụng vào bài, mình sẽ thử dùng từng tổ hợp cặp khóa cho tới khi ra flag.
```python3
import requests
    
def encrypt(key, plaintext):
    url = "http://aes.cryptohack.org/triple_des/encrypt/"
    url += key
    url += "/"
    url += plaintext
    url += "/"
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']


def encrypt_flag(key):
	url = "https://aes.cryptohack.org/triple_des/encrypt_flag/"
	url += key + "/"
	r = requests.get(url)
	js = r.json()
	return js['ciphertext']

key = b'\xfe'*8 + b'\x01'*8
key = key.hex()

flag = encrypt_flag(key)
flag = encrypt(key, flag)
print(bytes.fromhex(flag))
```
Bonus giải thích kĩ hơn 3DES: [link](https://hackmd.io/@phucrio17/cryptohack-symmetric-ciphers#Triple-DES)

Flag: *crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}*

**© 2023,Pham Quoc Trung. All rights reserved.**
