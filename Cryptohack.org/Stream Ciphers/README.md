# **Cryptohack.org**

# **STREAM CIPHERS WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### SYMMETRY
Some block cipher modes, such as OFB, CTR, or CFB, turn a block cipher into a stream cipher. The idea behind stream ciphers is to produce a pseudorandom keystream which is then XORed with the plaintext. One advantage of stream ciphers is that they can work of plaintext of arbitrary length, with no padding required.

OFB is an obscure cipher mode, with no real benefits these days over using CTR. This challenge introduces an unusual property of OFB.

*source.py*
```python
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/symmetry/encrypt/<plaintext>/<iv>/')
def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}


@chal.route('/symmetry/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

```
AES_OFB:
![Screenshot 2023-10-04 160031](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/ebf73e89-dec5-477a-987f-431677f72ccb)


Do *ciphertext = iv.hex() + encrypted.hex()*, mình dễ dàng có được iv và flag encrypted.

Để ý thì ở đây, *key* là không đổi. Vì vậy, mình có thể lấy khối encrypt bằng cách encrypt đoạn text bất kì dài bằng flag và xor nó với chính đoạn text ban đầu. *key* không đổi khiến cho khối encrypt đó giống với khối dùng để encrypt flag. Cuối cùng chỉ cần XOR khối đó với encrypted flag sẽ ra được flag

```python
import requests
from pwn import xor

def encrypt(plaintext, iv):
    url = 'https://aes.cryptohack.org/symmetry/encrypt/'
    url += plaintext.hex() + '/' + iv.hex() + '/'
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

def encrypt_flag():
    url = 'https://aes.cryptohack.org/symmetry/encrypt_flag/'
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

flag = bytes.fromhex(encrypt_flag())
iv = flag[:16]
flag = flag[16:]

plain = b'A'*len(flag)
key = xor(bytes.fromhex(encrypt(plain, iv)), plain)
print(xor(key, flag))
```

Flag: *crypto{0fb_15_5ymm37r1c4l_!!!11!}*

### BEAN COUNTER
I've struggled to get PyCrypto's counter mode doing what I want, so I've turned ECB mode into CTR myself. My counter can go both upwards and downwards to throw off cryptanalysts! There's no chance they'll be able to read my picture.

*source.py*
```python
from Crypto.Cipher import AES

KEY = ?

class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))

    def __repr__(self):
        self.increment()
        return self.value



@chal.route('/bean_counter/encrypt/')
def encrypt():
    cipher = AES.new(KEY, AES.MODE_ECB)
    ctr = StepUpCounter()

    out = []
    with open("challenge_files/bean_flag.png", 'rb') as f:
        block = f.read(16)
        while block:
            keystream = cipher.encrypt(ctr.increment())
            xored = [a^b for a, b in zip(block, keystream)]
            out.append(bytes(xored).hex())
            block = f.read(16)

    return {"encrypted": ''.join(out)}
```
AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/49e5ed7e-7d1c-40db-8542-f3118eff1c65)

Mình nghĩ challenge sẽ cho mình tìm ra được *keystream* đầu tiên bằng cách nào đó. Một block dài 16 bytes, và đây là mã hóa file png. Do không phải một người chơi Forensic nên mình đã phải thử đọc hex của vài file png và nhận ra 16 bytes đầu đều giống nhau.
```
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
```
Vì vậy mình có thể dễ dàng lấy được keystream đầu. Để ý thêm code class:
```python
class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))
```
Ở đây, mình thấy `step_up = False`, nên xuống dưới, `self.newIV = hex(int(self.value, 16) - self.stup)`. Tuy nhiên có lỗi chính tả ở đây khi đáng lẽ phải trừ đi `self.step`. Việc trừ đi `self.stup`, thứ có giá trị False đã khiến cho iv không tăng/giảm, và làm keystream luôn không đổi.

Vậy là không còn gì khó, mình chỉ cần xor keystream với từng block của file png bị mã hóa thôi.
```python
import requests
from pwn import *

def encrypt():
    url = "https://aes.cryptohack.org/bean_counter/encrypt/"
    r = requests.get(url)
    js = r.json()
    return js["encrypted"]

png = bytes.fromhex(encrypt())

png_bytes = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
keystream = xor(png_bytes, png[:16])

print(xor(keystream, png).hex())
```
Mình sẽ thu được đoạn hex của file png. Ném vào Cyberchef để render và mình ra được kết quả.
![](https://hackmd.io/_uploads/ByIAYWjg6.png)

Flag: *crypto{hex_bytes_beans}*

### CTRIME
There may be a lot of redundancy in our plaintext, so why not compress it first?

*source.py*
```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import zlib

KEY = ?
FLAG = ?

@chal.route('/ctrime/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    iv = int.from_bytes(os.urandom(16), 'big')
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))
    encrypted = cipher.encrypt(zlib.compress(plaintext + FLAG.encode()))

    return {"ciphertext": encrypted.hex()}
```
AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/a49462a6-6eed-49ca-af87-5a38ae1d48ed)

Mọi thứ trong thuật toán này đều ổn áp. Vì vậy, chúng ta phải nghĩ đến chuyện khai thác hàm `zlib.compress`
`Zlib.compress` trong python sử dụng thuật toán deflate để nén dữ liệu. Thuật toán deflate bao gồm 2 phương pháp chính là LZ77 encoding và Huffman encoding. Về Huffman encoding, đây đơn thuần là phương pháp encode theo từng ký tự một dựa trên cây Huffman, các ký tự xuất hiện nhiều như chữ 'e' sẽ được sub thành một chuỗi các bit ngắn hơn (3-4 bits thay vì 8 bits như bình thường), cách ký tự xuất hiện ít như chữ 'q' thì được encode bằng các bit dài hơn (không quá 7 bits). Default trong python thì cây Huffman được lấy theo quy chuẩn chung (fixed) nên cuối cùng thì đây chỉ là bước thay thế từng byte thành các bits tương ứng, không có tác dụng gì nhiều lắm.
Tiếp theo là LZ77, đây là một thuật toán khá phức tạp, hiểu đơn giản là nó sẽ thay các chuỗi ký tự bị lặp bằng cách tham chiếu đến chuỗi ký tự tương ứng đã được tìm thấy trước đó. Ví dụ minh họa đơn giản:  
AAAAABCDEE => A5BCDE2  
AAAAXBCDEE => A4XBCDE2  
ABABABABXYZT => AB4XYZT  
ABABABACXYZT => AB3ACXYZT  
ABCABCABCABCMNPQ => ABC4MNPQ  
ABCABCABCABXMNPQ => ABC3ABXMNPQ  
Từ các ví dụ trên, ta nhận thấy LZ77 sẽ encode ra các chuỗi có độ dài khác nhau nếu số chuỗi ký tự lặp khác nhau, cụ thể là lặp càng nhiều chuỗi, càng liên tục thì kết quả sau khi LZ77 càng ngắn. Mà CTR là một MODE encrypt giữ nguyên độ dài plaintext. Như vậy ta sẽ brute từng ký tự với một độ lặp nhất định và xem sự thay đổi độ dài của ciphertext, và ta sẽ chọn ký tự nào cho ra ciphertext có độ dài ngắn hơn. Minh họa:  
FLAG = "crypto{thisIsFlag}"  
input = "xxxx"  
=> plaintext = "xxxxcrypto{thisIsFlag}"  
len(zlib(plaintext)) min <=> input = "cccc" => Xác định được byte đầu của FLAG là 'c'  
input2 = 'cxcxcxcx'  
=> plaintext = "cxcxcxcxcrypto{thisIsFlag}"  
len(zlib(plaintext)) min <=> input = "crcrcrcr" => Xác định được phần tiếp theo là 'cr'  

Áp dụng vào code:
```python
import requests
from tqdm import tqdm

def encrypt(plaintext):
    url = "https://aes.cryptohack.org/ctrime/encrypt/"
    url += plaintext.encode().hex() + "/"
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

flag = ""
len_dict = {}

while True:
    for i in tqdm(range(127,31,-1)):
        payload = flag + chr(i)
        res = encrypt(payload * 5)
        len_dict[chr(i)] = len(res)
    char = min(len_dict, key=lambda x: len_dict[x])
    flag += char
    print(flag)
    len_dict.clear()
```
Flag: *cryto{CRIME_571ll_p4y5}*

### Logon Zero
Before using the network, you must authenticate to Active Directory using our timeworn CFB-8 logon protocol.

Connect at nc socket.cryptohack.org 13399

Attachment: *13399.py*
```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from os import urandom
from utils import listener

FLAG = "crypto{???????????????????????????????}"


class CFB8:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        IV = urandom(16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b''
        state = IV
        for i in range(len(plaintext)):
            b = cipher.encrypt(state)[0]
            c = b ^ plaintext[i]
            ct += bytes([c])
            state = state[1:] + bytes([c])
        return IV + ct

    def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt


class Challenge():
    def __init__(self):
        self.before_input = "Please authenticate to this Domain Controller to proceed\n"
        self.password = urandom(20)
        self.password_length = len(self.password)
        self.cipher = CFB8(urandom(16))

    def challenge(self, your_input):
        if your_input['option'] == 'authenticate':
            if 'password' not in your_input:
                return {'msg': 'No password provided.'}
            your_password = your_input['password']
            if your_password.encode() == self.password:
                self.exit = True
                return {'msg': 'Welcome admin, flag: ' + FLAG}
            else:
                return {'msg': 'Wrong password.'}

        if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}

        if your_input['option'] == 'reset_password':
            if 'token' not in your_input:
                return {'msg': 'No token provided.'}
            token_ct = bytes.fromhex(your_input['token'])
            if len(token_ct) < 28:
                return {'msg': 'New password should be at least 8-characters long.'}

            token = self.cipher.decrypt(token_ct)
            new_password = token[:-4]
            self.password_length = bytes_to_long(token[-4:])
            self.password = new_password[:self.password_length]
            return {'msg': 'Password has been correctly reset.'}


listener.start_server(port=13399)

```
AES_CFB:
![Screenshot 2023-10-05 081107](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/1b91527a-2b4c-4aa2-958b-43f0360d2f21)

Bỏ qua sơ đồ trên vì đây là CFB-8.

Ở đây chúng ta sẽ để ý hàm `decrypt` bởi lẽ đọc code, bạn sẽ thấy chúng ta không động được vào hàm `encrypt`:
```python
def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt
```
Hàm này sẽ lấy ra iv và ct từ ciphertext. Khởi tạo giá trị đầu của state là iv. Sau đó, đối với mỗi byte trong ct, ta sẽ thực hiện:
* XOR byte đó với byte đầu tiên của khối mã hóa ECB tạo ra từ state
* Kết quả thu được sẽ là byte đầu của plaintext, ở đây gọi là c
* Cập nhật state bằng cách bỏ đi byte đầu của state và thêm c vào cuối state 


Do `IV = ciphertext[:16]` và `ct = ciphertext[16:]`, chúng ta có thể kiểm soát được 2 thứ này. Đề bài đã gợi ý cho chúng ta về một lỗ hổng trong CFB-8 - ZeroLogon hay CVE-2020-1472. Mục tiêu của lỗ hổng này là làm cho plaintext trả về sẽ toàn là số 0. Vậy ta sẽ làm như nào?

Đầu tiên, ta sẽ truyền vào ciphertext toàn là số 0. Giả sử là 32 số 0. Khi đó:
```
IV = ciphertext[:16] = b'\x00' * 16
ct = ciphertext[16:] = b'\x00' * 16
```
Tiếp theo
```
cipher = AES.new(self.key, AES.MODE_ECB)
pt = b''
state = IV = b'\x00' * 16
```
Vào trong vòng lặp `for i in range(len(ct)):`
```
b = cipher.encrypt(state)[0]
```
Nếu mà bằng một key nào đó, cipher có byte đầu tiên là 0, hay b = 0, ta sẽ có
```
c = b ^ ct[i] = 0 ^ 0 = 0
pt += bytes([c]) hay pt = b'\x00'
state = state[1:] + bytes([ct[i]])
      = b'\x00'*15 + b'\x00'
      = b'\x00'*16 (không đổi)
```
Có thể thấy, state và key đều không đổi trong mỗi vòng lặp, cũng như các bytes của ct đều bằng 0 => ta sẽ thu được `pt = b'\x00' * 16`

Hàm `decrypt` được gọi từ chức năng `reset_password`. Ở đó ta có:
```python
token = self.cipher.decrypt(token_ct)
new_password = token[:-4]
self.password_length = bytes_to_long(token[-4:])
self.password = new_password[:self.password_length]
```
Như trên thì kết quả sẽ trả về `token = b'\x00' * 16`, khi đó
```
new_password = token[:-4] = b'\x00' * 12
self.password_length = bytes_to_long(token[-4:]) = 0
self.password = new_password[:self.password_length]
              = (b'\x00' * 12)[:0]
              = b''
```
Như vậy thì `new_password` sẽ rỗng. Hoàn toàn có thể lấy được flag thông qua option authenticate.

Vậy vấn đề ở đây là làm sao cho `cipher = AES.new(self.key, AES.MODE_ECB)` trả về giá trị có byte đầu là 0. Ở đây ta có option reset_connection:
```python
if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}
```

Mỗi khi thực thi nó sẽ trả về một key mới. Vì vậy ta chỉ cần thực hiện option này tới khi nào mà giá trị `cipher = AES.new(self.key, AES.MODE_ECB)`có byte đầu bằng 0.

Áp dụng những lý thuyết trên:
```python
from pwn import *
import json
from tqdm import tqdm

server = "socket.cryptohack.org"
port = 13399
conn = remote(server, port)

payload = b'\x00' * 32

re_conn = json.dumps({"option":"reset_connection"}).encode()
re_pass = json.dumps({"option":"reset_password", "token":payload.hex()}).encode()
au_pass = json.dumps({"option":"authenticate", "password":""}).encode()
conn.recvline()

for _ in tqdm(range(1000)):
    conn.sendline(re_pass)
    conn.recvline()
    conn.sendline(au_pass)
    res = conn.recvline().decode()
    if('flag' in res):
        print(res)
        break
    else:
        conn.sendline(re_conn)
        conn.recvline()
```

Flag: *crypto{Zerologon_Windows_CVE-2020-1472}*

### STREAM OF CONSCIOUSNESS
Talk to me and hear a sentence from my encrypted stream of consciousness.

*source.py*
```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import random


KEY = ?
TEXT = ['???', '???', ..., FLAG]


@chal.route('/stream_consciousness/encrypt/')
def encrypt():
    random_line = random.choice(TEXT)

    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    encrypted = cipher.encrypt(random_line.encode())

    return {"ciphertext": encrypted.hex()}
```

AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/fb5ffb93-b600-4b94-9e39-b7b4e75da436)

Sau khi thử gen ra nhiều kết quả, mình nhận ra có nhiều kết quả trùng nhau. Điều này chứng tỏ, dòng `cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))` tạo ra một khối mã hóa không giống nhau mỗi lần gọi.

Sau khi chạy hẳn mấy trăm request thì mình thấy có tổng cộng 22 đoạn mã. Vì flag bắt đầu bằng `crypto{` nên mình sẽ thử XOR 'crypto{' với từng đoạn mã một để tìm ra 7 bytes đầu của khối mã hóa.
Sau đó, mình sẽ XOR từng khối mã hóa mình có với từng 7 bytes đầu của 22 đoạn mã hóa. Khối mã hóa hợp lệ là khối cho ra nhiều đoạn text có thể `decode()` nhất.

Mình tìm ra nó là `b'\x89d\x82\x04\x1d\xcc\xf4'`

Vấn đề ở đây là tìm ra các kí tự còn lại của flag. Mình sẽ dựa trên 21 đoạn mã còn lại, dựa trên nghĩa của chúng để đoán kí tự tiếp theo, XOR nó với kí tự đã bị mã hóa ở cùng vị trí và thêm vào key. Dần dần, sẽ ra được flag (XOR Crib Attack)


Mình có viết một chương trình để phục vụ điều đó

```python
from pwn import *

global results_list
results_list = ['c044f16c7ca0984105f8b380c1b37b53d802b4b75986d4b5c545a56d625303a9b1cd2d4bcd92a4a5fd3b3812c3e1d606094fe3ece68a', 'de0cfb2479a3d4194dd4edcccafc3753c547e4b3468dd2a5df4aec626b174aade4cc240fc093a6f6f2702012d4e6de435d44efeab2', 'de0bf76879ecbd4d4dd0e2898df17250c202e2b74bc3d2a4d443ec776d121eefd8852b04dc91a5f6e1792d51c8aec8164a45a2ebe8d4da7ac54e71e5c6f15ba9b2852d290a81fd5bd7', 'c043ef2468a29c0c55c1edc08dda3758ce14f1a0598686a5c501ec776d164aa9f0d0241f8e8ee1bbfa72291e80ecce170964a5e2add1c07ad71e6efac6f842a8fb9d2c2d5e9bf3588d39408a0d97ccd8591ebc', 'c80ae62454ec870544ddf8ccc4f47953d902b4bb5bcd', 'c611f03b3d9b9c1405dee19e92', 'dd0cf06178ec96025cc2b49ed8fd7955c500b8f25f8fc7b5d843ab2364074aa7fed73b0edad1e185f66e355ddae6da42', 'd901f06c7cbc874d4dd4b484cce03751c214e7b74bc3d2a4d40db871641a04eff0cb2c4bc08ee1b4f27f2712c2f79b0d465aacafdac5c066960371f183b946b1b68028211f9cfb5a8634', 'de0ce3703dadd40344c2e0958de07a59c70bb4a6478ad5ecc14ca56d715302aef58b', 'ea16fb7469a38f0616c8a1dbdfa02351f415a7a71ad0f9fd8472aa37324706b2', 'c50bf46131ec841f4ad3f58ec1ea281cff0ff1ab0f87c9a29659ec686b1c1deff9ca3f4bcd8fa4b7e1656c5bd4aed210050deae0fa84c667db0772ea87ed47aabcc76a665e9cfa50c8541687068ed9d85515f6cb616bd7c6460452f38a', 'c044f16c7ca0984d49dee7898df66159d91ee0ba468dc1ecd043a8236b1c1eeff6c03c4bc194acf6f17d2f598e', 'cd0bee6864ec830449ddb498c5fa79578b13fcb35bc3efebdc0da066640503a1f685294bda98a2b9fd786c5ad5fdd9024749a2eee3c08e66de0f6aa392f14bb6be8f2b3a1bc8db15856013964888c98a5117ebcb60669ec34c5643f5c1c30c081952e2a9', 'cd16e7776ee1990c4ed8fa8b8df279588b2afdbe438ac8a9c354', 'dd0ce77778ec9c0257c2f19f81b36354c214b4b14e91d4a5d04aa923285302a0e685014bc592a0a2fb796c5fd9fdde0f4f0debe1add0c67bc54e7de294eb47a5bc8c64655e9cfa5091321287489ad0941413fb983923dcdf56567ebdd78b1a161a1cebe2cda0f5998d692f6842d1ce900f4c451d4aa8b2', 'de0ce3703dadd4014ac5b483cbb36354c209f3a10f97ceadc50db86b601d4abcf4c0250ecdddb5b9b3712912d3e19b0e485ff4eae1c8c167c54e7fed82b95baaba9d30291786f35784704cc2009aca9d1419f7886d6edb8a4b1844f4c38d121c1f5fe4e9cfe9a7d890686a3c5edc8b8947444c1b50e6d5a8357198a4b9e3b314748d167b32c60b6b051b147fe64ce7751d3bddba7174611a5f9d13925cb326', 'c817a26d7becbd4d4dd0f0ccccfd6e1cdc0ee7ba0f97c9ecd348ec6a6b531ea7f4853a02ce95b5f7b3556c51c1e09c1708', 'c70bae2454eb980105d6fbccc4fd3748c447d0bd438fdfecd043a823711606a3b1cd2d19898eb5a4f2752b5ad4aed4165d', 'cb11f62454ec830449ddb49fc5fc601cc30ef9fc', 'dd0ce72469a9861f4cd3f8898de77f55c500b4bb5cc3d2a4d059ec776d164abff0d63c4bca9caff1e73c2e5780fad411470dedfaf984cc6b96076af0c6eb41abaf9a6a', 'c010a2677ca2d31905d3f1ccd9fc65528b08e1a603c3c4b9c50da57725100ba1b1c72d4bc09aafb9e179281c', 'c10bf5246dbe9b184191f582c9b37f5ddb17edf2478681a0dd0dae66250402aaff85200e899aa4a2e03c214b80e0d4174c0c']



key = b'\x89d\x82\x04\x1d\xcc\xf4'


def print_xor_results():
    global key
    count = 0
    for j in results_list:
        print(count, xor(key, bytes.fromhex(j)[:len(key)]))
        count += 1

def extend_key():
    global key

    char = input("Nhập vào 1 kí tự: ").strip('\n')
    
    choice = int(input("Chọn một phần tử từ danh sách trên (nhập số): "))
    
    chosen_item = results_list[choice]
    add = xor(char.encode(), bytes.fromhex(chosen_item)[len(key)])
    
    key += add
    print("Key: ", key)

print_xor_results()
while(True):
    extend_key()
    print_xor_results()
```

Sau một hồi ngồi đoán:
```
Key:  Nhập vào 1 kí tự: n
Chọn một phần tử từ danh sách trên (nhập số): 12
Key:  b'\x89d\x82\x04\x1d\xcc\xf4m%\xb1\x94\xec\xad\x93\x17<\xabg\x94\xd2/\xe3\xa6\xcc\xb1-\xcc\x03\x05sj\xcf'
0 b"I shall, I'll lose everything if"
1 b'Why do they go on painting and b'
2 b'Would I have believed then that '
3 b"I'm unhappy, I deserve it, the f"
4 b'And I shall ignore it.n\xc6W\t\x98\xef\x82v.\x12'
5 b'Our? Why our?U\x06\xcc\x90Z\x0fN;\xe6x-/\xbf\n\x12\xf5HWT'
6 b'Three boys running, playing at h'
7 b'Perhaps he has missed the train '
8 b'What a nasty smell this paint ha'
9 b'crypto{k3y57r34m_r3u53_15_f474l}'
10 b"Love, probably? They don't know "
11 b'I shall lose everything and not '
12 b"Dolly will think that I'm leavin"
13 b'Dress-making and Millinery\x01\x15\xe2\x04\x04.'
14 b'These horses, this carriage - ho'
15 b'What a lot of things that then s'
16 b'As if I had any wish to be in th'
17 b"No, I'll go in to Dolly and tell"
18 b'But I will show him.\xe4\xf2P\xe8\xe5\xc1O\x07L\xae\xdeP'
19 b'The terrible thing is that the p'
20 b"It can't be torn out, but it can"
21 b"How proud and happy he'll be whe"
```
Flag: *crypto{k3y57r34m_r3u53_15_f474l}*
