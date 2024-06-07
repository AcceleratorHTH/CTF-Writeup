# FPTU SecAthon 2023

## **FPTU SecAthon 2023**

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

### Combine

The symmetric crypto algorithm is much more secure, but the problem of key distribution is annoying. Why don't we combine both symmetric and asymmetric algorithm in a crypto system. What a brilliant idea!

Attachment: _combine.py_

```python
#!/usr/bin/env python3

from Crypto.Util.number import getStrongPrime, bytes_to_long
from Crypto.Cipher import AES
from secret import flag, key

def encrypt_message(key, msg):
	BS = 16
	pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
	msg = pad(msg).encode()
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(msg).hex()
	return ciphertext

def encrypt_key(key):
	nbit = 2048
	p = getStrongPrime(nbit // 2)
	q = getStrongPrime(nbit // 2)
	n = p * q
	e = 3
	m = bytes_to_long(key)
	cipherkey = pow(m, e, n)
	return n, e, cipherkey

ciphertext = encrypt_message(key, flag)
n, e, c = encrypt_key(key)

print('n =', n)
print('e =', e)
print('cipherkey =', c)
print('ciphertext =', ciphertext)

```

_output.txt_

```
n = 17209865306489383127800020243389994329129743604782790572071575275930356482173664633977129059765483365641382694889746793832394394570779520318736174413698255275805470489995770799549145326336810606098666485462172397721883061380164674372281155031229403077923081446873681038939824476853501573626662210456685550050398627753809494063023262928406194832122173907376911569530179213802008987425021865006236985258208235745676711294952229465208427722435166889999294578405054346630724018303425483416613451938567146420297094727347064526763529390676971710365525083049556260598332852178425692853805520818042005192063672211992678540011
e = 3
cipherkey = 142196723273747238898852175173915220249887834079871068954399297555327440564641299650087764716642697466878642687260087329740593337673114537926971425515696694822194006024953138119955781575720865321942965774838545548158954058397248000
ciphertext = e6c2921a3edb52639e871ebad04f16ff4580870a8522295cf58914b09fee749afcdd94a0beb8471dbaa50ed37693653295d4e798798674e2048f5c233cd9aba1
```

Ở đây, flag được mã hóa thông qua AES\_ECB với block size là 16-bits, cùng với đó là key được mã hóa dựa trên RSA.

Nhìn vào output được cung cấp, mình nhận thấy _e = 3_, dấu hiệu cho lỗ hổng _small e_ trong RSA. Giải thích dễ hiểu thì khi _e_ quá nhỏ, _m^e_ sẽ nhỏ hơn _n_. Khi đó _m^e % n_ sẽ bằng _m^e_. Vậy thì đơn giản để tìm lại được key, ta chỉ cần lấy căn bậc _e_ của _cipherkey_.

```python
from Crypto.Util.number import *
from sympy import *
from Crypto.Cipher import AES


n = 17209865306489383127800020243389994329129743604782790572071575275930356482173664633977129059765483365641382694889746793832394394570779520318736174413698255275805470489995770799549145326336810606098666485462172397721883061380164674372281155031229403077923081446873681038939824476853501573626662210456685550050398627753809494063023262928406194832122173907376911569530179213802008987425021865006236985258208235745676711294952229465208427722435166889999294578405054346630724018303425483416613451938567146420297094727347064526763529390676971710365525083049556260598332852178425692853805520818042005192063672211992678540011
e = 3
cipherkey = 142196723273747238898852175173915220249887834079871068954399297555327440564641299650087764716642697466878642687260087329740593337673114537926971425515696694822194006024953138119955781575720865321942965774838545548158954058397248000
ciphertext = "e6c2921a3edb52639e871ebad04f16ff4580870a8522295cf58914b09fee749afcdd94a0beb8471dbaa50ed37693653295d4e798798674e2048f5c233cd9aba1"

ciphertext = bytes.fromhex(ciphertext)

key = long_to_bytes(int(real_root(cipherkey, 3))).decode()
print(key)

# key = "secret#keysummerSuperSecureAyyah"
```

Với key tìm được, mình thực hiện giải mã AES\_ECB và ra được flag.

```python
def unpad(s):
    return s[:-s[-1]]

def decrypt_message(key, ciphertext):
    BS = 16
    key = key.encode()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(plaintext_bytes).decode()
    return plaintext

ciphertext = "e6c2921a3edb52639e871ebad04f16ff4580870a8522295cf58914b09fee749afcdd94a0beb8471dbaa50ed37693653295d4e798798674e2048f5c233cd9aba1"

decrypted_message = decrypt_message(key, ciphertext)
print(decrypted_message)
```

Flag: _FUSEC{The\_combine\_crypto\_system\_is\_really\_secure!!!}_

### Secret Agent

The secret agents share private information through a secret services. We take it from a napped agent, but cannot get its private information without knowing secret id. Wrong trials will punch me!

```
nc 34.143.143.97 8000
```

Attachment: _chal\_server.py_

```python
import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import secret_client, flag
import socketserver
import sys

key = os.urandom(16)
iv1 = os.urandom(16)
iv2 = os.urandom(16)

def encrypt(msg):
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    enc = aes2.encrypt(aes1.encrypt(pad(msg, 16)))
    return iv1 + iv2 + enc


def decrypt(msg):
    iv1, iv2, enc = msg[:16], msg[16:32], msg[32:]
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    msg = unpad(aes1.decrypt(aes2.decrypt(enc)), 16)
    return msg


def create_user(requestHandler):
    requestHandler.request.sendall(b'Your client id: ')
    client_id = requestHandler.rfile.readline().rstrip(b'\n').decode()
    if client_id:
        data = {"client_id": client_id, "privileged_granted": False}
    else:
        # Default token
        data = {"client_id": secret_client, "privileged_granted": True}
    token = encrypt(json.dumps(data).encode())
    requestHandler.request.sendall(b"Your token: ")
    requestHandler.request.sendall(base64.b64encode(token) + b'\n')


def login(requestHandler):
    requestHandler.request.sendall(b'Your client id: ')
    client_id = requestHandler.rfile.readline().rstrip(b'\n').decode()
    requestHandler.request.sendall(b'Your token: ')
    raw_token = requestHandler.rfile.readline().rstrip(b'\n')
    try:
        raw_token = decrypt(base64.b64decode(raw_token))
    except:
        requestHandler.request.sendall(b"Failed! Check your token again\n")
        return None

    try:
        data = json.loads(raw_token.decode())
    except:
        requestHandler.request.sendall(b"Failed! Your token is malformed\n")
        return None

    if "client_id" not in data or data["client_id"] != client_id:
        requestHandler.request.sendall(b"Failed! Check your client id again\n")
        return None

    return data


def none_menu(requestHandler):
    requestHandler.request.sendall(b"1. New client\n")
    requestHandler.request.sendall(b"2. Log in\n")
    requestHandler.request.sendall(b"3. Exit\n")

    try:
        requestHandler.request.sendall(b"> ")
        inp = int(requestHandler.rfile.readline().rstrip(b'\n').decode())
    except ValueError:
        requestHandler.request.sendall(b"Invalid choice!\n")
        return None

    if inp == 1:
        create_user(requestHandler)
        return None
    elif inp == 2:
        return login(requestHandler)
    elif inp == 3:
        exit(0)
    else:
        requestHandler.request.sendall(b"Invalid choice!\n")
        return None


def user_menu(user, requestHandler):
    requestHandler.request.sendall(b"1. Show flag\n")
    requestHandler.request.sendall(b"2. Log out\n")
    requestHandler.request.sendall(b"3. Exit\n")

    try:
        requestHandler.request.sendall(b"> ")
        inp = int(requestHandler.rfile.readline().rstrip(b'\n').decode())
    except ValueError:
        requestHandler.request.sendall(b"Invalid choice!\n")
        return None

    if inp == 1:
        if "privileged_granted" in user and user["privileged_granted"]:
            requestHandler.request.sendall(flag + b'\n')
        else:
            requestHandler.request.sendall(b"Insuffcient permissions! Alerts triggered!!!\n")
        return user
    elif inp == 2:
        return None
    elif inp == 3:
        exit(0)
    else:
        requestHandler.request.sendall(b"Invalid choice!\n")
        return None

class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        user = None

        self.request.sendall(b"Super-secure secret sharing service for only privileged users!\n")
        self.request.sendall(b"I dare you to get me!\n")
        self.request.sendall(b"=====================================================\n")

        while True:
            if user:
                user = user_menu(user, self)
            else:
                user = none_menu(self)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def main(argv):
    host, port = '0.0.0.0', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)
```

Ở challenge này thì mình có thể tạo tài khoản và được cung cấp token cho tài khoản đó. Sau đó thì có thể thực hiện đăng nhập. Nếu mình có quyền "privileged\_granted" thì có thể truy cập được vào mục _show flag_ và lấy được flag.

Trước hết thì mình để ý hàm tạo user:

```python
def create_user(requestHandler):
    requestHandler.request.sendall(b'Your client id: ')
    client_id = requestHandler.rfile.readline().rstrip(b'\n').decode()
    if client_id:
        data = {"client_id": client_id, "privileged_granted": False}
    else:
        # Default token
        data = {"client_id": secret_client, "privileged_granted": True}
    token = encrypt(json.dumps(data).encode())
    requestHandler.request.sendall(b"Your token: ")
    requestHandler.request.sendall(base64.b64encode(token) + b'\n')
```

Có thể thấy, token là JSON dạng {"client\_id": client\_id, "privileged\_granted": True} được mã hóa thông qua hàm encrypt và base64. Cũng từ đoạn code, mình thấy rằng có thể dễ dàng lấy được đoạn token của secret\_client bằng cách để trống _client\_id_ khi tạo tài khoản.

```
Super-secure secret sharing service for only privileged users!
I dare you to get me!
=====================================================
1. New client
2. Log in
3. Exit
> 1
Your client id:
Your token: yDb0q2pNaoySGmGrFNNWNWooRRl4soz6/g9oMrcLQBmuO+6LMqJuD5Lqc+OzwCUidMuWixJjkx4Zcexawgfyz64c7DGgXDgizbAtIOtwFGBsN210v6bTPAwI/x/pJGmZ
```

Tuy nhiên thì token này cũng chưa ra ngay được flag vì muốn đăng nhập chúng ta cần phải điền cả _client\_id_. Vì vậy mình tiến tới xem xét các hàm liên quan tới mã hóa:

```python
key = os.urandom(16)
iv1 = os.urandom(16)
iv2 = os.urandom(16)

def encrypt(msg):
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    enc = aes2.encrypt(aes1.encrypt(pad(msg, 16)))
    return iv1 + iv2 + enc


def decrypt(msg):
    iv1, iv2, enc = msg[:16], msg[16:32], msg[32:]
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    msg = unpad(aes1.decrypt(aes2.decrypt(enc)), 16)
    return msg
```

Ở đây, hàm encrypt sử dụng 2 lần mã hóa AES\_CBC với key, iv1, iv2 được gen ra từ hàm _os.random(16)_ ở đầu chương trình. Quá trình mã hóa có thể được minh họa như sau:

```python
                  [M_1]             [M_2]             [M_3]
(CBC)               |                 |                 |
                    v                 v                 v 
                  (Enc)             (Enc)             (Enc)
                    |                 |                 |
                    v                 v                 v
[IV1] ----------> (Xor)      .----> (Xor)      .----> (Xor) 
                    |        |        |        |        |
                    v -------.        v -------.        v --- ...
                  [T_1]             [T_2]             [T_3]  
(CBC)               |                 |                 |
                    v                 v                 v 
                  (Enc)             (Enc)             (Enc)
                    |                 |                 |
                    v                 v                 v
[IV2] ----------> (Xor)      .----> (Xor)      .-----> (Xor) 
                    |        |        |        |         |
                    v -------.        v -------.         v --- ...
                  [C_1]             [C_2]              [C_3]
```

Quá trình thám mã:

```python
                  [C_1]             [C_2]             [C_3]
(CBC)               |                 |                 |
                    v -------.        v -------.        v --- ...
                  (Dec)      |      (Dec)      |      (Dec)
                    |        |        |        |        |
                    v        |        v        |        v
[IV2] ----------> (Xor)      .----> (Xor)      .----> (Xor)
                    |                 |                 |
                    v                 v                 v
                  [T_1]             [T_2]             [T_3]  
(CBC)               |                 |                 |
                    v -------.        v -------.        v --- ...
                  (Dec)      |      (Dec)      |      (Dec)
                    |        |        |        |        |
                    v        |        v        |        v
[IV1] ----------> (Xor)      .----> (Xor)      .----> (Xor)
                    |                 |                 |
                    v                 v                 v
                  [M_1]             [M_2]             [M_3]
```

Vì là CBC nên ở đây, mình sẽ thực hiện tấn công **Padding Oracle Attack**. Lý thuyết sẽ được dựa trên bài viết [này](https://nsbvc.blogspot.com/2019/01/vua-ngo-ra-su-vi-dieu-cua-padding.html).

Với bài này, phần token trong login chính là nơi chúng ta thực hiện tấn công. Message "Failed! Check your token again\n" sẽ là cơ sở để phát hiện unpadding thành công hay không.

Code:

```python
from tqdm import tqdm
from pwn import *
from base64 import *

r = remote('34.143.143.97', 8000)

 
def recv_line(x):
    for _ in range(x):
        r.recvline()
 
recv_line(3)
 
recv_line(3)
r.sendline(b"1")
r.send(b"\n")
token = r.recvline()

token = b64decode(token[30:158].decode())
print(token)
print(len(token))
 
true_token = [0] * 80
 
for i in range(64, 16, -16):
    for j in range(0, 16):
        for k in tqdm(range(0, 256)):
            if i == 64 and j == 0 and k == 0:
                continue
            query_token = token[:i-j-17]
            query_token += bytes([token[i-j-17] ^ k])
            for u in range(j):
                query_token += bytes([token[i-j-16+u] ^ true_token[i-j+16+u] ^ (j+1)])
            query_token += token[i-16:i+16]
            recv_line(3)
            r.sendline(b"2")
            r.sendline(b"trungpq")
            r.sendline(b64encode(query_token))
            res = r.recvline()
            if b"Check your token again" not in res:
                true_token[i+15-j] = k ^ (j+1)
                break
        print(bytes(true_token))
 
print(bytes(true_token))

```

Output sau khoảng 10p:

```
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"client_id": "fAiryTypeAn", "privileged_granted'
```

Đến đây thì mình đã biết được _client\_id_ là fAiryTypeAn. Thử login với token đã lấy được từ trước, mình ra được flag.

```
Super-secure secret sharing service for only privileged users!
I dare you to get me!
=====================================================
1. New client
2. Log in
3. Exit
> 2
Your client id: fAiryTypeAn
Your token: yDb0q2pNaoySGmGrFNNWNWooRRl4soz6/g9oMrcLQBmuO+6LMqJuD5Lqc+OzwCUidMuWixJjkx4Zcexawgfyz64c7DGgXDgizbAtIOtwFGBsN210v6bTPAwI/x/pJGmZ
1. Show flag
2. Log out
3. Exit
> 1
FUSEC{rewire_for_basic_padding_orarcle_attack_is_fresh_didnt_it???}
```

Flag: _FUSEC{rewire\_for\_basic\_padding\_orarcle\_attack\_is\_fresh\_didnt\_it???}_

### Special

I'm experimenting a new attack techniques but it takes too much time to attack. How long do I have to wait?

Attachment: _special.py_

```python
#!/usr/bin/env python3

from Crypto.Util.number import getRandomNBitInteger, isPrime, bytes_to_long
from secret import flag


def genSpecialPrime(m, lsbit, nbit):
	while True:
		a = getRandomNBitInteger(nbit // m)
		r = getRandomNBitInteger(lsbit)
		p = a**m + r
		if r < 2*a**(m/2) and isPrime(p):
			return p, r

nbit = 2048
m = 6
lsbit = 36
p, r = genSpecialPrime(m, lsbit, nbit // 2)
q, s = genSpecialPrime(m, lsbit, nbit // 2)
n = p * q
e = 65537
m = bytes_to_long(flag)
c = pow(m, e, n)

print('n =', n)
print('e =', e)
print('r =', r)
print('s =', s)
print('c =', c)
```

_output.txt_

```
m = 6
n = 5492976487480578679267506637417801509317575229841582749209362422880496777697661463095681941384511594820366511371078950067259638159638389989851901094616667910772899948116916895560657161074452965224886315236525532104338582761091946493205663174132497284245913314808985617596094177891747635436626372362419446572744233021469108886918772231670973970330484736435736890290124391275237703374323416608209748760112099103861040856470543532740357396508522280726638388570667399579137930936466246498207356915282942024097243750099523899175827041338927836612379110009635783586479804781742147071688918856302200006864480644483685727
e = 65537
r = 65871773553
s = 50658050575
c = 328506890795505985479314425320468974528937152189787155810049374466222414408309371075268525124782969010895427145735894650939612552930129921545287771508147208685473386844493855455126505968483417807661266701694249679381494984658286621393654760823114577720985012613334426848040215211775270445793784398458277660845650104875381989887737457174846940396779008778505642465746393480801263823838958304980787593119384354693228102651172949043206704478693630425605780458674874508775093796165405750695793617366872908551523437485079189142381300394920095207163887827407773610175995565670690368395275769023963778492110094765806536
```

Bài này thì cũng là một dạng về RSA. Từ code, ta thấy được hai số p,q được tạo ra từ hàm sau:

```python
def genSpecialPrime(m, lsbit, nbit):
	while True:
		a = getRandomNBitInteger(nbit // m)
		r = getRandomNBitInteger(lsbit)
		p = a**m + r
		if r < 2*a**(m/2) and isPrime(p):
			return p, r
```

Chúng ta đã biết n, e, c nhưng chúng đều ở trong điều kiện đủ để không khai thác được các cách thông dụng. Nhận thấy ngoài ra mình còn được cung cấp cả r,s là 2 giá trị trả về cùng với p,q dựa trên hàm gen số nguyên tố, mình đoán có thể khôi phục p,q bằng cách nào đó. Xem xét kĩ hàm _genSpecialPrime_, mình nhận thấy số nguyên tố trả về có dạng _a\*\*m + r_. Dựa trên số liệu bài cho, mình có thể viết lại p,q như sau:

```
p = a^6 + r
q = b^6 + s
```

Do đã biết n, và n = p \* q, mình có:

```
n = (a^6 + r)*(b^6 + s)
<=> (a*b)^6 + s*a^6 + r*b^6 + r*s - n = 0
Đặt a*b = x
```

Đến đây thì mình cũng khá là bế tắc. Sau khi bú chút hint thì mình nhận ra r,s là 2 số khá nhỏ. Khi đó, n sẽ xấp xỉ bằng (a\*b)^6. Để gần hơn thì mình sẽ lấy a\*b = căn bậc 6 của n-r\*s

```
s*a^6 + r*b^6 = n - r*s - x^6
Đặt n - r*s - x^6 = y
<=> s*a^6 + r*b^6 - y = 0
Nhân cả 2 vế với a^6
<=> s*a^12 + r*x^6 - y*a^6 = 0
```

Phương trình trên là phương trình bậc 2 1 ẩn, hoàn toàn có thể giải ra được a. Từ đó ta sẽ có được b và tính được p,q. Lúc đó, bài toán RSA sẽ không còn gì khó nữa.

```python
n = 5492976487480578679267506637417801509317575229841582749209362422880496777697661463095681941384511594820366511371078950067259638159638389989851901094616667910772899948116916895560657161074452965224886315236525532104338582761091946493205663174132497284245913314808985617596094177891747635436626372362419446572744233021469108886918772231670973970330484736435736890290124391275237703374323416608209748760112099103861040856470543532740357396508522280726638388570667399579137930936466246498207356915282942024097243750099523899175827041338927836612379110009635783586479804781742147071688918856302200006864480644483685727
e = 65537
r = 65871773553
s = 50658050575
c = 328506890795505985479314425320468974528937152189787155810049374466222414408309371075268525124782969010895427145735894650939612552930129921545287771508147208685473386844493855455126505968483417807661266701694249679381494984658286621393654760823114577720985012613334426848040215211775270445793784398458277660845650104875381989887737457174846940396779008778505642465746393480801263823838958304980787593119384354693228102651172949043206704478693630425605780458674874508775093796165405750695793617366872908551523437485079189142381300394920095207163887827407773610175995565670690368395275769023963778492110094765806536
m = 6


x = int((n - r * s) ** (1/6))
assert x ** 6 < n - r*s < (x+1)**6
y = n - r*s - x**6
R.<a> = PolynomialRing(ZZ)


f = s*a**12 - y * a**6 + r*(x)**6
a = f.roots()[0][0]
b = x // a
p = a**m + r
q = b**m + s
assert p * q == n

from Crypto.Util.number import long_to_bytes, bytes_to_long 

d = int(pow(e, -1, (p-1)* (q-1)))

print(long_to_bytes(int(pow(c,d,n))))
```

Flag: _FUSEC(Simplifier\_LSB\_Attack\_On\_Special\_Small\_Cases\_for\_RSA)_

**© 2023,Pham Quoc Trung. All rights reserved.**
