# Elliptic Curve

## **Cryptohack.org**

## **ELLIPTIC CURVE WRITEUP**

### **Author:**

* Pham Quoc Trung

### **Used Language:**

* Python3

### **Problem Solving:**

**Lý thuyết**\
https://nhattruong.blog/2022/03/06/khai-niem-duong-cong-eliptic/\
https://nhattruong.blog/2022/03/06/chuan-mat-ma-khoa-cong-khai-tren-duong-cong-elliptic-elliptic-curve-cryptography/

**EC Diffie Hellman**\
Trước tiên ta chọn một số nguyên $p$ lớn, với $p$ là số nguyên tố (nếu sử dụng đường cong Elliptic Zp) hoặc $p$ có dạng $2^m$(nếu chọn đường cong GF($2^m$)), và chọn 2 tham số $a$, $b$ tương ứng để tạo thành nhóm $E\_p(a,b)$. Ta gọi $G$ là điểm cơ sở của nhóm nếu tồn tại một số nguyên $n$ sao cho $nG$=0. Số nguyên $n$ nhỏ nhất như vậy được gọi là hạng của $G$.

Trong trao đổi khóa EC Diffie-Hellman, ta chọn một điểm $G$ có hạng $n$ lớn, và giao thức trao đổi khóa giữa Alice và Bob tiến hành như sau:

1. Alice chọn một số $n\_A$ < $n$ và giữ bí mật số $n\_A$ này. Sau đó trong $E\_p(a,b)$ Alice tính $Q\_A$ = $n\_AG$ và gửi cho Bob.
2. Tương tự Bob chọn một số bí mật $n\_B$, tính $Q\_B$ và gửi $Q\_B$ cho Alice.
3. Alice tạo khóa phiên bí mật là $S$ = $n\_A Q\_B$ =$n\_An\_BG$
4. Bob tạo khóa phiên bí mật là $S$ = $n\_B Q\_A$ = $n\_An\_BG$ (nhóm Abel có tính giao hoán) giống với khóa của Alice.

Trudy có thể chặn được $Q\_A$ và $Q\_B$, tuy nhiên chỉ có thể tính được điều này là bất khả thi như ta đã thấy ở phần trên.

Chú ý: khóa phiên $S$ là một điểm trong đường cong Elliptic, để sử dụng khóa này cho mã hóa đối xứng như DES hay AES, ta cần chuyển $S$ về dạng số thường.

#### Smooth Criminal

Spent my morning reading up on ECC and now I'm ready to start encrypting my messages. Sent a flag to Bob today, but you'll never read it.

Attachments: _source.py_

```python
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'

FLAG = b'crypto{??????????????????????????????}'


def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P: tuple, Q: tuple):
    # based of algo. in ICM
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P: tuple, n: int):
    # based of algo. in ICM
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def gen_shared_secret(Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = double_and_add(Q, n)
    return S.x


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


# Define the curve
p = 310717010502520989590157367261876774703
a = 2
b = 3

# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = Point(g_x, g_y)

# My secret int, different every time!!
n = randint(1, p)

# Send this to Bob!
public = double_and_add(G, n)
print(public)

# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = Point(b_x, b_y)

# Calculate Shared Secret
shared_secret = gen_shared_secret(B, n)

# Send this to Bob!
ciphertext = encrypt_flag(shared_secret)
print(ciphertext)
```

_output.txt_

```
Point(x=280810182131414898730378982766101210916, y=291506490768054478159835604632710368904)

{'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}
```

Ở đây, bậc của generator là smooth, nên chúng ta có thể tính được logarit rời rạc của mọi điểm trên đường cong sử dụng Pohlig-Hellman.

Pohlig-Hellman:

* Suppose we're solving the equation n\*P = Q where P and Q are points on a elliptic curve
* Since the curve is modular, there are only so many values that n\*P can take on before getting wrapped around. Let's call the total number of these values ord(P).
* Using an algorithm called Pollard's Rho, the time it takes to compute the ECDLP will be on the order of sqrt(ord(P))
* Say ord(P) has prime factors p1, p2, ... pn. The Pohlig Hellman algorithm lets us break the big ECDLP into a bunch of smaller ECDLP's with orders of p1, p2, ... pn. The answers to each of these mini-ECDLP's are then combined using the Chinese Remainder Theorem to give us n.
* Since the running time of this algorithm is on the order of sqrt(p1) + sqrt(p2) + ... + sqrt(pn), this is a lot faster if ord(P) can be factored into small primes

Dựa trên lý thuyết trên, có thể viết lại thuật toán này như sau:

```python
def PolligHellman(P,Q):
	zList = list()
	conjList = list()
	rootList = list()
	n = P.order()
	factorList = n.factor()
	for facTuple in factorList:
		P0 = (ZZ(n/facTuple[0]))*P
		conjList.append(0)
		rootList.append(facTuple[0]^facTuple[1])
		for i in range(facTuple[1]):
			Qpart = Q
			for j in range(1,i+1):
				Qpart = Qpart - (zList[j-1]*(facTuple[0]^(j-1))*P)
			Qi = (ZZ(n/(facTuple[0]^(i+1))))*Qpart
		zList.insert(i,discrete_log(Qi,P0,operation='+'))
		conjList[-1] = conjList[-1] + zList[i]*(facTuple[0]^i)
	return crt(conjList,rootList)
```

(Tham khảo paper `Weak Curves In Elliptic Curve Cryptography`)

Tuy nhiên, với sagemath, thực ra hàm discrete\_log trong EllipticCurve đã sử dụng Pohlig-Hellman. Vì vậy, với những bài như này mình có thể sử dụng trực tiếp luôn

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


msg = {'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}

p = 310717010502520989590157367261876774703
a = 2
b = 3

#When p is prime, Zmod and GF is the same
E = EllipticCurve(Zmod(p), [a,b])
# Generator point
G = E(179210853392303317793440285562762725654, 105268671499942631758568591033409611165)

# Bob's public key
B = E(272640099140026426377756188075937988094, 51062462309521034358726608268084433317)

# Our public key
A = E(280810182131414898730378982766101210916, 291506490768054478159835604632710368904)

# Compute Bob's private key
b = G.discrete_log(B)
shared_secret = (A * b).xy()[0]
iv = msg['iv']
ciphertext = msg['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))

```

Flag: _crypto{n07\_4ll\_curv3s\_4r3\_s4f3\_curv3s}_

#### Curveball

Here's my secure search engine, which will only search for hosts it has in its trusted certificate cache.

Connect at `socket.cryptohack.org 13382`

Attachment: _13382.py_

```python
#!/usr/bin/env python3

import fastecdsa
from fastecdsa.point import Point
from utils import listener


FLAG = "crypto{????????????????????????????????????}"
G = fastecdsa.curve.P256.G
assert G.x, G.y == [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my secure search engine backed by trusted certificate library!\n"
        self.trusted_certs = {
            'www.cryptohack.org': {
                "public_key": Point(0xE9E4EBA2737E19663E993CF62DFBA4AF71C703ACA0A01CB003845178A51B859D, 0x179DF068FC5C380641DB2661121E568BB24BF13DE8A8968EF3D98CCF84DAF4A9),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.bing.com': {
                "public_key": Point(0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.gchq.gov.uk': {
                "public_key": Point(0xDEDFC883FEEA09DE903ECCB03C756B382B2302FFA296B03E23EEDF94B9F5AF94, 0x15CEBDD07F7584DBC7B3F4DEBBA0C13ECD2D2D8B750CBF97438AF7357CEA953D),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            }
        }

    def search_trusted(self, Q):
        for host, cert in self.trusted_certs.items():
            if Q == cert['public_key']:
                return True, host
        return False, None

    def sign_point(self, g, d):
        return g * d

    def connection_host(self, packet):
        d = packet['private_key']
        if abs(d) == 1:
            return "Private key is insecure, certificate rejected."
        packet_host = packet['host']
        curve = packet['curve']
        g = Point(*packet['generator'])
        Q = self.sign_point(g, d)
        cached, host = self.search_trusted(Q)
        if cached:
            return host
        else:
            self.trusted_certs[packet_host] = {
                "public_key": Q,
                "curve": "secp256r1",
                "generator": G
            }
            return "Site added to trusted connections"

    def bing_it(self, s):
        return f"Hey bing! Tell me about {s}"

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        host = self.connection_host(your_input)
        if host == "www.bing.com":
            return self.bing_it(FLAG)
        else:
            return self.bing_it(host)


listener.start_server(port=13382)

```

Đường cong Elliptic P-256: https://neuromancer.sk/std/nist/P-256

Chương trình sẽ bắt chúng ta truyền vào JSON bao gồm các trường `host`, `private_key`, `curve` và `generator`. Chúng ta được biết các thông tin công khai của 3 domain trong đó có `public_key`. Khi chúng ta truyền input, `public_key` sẽ được tính bằng cách nhân `private_key` với `generator`, nếu trùng với `public_key` của domain `www.bing.com` thì sẽ trả về FLAG. Vậy thì chúng ta chỉ cần tìm ra `private_key` của nó là có thể có được FLAG. Tuy nhiên vì đây là Đường cong Elliptic P-256, việc sử dụng logarit rời rạc dường như là bất khả thi. Vậy phải làm như nào?

Vì đề bài là "CurveBall", chúng ta có thể liên tưởng tới một lỗ hổng có tên y hệt, và nó là CVE-2020-0601. Lỗ hổng này xảy ra ở khi ta được truyền vào phần tử sinh G và nó không được check xem có giống với phần tử sinh gốc của hệ thống sử dụng Elliptic Curve (Và hệ thống của chúng ta cũng đang như vậy). Khi đó, attacker có thể truyền vào $d'$ = $1$ và $G'$ = $Q$. Điều này làm attacker dễ dàng bypass khâu check publickey vì nó vẫn sẽ thỏa mãn do $Q'$ = $d'G'$ = $Q$.

Tuy nhiên, có một vấn đề là việc cho $d$ = $1$ đã bị filter. Chúng ta sẽ có một số cách để bypass:

* Gửi $d$ = $i$ và $Q'$ = $i^{-1}Q$ với $i^{-1}$ = `inverse(i, E.order())`
* Gửi $d$ = $i^{-1}$ và $Q'$ = $iQ$ với $i^{-1}$ = `inverse(i, E.order())`
* Gửi $d$ = $x+1$ và $Q'$ = $Q$ với `x = Q.order() + 1`

Giải thích cho cách thứ 3 thì thì Q.order() là số x đầu tiên thỏa mãn`x*Q=0`. Vì vậy, `(x+1)*Q = Q`

Áp dụng vào code, mình ra được flag:

```python
from sage.all import *
from pwn import *
import json
from Crypto.Util.number import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


Q = E((0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A))

conn = remote('socket.cryptohack.org', '13382')
conn.recvline()
'''
#Method 1
d = 2
Q = Q*int(inverse(2,E.order()))

#Method 2
d = int(inverse(2, E.order()))
Q = 2*Q
'''
# Method 3
d = int(Q.order() + 1)

payload = {"host": "www.bing.com","private_key": d,"curve": "secp256r1","generator": list(map(int,(Q.xy())))}
payload = (json.dumps(payload)).encode()

conn.sendline(payload)
print(conn.recvline())
```

Flag: _crypto{Curveballing\_Microsoft\_CVE-2020-0601}_

#### ProSign 3

This is my secure timestamp signing server. Only if you can produce a signature for "unlock" can you learn more.

Connect at `socket.cryptohack.org 13381`

Attachment: _13381.py_

```python
#!/usr/bin/env python3

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192
from utils import listener
from datetime import datetime
from random import randrange

FLAG = "crypto{?????????????????????????}"
g = generator_192
n = g.order()


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to ProSign 3. You can sign_time or verify.\n"
        secret = randrange(1, n)
        self.pubkey = Public_key(g, g * secret)
        self.privkey = Private_key(self.pubkey, secret)

    def sha1(self, data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()

    def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}

    def verify(self, msg, sig_r, sig_s):
        hsh = bytes_to_long(self.sha1(msg.encode()))
        sig_r = int(sig_r, 16)
        sig_s = int(sig_s, 16)
        sig = Signature(sig_r, sig_s)

        if self.pubkey.verifies(hsh, sig):
            return True
        else:
            return False

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'sign_time':
            signature = self.sign_time()
            return signature

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            r = your_input['r']
            s = your_input['s']
            verified = self.verify(msg, r, s)
            if verified:
                if msg == "unlock":
                    self.exit = True
                    return {"flag": FLAG}
                return {"result": "Message verified"}
            else:
                return {"result": "Bad signature"}

        else:
            return {"error": "Decoding fail"}


listener.start_server(port=13381)

```

Có thể thấy, đây là code minh họa cho việc ứng dụng Elliptic Curve vào chữ ký số (ECDSA).

Các bước khởi tạo chữ ký số trong thuật toán ECDSA bao gồm:

1. Tạo ra cặp khóa công khai và khóa bí mật cho người dùng: Để thực hiện điều này, ta cần tạo ra một đường cong elliptic và một điểm gốc trên đường cong. Sau đó, sử dụng thuật toán Diffie-Hellman, ta tính được khóa công khai và khóa bí mật cho người dùng.
2. Tạo ra thông điệp cần ký: Đây là thông tin cần được ký và gửi đi.
3. Tính toán giá trị băm của thông điệp: Sử dụng một hàm băm như SHA-256 hoặc SHA-512, ta tính toán được giá trị băm của thông điệp cần ký.
4. Tạo chữ ký số: Đầu tiên, ta tạo một số ngẫu nhiên gọi là $k$. Sau đó, tính toán đường cong elliptic $P = k \* G$, trong đó G là base point trên đường cong. Tiếp theo, tính toán giá trị $r = xP (mod n),$ trong đó $xP$ là hoành độ của điểm P trên đường cong elliptic và n là order của base point G. Sau đó, tính toán giá trị $s = k^{-1} \* (hash + d\*r) (mod n)$, trong đó $d$ là khóa bí mật của người ký và hash là giá trị băm của thông điệp cần ký. Cuối cùng, chữ ký số là cặp giá trị $(r,s).$
5. Gửi thông điệp và chữ ký số đến người nhận.

Sau khi nhận được thông điệp và chữ ký số, người nhận sẽ thực hiện quá trình xác thực để kiểm tra tính hợp lệ của chữ ký số.

Quá trình xác nhận (verification) chữ ký số trong ECDSA bao gồm các bước sau:

1. Nhận được thông điệp gốc M, chữ ký số $(r,s)$ và khóa công khai của người ký ECDSA (Q).
2. Tính băm SHA-1 hoặc SHA-256 của thông điệp gốc M, đây là giá trị h.
3. Tính $w = s^{-1} mod n$, với n là order của base point G trên đường cong elliptic, tương ứng với khóa cá nhân của người ký ECDSA.
4. Tính $u1 = hash.w mod n$ và $u2 = r.w mod n.$
5. Tính điểm $W = u1_G + u2_Q$ trên đường cong elliptic. Nếu W = O (điểm vô cùng), thì chữ ký số không hợp lệ.
6. Tính $r' = x(W) mod n$. Nếu $r'$ khác với giá trị $r$ được gửi kèm theo thì chữ ký số không hợp lệ.
7. Nếu $r'$ bằng với giá trị $r$ được gửi kèm theo, thì chữ ký số là hợp lệ. Ngược lại, nếu $r'$ khác với $r$ thì chữ ký số không hợp lệ.

Quá trình xác nhận chữ ký số trong ECDSA sẽ giúp cho người nhận thông điệp có thể đảm bảo rằng thông điệp đó được gửi từ người ký đã được xác thực và không bị sửa đổi trên đường truyền.

Quay lại với challenge của chúng ta, có lỗ hổng xảy ra khi chúng ta chọn số ngẫu nhiên $k$:

```python
def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}
```

Có thể thấy, số $k$ được lấy ngẫu nhiên trong khoảng từ 1 tới n. Đáng nói ở đây là ở dòng 2 ta có `n = int(now.strftime("%S"))` vì vậy n đã không còn là `g.order()` nữa mà là một số khá nhỏ, chỉ nằm trong khoảng 1 tới 59. Để ý thêm, $s = k^{-1} \* (hash + d\*r) (mod n)$. Ta có thể gọi `sign_time` để lấy được `hash`, `r`, `s` và bruteforce `k` để tính ngược lại `d`, hay `secret`. Khi đã có `secret`, ta hoàn toàn có thể tạo ra chữ ký số của riêng mình và gửi lên server.

Dưới đây là code khai thác:

```python
from pwn import *
import json
from ecdsa.ecdsa import *
import hashlib
from Crypto.Util.number import *
from datetime import datetime
from random import randrange

def sha1(data):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    return sha1_hash.digest()

conn = remote('socket.cryptohack.org', '13381')

conn.recvline()

payload = {"option":"sign_time"}
payload = (json.dumps(payload)).encode()

conn.sendline(payload)

output = conn.recvline().decode().strip()

r = int(output[41:89], 16)
s = int(output[100:148], 16)
hash = output[9:30] 
hash = bytes_to_long(sha1(hash.encode()))

g = generator_192
n = g.order()

# k = 1 to 59
# P = k*G
# r = x*P mod n
# s = k^{-1} * (hash + d*r) (mod n), d = secret
for k in range(1,60):
    secret = ((s*k - hash) * inverse(r, n)) % n
    pubkey = Public_key(g, g * secret)
    privkey = Private_key(pubkey, secret)

    now = datetime.now()
    m, n_vul = int(now.strftime("%m")), int(now.strftime("%S"))
    current = f"{m}:{n}"
    msg = f"unlock"
    hsh = sha1(msg.encode())
    sig = privkey.sign(bytes_to_long(hsh), randrange(1, n_vul))
    payload = json.dumps({"option": "verify", "msg": msg, "r": hex(sig.r), "s": hex(sig.s)})

    conn.sendline(payload)
    print(conn.recvline())
```

Flag: _crypto{ECDSA\_700\_345y\_70\_5cr3wup}_
