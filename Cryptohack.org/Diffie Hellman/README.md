# **Cryptohack.org**

# **DIFFIE HELLMAN WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### Diffie-Hellman
1. Alice và Bob thỏa thuận sử dụng chung một số nguyên tố $p$ và căn nguyên thủy $g$
2. Alice chọn một số nguyên bí mật $a$, và gửi cho Bob giá trị $A$ = $g^a$ mod $p$
3. Bob chọn một số nguyên bí mật $b$, và gửi cho Alice giá trị $B$ = $g^b$ mod $p$
4. Alice tính $s$ = $B^a$ mod $p$
5. Bob tính $s$ = $A^b$ mod $p$

Cả Alice và Bob đều có được giá trị chung cuối cùng vì $(g^a)^b$ = $(g^b)^a$ mod $p$. Lưu ý rằng chỉ có $a$, $b$ và $s$ là được giữ bí mật. Tất cả các giá trị khác như $p$, $g$, $A$ và $B$ được truyền công khai. Sau khi Alice và Bob tính được bí mật chung, cả hai có thể sử dụng nó làm khóa mã hóa chung chỉ có hai người biết để gửi dữ liệu trên kênh truyền thông mở.

### Parameter Injection
You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at `nc socket.cryptohack.org 13371`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x92832cafd045eb4b070651f025cd8726fd477731b2b2fe4d118f38c1d06cf0d81051c5d86445f86cb65f45fc956cc09c654964a1a41c43c909c0de19e4c227b6f54ce132d7b75fc3b551bf9717050677895ee354f09c9d4074554ac9041d4aba9745802beae88dc5f92395815cd200b4545a07387c160dd7565046d68e1ef3c74b2bcb71b5bcb7569cf43c921e1b394eb121562b55f9fbd898ea688ecb58d796fe35b7cdd76a775e528261d98fa48d5745e89abfecd951f997042969a13bd73b"}
Send to Bob: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x92832cafd045eb4b070651f025cd8726fd477731b2b2fe4d118f38c1d06cf0d81051c5d86445f86cb65f45fc956cc09c654964a1a41c43c909c0de19e4c227b6f54ce132d7b75fc3b551bf9717050677895ee354f09c9d4074554ac9041d4aba9745802beae88dc5f92395815cd200b4545a07387c160dd7565046d68e1ef3c74b2bcb71b5bcb7569cf43c921e1b394eb121562b55f9fbd898ea688ecb58d796fe35b7cdd76a775e528261d98fa48d5745e89abfecd951f997042969a13bd73b"}
Intercepted from Bob: {"B": "0x603a1ff9bff4f88cbebcc9ffebdc9c3541ad9575cc6e0f9cdb82e802351808d077e64bc8be0fb06224d0fe9d7f2cfae5a3fdf23c8495f4da097b27000b9d4fb532616a9d9a7036fdaf3ddfa5b7ce2d5918696ec4d6baa84fe63f5fce1a01a16b12eab0b30c58a10d4dd8b147bdef206bb3923a440f142d1f448edf540b3145704fcd116069126adf00ae846136a130e8620f1f474ce9f4e49d03e500f8b487db890cdc737fb577a3bb6ef0d84bbecebb108fb25f14891ad838c162560cccd247"}
Send to Alice: {"B": "0x603a1ff9bff4f88cbebcc9ffebdc9c3541ad9575cc6e0f9cdb82e802351808d077e64bc8be0fb06224d0fe9d7f2cfae5a3fdf23c8495f4da097b27000b9d4fb532616a9d9a7036fdaf3ddfa5b7ce2d5918696ec4d6baa84fe63f5fce1a01a16b12eab0b30c58a10d4dd8b147bdef206bb3923a440f142d1f448edf540b3145704fcd116069126adf00ae846136a130e8620f1f474ce9f4e49d03e500f8b487db890cdc737fb577a3bb6ef0d84bbecebb108fb25f14891ad838c162560cccd247"}
Intercepted from Alice: {"iv": "b1ced97538319178619c3fce18d01d6d", "encrypted_flag": "a42b0125c670876f832f2bf6854b86fa2162735de9233d4a4f13dffcc7ea5ee1"}
{"iv": "b1ced97538319178619c3fce18d01d6d", "encrypted_flag": "a42b0125c670876f832f2bf6854b86fa2162735de9233d4a4f13dffcc7ea5ee1"}
```


Bài này cho phép mình đứng giữa cuộc trao đổi của Alice và Bob, tùy ý sửa đổi nội dung được gửi. Sau cùng, Alice sẽ gửi `iv` và `encrypted_flag` cho Bob.

Ý tưởng của mình là gửi B = 1. Khi đó dễ dàng biết được s = B^a mod p = 1^a mod p = 1.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
import json


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
    
conn = remote("socket.cryptohack.org", "13371")

A = conn.recvuntil(b"}").decode().strip()
conn.sendline(A[24:].encode())
conn.recvuntil(b'}')
conn.sendline(b'{"B":"0x01"}')
infor = conn.recvuntil(b'}').decode().strip()[39:]
infor = json.loads(infor)

shared_secret = 1
iv = infor['iv']
ciphertext = infor['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))
```
Flag: *crypto{n1c3_0n3_m4ll0ry!!!!!!!!}*

### Export-grade
Alice and Bob are using legacy codebases and need to negotiate parameters they both support. You've man-in-the-middled this negotiation step, and can passively observe thereafter. How are you going to ruin their day this time?

Connect at `nc socket.cryptohack.org 13379`

```
Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Send to Bob: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Intercepted from Bob: {"chosen": "DH1024"}
Send to Alice: {"chosen": "DH1024"}
Intercepted from Alice: {"p": "0xf2639ce2bdb2e67154813bcbda8e5a09ddaa1235c5e76300602e29ada9dd6dfddf36b3c6a676891ddb1462de67cc27a45f84d8720b8bfdcb653c82814397998e84aafca63a8b4ae05d3193e7566173441d505dc3caea006f938d421de7e80748297496436e559fe9c443201de066cd7570a8a40c80a306309dfb4da48277858b", "g": "0x2", "A": "0x30c1c9627d51042c163bac20c6edb2f7680868cee34a2f71ce8c2f7432934622e331a43fc25159dc9383088605a7476f4f773a5a625189d49d832ea79dd04bad5235e847e5a900a5c35f7f6ca1ecaf57dc4c9cd86026decf6848c9439056fad3642ea546d1331a11d66715403052514b1c4c7b874eb5d2e7ccfbdd7ceca4ded"}
Intercepted from Bob: {"B": "0x10435051c95cdd8fa9436ae0bbe49aa2c4e767673257bcc1abee9ea1144aab0c694e07a2353aec72b28a839ecb50a10e93d29b81abdea059e7728b0d349b72476afb6f1993639768ca84da8a02dc1e3f08bcbba647462258230d6d18dafe3f604f187d26675cb9b67d6219ca058e6b6a4b6e322511744316cfcdec2548d0129b"}
Intercepted from Alice: {"iv": "3e4f208eb32be9c0da46bebda95562e2", "encrypted_flag": "9d8744e8dd0dd2c96f6dfc286edb6bda8cd713b838bad94d5b76298f77588685"}
```

Ở đây, Alice cho Bob chọn kiểu Diffie-Hellman, sau đó sử dụng nó để trao đổi khóa. Dữ liệu trả về là các khóa công khai.
Mình sẽ bắt Bob chỉ được chọn DH64. Khi đó, các khóa bí mật sẽ chỉ là 64-bit. Mình có thể dễ dàng giải bài toán logarith rời rạc để tìm ra chúng.

Trước hết, sử dụng pwntool để lấy dữ liệu từ server
```python
from pwn import *
import json

conn = remote("socket.cryptohack.org", "13379")

conn.recvuntil(b'Send to Bob:')
conn.sendline(b'{"supported": ["DH64"]}')
conn.recvline(b'Send to Alice:')
conn.sendline(b'{"chosen": "DH64"}')

Alice = json.loads(conn.recvline().decode().strip()[39:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
infor = json.loads(conn.recvline().decode().strip()[24:])

p = int(Alice['p'], 16)
g = int(Alice['g'], 16)
A = int(Alice['A'], 16)
B = int(Bob['B'], 16)

print(f"p = {p}\ng = {g}\nA = {A}\nB = {B}\ninfor = {infor}")
```

Ta có $B$ = $g^b$ mod $p$. Mình sẽ sử dụng logarith rời rạc trong sagemath để tính b.

```
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.5, Release Date: 2022-01-30                     │
│ Using Python 3.10.6. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: G = Integers(16007670376277647657)
sage: B = G(405929529387091256)
sage: g = G(2)
sage: b = B.log(g)
sage: b
856295849221861333
```

Tìm ra b thì dễ dàng tính được s qua công thức $s$ = $A^b$ mod $p$ để giải mã flag
```python
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
    

p = 16007670376277647657
g = 2
A = 12703859298456983579
B = 405929529387091256
infor = {'iv': '2ec5ac64fba6a1667aacb2ebdaaa895a', 'encrypted_flag': '7842eaf213d949c9255c48392cd8eab1e8793ae6c75b3ca7b9140407bbf90067'}

b = 856295849221861333

shared_secret = pow(A,b,p)
iv = infor['iv']
encrypted_flag = infor['encrypted_flag']

print(decrypt_flag(shared_secret, iv, encrypted_flag))
```
Flag: *crypto{d0wn6r4d35_4r3_d4n63r0u5}*

### Static Client
You've just finished eavesdropping on a conversation between Alice and Bob. Now you have a chance to talk to Bob. What are you going to say?

Connect at `nc socket.cryptohack.org 13373`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xedcf481fd750b2fc7ee5daa95b90f42657e071ea39421bc56c2fdfc62a893e3a1fa1ebdd29f60e5ce51d313d0774ed061a35b0daee81a4ef4b8ee3748643bb61b805e60704e79b8567c388f1b6c5ed0c8bb00b717f0737e4fef99a18f8223c252da15f01951a3fa4be570035d2d66aa7a15d7f8aba28fb997cdbf2dbfca3f61f53b94547ce20c702e6d8567e4ff4354ff205028cf75924e8e526082384ed2ee29e63e01d5012007fe180c68a986e186be6ed9b92736955c3fab5d6739b1cdc4a"}
Intercepted from Bob: {"B": "0x8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0"}
Intercepted from Alice: {"iv": "1249b18ac1720c3ecf0335bb3b6a3ce7", "encrypted": "9b136c4de5bcf1618ec9ab6ffa05fa87153508fc248932fd96aee39f5aadff91"}
Bob connects to you, send him some parameters: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xedcf481fd750b2fc7ee5daa95b90f42657e071ea39421bc56c2fdfc62a893e3a1fa1ebdd29f60e5ce51d313d0774ed061a35b0daee81a4ef4b8ee3748643bb61b805e60704e79b8567c388f1b6c5ed0c8bb00b717f0737e4fef99a18f8223c252da15f01951a3fa4be570035d2d66aa7a15d7f8aba28fb997cdbf2dbfca3f61f53b94547ce20c702e6d8567e4ff4354ff205028cf75924e8e526082384ed2ee29e63e01d5012007fe180c68a986e186be6ed9b92736955c3fab5d6739b1cdc4a"}
Bob says to you: {"B": "0x8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0"}
Bob says to you: {"iv": "aae2cdd8d2547a1e0c640b7429e6596b", "encrypted": "7c73ce982f6d7416b76373378fc90860f52517a4eb43e71df63975e1d24aae04e3a3e874fee57dde00f17b3761ef178577b5680d2460a53c8d3df06db0b4e56bd626fc3b53752a72b5dfc67bf043e2c9"}
```
Khác với trước, giờ mình có thể gửi yêu cầu tới Bob, rồi Bob sẽ trả về *B*, *iv* và *encrypted_flag*. 

Ở đây, ta biết *shared_secret* của Bob sẽ được tính bằng công thức $s$ = $A^b$ mod $p$. Vậy, mình có thể gửi cho Bob g = A. Khi đó, khóa B gửi đi của B sẽ trở thành $B$ = $g^b$ mod $p$ = $A^b$ mod $p$ = $s$. Nếu số bí mật b của Bob không đổi (Đề bài là static client) thì $s$ ở đây chính là *shared_secret* ban đầu khi trao đổi khóa với Alice.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
import json


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
    
conn = remote("socket.cryptohack.org", "13373")

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])
payload = {"p" : Alice['p'], "g" : Alice['A'], "A": "0xff"}
conn.sendline(json.dumps(payload).encode())

s = conn.recvline().decode().strip()[71:-2]
conn.recvline()


shared_secret = int(s, 16)
iv = info['iv']
ciphertext = info['encrypted']

print(decrypt_flag(shared_secret, iv, ciphertext))

```

Flag: *crypto{n07_3ph3m3r4l_3n0u6h}*

### Static Client 2
Bob got a bit more careful with the way he verifies parameters. He's still insisting on using the p and g values provided by his partner. Wonder if he missed anything?

Connect at `nc socket.cryptohack.org 13378`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xb2137c78247c9741b7b7e163fa3591a71e22864b5c50d7fe7c163e2223f537ae743ab81e6c4e1c891ed872dffd5ca77544fb7c0d730844203ce7e2defec6fa89b13ce51ad4244deac72ce97776e6c2bc843268023eb0737b8de132445eabcbf133b5d13cd55670142243ee8b8f42d84cc3f156c3bfaf897964680a6ae2c2ee74e236f06f52b405e90becea8f52c9cbabcb9179750089e7d6d773867c24e9c14971f2998c34b14364b13d5e19fc31854435a6f5b4045190af31ad5f7e4f90c0e7"}
Intercepted from Bob: {"B": "0xd0d69585c6586c3b1a23e04245826be6db4aed1c9bc70f7110a30165ca878d31434aa357c2bd26d3c398284a17319504e1aeead141234afeb57dfef11417fdec44b21cea83920f300f4e0c3fb573a895371b24652c5e6ea0539b7719f0f966ac7adb9a292cc49f4d8b39560e02fa82aab3c273cc7df512a80e2de6f0e8840c00554f09460eaa2e221173a9ca13182d4e1342b1e54965e16ca5fc23b1aae80aedc7fb80e1aa9be8b0274812676e8e570e1abf65eea0c49f18794a5afba975c7c7"}
Intercepted from Alice: {"iv": "0e0c4321b016de2eb36b01d2df93ed75", "encrypted": "2a1867ceba61e4b84c6f02b48628c75e33a068ea464594c4317abf28283f2d44dc75fc95881682aafce2dc98b39a555c"}
Bob connects to you, send him some parameters: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g":"0xb2137c78247c9741b7b7e163fa3591a71e22864b5c50d7fe7c163e2223f537ae743ab81e6c4e1c891ed872dffd5ca77544fb7c0d730844203ce7e2defec6fa89b13ce51ad4244deac72ce97776e6c2bc843268023eb0737b8de132445eabcbf133b5d13cd55670142243ee8b8f42d84cc3f156c3bfaf897964680a6ae2c2ee74e236f06f52b405e90becea8f52c9cbabcb9179750089e7d6d773867c24e9c14971f2998c34b14364b13d5e19fc31854435a6f5b4045190af31ad5f7e4f90c0e7", "A":"0x02"}
Bob says to you: {"error": "That g value looks mighty suspicious"}
```

Trông cũng giống bài trước, tuy nhiên cách làm đã được fix. Vậy chúng ta phải nghĩ ra cách khác. Ở đây sẽ là dựa vào $p$, hay chính xác là hướng đến một $p$ là **smooth number**.

Về cơ bản, một số n-smooth number là số có các thừa số nguyên tố đều nhỏ hơn hoặc bằng n. Cơ mà để làm gì?

Trong bài toán Logarit rời rạc, có thuật toán gọi là Pohlig-Hellman. Thuật toán này khi được sử dụng với các nhóm smooth (smooth p) có thể dễ dàng giải bài toán logarit rời rạc. Điều kiện ở đây là smooth p + 1 phải là số nguyên tố.

https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm

Vậy ở đây ta muốn tìm một p có thể viết dưới dạng tích của các số nguyên tố nhỏ (do đó tạo ra nhiều nhóm con nhỏ) để sau này dễ dàng phân tích thành thừa số nguyên tố. Một số phương pháp mà người ta có thể thử là: 
* Primorial: Viết số p-smooth là tích của mọi số nguyên tố liên tiếp (tức là 2 * 3 * 5 * 7). *
* Factorial: Tạo tích của các số thừa số nhỏ tăng theo lũy thừa nào đó bằng cách tính tích của mọi số (tức là 2 * 3 * 4 * 5 ...) cho đến khi bạn tìm thấy p-smooth như mong muốn. Lưu ý: hãy nghĩ rằng kết quả cuối cùng sẽ chỉ chứa các thừa số nguyên tố. Ví dụ: 4 không phải là số nguyên tố nhưng có thể được viết là 2^2 trong đó cơ số 2 của bạn là số nguyên tố (điều này đề cập đến định lý cơ bản của số học: Mọi số nguyên lớn hơn 1 là số nguyên tố hoặc có thể được viết dưới dạng tích các thừa số nguyên tố của nó ).

Ở đây mình sẽ chọn cách thứ 2 vì nó sẽ nhanh hơn. Sau đó mình sử dụng số nguyên tố p-smooth + 1. Bằng cách này, khi Bob gửi cho mình B, đó sẽ là 1 số mà ta hoàn toàn có thể tính ngược lại b thông qua Logarith rời rạc sử dụng Pohlig-Hellman

```python
from pwn import *
import json
from Crypto.Util.number import isPrime

conn = remote("socket.cryptohack.org", 13378)

def get_nsmooth(n):
    i = 2
    p_smooth = 1
    for _ in range(1000):
        if p_smooth < n or not isPrime(p_smooth + 1):
            p_smooth *= i
            i += 1
        else:
            break

    if(p_smooth > p and isPrime(p_smooth + 1)):
        return p_smooth
    else:
        return -1

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])
p = int(Alice['p'], 16)
    
p_smooth = get_nsmooth(p)
print(f"p_new = {p_smooth + 1}")

payload = {'p': f'{hex(p_smooth + 1)}', 'g': '0x02', 'A': Alice['A']}
payload = json.dumps(payload).encode()

conn.sendline(payload)
B = conn.recvline().decode().strip()[71:-2]
B = int(B, 16)
print(f"B = {B}\ng = 2\nA = {int(Alice['A'], 16)}\np = {int(Alice['p'], 16)}\niv = {info['iv']}\nencrypted = {info['encrypted']}")
```

Sử dụng B thu được và g để tìm ra b sử dụng sagemath discrete_log
```
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.5, Release Date: 2022-01-30                     │
│ Using Python 3.10.6. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: p_new = 211610334721925248295571704107762986587946391083761306765577830155780903308444721678617883710831709407225912
....: 41807108382859295872641348645166391260040395583908986502774347856154314632614857393087562331369896964916313777278292
....: 96520278062630483972525432308332124593592034544576046931571668880818138608393573770528435339586952086174215612749638
....: 50907436023090498209349171347554618730129457049389551327246630758804369959040936547093495526569656105465403720484210
....: 26608925808493978164019986593442564905462745669412326023291812269608558332157759989142549649265359278848084868920655
....: 698461242425344000000000000000000000000000000000000000000000000000000000000000000000000000001
....: B = 1600729160738925969058103184728822977949974564637406354038540199676215526297798147821613486406916540653800683149
....: 59785767853439240452801998048915395942179651207760147591350824251210426090210055280816549042813602445078273544574475
....: 46944225866080782042852597289847705024436037858968761035090575707827446431870582128988960557196060711830455235473950
....: 82899280410250574666923154481615031969792114266918194572453521149320090704020682099779986161228831722308894105906923
....: 01951911223761282657222638891640442839658757635514445826007981483807580104208867763910610010473053646720408322053462
....: 71901253494378160709499034229971447322456128744848304514349631590285459515180345452750189
....: g = 2
sage: G = Integers(p_new)
sage: b = discrete_log(G(B), G(g))
sage: b
1919572943691512325783103720167834163677411292709378502535498859989993544026380143919501049584589675317643993465536543895780854808442293000014297210200227069779643763121704810281976733978781152126062646602812482025293137787739116693980988513420732289020477701182639042794562638875881378349771734410919106042203493166198706573467903966100368713572415175654342828296086659529676015616513470105470901979846373335352656586302787870238998914215908919919219987614105175
```
Có thể thấy, dù B rất dài nhưng nhờ có số p như trên, ta hoàn toàn có thể lấy lại được b nhanh chóng.

Cuối cùng, sử dụng A, b, p để tính ra flag
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    

A = 2052730840778522725669668850809100712528424084675319406137452322054730931900872505650905496995116498865694271228892449276411398359180769611581068217937446024620680285675403816343216083830861126241167102300716748426835012242070425228077263131787826383516688770855625484564656277372321822956964293646818485386901681307133741734402033783689740031735720766591298216351519474361285666397800101752787565713771157365592038104615137119676266163984114479946897453459568557
b = 1919572943691512325783103720167834163677411292709378502535498859989993544026380143919501049584589675317643993465536543895780854808442293000014297210200227069779643763121704810281976733978781152126062646602812482025293137787739116693980988513420732289020477701182639042794562638875881378349771734410919106042203493166198706573467903966100368713572415175654342828296086659529676015616513470105470901979846373335352656586302787870238998914215908919919219987614105175
p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
iv = 'fb884e8e30e911a3bfbe45bce9f72967'
encrypted = '7ad7f3c9b9ecbd329b2f5bc7d85f459a8f7b07b10670648dd22895fb66bbaf0ae3e5279a8b5fe917192c57641fbd3acd'

print(decrypt_flag(pow(A,b,p), iv, encrypted))
```
Flag: *crypto{uns4f3_pr1m3_sm4ll_oRd3r}*


### Additive
Alice and Bob decided to do their DHKE in an additive group rather than a multiplicative group. What could go wrong?

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at `nc socket.cryptohack.org 13380`
```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xe934888a059a8395fc4c28b8fb79aeac618a691f50b185fbc75a53223985758c8a23fa3112b6d75c483179f933f19cbc5806b824b542c2b70908b5e48f2d389839236f5bf8f9859bba758de6fa6faeb8992ce576051689f38dd06a2b8ea59ca2a8ab4562166a5f96a4870d49a7b3ba5f3474c81831fa1920ee9071385a226849da3106258b36e6ceea4b09ddb18d66860f471c202fed3646a59f0c6dab8c18390d334e4c2222272437fcd215512728364ecf11199827178c436917a713812683"}
Intercepted from Bob: {"B": "0xf7702e78b6af7646301422ff13e9395368830173a6df07005553b6d2862a45470fde3284e7f52371b2120349fcce20d425a9bd12715da9a0901e2cdf27e0412c5fa45f9b0854c570633decd511b3da61eb088398ed69f3d51274e9f870d0a52be2ce4cb1fd3187d27509a64c77bdf598e840d5672b7e96a96ec4b2dc103dd82d3c58a0922051b088020c7f40c6446ec4f7baf582d87e1b54d51f9d25ce46166084b0ec0fbea3635858516b0f9effa4f50d160d86af12af7d689c2fda50c5369d"}
Intercepted from Alice: {"iv": "2309518f3a14126e348581233d705be1", "encrypted": "447f036f950f6d61a4ea199ca0b85f825b9e27699b1dda8be8d71b499a51bd0a3f7e4a9db3c889293afccf1bbf0f040f"}
```
Chương trình cho chúng ta đủ thông tin công khai và không cho input gì hết.

Theo như mình tìm hiểu thì bình thường DH sử dụng Multiplicative group. Nếu sử dụng Additive group, nó sẽ thành kiểu như này:
1. Alice và Bob thỏa thuận sử dụng chung một số nguyên tố $p$ và căn nguyên thủy $g$
2. Alice chọn một số nguyên bí mật $a$, và gửi cho Bob giá trị $A$ = $g*a$ mod $p$
3. Bob chọn một số nguyên bí mật $b$, và gửi cho Alice giá trị $B$ = $g*b$ mod $p$
4. Alice tính $s$ = $B*a$ mod $p$
5. Bob tính $s$ = $A*b$ mod $p$

Ơ thế dễ vl :v code thôi
```python
from pwn import *
import json
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

conn = remote("socket.cryptohack.org", 13380)

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])


B = int(Bob['B'], 16)
g = 2
p = int(Alice['p'], 16)
A = int(Alice['A'], 16)
iv = info['iv']
encrypted = info['encrypted']

b = B*int(inverse(g, p))
s = A*b % p

print(decrypt_flag(s, iv, encrypted))
```

Flag: *crypto{cycl1c_6r0up_und3r_4dd1710n?}*

**© 2023,Pham Quoc Trung. All rights reserved.**
