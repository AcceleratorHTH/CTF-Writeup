# FPTU SecAthon 2024

## **FPTU SecAthon 2024**

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

> Thật ra, cả 2 bài này đều có thể giải dễ dàng bằng GPT. Thậm chí mình đã không cần phải hiểu đề. Cơ mà mình vẫn muốn thử thách xem liệu mình có tự làm được không nên write-up này đã ra đời.

### CRYPTO

Flag format: `FUSec{...}`

Hãy phân tích chương trình mã hóa sau để giải mã chuỗi sau: \['159.96.34.204', '136.182.188.58', '155.20.31.30', '12.234.113.15', '153.170.118.69', '189.152.240.17', '180.27.111.161', '87.205.101.118', '45.1.136.2', '122.3.3.3']

```python
import socket
import struct

def cipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytearray(o)

def encr(pt, k):
    ed = cipher(k, pt.encode('utf-8'))
    padding_length = (4 - len(ed) % 4) % 4
    ed += bytes([padding_length] * padding_length)
    ipa = d2ip(ed)
    return ipa

def d2ip(d):
    ipa = []
    for i in range(0, len(d), 4):
        pd = d[i:i+4]
        if len(pd) < 4:
            pd += b'\x00' * (4 - len(pd))
        ip = socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))
        ipa.append(ip)
    return ipa

def main():
    key = bytearray('supersecretkey', 'utf-8')
    plaintext = "hiyou"
    ipa = encr(plaintext, key)
    print("IPv4 Encoded Data:", ipa)

if __name__ == "__main__":
    main()
```

#### Analysis:

Ở đây, ta sẽ để ý hàm để mã hóa:

```python
def encr(pt, k):
    ed = cipher(k, pt.encode('utf-8'))
    padding_length = (4 - len(ed) % 4) % 4
    ed += bytes([padding_length] * padding_length)
    ipa = d2ip(ed)
    return ipa
```

Hàm `encr` sẽ gọi hàm `cipher` để mã hóa pt. Kết quả sau đó sẽ được thêm padding sao cho độ dài của `ed` là bội số của 4. Kết quả sau đó sẽ được truyền vào hàm `d2ip`:

```python
def d2ip(d):
    ipa = []
    for i in range(0, len(d), 4):
        pd = d[i:i+4]
        if len(pd) < 4:
            pd += b'\x00' * (4 - len(pd))
        ip = socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))
        ipa.append(ip)
    return ipa
```

Hàm này sẽ chia ciphertext của chúng ta thành từng block 4 bytes, nếu không đủ 4 bytes sẽ thêm bytes \x00. Sau đó, mỗi block này sẽ được chuyển thành một địa chỉ IP sử dụng `socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))`. Kết quả sẽ trả về 1 list các IP. Hàm này có thể dễ dàng được reverse:

```python
def ip2d(ipa):
    d = bytearray()
    for ip in ipa:
        d += struct.unpack('!I', socket.inet_aton(ip))[0].to_bytes(4, byteorder='big')
    return d
```

Giờ ta phải tìm cách để decrypt. Để làm được, ta phải nhìn vào hàm `cipher`:

```python
def cipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytearray(o)
```

Hàm này sẽ nhận vào một key là `k` và plaintext là `d`. Có khá nhiều các phép tính có thể gây rối, tuy nhiên, thật ra chúng ta chỉ cần quan tâm vào chỗ liên quan tới plaintext:

```python
o.append(c ^ S[(S[i] + S[j]) % 256])
```

Sau cùng, kết quả trả về chỉ là một phép XOR của từng kí tự trong plaintext với một số được biến đổi phụ thuộc vào key. Nếu ta biết key, ta chỉ cần cho ciphertext vào hàm này là sẽ ra được plaintext.

#### Solution:

```python
import socket
import struct

def uncipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(o)

def decr(ct, k):
    ed = ip2d(ct)
    padding_length = ed[-1]
    ed = ed[:-padding_length]
    pt = uncipher(k, ed)
    return pt
    
def ip2d(ipa):
    d = b''
    for ip in ipa:
        d += struct.unpack('!I', socket.inet_aton(ip))[0].to_bytes(4, byteorder='big')
    return d

ipa = ['159.96.34.204', '136.182.188.58', '155.20.31.30', '12.234.113.15', '153.170.118.69', '189.152.240.17', '180.27.111.161', '87.205.101.118', '45.1.136.2', '122.3.3.3']
key = b'supersecretkey'

flag = decr(ipa, key)
print("Flag:", flag.decode())
```

Flag: _FUSec{howdyiamnowinyourhanddecrypted}_

### Passio

#### Description:

Bobby asked me for help with a RSA problem without n, I looked at it then told him "Are you sure?"

Flag format: `FUSec{...}`

#### Attachments:

_passio.py_

```python
from Crypto.Util.number import bytes_to_long, getPrime

flag = [REDACTED]
m = bytes_to_long(flag)

def encrypt(m):
    e = 65537
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    c = pow(m,e,n)
    a = (p-q)**2
    b = (- a + p**2 + (n/p)**2 )//2
    return e,c,a,b

e,c,a,b = encrypt(m)
print(f"e = {e}")
print(f"c = {c}")
print(f"a = {a}")
print(f"b = {b}")
```

_output.txt_

```
e = 65537
c = 4894338948230470402928707660063586665636133877586628109286241259878275641109260494250817384130584823023329214861979751690561963081617330374455480937234003034778422057395258010775097230080392424358571869844921255624947595968885461336534123911023572529241708327941415913437014197548383286789776095955388635342283203973058210421769275756231192136995375798956898692310541958709215238144712661194018824033701744341479923354157538062092566495209486033904676472485258630642100327543009349262295112047920247519664433630167562500666323341592847174220829798027284008552903119224441839814665400078900184486541916998240568904705
a = 393456223857499815661440893717237240259558532366307287354939441196311328949860421416124009442050320948087336435143720894089753027228194240947622428203376810145932210705733770034443667398090161183195152510628824806145343323163571130613629037517397113076778861973589406580949978852396850740937967511740793366718048124032828534650408728081568348328248119414349235373240606071821213323875846349460120944891074555047511689135169428789631873739254733345142491718992571738713056167486886120514825916775402671062923588643868842453016804611449814240016650065033987944589204140386114206477925791659758110022008860563780659396
b = 11997006831727597838859364379547062689932572744654083166666125612150864313407998295085610421366633182857541448885000307627927684124124072436714719725683483054325256112952201064675498215555364445264410432688875142865327809337551169797877858548294909424784553164763477253336970584908792648056372024900456778666784310573833378011487122136965254930590589667169199039644211411717263218811900115539686093700331167756218836245807831177200156278406549658828318058079509048851064280486981767162435384614595648983175096386101363481286000348432698288589000697700575297289732367910581200141589916469083271346255824183497275727827
```

#### Analysis:

Đây là một bài về RSA. Do p, q là 1024 bit nên có vẻ khá là secure (mình định bảo là bỏ ý định factor N xong nhận ra đếu có N). Có vẻ ta chỉ có thể dựa vào 2 giá trị được cho là `a` và `b`. Hai số này được tạo ra như sau:

$$
a = (p - q)^2 \\ b = \frac{-a + p^2 + \left(\frac{n}{p}\right)^2}{2}
$$

Ta có thể biến đổi thành&#x20;

$$
p^2 - 2pq + q^2 = a \\ p^2 + q^2 = a + 2b
$$

Sử dụng phương pháp thế ta sẽ tính được p\*q (hay N):

$$
pq = b
$$

Thay lại vào phương trình dưới, ta sẽ có như sau:

$$
(p + q)^2 - 2b = a + 2b \\ <=> (p + q)^2 = a + 4b \\ <=> |p + q| = \sqrt{a + 4b}
$$

Có tổng và tích, ta sẽ tìm được p, q và khôi phục được flag.

#### Solution:

```python
from Crypto.Util.number import *
from math import isqrt

e = 65537
c = 4894338948230470402928707660063586665636133877586628109286241259878275641109260494250817384130584823023329214861979751690561963081617330374455480937234003034778422057395258010775097230080392424358571869844921255624947595968885461336534123911023572529241708327941415913437014197548383286789776095955388635342283203973058210421769275756231192136995375798956898692310541958709215238144712661194018824033701744341479923354157538062092566495209486033904676472485258630642100327543009349262295112047920247519664433630167562500666323341592847174220829798027284008552903119224441839814665400078900184486541916998240568904705
a = 393456223857499815661440893717237240259558532366307287354939441196311328949860421416124009442050320948087336435143720894089753027228194240947622428203376810145932210705733770034443667398090161183195152510628824806145343323163571130613629037517397113076778861973589406580949978852396850740937967511740793366718048124032828534650408728081568348328248119414349235373240606071821213323875846349460120944891074555047511689135169428789631873739254733345142491718992571738713056167486886120514825916775402671062923588643868842453016804611449814240016650065033987944589204140386114206477925791659758110022008860563780659396
b = 11997006831727597838859364379547062689932572744654083166666125612150864313407998295085610421366633182857541448885000307627927684124124072436714719725683483054325256112952201064675498215555364445264410432688875142865327809337551169797877858548294909424784553164763477253336970584908792648056372024900456778666784310573833378011487122136965254930590589667169199039644211411717263218811900115539686093700331167756218836245807831177200156278406549658828318058079509048851064280486981767162435384614595648983175096386101363481286000348432698288589000697700575297289732367910581200141589916469083271346255824183497275727827

P = b
S = isqrt(a+4*b)

# x**2 - Sx + P = 0
delta = S**2 - 4*P

x1 = (S + isqrt(delta)) // 2
x2 = (S - isqrt(delta)) // 2

if(isPrime(x1)):
    p = x1
else:
    p = x2

# RSA
N = P
q = N // p
phi = (p-1)*(q-1)
d = inverse(e, phi)

flag = long_to_bytes(pow(c, d, N))
print("Flag:",flag.decode())
```

Flag: _FUsec{S1mpl3\_biN0m1al\_sQu4r3}_



**© 2024,Pham Quoc Trung. All rights reserved.**
