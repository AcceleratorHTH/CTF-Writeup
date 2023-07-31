# **UIUCTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### Three-Time Pad
"We've been monitoring our adversaries' communication channels, but they encrypt their data with XOR one-time pads! However, we hear rumors that they're reusing the pads...\n\nEnclosed are three encrypted messages. Our mole overheard the plaintext of message 2. Given this information, can you break the enemy's encryption and get the plaintext of the other messages?"

Attachment: c1,c2,c3,p2

Ở bài này ta có 3 file p1, p2, p3 bị XOR với một one-time pads để tạo nên 3 file c1, c2, c3. Đề bài cung cấp cho ta 3 file mã hóa và p2.\
Trong đề bài, ta được biết tác giả chỉ dùng 1 pad để XOR với mỗi file. Vậy thì mọi chuyện đã trở nên đơn giản hơn. Sử dụng tính đối xứng của XOR, ta chỉ cần XOR p2 với c2 để tìm ra pad. Tiếp theo sử dụng pad đó để XOR với c1 và c3, ta sẽ ra được p1 và p3.
```python3
from pwn import *

c1 = read('c1')
c2 = read('c2')
c3 = read('c3')
p2 = read('p2')

pad = xor(p2,c2)
p1 = xor(c1,pad)
p3 = xor(c3,pad)

print("p1 = ",p1)
print("p2 = ",p2)
print("p3 = ",p3)
```
Flag: uiuctf{burn_3ach_k3y_aft3r_us1ng_1t}

### At Home
Mom said we had food at home

Attachment: chal.py
```python3
from Crypto.Util.number import getRandomNBitInteger

flag = int.from_bytes(b"uiuctf{******************}", "big")

a = getRandomNBitInteger(256)
b = getRandomNBitInteger(256)
a_ = getRandomNBitInteger(256)
b_ = getRandomNBitInteger(256)

M = a * b - 1
e = a_ * M + a
d = b_ * M + b

n = (e * d - 1) // M

c = (flag * e) % n

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
```
chal.txt
```
e = 359050389152821553416139581503505347057925208560451864426634100333116560422313639260283981496824920089789497818520105189684311823250795520058111763310428202654439351922361722731557743640799254622423104811120692862884666323623693713
n = 26866112476805004406608209986673337296216833710860089901238432952384811714684404001885354052039112340209557226256650661186843726925958125334974412111471244462419577294051744141817411512295364953687829707132828973068538495834511391553765427956458757286710053986810998890293154443240352924460801124219510584689
c = 67743374462448582107440168513687520434594529331821740737396116407928111043815084665002104196754020530469360539253323738935708414363005373458782041955450278954348306401542374309788938720659206881893349940765268153223129964864641817170395527170138553388816095842842667443210645457879043383345869
```

Thoạt nhìn thì đây giống một bài liên quan tới RSA, với những dữ kiện được cung cấp sẵn là n, e và c. Mình không tìm ra được ý tưởng gì về những thứ đề bài cho về a, b, a_, b_, nên mình đã đọc kĩ lại code thì đây không phải RSA :v. n, e, c chỉ đơn giản là tên biến. Vì vậy, mình sẽ brute-force dựa trên công thức của c
```
    c = (flag * e) % n 
<=> flag*e = k*n + c
```
Code đơn giản để brute-force:
```python3
from Crypto.Util.number import *

e = 359050389152821553416139581503505347057925208560451864426634100333116560422313639260283981496824920089789497818520105189684311823250795520058111763310428202654439351922361722731557743640799254622423104811120692862884666323623693713
n = 26866112476805004406608209986673337296216833710860089901238432952384811714684404001885354052039112340209557226256650661186843726925958125334974412111471244462419577294051744141817411512295364953687829707132828973068538495834511391553765427956458757286710053986810998890293154443240352924460801124219510584689
c = 67743374462448582107440168513687520434594529331821740737396116407928111043815084665002104196754020530469360539253323738935708414363005373458782041955450278954348306401542374309788938720659206881893349940765268153223129964864641817170395527170138553388816095842842667443210645457879043383345869

k = 0
while True:
    flag = long_to_bytes((k*n + c) // e)
    if b'uiuctf{' in flag:
        print(flag)
        break
    k = k + 1
```
Flag: uiuctf{W3_hav3_R5A_@_h0m3}

### crack_the_safe
"I found this safe, but something about it seems a bit off - can you crack it?"

Attachment: chal.py
```python3
from Crypto.Cipher import AES
from secret import key, FLAG

p = 4170887899225220949299992515778389605737976266979828742347
ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")

def crack_safe(key):
    return pow(7, int.from_bytes(key, 'big'), p) == 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759

assert crack_safe(key) and AES.new(key,AES.MODE_ECB).decrypt(ct) == FLAG
```

Đây là một bài liên quan tới AES ECB. Ở đây đã có sẵn cipher, việc của chúng ta là tìm key. Dữ kiện duy nhất có liên quan tới key là hàm *crack_safe*.
```python3
def crack_safe(key):
    return pow(7, int.from_bytes(key, 'big'), p) == 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
```
Nhìn qua, mình nhận thấy có thể sử dụng Logarit rời rạc để tính được key. Mình thử sử dụng sage math để làm việc này
```python3
from sage.all import *

#y = g^x mod p

def rev_exp_func(data,e,p):
    G = Integers(p)
    return G(data).log(G(e))
 
g = 7
y = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347
x = rev_exp_func(y, g, p)
print(x)
print(pow(g, x, p) == y)
```

Tuy nhiên xem chừng sử dụng logarith rời rạc có sẵn trong sage có vẻ mất khá nhiều thời gian nên mình phải tự implement nó:
```python3
from sage.all import crt, factor

#y = g^x mod p

def babystep_giantstep(g, y, p, q=None):
    if q is None:
        q = p - 1
    m = int(q**0.5 + 0.5)
    table = {}
    gr = 1  
    for r in range(m):
        table[gr] = r
        gr = (gr * g) % p
    try:
        gm = pow(g, -m, p)  
    except:
        return None
    ygqm = y                
    for q in range(m):
        if ygqm in table:
            return q * m + table[ygqm]
        ygqm = (ygqm * gm) % p
    return None
 
def pohlig_hellman_DLP(g, y, p):
    crt_moduli = []
    crt_remain = []
    for q, _ in factor(p-1)[:-1]:
        x = babystep_giantstep(pow(g,(p-1)//q,p), pow(y,(p-1)//q,p), p, q)
        if (x is None) or (x <= 1):
            continue
        crt_moduli.append(q)
        crt_remain.append(x)
    x = crt(crt_remain, crt_moduli)
    print(crt_remain, crt_moduli)
    return x
 
g = 7
y = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347
x = pohlig_hellman_DLP(g, y, p)
print(x)
print(pow(g, x, p) == y)
```
Kết quả trả về:
```
[3, 13, 500, 52782, 9948705845, 104851607833] [19, 151, 577, 67061, 18279232319, 111543376699]
218431302567753383798750014148619
False
```
Tuy nhiên, mình thử lấy kết quả trả về làm key thì bị lỗi về số bits. Check thử thì mình thấy giá trị trả về mới có 108-bits. Đối với AES, mình sẽ cần 128-bits. Vì vậy ở đây mình sẽ brute-force key thật như sau:
```python3
from Crypto.Util.number import *

y = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
p = 4170887899225220949299992515778389605737976266979828742347
x = 218431302567753383798750014148619
crt_moduli = [19, 151, 577, 67061, 18279232319, 111543376699]

m = 1
for i in crt_moduli:
    m *= i
    
k = 0
while True:
    key = x + k*m
    if pow(7,key,p) == y:
        print(key)
        break
    k+=1
```
Để hiểu đống code trên, hãy nhìn vào nguyên tắc cơ bản của Thuật toán Phần dư Trung Quốc (Chinese Remainder Theorem - CRT).

CRT được sử dụng để giải hệ phương trình dạng x ≡ a (mod m), trong đó a và m là các số nguyên. Nếu m là các số nguyên tố cùng nhau, thì có một giải pháp duy nhất cho hệ phương trình này modulo M, trong đó M là tích của tất cả m.

Trong trường hợp của thuật toán Pohlig-Hellman, m chính là tích của các số nguyên tố q (crt_moduli), và x là giải pháp tìm được thông qua thuật toán Pohlig-Hellman.

Tuy nhiên, do dữ liệu vấn đề, có thể có nhiều giải pháp x khác nhau thỏa mãn g^x ≡ y (mod p). Những giải pháp này có thể được biểu diễn dưới dạng x + k\*m, với k là một số nguyên không âm. Điều này xuất phát từ sự thực rằng nếu x là một nghiệm của g^x ≡ y (mod p), thì x + k*m cũng sẽ là một nghiệm, vì m chia hết cho p - 1.

Do vậy, mình brute-force các x có thể và tìm ra x thỏa mãn pow(7,x,p) == y. Giờ đây, việc còn lại là giải mã AES thoi
```python3
from Crypto.Util.number import *
from Crypto.Cipher import AES

ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")
key = 201920744490721838622302286278878924260

print(AES.new(long_to_bytes(key), AES.MODE_ECB).decrypt(ct))
```
Flag: uiuctf{Dl0g_w/\_\_UnS4F3__pR1Me5_}

**© 2023,Pham Quoc Trung. All rights reserved.**
