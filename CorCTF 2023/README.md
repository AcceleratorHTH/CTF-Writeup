# **COR\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### fizzbuzz100
lsb oracles are pretty overdone... anyway here's fizzbuzz
```
nc be.ax 31100
```
Attachment: fizzbuzz100.py
```python3
#!/usr/local/bin/python
from Crypto.Util.number import *
from os import urandom

flag = open("flag.txt", "rb").read()
flag = bytes_to_long(urandom(16) + flag + urandom(16))

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
assert flag < n
ct = pow(flag, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")

while True:
    ct = int(input("> "))
    pt = pow(ct, d, n)
    out = ""
    if pt == flag:
        exit(-1)
    if pt % 3 == 0:
        out += "Fizz"
    if pt % 5 == 0:
        out += "Buzz"
    if not out:
        out = pt
    print(out)

```
Bài này là một dạng về mã hóa RSA. Ở đây, challenge đã cho mình sẵn n, e và c mỗi khi netcat đến server, sau đó nhận input từ người dùng và gán vào biến ct. Thực hiện giải mã ct theo công thức trong RSA và sau một số điều kiện sẽ in ra biến out.\
Vấn đề ở đây là khi chúng ta input cipher của chúng ta vào, điều kiện *if pt == flag* sẽ trả về TRUE và chương trình sẽ exit. Ngoài ra ở đây còn 2 điều kiện khác nữa. Vậy phải làm như nào đây?\
Ban đầu, do khi mình input 1 số nào đó (Giả sử như thời điểm mình connect thì là 4) thì chương trình vượt qua được hết các điều kiện và in ra pt. Lúc này, pt được tính bằng công thức *pt = pow(4,d,n)*. Với n và pt đã biết, mình có thử tính d sử dụng Logarith rời rạc.
```python3
from sage.all import *

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
 
ct = 4
pt = 23912697534195278989342718621762492541414084630039493484756678452954565288495951623572040006829310369146573686633489722242564914439443949985456331258970863215408396964118583585223447461516691868779784083681853353565726246703905888910972549433441009915753494418680419447035642985055275467484189437099313348324
n = 131308582406707149982473652198614944202593926307081187318506348336877374738499044274769908687309433754003064219149985647802452457841653104937149435448010569522854472124267915673736323460042450738172537799218981410345992653635622033327183254337754812299124447788944034725286980798367062358129904707823701930691
d = pohlig_hellman_DLP(ct, pt, n)
print(d)
print(pow(ct, d, n) == pt)
```

Tuy nhiên xem chừng cách nào có vẻ không khả thi bởi lẽ pt và n quá lớn. Vậy chỉ có cách nhập input kiểu gì sao cho khi giải mã vẫn ra được flag nhưng không phải là input cipher. Kiểu quái gì làm được như vậy nhỉ???

Tới đây mình mới research về một thứ trong đề bài: RSA Least Significant Bit Oracle Attack. Mình phải modify input kiểu gì để sao cho sau khi giải mã mình có thể đảo ngược lại những gì mình để modify. Ở đây ta biết rằng trong RSA c được tính bởi công thức:
```
c = m^e mod n
```
và ta sẽ giải mã bằng công thức:
```
m = c^d mod n
```
Vậy nếu ta nhân c với 2^e mod n thì sao?
```
c' = c * (2^e mod n) = (2*m)^e mod n
```
Lúc này server sẽ giải mã như sau:
```
m' = c'^d mod n
   = ((2*m)^e mod n)^d mod n
Vì đây là RSA => ed ≡ 1 (mod φ(n))
Từ đó ta có:
m' = (2*m)^(e*d) mod n
```
Định lý Euler-Fermat nói rằng nếu a và n là hai số nguyên tố cùng nhau (tức là gcd(a, n) = 1), và φ(n) là hàm Euler (số lượng số nguyên dương bé hơn n và nguyên tố cùng nhau với n), thì a^φ(n) ≡ 1 (mod n). Áp dụng vào đây ta có
```
m' = 2m
```
Giờ đây chỉ cần chia 2 ta sẽ có được flag dưới dạng đã bị dịch sang phải 1 bit. Sử dụng 3,4,5,.. sẽ dịch phải 2,3,.. bits. Điều này sẽ góp ích về sau.

Áp dụng vào bài của chúng ta, chỉ việc connect đến server và gửi *ct\*pow(2,e,n)*, thử nhiều lần hoặc thay bằng số khác để vượt hết các điều kiện và lấy flag thôi.

```python3
from pwn import *
from Crypto.Util.number import *
r = remote('be.ax', 31100)

r.recvuntil('n = ')
n = int(r.recvline().strip())
r.recvuntil('e = ')
e = int(r.recvline().strip())
r.recvuntil('ct = ')
ct = int(r.recvline().strip())

new_ct = ct * pow(2, e, n)

r.sendline(str(new_ct))

response = r.recvline().decode()
print('Server response:', response)

try:
    response = response.replace("> ", "")
    response_int = int(response)
    response_bytes = long_to_bytes(response_int // 2)
    print('Response in bytes:', response_bytes)
except ValueError:
    print("The response wasn't an integer, couldn't convert to bytes.")

r.close()
```
Flag: corctf{h4ng_0n_th15_1s_3v3n_34s13r_th4n_4n_LSB_0r4cl3...4nyw4y_1snt_f1zzbuzz_s0_fun}

### fizzbuzz101
'but in real fizzbuzz you say the number' - someone, probably
```
nc be.ax 31101
```
Attachment: fizzbuzz101.py
```python3
#!/usr/local/bin/python
from Crypto.Util.number import *
from os import urandom

flag = open("flag.txt", "rb").read()
flag = bytes_to_long(urandom(16) + flag + urandom(16))

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
assert flag < n
ct = pow(flag, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")

while True:
    ct = int(input("> "))
    pt = pow(ct, d, n)
    out = ""
    if pt == flag:
        exit(-1)
    if pt % 3 == 0:
        out += "Fizz"
    if pt % 5 == 0:
        out += "Buzz"
    if not out:
        out = "101"
    print(out)

```
Đoạn code gần như y hệt bài 100. Tuy nhiên ở đây khi ta vượt được 3 điều kiện đầu thì biến out sẽ biến thành 101 và in ra. Vậy phải bypass kiểu gì bây giờ?

**Hiện tại thì mình cũng chịu :v Sẽ cập nhật sau**
