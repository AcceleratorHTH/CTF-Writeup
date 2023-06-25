# **GOOGLE\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

**Author:**

- Pham Quoc Trung

**Used Language:**

- Python3

**Problem Solving:**

1/ LEAST COMMON GENOMINATOR?

Someone used this program to send me an encrypted message but I can't read it! It uses something called an LCG, do you know what it is? I dumped the first six consecutive values generated from it but what do I do with it?!

Attachment:

- dump.txt
- flag.txt
- generate.py
- public.pem

Problem analysis:

Ở đây thì đề bài có đề cập tới một khái niệm là LCG. Sau khi mình thử tra theo tên challenge này thì có vẻ không đúng. Tìm tòi một hồi thì mình đã tìm ra nó là “Linear congruential generator”, một thuật toán sinh số giả ngẫu nhiên (Pseudo Random Number Generation - PRNG)

![image](https://github.com/AcceleratorHTH/CEA201/assets/86862725/25a62ab0-c392-4434-9f4a-923fcda4ea63)

Về cơ bản thì thuật toán này sẽ chỉ sử dụng một hàm đệ quy:

Xn+1= (aXn+ c) mod m

Trong đó:

- m, 0 < m: mô đun “modulus”, thường là một số đủ lớn, như 2^32, 2^31– 1, 2^48, 2^64
- a, 0 < a < m: Hằng số nhân “multiplier”
- c, 0 ≤ c < m: Hằng số cộng thêm “increment”
- X0, 0 ≤ X0 < m : “seed”, giá trị khởi tạo

Chu kỳ của LCG lớn nhất là m, và để LCG sinh ra tất cả các giá trị trong chu kỳ với mọi giá trị khởi tạo (full-period) thì sẽ cần những điều kiện ràng buộc sau:

- m và c là nguyên tố cùng nhau.
- a-1 chia hết cho mọi thừa số nguyên tố của m
- a-1 chia hết cho 4 nếu m chia hết cho 4.

Các bạn có thể xem thêm tại đây:

<https://en.wikipedia.org/wiki/Linear_congruential_generator>

Nhưng đống này thì liên quan gì đến challenge? Mình thử mở code file **generate.py**

``` python3
from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []
    
    dump = True
    items = 0
    dump_file = open("dumptest.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break
        
        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break


    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)

    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())
```

Ở đây thì mình có thể thấy được class liên quan tới LCG của chúng ta. Khác một chút so với mình vừa phân tích, nó sử dụng m cho multiplier, c cho increment, và n cho modulus

Đọc qua đoạn code dung LCG thì mình nhận ra nó hoạt động như sau:

- Dùng thuật toán LCG để gen ra hàng loạt các số ngẫu nhiên
- Dump 6 kết quả đầu tiên vào file **dump.txt**
- Tạo ra 1 array chứa 8 số nguyên tố 512 bits (*primes\_arr*)

Việc còn lại là dùng kết quả thu được để tạo nên một challenge về RSA:

- Tạo ra public key n bằng cách nhân các số nguyên tố thu được ở trên với nhau
- Tạo ra totient Phin bằng cách nhân hiệu với 1 của các số nguyên tố trên với nhau
- Tạo ra private key d với e trong *config*
- Lấy flag ra từ *config* và encrypt nó, viết vào file **flag.txt** dưới dạng bytes theo little-endian
- Export rsa key vào file **public.pem**
- Việc chúng ta cần làm ở đây là giải mã được flag, hay chúng ta cần tính được private key d.

Problem solving:

Do rsa public key đã được export vào file **public.pem** nên mình có thể lấy được n và e từ đó.

Ban đầu, mình dùng 6 số được dump ở trong file **dump.txt** để tính d (Đương nhiên là sai bét rồi :v). Ngồi nghĩ lại thì mình nghĩ liệu có thể tính ngược lại các tham số m, a, c ở trong LCG dựa trên 6 số đó không. 

Như ở trên thì mình đã biết rằng:

Xn+1= (aXn+ c) mod m

Đây chỉ đơn giản là một phương trình có 3 ẩn. Với 6 số được gen ra từ nó, mình nghĩ mình hoàn toàn có thể tính được chúng. Mình có:

X1= (aX0+ c) mod m

X2= (aX1+ c) mod m

X3= (aX2+ c) mod m

Ba phương trình trên tương đương với:

aX0+c=k1m+X1

aX1+c=k2m+X2

aX2+c=k3m+X3

Tuy nhiên, giờ thì mình lại có tận 6 ẩn nhưng chỉ có 3 phương trình. Mọi chuyện có vẻ đi vào bế tắc cho đến khi mình tìm được trang này:

<https://tailcall.net/posts/cracking-rngs-lcgs/>

Ở đây, họ đã có sẵn code để có thể lấy được m, a, c từ các số được sinh ra bởi LCG. Mình đã đọc và chưa thực sự hiểu sâu về phần phân tích tiếp theo nên mình sẽ nghiên cứu và ghi lại sau. Giờ thì cứ dùng số code mà người viết đã cung cấp để giải đã. Mình viết một file **lcg.py** để tìm ra 3 tham số đó:

```python3
import math
import functools

reduce = functools.reduce
gcd = math.gcd

X = [
    2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385,
    6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115,
    2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287,
    4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792,
    7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612,
    2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197
]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)


lcg = crack_unknown_modulus([
    2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385,
    6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115,
    2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287,
    4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792,
    7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612,
    2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197
])

print(lcg)

```
![image](https://github.com/AcceleratorHTH/CEA201/assets/86862725/ca2c1d90-7dd3-465c-bfe8-e87941731f52)

Và thật tuyệt là nó đã hoạt động. Giờ đây khi đã có đủ những tham số của thuật toán LCG sử dụng trong challenge, mình chỉ cần sửa code của **generate.py** đi một chút là có thể ra được kết quả. Đây là code để giải challenge này của mình:

```python3
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime
from Crypto.PublicKey import RSA

# Read the public key from the file
with open('public.pem', 'r') as f:
    key = RSA.importKey(f.read())

e = key.e
n = key.n

class LCG:
    # the "multiplier"
    lcg_m = 99470802153294399618017402366955844921383026244330401927153381788409087864090915476376417542092444282980114205684938728578475547514901286372129860608477 
     # the "increment"
    lcg_c = 3910539794193409979886870049869456815685040868312878537393070815966881265118275755165613835833103526090552456472867019296386475520134783987251699999776365
    # the "modulus"
    lcg_n = 8311271273016946265169120092240227882013893131681882078655426814178920681968884651437107918874328518499850252591810409558783335118823692585959490215446923

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []
    
    items = 0

    primes_n = 1
    while True:
        for i in range(8):
            while True:
                prime_candidate = lcg.next()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != 512:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break
        
        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = inverse(e, phi)

    # Read the encrypted flag
    with open('flag.txt', 'rb') as f:
        enc_flag = int.from_bytes(f.read(), 'little')

    flag = pow(enc_flag, d, n)
    print(long_to_bytes(flag))

```

Và khi chạy code, ta sẽ nhận được kết quả:
![image](https://github.com/AcceleratorHTH/CEA201/assets/86862725/8785cabe-ab36-46ef-b242-ea85afc68d5d)

Flag: CTF{C0nGr@tz\_RiV35t\_5h4MiR\_nD\_Ad13MaN\_W0ulD\_b\_h@pPy}

**© 2023,Pham Quoc Trung. All rights reserved.**



















