# Squ1rrel CTF 2024

## **SQU1RREL CTF 2024**

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

### Lazy RSA

#### Description

Generating primes is too hard, but I did find a couple posted online!

```
n: 23690620655271165329693230765997410033604713853187305472268813793031152348107488119317901392104240429826482611449247251262846508667797483465355228800439339041030982259847598574606272955688345490638311164838117491821117626835340577511562130640807587611523935604871183668968359720411023759980144229161581597397061850707647104033348795132205561234674677139395868595692235525931999596382758921793937149945229459379437008216713404350896206374483356969246476531491049930769999387038678280465689487577291475554699094024761030833540509263174840007922218340417888061099317752496279552046029470370474619439450870110783844218281
e: 65537
ct: 11420169733597912638453974310976296342840438772934899653944946284527921765463891354182152294616337665313108085636067061251485792996493148094827999964385583364992542843630846911864602981658349693548380259629884212903554470004231160866680745154066318419977485221228944716844036265911222656710479650139274719426252576406561307088938784324291655853920727176132853663822020880574204790442647169649094846806057218165102873847070323190392619997632103724159815363319643022552432448214770378596825200154298562513279104608157870845848578603703757405758227316242247843290673221718467366000253484278487854736033323783510299081405
```

#### Solution

Bài đầu thì không có gì khó. Mình chỉ cần lấy ra `p` sử dụng `factordb` sau đó tiến hành decrypt là ra được flag

```python
from Crypto.Util.number import *

n = 23690620655271165329693230765997410033604713853187305472268813793031152348107488119317901392104240429826482611449247251262846508667797483465355228800439339041030982259847598574606272955688345490638311164838117491821117626835340577511562130640807587611523935604871183668968359720411023759980144229161581597397061850707647104033348795132205561234674677139395868595692235525931999596382758921793937149945229459379437008216713404350896206374483356969246476531491049930769999387038678280465689487577291475554699094024761030833540509263174840007922218340417888061099317752496279552046029470370474619439450870110783844218281
e = 65537
ct = 11420169733597912638453974310976296342840438772934899653944946284527921765463891354182152294616337665313108085636067061251485792996493148094827999964385583364992542843630846911864602981658349693548380259629884212903554470004231160866680745154066318419977485221228944716844036265911222656710479650139274719426252576406561307088938784324291655853920727176132853663822020880574204790442647169649094846806057218165102873847070323190392619997632103724159815363319643022552432448214770378596825200154298562513279104608157870845848578603703757405758227316242247843290673221718467366000253484278487854736033323783510299081405

p = 136883787266364340043941875346794871076915042034415471498906549087728253259343034107810407965879553240797103876807324140752463772912574744029721362424045513479264912763274224483253555686223222977433620164528749150128078791978059487880374953312009335263406691102746179899587617728126307533778214066506682031517
q = n // p

d = inverse(e, (p-1)*(q-1))

print(long_to_bytes(pow(ct, d, n)))
```

Flag: _squ1rrel{laziness\_will\_be\_the\_answer\_eventually}_

### RSA RSA RSA

#### Description

I had something so important to say that I just had to tell three of my friends!

```
e: 3
n1: 96137714481560340073780038250015316564930752333880363375193088083653975552334517899735106334409092229494004991796910602440032630762575914714152238916128674595912438177270978040111855327624812652948702562503276973409716595778936978757384935820012322432156169815110042972411989274515686945691887468406312791931
ct1: 45640508926729498938915879450220374487095109122207451961200230820161694723491945276893630019713859109920025191680053056485030809079137883906737197875968862878423820820515399840094772412319820062860149582361429346029277273870654355752499436360499181221418835401103925420623212341317366954144592892392013649421
n2: 90990790933807553440094447797505116528289571569256574363585309090304380702927241663491819956599368816997683603352289726407304960362149545383683196526764288524742203975596414405902155486632888712453606841629050125783639571606440840246928825545860143096340538904060826483178577619093666337611264852255012241011
ct2: 58149644956871439128498229750735120049939213159976216414725780828349070974351356297226894029560865402164610877553706310307735037479690463594397903663323983980128060190648604447657636452565715178438939334318494616246072096228912870579093620604596752844583453865894005036516299903524382604570097012992290786402
n3: 86223965871064436340735834556059627182534224217231808576284808010466364412704836149817574186647031512768701943310184993378236691990480428328117673064942878770269493388776005967773324771885109757090215809598845563135795831857972778498394289917587876390109949975194987996902591291672194435711308385660176310561
ct3: 16168828246411344105159374934034075195568461748685081608380235707338908077276221477034184557590734407998991183114724523494790646697027318500705309235429037934125253625837179003478944984233647083364969403257234704649027075136139224424896295334075272153594459752240304700899700185954651799042218888117178057955
```

#### Solution

Với bài này, ta sẽ sử dụng `Hastad's Broadcast Attack`.

> Chi tiết kỹ thuật: [https://drx.home.blog/2019/03/01/crypto-rsa/](https://drx.home.blog/2019/03/01/crypto-rsa/)

```python
from sage.all import *
from Crypto.Util.number import *
from gmpy2 import iroot

e = 3
n1 = 96137714481560340073780038250015316564930752333880363375193088083653975552334517899735106334409092229494004991796910602440032630762575914714152238916128674595912438177270978040111855327624812652948702562503276973409716595778936978757384935820012322432156169815110042972411989274515686945691887468406312791931
ct1 = 45640508926729498938915879450220374487095109122207451961200230820161694723491945276893630019713859109920025191680053056485030809079137883906737197875968862878423820820515399840094772412319820062860149582361429346029277273870654355752499436360499181221418835401103925420623212341317366954144592892392013649421
n2 = 90990790933807553440094447797505116528289571569256574363585309090304380702927241663491819956599368816997683603352289726407304960362149545383683196526764288524742203975596414405902155486632888712453606841629050125783639571606440840246928825545860143096340538904060826483178577619093666337611264852255012241011
ct2 = 58149644956871439128498229750735120049939213159976216414725780828349070974351356297226894029560865402164610877553706310307735037479690463594397903663323983980128060190648604447657636452565715178438939334318494616246072096228912870579093620604596752844583453865894005036516299903524382604570097012992290786402
n3 = 86223965871064436340735834556059627182534224217231808576284808010466364412704836149817574186647031512768701943310184993378236691990480428328117673064942878770269493388776005967773324771885109757090215809598845563135795831857972778498394289917587876390109949975194987996902591291672194435711308385660176310561
ct3 = 16168828246411344105159374934034075195568461748685081608380235707338908077276221477034184557590734407998991183114724523494790646697027318500705309235429037934125253625837179003478944984233647083364969403257234704649027075136139224424896295334075272153594459752240304700899700185954651799042218888117178057955

Cs = [ct1, ct2, ct3]
Ns = [n1, n2, n3]

m_e = crt(Cs, Ns)
m = m_e.nth_root(e)
print(long_to_bytes(int(m)))
```

Flag: _squ1rrel{math\_is\_too\_powerful\_1q3y41t1s98u23rf8}_

### Partial RSA

#### Description

Hmm? What's wrong with using the same flag format again? Whisper it in my ear so they don't hear.

```
n: 103805634552377307340975059685101156977551733461056876355507089800229924640064014138267791875318149345634740763575673979991819014964446415505372251293888861031929442007781059010889724977253624216086442025183181157463661838779892334251775663309103173737456991687046799675461756638965663330282714035731741912263
e: 3
ct: 24734873977910637709237800614545622279880260333085506891667302143041484966318230317192234785987158021463825782079898979505470029030138730760671563038827274105816021371073990041986605112686349050253522070137824687322227491501626342218176173909258627357031402590581822729585520702978374712113860530427142416062
```

#### First stage:

Ban đầu, do `e=3` nên mình đã thử sử dụng lỗ hổng `small e, small m`:

```python
# Small e attack
from Crypto.Util.number import *
from gmpy2 import iroot

def attack(c:int, e:int) -> int:
    return int(iroot(c, e)[0])

n = 103805634552377307340975059685101156977551733461056876355507089800229924640064014138267791875318149345634740763575673979991819014964446415505372251293888861031929442007781059010889724977253624216086442025183181157463661838779892334251775663309103173737456991687046799675461756638965663330282714035731741912263
e = 3
ct =  24734873977910637709237800614545622279880260333085506891667302143041484966318230317192234785987158021463825782079898979505470029030138730760671563038827274105816021371073990041986605112686349050253522070137824687322227491501626342218176173909258627357031402590581822729585520702978374712113860530427142416062

dec = attack(ct, e)
print(dec.to_bytes((dec.bit_length() + 7) // 8, "big"))
```

Tuy nhiên là đếch ra :v Có vẻ `m` ở đây đã bị pad bằng cách nào đó?

```
b"\x14\xd0j\x13\x18\xfe\xfc\x8d\x81.\xcf\xda\xf2)\x81'\xf4G\x95\xf1\xa3Y\xbe\x07\x98B\x86W\x12\xc0\x08\xb0\x87\x82:\xbb\xca\x81h\x9e\xc0\x8a}"
```

Đọc kĩ lại đề bài, mặc dù thoạt tiên mình thấy nó chả có mẹ gì hint cả. Ai chả biết là flag format vẫn thế @@??? Tuy nhiên, do `e=3`, mình chợt nhớ ra có một kiểu tấn công nâng cao và mình chưa tiếp xúc nhiều lắm

#### Stereotyped messages

Chúng ta đều biết việc tìm nghiệm của 1 đa thức trên trường số nguyên có thể nói là rất dễ dàng. Tuy nhiên, tìm nghiệm của 1 đa thức trong 1 trường hữu hạn là một vấn đề khó để giải quyết:

```
f(x) = 0 mod N
```

Hãy ký hiệu N là một số nguyên lớn và chúng ta có đa thức nguyên đơn biến f(x) với bậc n, tức là:

$$
f(x) = x^N + a_{n-1}x ^ {n-1}+a_{n-2}x ^ {n-2}+...+a_1n+a_0
$$

Hơn nữa, giả sử có một nghiệm nguyên x0 cho phương trình modulo `f(x) ≡ 0 mod N, x0 < N^(1/n). D`. Coppersmith đã chỉ ra cách có thể khôi phục giá trị này trong thời gian đa thức bằng cách sử dụng **định lý của Howgrave-Graham**

**Định lý:** Xét g(x) là đa thức một biến có n đơn thức (đa thức chỉ có một số hạng) và m là một số nguyên dương. Nếu chúng ta có một số giới hạn X và các phương trình sau đúng:

$$
g(x_0) \equiv 0 \;mod \;N^m, |x_0| \leq X
$$

$$
||g(xX)|| < \frac{N^m}{\sqrt{n}}(10)
$$

sau đó g(x0) = 0 có nghiệm là một số nguyên.

Lý do sử dụng lattice:

* Nếu chúng ta có một số đa thức có cùng gốc x0 trên $$N^m$$ , chúng ta có thể biểu diễn mỗi đa thức đó dưới dạng một hàng từ một lattice. Sau đó, mỗi tổ hợp tuyến tính của các hàng từ latice sẽ tạo ra một đa thức khác có nghiệm x0.&#x20;
* Sau đó, bằng cách sử dụng **thuật toán LLL** trên lattice được thiết kế đặc biệt, trong thời gian đa thức, chúng ta có thể tìm thấy một cơ sở lattice rút gọn khác, sao cho chuẩn của vectơ ngắn nhất từ cơ sở rút gọn sẽ thỏa mãn bất đẳng thức (10) đã nêu ở trên.
* Hãy xác định vectơ ngắn nhất trong cơ sở rút gọn là $$v = (v_0,v_1,… ,v_n)$$. Ta xây dựng đa thức g(x):

$$
g(x) = v_0+\frac{v_1}{X}x+\frac{v_2}{X^2}x^2+...+\frac{v_n}{X^n}x^n
$$

Vì g(x) nằm trên mạng tinh thể nên chúng ta biết rằng:

$$
g(x_0) \equiv 0 \;mod \;N^m
$$

$$
|x|  \leq X
$$

$$
deg(g) = n
$$

$$
||g(xX)|| < \frac{N^m}{\sqrt{n+1}}
$$

Theo các kết quả từ định lý trên, chúng ta có thể kết luận rằng g(x) = 0 đúng với các số nguyên.

Ta có thể dễ dàng tạo các đa thức cùng root x0 trên $$N^m$$ . Xét họ các đa thức $$g_{i,j}(x)$$:

$$
g_{i,j}(x_0) \equiv x^j \;mod \;N^{m-i} f^i(x)
$$

$$
0  \leq i < m\\
$$

$$
0  \leq j < deg(f)\\
$$

Theo thiết kế, tất cả chúng đều có chung gốc x0 trên $$N^m$$ , tức là $$g_{i,j}(x0) ≡ 0 \;mod\; N^m$$ . Giá trị của m càng lớn thì ta lập được càng nhiều đa thức. Chúng ta xây dựng càng nhiều đa thức thì mạng càng lớn và thời gian thu gọn mạng sẽ càng lớn.

Bây giờ, hãy tưởng tượng Eve chặn được một tập hợp các tin nhắn ở dạng rõ ràng giữa Alice và Bob. Các tin nhắn là:

```
The password for AES usage is: 4{8dXY!
The password for AES usage is: 31kTbwj
The password for AES usage is: 2rr#ETh
···
The password for AES usage is: &H,45zU
```

Sau đó, Alice và Bob bắt đầu trao đổi các tệp được mã hóa bằng AES bằng mật khẩu đã giao tiếp. Nếu nhận được mật khẩu mới, họ sẽ bắt đầu sử dụng ngay lập tức. Tuy nhiên, họ nhận ra rằng điều này hoàn toàn không an toàn và đã tăng cường bảo mật bằng cách sử dụng RSA.

Giả sử Alice muốn gửi một thông điệp chuỗi mã hóa RSA `s` cho Bob. Đầu tiên cô ấy chuyển nó thành số nguyên `m`. Sau đó, cô ấy mã hóa nó bằng cách sử dụng khóa công khai Bob`(N,e)`, tức là `c = m**e mod n` và gửi tin nhắn được mã hóa `c` qua địa chỉ không an toàn.

Khóa công khai của Bob là `(N,3)`, trong đó độ dài bit của N là 512. Ta có thể thấy các thông điệp trên có phần đầu giống hệ nhau chỉ khác 7 bytes cuối hay còn gọi là `stereotyped messages`. Và chúng ta có thể dựa và điều này để khai triển cuộc tấn công. Vậy thông điệp sẽ có cấu trúc như sau:

```
s' = "The password for AES usage is: C1C2…C7"
```

Mục tiêu sẽ là tìm nghiệm x của đa thưc có dạng như sau:

$$
(a+x)^2 -c=0\;mod\;N
$$

Ta sẽ tách phần đầu của thông điệp ra và thêm các bytes `b'\x00'` vào cuối.

```python
sage: padding = b'\x00'*7
sage: B = b'The password for AES usage is: '
sage: a = B + padding
sage: a
b'The password for AES usage is: \x00\x00\x00\x00\x00\x00\x00'
sage: x = b'\xff'*7
```

Để minh họa cuộc tấn công tốt hơn, chúng ta sẽ xây dựng một đa thức nhiều biến trên vành số nguyên, thay vì một biến.

```python
sage: R.<X,N,a,c> = ZZ[]
```

Bây giờ, chúng ta đã sẵn sàng xây dựng đa thức f(X):

```python
sage: f = (X+a)**3 - c
sage: f
X^3 + 3*X^2*a + 3*X*a^2 + a^3 - c
```

Matrix ta để thực hiện tấn công có dạng như sau:

```python
sage: M = matrix([[X^3, 3*X^2*a, 3*X*a^2, a^3-c],[0,N*X^2,0,0],[0,0,N*X,0],[0,0,0,N]])
sage: M
[    X^3 3*X^2*a 3*X*a^2 a^3 - c]
[      0   X^2*N       0       0]
[      0       0     X*N       0]
[      0       0       0       N]
```

Lattice của ta đã sẵn sàng. Chúng ta có thể bắt đầu thuật toán LLL:

```python
sage: B = M.LLL()
```

Vectơ ngắn nhất B\[0] trong cơ sở rút gọn của chúng ta chứa các hệ số mà chúng ta cần để xây dựng đa thức g trên vành hữu tỉ. Chúng ta có thể dễ dàng xây dựng nó bằng cách sử dụng SageMath

```python
sage: R.<x> = QQ[]
sage: Q = sum([B[0][i]*(x**i)/(X_const**i) for i in range(4)])
```

Theo định lý đã nêu, đa thức cuối cùng phải có nghiệm là các số nguyên. Và thực sự như vậy:

```python
sage: sol = Q.roots(ring=ZZ)[0][0]
sage: type(sol)
<type ’sage.rings.integer.Integer’>
```

Như vậy sol chính là giá trị mà ta cần tìm.

#### Solution

Đống lý thuyết thì có vẻ lú. Sau cùng, nếu đã hiểu sơ qua, bạn chỉ cần tìm một script thực hiện cuộc tấn công này và thay một số tham số để cho phù hợp

Ở đây, do không biết độ dài của đoạn flag chưa biết, mình sẽ bruteforce nó:

```python
from Crypto.Util.number import *
from sage.all import *
from tqdm import tqdm

n = 103805634552377307340975059685101156977551733461056876355507089800229924640064014138267791875318149345634740763575673979991819014964446415505372251293888861031929442007781059010889724977253624216086442025183181157463661838779892334251775663309103173737456991687046799675461756638965663330282714035731741912263
e = 3
c =  24734873977910637709237800614545622279880260333085506891667302143041484966318230317192234785987158021463825782079898979505470029030138730760671563038827274105816021371073990041986605112686349050253522070137824687322227491501626342218176173909258627357031402590581822729585520702978374712113860530427142416062

known = b"squ1rrel{"
known_int = bytes_to_long(known)

for i in tqdm(range(100)):
    try:
        x = PolynomialRing(Zmod(n), 'x').gen()
        f = (known_int * 2**(i * 8) + x)**e - c
        ans = f.small_roots(X = 2**(i * 8), beta = 0.5)[0]
        print(known.decode() + long_to_bytes(int(ans)).decode())
        break
    except:
        continue
```

Flag: _squ1rrel{wow\_i\_was\_betrayed\_by\_my\_own\_friend}_

> Bằng 1 cách nào đó, khi mình thử các script khác thì cái của mình nhanh vl :v

### Squ1rrel treasury

#### Description:

We recently opened a new bank, our exchange rate is pretty poor though

`nc treasury.squ1rrel-ctf-codelab.kctf.cloud 1337`

#### Attachment:

_chal.py_

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
import os
from secrets import KEY, FLAG
import random

ACCOUNT_NAME_CHARS = set([chr(i) for i in range(ord('a'), ord('z')+1)] + [chr(i) for i in range(ord('A'), ord('Z')+1)])
FLAG_COST = random.randint(10**13, 10**14-1)

def blockify(text: str, block_size: int):
    return [text[i:i+block_size] for i in range(0, len(text), block_size)]

def pad(blocks: list, pad_char: chr, size: int):
    padded = []
    for block in blocks:
        tmp = block
        if len(block) < size:
            tmp = tmp + pad_char*(size-len(tmp))
        elif len(block) > size:
            print("Inconsistent block size in pad")
            exit(1)
        padded.append(tmp)
    return padded

class Account:
    def __init__(self, iv: bytes, name: str, balance: int):
        self.__iv = iv
        self.__name = name
        self.__balance = balance

    def getIV(self):
        return self.__iv

    def getName(self):
        return self.__name

    def getBalance(self):
        return self.__balance

    def setBalance(self, new_balance):
        self.__balance = new_balance

    def getKey(self):
        save = f"{self.__name}:{self.__balance}".encode()
        blocks = blockify(save, AES.block_size)
        pblocks = pad(blocks, b'\x00', AES.block_size)
        cipher = AES.new(KEY, AES.MODE_ECB)
        ct = []
        for i, b in enumerate(pblocks):
            if i == 0:
                tmp = strxor(b, self.__iv)
                ct.append(cipher.encrypt(tmp))
            else:
                tmp = strxor(strxor(ct[i-1], pblocks[i-1]), b)
                ct.append(cipher.encrypt(tmp))
        ct_str = f"{self.__iv.hex()}:{(b''.join(ct)).hex()}"
        return ct_str

    def load(key: str):
        key_split = key.split(':')
        iv = bytes.fromhex(key_split[0])
        ct = bytes.fromhex(key_split[1])
        cipher = AES.new(KEY, AES.MODE_ECB)
        pt = blockify(cipher.decrypt(ct), AES.block_size)
        ct = blockify(ct, AES.block_size)
        for i, p in enumerate(pt):
            if i == 0:
                pt[i] = strxor(p, iv)
            else:
                pt[i] = strxor(strxor(ct[i-1], pt[i-1]), p)
        pt = b''.join(pt)
        pt_split = pt.split(b':')
        try:
            name = pt_split[0].decode()
        except Exception:
            name = "ERROR"
        balance = int(pt_split[1].strip(b'\x00').decode())
        return Account(iv, name, balance)

def accountLogin():
    print("\nPlease provide your account details.")
    account = input("> ").strip()
    account = Account.load(account)
    print(f"\nWelcome {account.getName()}!")
    while True:
        print("What would you like to do?")
        print("0 -> View balance")
        print(f"1 -> Buy flag ({FLAG_COST} acorns)")
        print("2 -> Save")
        opt = int(input("> ").strip())
        if opt == 0:
            print(f"Balance: {account.getBalance()} acorns\n")
        elif opt == 1:
            if account.getBalance() < FLAG_COST:
                print("Insufficient balance.\n")
            else:
                print(f"Flag: {FLAG}\n")
                account.setBalance(account.getBalance()-FLAG_COST)
        elif opt == 2:
            print(f"Save key: {account.getKey()}\n")
            break                


def accountNew():
    print("\nWhat would you like the account to be named?")
    account_name = input("> ").strip()
    dif = set(account_name).difference(ACCOUNT_NAME_CHARS)
    if len(dif) != 0:
        print(f"Invalid character(s) {dif} in name, only letters allowed!")
        print("Returning to main menu...\n")
        return
    account_iv = os.urandom(16)
    account = Account(account_iv, account_name, 0)
    print(f"Wecome to Squirrel Treasury {account.getName()}")
    print(f"Here is your account key: {account.getKey()}\n")

if __name__ == "__main__":
    while True:
        print(r"""
              ⠀⠀⠀⠀⠀⠀⠀ ⢀⣀⣤⣄⣀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢴⣶⠀⢶⣦⠀⢄⣀⠀⠠⢾⣿⠿⠿⠿⠿⢦⠀⠀ ___  __ _ _   _/ |_ __ _ __ ___| |           
⠀⠀⠀⠀⠀⠀⠀⠀⠺⠿⠇⢸⣿⣇⠘⣿⣆⠘⣿⡆⠠⣄⡀⠀⠀⠀⠀⠀⠀⠀/ __|/ _` | | | | | '__| '__/ _ \ |            
⠀⠀⠀⠀⠀⠀⢀⣴⣶⣶⣤⣄⡉⠛⠀⢹⣿⡄⢹⣿⡀⢻⣧⠀⡀⠀⠀⠀⠀⠀\__ \ (_| | |_| | | |  | | |  __/ |            
⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡈⠓⠀⣿⣧⠈⢿⡆⠸⡄⠀⠀⠀⠀|___/\__, |\__,_|_|_|  |_|  \___|_|            
⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣈⠙⢆⠘⣿⡀⢻⠀⠀⠀⠀        |_|                                    
⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠹⣧⠈⠀⠀⠀⠀ _____                                         
⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠈⠃⠀⠀⠀⠀/__   \_ __ ___  __ _ ___ _   _ _ __ ___ _   _ 
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀  / /\/ '__/ _ \/ _` / __| | | | '__/ _ \ | | |
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀ / /  | | |  __/ (_| \__ \ |_| | | |  __/ |_| |
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀ \/   |_|  \___|\__,_|___/\__,_|_|  \___|\__, |
⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀                                         |___/ 
⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣿⣿⠿⠿⠿⠿⠿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
              """)
        print("Welcome to squ1rrel Treasury! What would you like to do?")
        print("0 -> Login")
        print("1 -> Create new account")
        opt = int(input("> ").strip())
        if opt == 0:
            accountLogin()
        elif opt == 1:
            accountNew()
```

#### Solution:

Với bài này, khi kết nối tới server, ta sẽ có 2 lựa chọn là tạo tài khoản hoặc login. Với chức năng tạo tài k

```python
def accountNew():
    print("\nWhat would you like the account to be named?")
    account_name = input("> ").strip()
    dif = set(account_name).difference(ACCOUNT_NAME_CHARS)
    if len(dif) != 0:
        print(f"Invalid character(s) {dif} in name, only letters allowed!")
        print("Returning to main menu...\n")
        return
    account_iv = os.urandom(16)
    account = Account(account_iv, account_name, 0)
    print(f"Wecome to Squirrel Treasury {account.getName()}")
    print(f"Here is your account key: {account.getKey()}\n")
```

Ta sẽ được yêu cầu nhập tên tài khoản. Có một số ràng buộc là nó chỉ được chứa các chữ cái trong bảng chữ cái (được phép viết hoa). Sau đó, nó sẽ tiến hành tạo ra một key cho tài khoản của chúng ta sử dụng để đăng nhập. Key này được tạo như sau:

```python
def getKey(self):
        save = f"{self.__name}:{self.__balance}".encode()
        blocks = blockify(save, AES.block_size)
        pblocks = pad(blocks, b'\x00', AES.block_size)
        cipher = AES.new(KEY, AES.MODE_ECB)
        ct = []
        for i, b in enumerate(pblocks):
            if i == 0:
                tmp = strxor(b, self.__iv)
                ct.append(cipher.encrypt(tmp))
            else:
                tmp = strxor(strxor(ct[i-1], pblocks[i-1]), b)
                ct.append(cipher.encrypt(tmp))
        ct_str = f"{self.__iv.hex()}:{(b''.join(ct)).hex()}"
        return ct_str
```

Đầu tiên, nó tạo ra một chuỗi bytes chứa `name:balance`, ở đây `balance` được truyền vào là 0. Tiến hành chia chuỗi trên thành từng block 16-bytes. Với các block không đủ 16-bytes, ta sẽ tiến hành padding bằng các bytes `\x00`. Quá trình mã hóa được tiến hành như sau:

* Block đầu tiên sẽ được XOR với IV (được tạo random 16-bytes) trước đó. Sau đó tiến hành encrypt sử dụng `AES_ECB`.
* Với các block còn lại, chúng sẽ được XOR với block được mã hóa trước đó và encrypt sử dụng `AES_ECB`.

Có thể thấy thật ra đây là một dạng `AES_CBC` với phương thức mã hóa sử dụng `ECB`. Cuối cùng, key sẽ được trả về dưới dạng chuỗi `iv:ciphertext`.

Đến với chức năng đăng nhập, ta có như sau:

```python
def accountLogin():
    print("\nPlease provide your account details.")
    account = input("> ").strip()
    account = Account.load(account)
    print(f"\nWelcome {account.getName()}!")
    while True:
        print("What would you like to do?")
        print("0 -> View balance")
        print(f"1 -> Buy flag ({FLAG_COST} acorns)")
        print("2 -> Save")
        opt = int(input("> ").strip())
        if opt == 0:
            print(f"Balance: {account.getBalance()} acorns\n")
        elif opt == 1:
            if account.getBalance() < FLAG_COST:
                print("Insufficient balance.\n")
            else:
                print(f"Flag: {FLAG}\n")
                account.setBalance(account.getBalance()-FLAG_COST)
        elif opt == 2:
            print(f"Save key: {account.getKey()}\n")
            break         
```

Ta sẽ được yêu cầu nhập `key` của tài khoản để đăng nhập. Key này sẽ được truyền vào hàm `load` để check độ legit:

```python
def load(key: str):
        key_split = key.split(':')
        iv = bytes.fromhex(key_split[0])
        ct = bytes.fromhex(key_split[1])
        cipher = AES.new(KEY, AES.MODE_ECB)
        pt = blockify(cipher.decrypt(ct), AES.block_size)
        ct = blockify(ct, AES.block_size)
        for i, p in enumerate(pt):
            if i == 0:
                pt[i] = strxor(p, iv)
            else:
                pt[i] = strxor(strxor(ct[i-1], pt[i-1]), p)
        pt = b''.join(pt)
        pt_split = pt.split(b':')
        try:
            name = pt_split[0].decode()
        except Exception:
            name = "ERROR"
        balance = int(pt_split[1].strip(b'\x00').decode())
        return Account(iv, name, balance)
```

Nó sẽ tách `iv` và `ciphertext` ra để tiến hành giải mã. Đoạn này cũng giống kiểu giải mã của `AES_CBC`, các bạn có thể xem qua ở ảnh dưới. Kết quả trả về `iv`, `name` và `balance` của tài khoản chứa trong key.

<figure><img src="../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

Sau khi đăng nhập thành công, ta sẽ có thể mua flag với một giá ngẫu nhiên trong `10**13, 10**14-1`. Với `balance` bằng 0 được truyền vào từ đầu thì có vẻ là sẽ không đủ để mua. Vậy ta phải tìm cách để có thể tăng số `balance` này lên.

Để ý, ta có thể kiểm soát được `iv` truyền vào. Ở đây mình sẽ sử dụng kỹ thuật `Bit flip` trong `AES_CBC`. Giả sử mình có một tài khoản tên là `t`. Khi đó, plaintext trước khi mã hóa sẽ chỉ có 1 block và có dạng&#x20;

```python
plaintext_block = b't:0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Block trên sẽ được XOR với IV và ra được ciphertext sau khi decrypt bằng `ECB` (trước khi XOR với IV để ra lại plaintext). Ở bài này, `KEY` truyền vào `AES_ECB` là không đổi (có thể gây ra vuln), tuy nhiên miễn là vẫn đang trong 1 session thì ta sẽ không cần để ý tới điều này. Thật vậy, ta luôn có thể tính được giá trị của ciphertext sau khi decrypt bằng `ECB` bằng cách lấy IV gốc XOR với khối plaintext mình ghi phía trên. Giả sử mình ra được  như sau:

<pre class="language-python"><code class="lang-python">token_inf = bytes.fromhex(token[33:])
plaintext = b't:0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
pblock = xor(plaintext, token_iv)
<strong># b'\xdf\xb9\x8f\xb98\xdb\xeaa\x1b\x9c\xdf\x7f\x0f@\xa8\x8b'
</strong></code></pre>

Khi này, mình sẽ tạo ra một plaintext mới như sau:

```python
payload_plaintext = b't:99999999999999'
```

IV mới sẽ được tính bằng cách XOR 2 chuỗi trên với nhau:

```python
payload_iv = xor(payload_plaintext, pblock).hex()
# b'\xab\x83\xb6\x80\x01\xe2\xd3X"\xa5\xe6F6y\x91\xb2'
```

Khi này, nếu ta đăng nhập với key dạng `payload_iv:ciphertext`, đoạn plaintext được tính ra chắc chắn sẽ là payload của chúng ta. Với số tiền là 13 số 9 (== 10\*\*14 - 1), ta chắc chắn sẽ mua được FLAG.

Code solution:

```python
from pwn import *

conn = remote("treasury.squ1rrel-ctf-codelab.kctf.cloud", 1337)

def recvLine(n):
    for _ in range(n):
        conn.recvline()

print("[+] Getting Flag.....")

# Banner,menu
recvLine(20)

# Get Token
conn.sendline(b'1')
conn.sendline(b't')

recvLine(3)

token = conn.recvline().decode().strip()[26:]

# Banner,menu
recvLine(20)

# Make malicious token
token_iv = bytes.fromhex(token[:32])
token_inf = bytes.fromhex(token[33:])
plaintext = b't:0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
pblock = xor(plaintext, token_iv)

payload_plaintext = b't:99999999999999'
payload_iv = xor(payload_plaintext, pblock).hex()
payload_token = payload_iv + ":" + token_inf.hex()

# Send payload
conn.sendline(b'0')
conn.sendline(payload_token.encode())

recvLine(8)

conn.sendline(b'1')

# Flag
print("[+] Found flag!")
print("[+] " + conn.recvline().decode().strip()[2:])
```

Flag: _squ1rrel{7H3\_4C0rN\_3NCrYP710N\_5CH3M3\_15\_14CK1N6}_

### Squ1rrel Lottery

#### Description

Welcome to the squ1rrel lottery! 9 winning numbers will be selected, and if any of your tickets share 3 numbers with the winning ticket you'll win a flag!

Hint: This is a math challenge

`nc 34.132.166.199 11112`

#### Solution

Dự định là bài này sẽ là bài hay nhất :v Cơ mà khi đọc writeup thì mình thấy chán do không có kỹ thuật gì nên mình sẽ để wu ở đây

{% embed url="https://nightxade.github.io/ctf-writeups/writeups/2024/squ1rrel-CTF-2024/crypto/squ1rrel-lottery.html" %}
