# **NahamCon\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### RSA Intro
What *is* RSA? Really Spicy Applesauce? Ridiculously Smart Alpaca? Random Squirrel Alliance? Nope, not at all. Just some dudes who made a cool public-key cryptosystem!

Author: Gary

Attachment: chal.py
```python3
from Crypto.Util.number import getStrongPrime, getPrime, bytes_to_long as b2l

FLAG = open('flag.txt', 'r').read().strip()
OUT = open('output.txt', 'w')

l = len(FLAG)
flag1, flag2, flag3 = FLAG[:l//3], FLAG[l//3:2*l//3], FLAG[2*l//3:]

# PART 1
e = 0x10001
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
ct = pow(b2l(flag1.encode()), e, n)
OUT.write(f'*** PART 1 ***\ne: {e}\np: {p}\nq: {q}\nct: {ct}')

# PART 2
e = 3
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
ct = pow(b2l(flag2.encode()), e, n)
OUT.write(f'\n\n*** PART 2 ***\ne: {e}\nn: {n}\nct: {ct}')

# PART 3
e = 65537
p = getPrime(24)
q = getPrime(24)
n = p*q

fl = round(len(flag3)/4)
f3_parts = [flag3[i:i+4] for i in range(0, len(flag3), 4)]
assert ''.join(f3_parts) == flag3
ct_parts = []
for part in f3_parts:
    pt = b2l(part.encode())
    assert pt < n
    ct = pow(pt, e, n)
    ct_parts.append(ct)

OUT.write(f'\n\n*** PART 3 ***\ne: {e}\nn: {n}\nct: {ct_parts}')
```

Ở bài này mình sẽ phân tích từng part. Trước hết là part 1:
```python3
# PART 1
e = 0x10001
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
ct = pow(b2l(flag1.encode()), e, n)
OUT.write(f'*** PART 1 ***\ne: {e}\np: {p}\nq: {q}\nct: {ct}')
```
Part 1 này, mình được cung cấp 3 dữ liệu là e, p, q và c. Mọi thứ cơ bản đã có sẵn, việc chúng ta cần chỉ là tính *n = p * q*, tính *phi = (p-1)\*(q-1)* và *d = e^-1 (mod phi)*. Cuối cùng, giải mã c bằng công thức m = c^d (mod n).

```python3
e1= 65537
p1 = 152933908726088000025981821717328900253841375038873501148415965946834656401640031351528841350980891403699057384028031438869081577476655254545307973436745130347696405243778481262922512227444915738801835842194123487258255790292004204412236314558718035967575479232723997430178018130995420315759809636522091902529
q1 = 173403581892981708663967289381727914513043623656015065332774927693090954681172215632003125824638611519248812013286298011144213434368768979531792528759533473573346156338400142951284462417074992959330154930806611253683603690442142765076944118447174491399811297223146324861971722035746276165056022562961558299229
d1 = inverse(e1, (p1 -1) * (q1 - 1))
c1 = 24900222896050719055946861973957246283663114493271057619080357155524140641110166671081924849912377863714741017586072836978357770860853088772671413685690588862677870057778743649753806625109141461870634890427341765490174013453580041222600439459744928592280825572907034701116518706347830413085865254963646096687533779205345001529893651672061316525244476464884343232361498032095529980932018530224029715267731845742371944443150142380656402289372470902457020777826323051802030062577945893807552316343833971210833255536637260838474638607847822451324479398241526919184038034180388382949827367896808363560947298749154349868503
m1 = long_to_bytes(pow(c1, d1, p1*q1)).decode("ascii")
```
Tiếp theo đến part 2. Ở đây chúng ta được cung cấp e, n và c.
```python3
# PART 2
e = 3
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
ct = pow(b2l(flag2.encode()), e, n)
OUT.write(f'\n\n*** PART 2 ***\ne: {e}\nn: {n}\nct: {ct}')
```
Dù chỉ có 2 dữ kiện nhưng việc e = 3, một số rất nhỏ đã tạo nên lỗ hổng small e. Để dễ hình dung:
```
e = 3 <=> c = m^3 (mod n) | ==> m = c^1/3
     Do m nhỏ => m^3 < n  |
```
Vậy là đơn giản chỉ cần căn bậc 3 của c, ta sẽ giải mã được part 2. Lưu ý hàm *long_to_bytes* của thư viện Crypto chỉ dùng với Integer, nên mình sẽ dùng hàm *real_root* của thư viện Sympy.
```python3
e2 = 3
n2 = 17832697294201997154036617011957221780954165482288666773904510458098283881743910060438108775052144170769164876758249100567442926826366952851643073820832317493086415304740069439166953466125367940677570548218324219386987869433677168670642103353927101790341856159406926994785020050276564014860180970395749578442970075496442876475883003906961049702649859496118324912885388643549649071478725024867410660900848046927547400320456993982744075508818567475254504481562096763749301743619222457897353143558783627148704136084952125284873914605708215421331001883445600583624655438154001230490220705092656548338632165583188199066759
c2 = 55717486909410107003108426413232346564412491530111436942121941739686926249314710854996834619
m2 = long_to_bytes(int(real_root(c2, 3))).decode("ascii")
```

Cuối cùng là part3:
```python3
# PART 3
e = 65537
p = getPrime(24)
q = getPrime(24)
n = p*q

fl = round(len(flag3)/4)
f3_parts = [flag3[i:i+4] for i in range(0, len(flag3), 4)]
assert ''.join(f3_parts) == flag3
ct_parts = []
for part in f3_parts:
    pt = b2l(part.encode())
    assert pt < n
    ct = pow(pt, e, n)
    ct_parts.append(ct)

OUT.write(f'\n\n*** PART 3 ***\ne: {e}\nn: {n}\nct: {ct_parts}')
```
Ở đây thì message bị chia ra làm các part và mã hóa từng part. Mình được cung cấp đủ e, n và c của chúng. Để giải mã được bằng công thức *m = c^d (mod n)* thì chúng ta cần tính được d thông qua p,q. Để ý ở đây n là một số nguyên tố không lớn, ta có thể factor nó ra và lấy từng cặp giá trị cho p,q. Với bài này thì sau khi factor chỉ ra 2 giá trị duy nhất, nên mình sẽ gán nó là p,q luôn và tiến hành giải mã
```python3
e3 = 65537
p3 = 8885719
q3 = 12121807
d3 = inverse(e3, (p3-1)*(q3-1))
n3 = p3 * q3
c_parts = [18128889449669, 12202311999558, 10705744036504, 23864757944740]
m_parts = [long_to_bytes(pow(ct, d3, n3)) for ct in c_parts]
m3 = ''.join([pt.decode('utf-8') for pt in m_parts])
```

Tiến hành ghép kết quả 3 part với nhau, mình ra được flag. Full solution python: [RSAIntro](https://github.com/AcceleratorHTH/CTF-Writeup/blob/main/NahamCon%20CTF%202023/Source/RSAIntro.py)

Flag: flag{361862d054e2a9abe41cc315517cfa31}

### RSA Outro
I didn't feel like fitting this one in the RSA Intro, so here is an RSA Outro!

Author: Gary

Attachment: chal.py
```python3
from Crypto.Util.number import getStrongPrime, isPrime, inverse, bytes_to_long as b2l

FLAG = open('flag.txt', 'r').read()

# safe primes are cool 
# https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
while True:
    q = getStrongPrime(512)
    p = 2*q + 1
    if (isPrime(p)):
        break

n = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = inverse(e, phi)

pt = b2l(FLAG.encode())
ct = pow(pt,e,n)

open('output.txt', 'w').write(f'e: {e}\nd: {d}\nphi: {phi}\nct: {ct}')
```
output.txt
```
e = 65537
d = 53644719720574049009405552166157712944703190065471668628844223840961631946450717730498953967365343322420070536512779060129496885996597242719829361747640511749156693869638229201455287585480904214599266368010822834345022164868996387818675879350434513617616365498180046935518686332875915988354222223353414730233
phi = 245339427517603729932268783832064063730426585298033269150632512063161372845397117090279828761983426749577401448111514393838579024253942323526130975635388431158721719897730678798030368631518633601688214930936866440646874921076023466048329456035549666361320568433651481926942648024960844810102628182268858421164
ct = 37908069537874314556326131798861989913414869945406191262746923693553489353829208006823679167741985280446948193850665708841487091787325154392435232998215464094465135529738800788684510714606323301203342805866556727186659736657602065547151371338616322720609504154245460113520462221800784939992576122714196812534
```

Ở đây q là một số nguyên tố 512-bit, khá lớn để có thể sử dụng các cách như factor hay divisor. Tuy nhiên ở bài này sử dụng phép toán để gán giá trị cho p là *p = 2\*q + 1*. Điều này vô tình tạo nên điểm yếu cho thuật toán RSA này. Do đã biết giá trị của *phi*, nên ta có thể làm như sau:
```
    phi = (p-1)*(q-1)
<=> phi = 2*q*(q-1)
<=> 2*q^2 - 2*q - phi = 0
```
Phép toán trên là một phương trình bậc 2 một ẩn, ta hoàn toàn có thể tính được q rồi tính ngược lại p. Lúc này, mọi chuyện còn lại không có gì khó khăn nữa. Mình sẽ sử dụng hàm solve thư viện Sympy cho công việc này.
```python3
from Crypto.Util.number import isPrime, long_to_bytes
from sympy import symbols, Eq, solve
e = 65537
d = 53644719720574049009405552166157712944703190065471668628844223840961631946450717730498953967365343322420070536512779060129496885996597242719829361747640511749156693869638229201455287585480904214599266368010822834345022164868996387818675879350434513617616365498180046935518686332875915988354222223353414730233
phi = 245339427517603729932268783832064063730426585298033269150632512063161372845397117090279828761983426749577401448111514393838579024253942323526130975635388431158721719897730678798030368631518633601688214930936866440646874921076023466048329456035549666361320568433651481926942648024960844810102628182268858421164
ct = 37908069537874314556326131798861989913414869945406191262746923693553489353829208006823679167741985280446948193850665708841487091787325154392435232998215464094465135529738800788684510714606323301203342805866556727186659736657602065547151371338616322720609504154245460113520462221800784939992576122714196812534

q = symbols('q')

phi = 245339427517603729932268783832064063730426585298033269150632512063161372845397117090279828761983426749577401448111514393838579024253942323526130975635388431158721719897730678798030368631518633601688214930936866440646874921076023466048329456035549666361320568433651481926942648024960844810102628182268858421164

equation = Eq(2*q**2 - 2*q - phi, 0)

solution = solve(equation, q)

for sol in solution:
    if isPrime(int(sol)):
        q = int(sol)

p = 2*q + 1
n = p*q
m = long_to_bytes(pow(ct,d,n)).decode()
print(m)
```

Flag: flag{8b76b85e7f450c39502e71c215f6f1fe}

**© 2023,Pham Quoc Trung. All rights reserved.**
