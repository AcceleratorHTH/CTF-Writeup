# **ASCIS 2023 QUAL**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving**
### Crypto Gym
Welcome to crypto gym. First thing first, do 10 pushup

Attachment: *pushup.sage*
```python
from Crypto.Util.number import *

flag = b"ASCIS{W3llDone_hitting_the_crypto_gym}"
p = random_prime(2^64,False,2^63)
k = 100
N = p^k
R.<x> = PolynomialRing(Zmod(N), implementation="NTL")

pol = R([getrandbits(303) for _ in range(8)])
rem = pol(bytes_to_long(flag))
pol2 = pol - rem

print(p)
print(pol2)
```
*output.txt*
```
11297687362481059303
13610397498137460052595710607775600966440673986561720083617038392214152560062011019976773770*x^7 + 3566392303389726626006032793588065859583087165101596345460586029577767956788324980852746288*x^6 + 7227318468293576946551014881082996672111192766111924180025635102400282562890972644421351500*x^5 + 7771302680925353252595662292109560220768956546753457049454904993425020919927767061221486221*x^4 + 139083310005991713122570444648981888435044361344964087355309478527640012858625517580301911*x^3 + 10431965883129539716182417642690446218733007501683833779007525409139657460951379770712373102*x^2 + 2655891997688433325155635727515206873804011670907688662530856511275429726187800190339210214*x + 1990468213382663050992514193186549986027466683418508635770777413817551279002416425502329820086861584095472837291418005624773513401408758670436382582234048163799788806226626593153501000046514398963951902046012093096889627829382025385675885186988109953010009115770485200550815315808412991631351114821645247484757612802395935646091741255310372634948676346139337203740284867648614092382676490768142323752125479973383639263480304615000184481073131150356830470611732683436270896044490259474247417693471208508957222774925150961910011882960781392579006359531632257744162604999333815810546399453824586710812096069645634464088126006346744764154042984373078867489476719514098331516466106097935211336674536065610816999665679040973651579582751231452003697987383534147985850684095100628612367594611200815680857874889854961710361062023098850129552718682182379299432474772126322312705937896898977384049986981576727484443307309856882552658648662622011836915288387316856549038216691517631404710419267570370185868331551998817164408824273037138508139872246840469178118447891408840689533252470570577069433326089871730774552442047182123932923084697422550196675689928558048170639744494377903971022314792618672680983240190918645044793065660686668847439068894202593794701984461427031780284501758478606643641114708694491715239872860200373088774910354567584766353453900023065619777887852835339101628894266209543584386397885981697802413486043807559982651878851431362770011433278158871282099680537195876295632087913919009624832811111375020850262854356800201139600896028683597688967045073054430644328634631654532540097138840888709833107492434165723295378716876382870562787875916326125400715648718443161316211216677436938376005080710347157377831498391277043220453740841631935922506793862323094941018556991395626031998291221412221183144473483101854286315619799724635496211825342536058324502706123278966607771777568594929815999891921492775
```

Bài này flag n?m luôn trên file source nên mình cung ch? c?n ph?i làm gì :v. S? nghiên c?u sau.

Flag: *ASCIS{W3llDone_hitting_the_crypto_gym}*

### I_dont_know_how_to_name_this_chall
This is a description. Good luck

Attachments: *chall_fixed.sage*
```python
from Crypto.Random.random import getrandbits
from Crypto.Util.number import bytes_to_long

nbits = 128
while True:
    mul = getrandbits(nbits)
    add = getrandbits(nbits)
    modulus = getrandbits(nbits)
    if mul < modulus and add < modulus:
        break

def gen_num(bits):
    truncate = bits
    seed = getrandbits(511)
    gen_num = 41

    xx = []
    yy = [] 
    
    for _ in range(gen_num):
        seed = (mul * seed + add) % modulus
        xx.append(seed)
        yy.append(seed >> (nbits-truncate))
    return xx, yy

_, ee = gen_num(18)
_, ff = gen_num(20)

a = ee[-1]
b = ff[-1]
c = getrandbits(1024)
p = next_prime(a * c + getrandbits(512))
q = next_prime(b * c + getrandbits(512))

flag = '<REDACTED>'
N = p * q
e = 65537
m = bytes_to_long(flag.encode())
enc = pow(m, e, N)

print(f'enc = {enc}')
print(f'N = {N}')
print(f'ee = {ee[:-1]}')
print(f'ff = {ff[:-1]}')
print(f'a = {mul}')
print(f'c = {add}')
print(f'm = {modulus}')
```
*output.txt*
```
enc = 4782207738169357679017263311695366580149461241803922088835452812820137537830281562950634059939171784035642202164746425519370563906663225547286363495366866588141853586109553019469599011984795232666657032457349167541183811442599555965876853759790930565452169138123206051344200109808603093521161556603615660329142949615063443855551027286822234646698015310643407246009689006200152818931447476595216569044114220319818061396623338764899012025923470408152189436065437542065068815744124506169026323905222443334212867601172364249248963768649488580249031694113977946046461290930755706144535271632419505875554486279354334709794323960679
N = 3964970058588757148381961704143056706462468814335020245520977895524549102412775370911197710398920529632256746343939593559572847418983212937475829291172342816906345995624544182017120655442222795822907477729458438770162855927353619566468727681852742079784144920419652981178832687838498834941068480219482245959017445310420267641793085925693920024598052216950355088176712030006651946591651283046071005648582501424036467542988971212512830176367114664519888193885765301505532337644978456428464159474089450883733342365659030987687637355512103402573155030916404165387863932234088255017821889649456947853403395704387479968208359004918561
ee = [167323, 194700, 130745, 7156, 65616, 200175, 106106, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV200382, 22272, 14195, 200195, 70505, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV]
ff = [300710, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV548412, 650282, 195040, 74550, 158762, 797511, 322315, 821880, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV284265, 537835, 226489]
a = 43787291635671214792919526096167649451
c = 156497500579206068939331641182566791023
m = 273364800599018888270443304662600024273
```



### let's duel
I really want to play MTG with someone.

Attachments: *chall_fixed_final.py*
```python
from hashlib import *
import os
from Crypto.Util.number import *


q = 2^32 - 5
n = 256
def bytes_to_seedlist(seedbytes):
    seedlist = []
    for i in range(16):
        seedlist.append(bytes_to_long(seedbytes[i*4:i*4+4]))
    return seedlist

def sample_poly(seed , lower , upper):
    prng = PRNG(seed)
    polylist = []
    for i in range(n):
        polylist.append((prng.raw_rand() % (upper - lower)) + lower)
    return polynomial(polylist)
def encode_m(m):
    m = bytes_to_long(m)
    flist = []
    for i in range(n):
        flist = [m&1] + flist
        m >>= 1
    return polynomial(flist)

class PRNG:
    def __init__(self , seed):
        self.state = bytes_to_seedlist(seed)
        
        self.m = 8723550600886591460
        # f = [randint(0 , self.m) for _ in range(16)]
        self.f = [385590684360, 111617452318, 131804337312, 300824916689, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV107293144053, 703516825252, 541402940593, 624566048630]
        self.d = 16
        for i in range(self.d):
            self.generate()
    def generate(self):
        res = 0
        for i in range(self.d):
            res += self.f[i] * self.state[i]
            res %= self.m
        self.state = self.state[1:] + [res]
    def raw_rand(self):
        temp = self.state[0]
        self.generate()
        return temp

class polynomial:
    def __init__(self,flist):
        n = 256
        if type(flist) == list:
            assert len(flist) == n
            self.f = [flist[i] % q for i in range(n)]

    def __add__(self , other):
        assert type(other) == polynomial
        return polynomial([(self.f[i] + other.f[i])%q for i in range(n)])
    def __sub__(self , other):
        assert type(other) == polynomial
        return polynomial([(self.f[i] - other.f[i])%q for i in range(n)])
    def __mul__(self , other):
        assert type(other) == polynomial
        res = [0 for _ in range(n)]
        for i in range(n):
            for j in range(n-i):
                res[i+j] += self.f[i] * other.f[j]
                res[i+j] %= q
        for j in range(1, n):
            for i in range(n-j, n):
                res[i+j-n] -= (self.f[i] * other.f[j])
                res[i+j-n] %= q
        return polynomial(res)

flag = b'<REDACTED>'
assert flag[:8] == b'ASCIS{it' and flag[-1:] == b'}' and len(flag) == 32
print(f'hash_list: {list(map(lambda x: sha256(x).digest(), [flag[i:i+5] for i in range(0, len(flag), 5)][:-1]))}')

A = sample_poly(os.urandom(64) , 0 , 2**32 - 5)
e = sample_poly(os.urandom(64) , -4 , 4)
s = encode_m(flag)
b = A*s + e
print(b.f)
print(A.f)
```
*output.txt*
```
hash_list: [b'\xb6\xb1\xdahR\xef\xb5\xc4\x96\xc9\x87\xe3;K\xf2|(\xc2?\x8b\xd3B\xdc\xc7\x13\xd2\x82[=\xa9\xc3\xfb', b'\xb0"\x8fl8\xc0Z1\x97\x88ct\x8a\xf1\xea\xc8.\xe0Q=\x0e\xd9\x86\xbc\x89\xc2\xbb\x9dT\xc6}Z', b'\xc1\x9d\x81\xe4\xed\xaa\x8a\xa0\xb6\xcb\x15\xc6\xd2yv\x1f\x8f\xac\x839\xa4&}\x1c\xa8\xc3\x15"\x87r!\xe2', b'\xf26\x95*\x0c\xd2\xca\xd8xE\xbf\xf3P \xcc\xd7l\xebx\xdcW\xb2\x8e\x06\xfa\xd7r\xc0~\xdf\x18`', b'\x1f\xfa>\xea\xe2{-\x13:\xfe,`\x01j\xec\xa0\x15hl\xa5\\\x88\x9eQ[\x12\x1es7\xe3w\xa5', b"'cE\x04\xae\x04\x88\xdb\xe6\x0b\x9b}\xf7\x1d]\xedH\xf3:|\x12s\x0f\xc2\xa1v\xa2k\xf4\xbazJ"]
[4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV1545834191, 790968817, 2015602796, 2973360521, 1871688489, 2744199016, 3790735376, 137555270, 1278025029, 3802308861, 3114891940, 3957760227, 2039267510, 2555990791, 564591932, 844115070, 709763793, 1413511597, 3223782810, 3762408596, 3237568557, 1506656324, 640118751, 3457884507, 2042392508, 3621570353, 2618427178, 3143980384, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV614386809, 3276667439, 1909302811, 2207910705, 3672171769, 1892473412, 2106619998, 3509534363, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2012416867, 192505113, 3114220319, 1331292762, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2127021357, 3299398789, 3177792605, 3096187832, 617393158, 3105265865, 3200579500, 2180602657, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV753809702, 2492856611, 2824277079, 2542382957, 304365097, 1407108023, 179330351, 3572907626, 2987119926, 1837821380, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV1122173200, 916028602, 2063630491, 397805198, 1714268681, 3482358218, 1527006125, 972019432, 1178792742, 321122436, 1198282426, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2888766800, 23922410, 988643330, 1734233855, 3610553547, 2881678944, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3904323348, 3116210769, 371569431, 859621792, 3873282560, 3657629936, 2165332329, 3648500937, 1596125288, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2320593952, 2794811414, 711422896, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3241117779, 640856507, 3473767594, 1713562536, 3684876849, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3699184121, 794095422, 1786769052, 1636765552, 1268289826, 3988009796, 3507703205, 277522927, 3281391735, 3061479622, 2054288077, 320590104, 1155984065, 2345911582, 1311189685, 2417274203, 3663636979, 1355104029, 954525006, 1565182940, 2623166114, 2244058414, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3213795177, 2648382777, 2574807466, 1859819418, 724070108, 2468329063, 519293835, 3786683045, 2138218831, 1129997749, 3957889649, 1690256184, 1279827160, 906462778, 337831463, 3731171015, 3668852053, 220581961, 288435651, 2016496414, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2347510467, 4180730265, 1161045967, 3252278061, 1005098266]
[287970464, 2164888233, 3900314872, 2803578471, 2100597265, 1816431874, 3107577409, 2442807705, 521828921, 3057968421, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV295613802, 3783064449, 901463863, 3903514026, 1296050662, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2498770917, 1402362082, 3632530868, 649841672, 1843661157, 786836159, 2485753489, 2839031237, 3731848071, 2817378681, 3403169521, 2015560787, 1822700770, 161085328, 286530859, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3922986170, 2367251329, 988621856, 3722976714, 3538009554, 213747765, 1299739489, 3466643630, 370290663, 2976632085, 3044010057, 3168989507, 2278979483, 922376384, 2082045756, 784991240, 2824840459, 1611316601, 1606912636, 136325361, 1489816993, 3045086708, 3764326204, 1475244981, 629654012, 1988643969, 3286999466, 3195304933, 1606659017, 736848220, 2158974982, 347685569, 332414878, 207979890, 3372005421, 298012257, 2758990980, 3310277688, 349598758, 2378166773, 1464638028, 3273217830, 3763703130, 1389744097, 714695881, 1685453463, 3570078034, 1037471531, 3873616449, 951661170, 2805305208, 2306223616, 3687866993, 3305452882, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV1267048809, 2563600344, 3204565645, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV3282001667, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV2526277849, 63039371, 947719144, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV873083062, 3035068564, 129826698, 682624376, 1041985948, 2300167185, 1985311187, 2158495582, 2574786951, 3239489764, 2005786117, 2399685911, 2157700060, 2548490153, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV770751334, 3357701211, 3406246261, 1758771097, 3755060295, 2398178683, 3380424195, 2048522566, 715325180, 3534765975, 3742183516, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV1491689975, 3149230417, 1602027685, 1683352963, 3846848863, 3139684322, 62856240, 2244885460, 2895665432, 297531570, 1074403985, 1653386664, 95133646, 3476903462, 3606247651, 2399138344, 3186466372, 1956121684, 870920533, 3595320696, 3247874941, 3529506430, 2118652780, 2130399537, 2721787296, 1790856026, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV564703315, 237694859, 2591207021, 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV1497714995, 1682915718, 968837565]
```
Vì hi?n t?i mình v?n khá ngu v? Lattice nên mình dã th? copy 1 s? do?n code d? paste lên Github, và mình tìm du?c m?t challenge tuong t? c?a gi?i D^3CTF 2023

https://github.com/shal10w/d3ctf2023-d3bdd/tree/main

---------------------
Ngoài ra thì còn m?t cách khác.
? dây, ta du?c cho 6 m?nh c?a flag, m?i m?ng là mã hóa SHA256 c?a 5 kí t? flag. Mình có th? brute-force SHA256 t?ng m?nh.

? dây mình s? d?ng code C:
```cpp
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include <cmath>
#include <openssl/sha.h>

const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"; 

std::string target_hash;

std::atomic<bool> found(false);
std::string yepassword;

void crack(int start, int end){
    // just to c5 only
    if (end > strlen(charset)) {
        end = strlen(charset);
    }
    for (int c1 = 0; c1 < (strlen(charset)); ++c1) {
        for (int c2 = 0; c2 < strlen(charset); ++c2) {
            for (int c3 = 0; c3 < strlen(charset); ++c3) {
                for (int c4 = 0; c4 < strlen(charset); ++c4) {
                    for (int c5 = start; c5 < end; ++c5) {
                        if (found) {
                            return;
                        }
                        std::string password = "";
                        password += charset[c1];
                        password += charset[c2];
                        password += charset[c3];
                        password += charset[c4];
                        password += charset[c5];
                        // std::cout << password << std::endl;
                        // generate hex of sha256
                        unsigned char hash[SHA256_DIGEST_LENGTH];
                        SHA256_CTX sha256;
                        SHA256_Init(&sha256);
                        SHA256_Update(&sha256, password.c_str(), password.size());
                        SHA256_Final(hash, &sha256);
                        std::stringstream ss;
                        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                        {
                            ss << std::hex << (int)hash[i];
                        }
                        std::string sha256_hash = ss.str();
                        // std::cout << sha256_hash << std::endl;
                        if (sha256_hash == target_hash) {
                            found = true;
                            yepassword = password;
                            return;
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    target_hash = argv[1];

  int num_threads = 8;
  std::vector<std::thread> threads;

  uint64_t workload = strlen(charset);
  uint64_t work_per_thread = workload / num_threads + 1;

  for(int i = 0; i < num_threads; i++) {
  
    int start = i * work_per_thread;
    int end = start + work_per_thread;
    // std::cout << start << " " << end << std::endl;
    
    threads.push_back(std::thread(crack, start, end));
  
  }

  for(auto& t : threads) {
    t.join();
  }

  if(found) {
    std::cout << "Password found: " << yepassword << std::endl;
  }
  else {
    std::cout << "Password not found" << std::endl;
  }

  return 0;

}
```

