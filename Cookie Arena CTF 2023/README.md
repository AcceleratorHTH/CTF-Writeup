# **Cookie\_Arena\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**

### Basic Operator
Sử dụng kiến thức toán học và cấu trúc đại số để giải mã flag\
**Format FLAG: CHH{XXX}**

Attachment:
chal.py
```python3
from Crypto.Util import number

def padding_pkcs7(data,block_size=4):
	tmp = len(data) + (block_size - len(data) % block_size)
	return data.ljust(tmp,bytes([block_size-(len(data)%block_size)]))

def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))

def plus_func(data,shift):
	return (data+shift)&0xffffffff

def mul_func(data,mul):
	return (data*mul)&0xffffffff

def xor_shift_right_func(data,bit_loc):
	return (data^(data>>bit_loc))&0xffffffff

def pow_func(data,e,p):
	return pow(data,e,p)

def exp_func(data,base,p):
	return pow(base,data,p)

def ecb_mode(data):
	return list(pow_func(exp_func(xor_shift_right_func(mul_func(plus_func(block,3442055609),2898124289),1),e,p),e,p) for block in split_block(padding_pkcs7(data,4),4))

if __name__=='__main__':
	p = 1341161101353773850779
	e = 2
	mess = b'CHH{CENSORED}'
	cipher_flag = ecb_mode(mess)
	print(cipher_flag)

```
cipher.txt
```
Cipher:
[752589857254588976778, 854606763225554935934, 102518422244000685572, 779286449062901931327, 424602910997772742508, 1194307203769437983433, 501056821915021871618, 691835640758326884371, 778501969928317687301, 1260460302610253211574, 833211399330573153864, 223847974292916916557]
```

Ở bài này, mình thấy flag được mã hóa thông qua nhiều funtion. Ý tưởng đơn giản là mình sẽ viết ngược lại từng hàm và chạy. Theo thứ tự trong hàm *ecb_mode* thì mình sẽ dịch ngược *pow_func, exp_func, xor_shift_right_func, mul_func, plus_func, split_block* và *padding_pkcs7.*

Đầu tiên là *pow_func*:
```python3
def pow_func(data,e,p):
	return pow(data,e,p)
```

Ở đây thì new_data = data^e (mod p). Để có thể tính lại được data thì thoạt nhìn, nó có vẻ là một bài toán khó. Tuy nhiên, để ý trong đoạn code thì e = 2 nên new_data = data^2 (mod p), hay data^2 ≡ new_data (mod p). Vấn đề này có thể được giải quyết thông qua thuật toán Cipolla's hoặc Tonelli-shanks. Ở đây, mình sử dụng sagemath để thực hiện nó.

```python3
def rev_pow_func(data,e,p):
    Zn = Zmod(p)
    return  Zn(data).sqrt(all=True)

data1a = []
data1b = []

for x in data:
    data1a.append(rev_pow_func(x,e,p)[0])
    data1b.append(rev_pow_func(x,e,p)[1])
    
print(data1a)
print(data1b)
```
Mình dùng sqrt(all=True) để có thể liệt kê đủ nghiệm cần tìm. Nếu các bạn dùng nth_root(2), các bạn sẽ cần dùng p trừ đi kết quả thu được để lấy được nghiệm còn lại.

Tiếp theo là tới hàm *exp_func*:
```python3
def exp_func(data,base,p):
	return pow(base,data,p)
```

Khác với hàm trước, ở đây new_data = base ^ data (mod p), hay base^data ≡ new_data (mod p). Đây là bài toán về logarit rời rạc. Mình sẽ dùng luôn hàm của sagemath.
```python3
def rev_exp_func(data,e,p):
    G = Integers(p)
    return G(data).log(G(e))

data2a = []
data2b = []

for x in data1a:
    data2a.append(rev_exp_func(x,e,p))
for x in data1b:
    data2b.append(rev_exp_func(x,e,p))

print(data2a)
print(data2b)
```

Ở đây mình có thể thấy được 1 số số mà chắc chắn không phải đáp án cho flag. Các bạn chạy thử code sẽ thấy rõ. Mình viết một đoạn code nhỏ để tạo nên một mảng đúng duy nhất:
```python3
def generate_array(a, b):
    return [b[i] if a[i] > 670000000000000000000 and b[i] < 670000000000000000000 else a[i] for i in range(min(len(a), len(b)))]

data2 = generate_array(data2a,data2b)
print(data2)
```
Giờ thì không phải thao tác trên 2 mảng nữa. Giờ đến lượt hàm *xor_shift_right_func*:
```python3
def xor_shift_right_func(data,bit_loc):
	return (data^(data>>bit_loc))&0xffffffff
```
Ở đây thì bit_loc == 1. Đầu tiên, data được dịch sang phải 1 bit, sau đó XOR với data gốc. Kết quả được AND với 0xffffffff. 0xffffffff là một hằng số hexa, tương đương với một số nguyên 32 bit với tất cả các bit đều là 1. Phép AND này đảm bảo rằng kết quả cuối cùng sẽ nằm trong phạm vi 32 bit.

Khi data >> 1, bit đầu của data bây giờ sẽ là 0. Khi đó, ta chỉ cần lấy bit tại cùng vị trí của kết quả XOR với 0, sẽ ra được bit đầu của data gốc. Để dễ hiểu hơn thì:

Giả sử data = **1011010**\
và data >> 1 = 0**101101** (số 0 được thêm vào cho phép dịch)\
XOR:\
**1011010**\
0**101101** \
1110111

Vậy thì ở đây, ta chỉ cần cho bit đầu của kết quả XOR với 0 sẽ ra bit đầu của data. Lấy bit đầu đó XOR với bit thứ 2 của new_data, sẽ ra được bit 2 của data gốc. Cứ như thế sẽ ra được data gốc.\
Ý tưởng ở đây sẽ là tạo ra mảng chứa 1 bit 0 trước, lấy bit 0 đó XOR với bit đầu của new_data. Ra kết quả bao nhiêu sẽ add lại vào mảng trên để XOR tiếp với bit thứ 2 của new_data. Cứ như thế sau khi XOR hết, xóa số 0 ban đầu của mảng đi, ta sẽ được data gốc.
```python3
def rev_xor_shift_right_func(data):
    data = format(data, "032b")
    cal_data = [0]
    for i in range(32):
        cal_data.append(cal_data[i] ^ int(data[i]))
    return int("".join(str(i) for i in cal_data[1:]), 2)

data3 = []
for i in data2:
    data3.append(rev_xor_shift_right_func(i))

print(data3)
```

Giờ đến *mul_func*:
```python3
def mul_func(data,mul):
	return (data*mul)&0xffffffff
```

Với hàm này, hãy để ý 0xffffffff là số lẻ trong decimal. Từ đó, ta có thể áp dụng công thức:
```
a & b = a % (b+1) với b lẻ
```
new_data = (data * mul) % (0xffffffff + 1)\
hay (data * mul) ≡ new_data % (0xffffffff + 1)

Sử dụng nghịch đảo modun của mul để giải phương trình trên, giải thích cho điều này:

(data * mul) ≡ new_data % (0xffffffff + 1)\
<=> data * mul * mul^-1 ≡ (new_data * mul^-1) % (0xffffffff + 1)\
Mà mul * mul^-1 = 1(t/c nghịch đảo modun)\
<=> data ≡ (new_data * mul^-1) % (0xffffffff + 1)\
Với data < (0xffffffff + 1), data % (0xffffffff + 1) sẽ bằng data
```python3
def rev_mul_func(data, mul):
    return (data * int(gmpy2.invert(mul, 0xffffffff + 1))) & 0xffffffff

data4 = []
for i in data3:
    data4.append(rev_mul_func(i, 2898124289)) 

print(data4)
```
Tiếp tục là với hàm *plus_func*:
```python3
def plus_func(data,shift):
	return (data+shift)&0xffffffff
```
Này thì đơn giản là phép cộng, chúng ta sẽ trừ đi
```python3
def rev_plus_func(data, shift):
    return (data - shift) & 0xffffffff

data5 = []
for i in data4:
    data5.append(rev_plus_func(i, 3442055609)) 

print(data5)
```
Đến hàm *split_block*:
```python3
def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))
```
Mình sẽ viết hàm để join chúng lại:
```python3
def join_blocks(blocks):
    return b''.join(block.to_bytes((block.bit_length() + 7) // 8, 'little') for block in blocks)

data6 = join_blocks(data5)
print(data6)
```
Đến đây thì dường như chúng ta đã ra được flag, mình nghĩ là không cần thiết phải viết hàm để bỏ pad đi lắm. Nhưng nếu các bạn muốn tham khảo thì đây là nó:
```python3
def unpadding_pkcs7(padded_data):
    padding_size = padded_data[-1]
    return padded_data[:-padding_size]

print(unpadding_pkcs7(data6))
```

Flag: CHH{w3lc0m3_70_7h3_m47h_w0rld(1_h4t3_1t_th3r3)}

À quên, đây là mình trình bày code để các bạn có thể step-by-step các bước. Final code mình sẽ để [ở đây]() nhé :v

### Knapsack Ls
Hệ thống mã hóa giựa trên bài toán Knapsack (bài toán xếp ba lô) đã bị coi là lỗi thời, nhưng điều đó không có nghĩa là nó có thể bị phá giải quá dễ dàng. Dựa vào implementation của mã hóa Knapsack trong knapsack.py, giải mã cipher để thu hồi flag.\
**Format FLAG: CHH{XXX}**

Attachments:
pub_key.txt
```
[43840113305581131795279797789093610869, 25671162443490210031784763050767207532, 6001769265119430614631782649952643356, 73521673497713025029239337461919881111, 86207439010568594314162414481970962317, 47714522703176373455115652188956101728, 39013785450660799339071487833855117053, 99720328779553130323261570624699472274, 56801730014082032103764648702913670605, 56875947939072280053341910569703290481, 6777018736332231356360273109122323983, 64282820255623342830695520268826453473, 21510177863483107761513368858017158458, 88999212996376205373411604716481814294, 21167180433710172715561410769658980338, 53988354426206626048276676648717671789, 82454574554107632872906561271793885103, 34238518652709304551635369779340095136, 5081213770246109310854315030563596017, 35676546839591659980876620994236683080, 61804490028276149551813742275879895343, 47868484398459384397990013507113194128, 79141732458875716511767486956076635010, 89768484644472604982812438158836379513, 108665660470366488973920414914088436457, 42013527007997056247679460159005166736, 59516238668397055079712758172437350204, 12247246885302547631808898114678421540, 68119702452821826703846268698978422087, 46477361269068664125259653428529967798, 104192935540102711457274510496328770849, 39480897318804270587289396967546023715]
```
knapsack.py
```python3=
from Crypto.Util import number
from Crypto.Util.Padding import pad,unpad

def split_block(data:bytes, block_size:int):
	for i in range(0,len(data),block_size):
		yield data[i:i+block_size]

def convert_bytes_bin(data:bytes, bit_size:int)->list:# little endian 
	data = int.from_bytes(data,'little')
	return [(data//(1<<i))&1 for i in range(bit_size)]

def convert_bin_bytes(data:list, bit_size:int)->bytes:# little endian 
	data = sum(data[i]<<i for i in range(bit_size))
	return data.to_bytes(bit_size//8,'little')

class Server:
	def __init__(self,bits):
		self.q,self.r = 0,0
		self.W = []
		## pub_key
		self.H = []
		
		self.block_size = 32 ## in bits
		assert bits&7 == 0 , "Must diviable by 8"
		assert bits>self.block_size+1, "Must larger than block_size"
		self.bits_protocol = bits
	
	def generate(self):
		# tmp = self.bits_protocol//self.block_size
		tmp = 2
		while True:
			self.W = []
			for i in range(1,self.block_size+1):
				self.W.append(number.getRandomRange(sum(self.W)+1,1<<(i*tmp) ))	
			# print(self.W)
			if sum(self.W)>(1<<self.bits_protocol):continue
			self.q = number.getRandomRange(sum(self.W),1<<(self.bits_protocol))
			self.r = number.getRandomRange(1,self.q)
			if number.GCD(self.r,self.q)!=1:continue
			break
			
		for i in range(self.block_size):
			self.H.append((self.W[i]*self.r)%self.q)
		# print(self.W)
	
	def encrypt(self,message: bytes) -> bytes:
		if len(message)%(self.block_size>>3)!=0: message = pad(message,self.block_size>>3)
		cipher_bytes = b''
		for data in split_block(message,self.block_size>>3):
			tmp = convert_bytes_bin(data,self.block_size)
			tmp = sum((a*b) for a,b in zip(tmp,self.H))#%self.q
			# print((tmp.bit_length()+7)//8)
			cipher_bytes += tmp.to_bytes((self.bits_protocol>>3)+1,'little')
		return cipher_bytes
	
	def __repr__(self):
		return f"public key: {self.H}"
	
if __name__=='__main__':
	server = Server(128)
	server.generate()
	m = b'CTF{CENSORED}'
	c = server.encrypt(m)
	print(c)
	print(server)
```
cipher.txt
```
b'\xe7\x81W\x8eA0\xb0\x92tM\xc9\x06\x07~$\xef\x01\x0c\x16\x8cP\x11l\x81\xe8\xa7\xa3\x0e\xec\x8a~\xe9Z\x02\xb28\x92z^\x16m\xb5\x80o\xf6\xd9\xec@\xc0\x85\x02\xdbvo\x8bB\xb3\xa2\xe4\x00\x01\xc2\xcaL\xdb\x8a\t\x03\xaf\xa528\xc8\xa1\xf6\x05u\xeb\xc0\xcbc\x06\xd8 \x02\xca@E&\xf0d4A\x85\x04\x84p~\xa5\t\xfe\x02\xd9\xa8\xcbp\xb9\xe8\x14\x04\x9a\xb9\x16#\x0b\xb8\x98\x90\x02\x8c\xe2\xf1\x8a\xf1\xe3Z\xe4\xff\xb4"\xeb\x86k\x97\x1b\x02IsN%\xd5\xect\x96\xb3\xe7\xf5Mw\xe6S\xbd\x02\xb7\xc4\xe9\xa6\x019q\xc9\xdd\xaf\xad9bG\xd8\x1e\x02\x18{\xc6q\xbe=\x97&\x18qj\xed\xfd\xb8\x94\xfd\x01'
```
Về knapsack và cách giải mã nó, các bạn có thể tham khảo bài viết [này](https://drx.home.blog/2019/02/24/crypto-he-ma-merkle-hellman/) (Cảm ơn tác giả vì đã giải thích khá dễ hiểu)


Mình chạy thử file knapsack.py sau khi uncomment dòng # print((tmp.bit_length()+7)//8) thì nhận thấy message bị chia thành từng block 4 bytes và từ 4 bytes đó encrypt được cipher dài 17 bytes. Từ đó, mình sẽ chia cipher thành từng block 17 bytes và để ý little endian nên phải đảo ngược. 

```python
from Crypto.Util.number import *

cipher = b'\xe7\x81W\x8eA0\xb0\x92tM\xc9\x06\x07~$\xef\x01\x0c\x16\x8cP\x11l\x81\xe8\xa7\xa3\x0e\xec\x8a~\xe9Z\x02\xb28\x92z^\x16m\xb5\x80o\xf6\xd9\xec@\xc0\x85\x02\xdbvo\x8bB\xb3\xa2\xe4\x00\x01\xc2\xcaL\xdb\x8a\t\x03\xaf\xa528\xc8\xa1\xf6\x05u\xeb\xc0\xcbc\x06\xd8 \x02\xca@E&\xf0d4A\x85\x04\x84p~\xa5\t\xfe\x02\xd9\xa8\xcbp\xb9\xe8\x14\x04\x9a\xb9\x16#\x0b\xb8\x98\x90\x02\x8c\xe2\xf1\x8a\xf1\xe3Z\xe4\xff\xb4"\xeb\x86k\x97\x1b\x02IsN%\xd5\xect\x96\xb3\xe7\xf5Mw\xe6S\xbd\x02\xb7\xc4\xe9\xa6\x019q\xc9\xdd\xaf\xad9bG\xd8\x1e\x02\x18{\xc6q\xbe=\x97&\x18qj\xed\xfd\xb8\x94\xfd\x01'

pub_key = [43840113305581131795279797789093610869, 25671162443490210031784763050767207532, 6001769265119430614631782649952643356, 73521673497713025029239337461919881111, 86207439010568594314162414481970962317, 47714522703176373455115652188956101728, 39013785450660799339071487833855117053, 99720328779553130323261570624699472274, 56801730014082032103764648702913670605, 56875947939072280053341910569703290481, 6777018736332231356360273109122323983, 64282820255623342830695520268826453473, 21510177863483107761513368858017158458, 88999212996376205373411604716481814294, 21167180433710172715561410769658980338, 53988354426206626048276676648717671789, 82454574554107632872906561271793885103, 34238518652709304551635369779340095136, 5081213770246109310854315030563596017, 35676546839591659980876620994236683080, 61804490028276149551813742275879895343, 47868484398459384397990013507113194128, 79141732458875716511767486956076635010, 89768484644472604982812438158836379513, 108665660470366488973920414914088436457, 42013527007997056247679460159005166736, 59516238668397055079712758172437350204, 12247246885302547631808898114678421540, 68119702452821826703846268698978422087, 46477361269068664125259653428529967798, 104192935540102711457274510496328770849, 39480897318804270587289396967546023715]

ret = []
for i in range(0, len(cipher), 17):
    ret.append(bytes_to_long(cipher[i:i+17][::-1]))

print(ret)

#ret = [658157336740748078513617478988103909863, 801407625220710617526900261195778627084, 858350295117626581440717262420549187762, 1033531137623151498590666148185839204059, 724221695429542151115546890883063522735, 1018238732058127372071660634048746045642, 872766527203138414179370420050858846425, 717240107460880717639441069017041855116, 932224460090972223441905899076223660873, 721564557670160331780121586296716641463, 677349261871154149350748837802592860952]
```
Giờ thì mình cần một hàm để giải mã knapsack. Ở đây, mình sử dụng code giải bài [Archaic](https://github.com/ctfs/write-ups-2014/tree/master/asis-ctf-quals-2014/archaic) của ASIS CTF quals 2014. Đây là lời giải của chính btc, nên có vẻ khá uy tín. 
```python=
#from Crypto.Util.number import *
from sage.all import *

cipher = b'\xe7\x81W\x8eA0\xb0\x92tM\xc9\x06\x07~$\xef\x01\x0c\x16\x8cP\x11l\x81\xe8\xa7\xa3\x0e\xec\x8a~\xe9Z\x02\xb28\x92z^\x16m\xb5\x80o\xf6\xd9\xec@\xc0\x85\x02\xdbvo\x8bB\xb3\xa2\xe4\x00\x01\xc2\xcaL\xdb\x8a\t\x03\xaf\xa528\xc8\xa1\xf6\x05u\xeb\xc0\xcbc\x06\xd8 \x02\xca@E&\xf0d4A\x85\x04\x84p~\xa5\t\xfe\x02\xd9\xa8\xcbp\xb9\xe8\x14\x04\x9a\xb9\x16#\x0b\xb8\x98\x90\x02\x8c\xe2\xf1\x8a\xf1\xe3Z\xe4\xff\xb4"\xeb\x86k\x97\x1b\x02IsN%\xd5\xect\x96\xb3\xe7\xf5Mw\xe6S\xbd\x02\xb7\xc4\xe9\xa6\x019q\xc9\xdd\xaf\xad9bG\xd8\x1e\x02\x18{\xc6q\xbe=\x97&\x18qj\xed\xfd\xb8\x94\xfd\x01'

pub_key = [43840113305581131795279797789093610869, 25671162443490210031784763050767207532, 6001769265119430614631782649952643356, 73521673497713025029239337461919881111, 86207439010568594314162414481970962317, 47714522703176373455115652188956101728, 39013785450660799339071487833855117053, 99720328779553130323261570624699472274, 56801730014082032103764648702913670605, 56875947939072280053341910569703290481, 6777018736332231356360273109122323983, 64282820255623342830695520268826453473, 21510177863483107761513368858017158458, 88999212996376205373411604716481814294, 21167180433710172715561410769658980338, 53988354426206626048276676648717671789, 82454574554107632872906561271793885103, 34238518652709304551635369779340095136, 5081213770246109310854315030563596017, 35676546839591659980876620994236683080, 61804490028276149551813742275879895343, 47868484398459384397990013507113194128, 79141732458875716511767486956076635010, 89768484644472604982812438158836379513, 108665660470366488973920414914088436457, 42013527007997056247679460159005166736, 59516238668397055079712758172437350204, 12247246885302547631808898114678421540, 68119702452821826703846268698978422087, 46477361269068664125259653428529967798, 104192935540102711457274510496328770849, 39480897318804270587289396967546023715]
nbit = len(pub_key)
#ret = []
#for i in range(0, len(cipher), 17):
#    ret.append(bytes_to_long(cipher[i:i+17][::-1]))

#print(ret)

ret = [658157336740748078513617478988103909863, 801407625220710617526900261195778627084, 858350295117626581440717262420549187762, 1033531137623151498590666148185839204059, 724221695429542151115546890883063522735, 1018238732058127372071660634048746045642, 872766527203138414179370420050858846425, 717240107460880717639441069017041855116, 932224460090972223441905899076223660873, 721564557670160331780121586296716641463, 677349261871154149350748837802592860952]
for x in range(10):
    A = Matrix(ZZ,nbit+1,nbit+1)

    for i in range(nbit):
        A[i,i] = 1

    for i in range(nbit):
        A[i,nbit] = pub_key[i]

    A[nbit,nbit] = -int(ret[x])

    res = A.LLL()
    print(res)
```
Mình sẽ chạy đoạn code trên bằng sage -python, cùng với đó là các pipeline | grep 0 | grep 1 | grep -v "-". Mình làm như vậy để có thể lọc ra được các short-vector ứng với mỗi block cần thiết cho bước giải mã tiếp theo.

Với mỗi short-vector thu được, mình sẽ chuyển nó từ hệ nhị phân little-endian về dạng bytes để đọc được flag
```python=
from Crypto.Util.number import long_to_bytes

def binary_array_to_little_endian_bytes(binary_array):
    little_endian_array = [binary[::-1] for binary in binary_array]
    
    long_int_array = [int(binary, 2) for binary in little_endian_array]
    
    bytes_array = [long_to_bytes(long_int) for long_int in long_int_array]
    
    return bytes_array

binary_array = ['110000100010101001100010110111100','110101100111011000101100000011100','101011000010110011000110110101100','111110101000110010101100111110100','010001100100111000001100110101100','110011000111011011111010001011100','000101101100110001001110110011000','011001100000110001001110110011000','111110101010011000101100110011100','100111101000010010000100100001000']
little_endian_bytes = binary_array_to_little_endian_bytes(binary_array)

for bytes_data in little_endian_bytes:
    print(bytes_data)
```

Và đây là kết quả mình thu được: 
```
b'{FTC'
b'p4nk'
b'kc45'
b'_51_'
b'k0rb'
b't_n3'
b'3r3h'
b'3r0f'
b's4e_'
b'!!!y'
```

Viết lại bằng tay(mình lười code :v) hoặc dùng code, ta sẽ thu được flag.

Flag: CHH{kn4p54ck_15_br0k3n_th3r3f0r3_e4sy!!!}


### Rubic Cipher
Flag đã được xáo trộn bằng một thuật toán dựa trên cơ chế xoay khối rubik, tìm hiểu và áp dụng cơ chế này để thu hồi flag\
**Format FLAG: CHH{XXX}**

Attachments:
rubik.txt
```

         | 0  1  2  |
         | 3  4  5  |
         | 6  7  8  |

9  10 11 | 12 13 14 | 15 16 17 | 18 19 20 
21 22 23 | 24 25 26 | 27 28 29 | 30 31 32
33 34 35 | 36 37 38 | 39 40 41 | 42 43 44
		     
           45 46 47 
           48 49 50
           51 52 53		 

```
scramble_sequence.txt
```
(F, AAAAAAAAABBBCCCDDDEEEBBBCCCDDDEEEBBBCCCDDDEEEFFFFFFFFF) = AAAAAABBBBBFCCCADDEEEBBFCCCADDEEEBBFCCCADDEEEDDDFFFFFF

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

IV = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv"
KEY="D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```
cipher.txt
```
b';V".24$9\x0cw`\x02 \x16\x0b9j:2F\x128-x?\x05C\x1b3$\nShX*W\x01,\x025\x01\x0e\x17\x17\x01\x1c>X\x02C=\x00<\x1a0\x18>\x06\x00JE\x1e\x00\x16X\x0b \x0c\x1d\x08\r9\x0b0\x12q\x1fRS7\x0f3\x01tfa)\x07\x0ee3\n(<\x163j\x0b0.Z%%q8j$2'
```
Hãy phân tích một chút về những gì chúng ta được cung cấp. File rubik.txt đã cho mình một mô hình cục rubik ban đầu với những số được đánh trên từng ô của rubik. Ở file scramble_sequence.txt, dòng đầu cho chúng ta biết được trạng thái của rubik sau khi thực hiện xoay "F". Đối với các bạn chơi rubik thì điều này sẽ tương đối dễ hiểu. Đoạn sau có sự xuất hiện của IV và KEY, mình có thể nhận ra dạng mã hóa CBC. Ở đây chúng ta thấy IV dài 54-bytes, nên mình sẽ phải chia cipher text ra từng block 54-bytes. Key cho thuật toán mã hóa trong CBC lần này là một tổ hợp xoay rubik. 

Vậy thì ở đây, điều khó nhất là mình phải dựng được hàm để xoay rubik bằng python. May mắn cho mình, challenge này tương tự như một challenge trong giải rgbCTF 2020 - RubikCBC. Ở trong writeup [này](https://dunsp4rce.github.io/rgbCTF-2020/cryptography/2020/07/14/RubikCBC.html), người viết đã dựng sẵn cho mình hàm *scramble*. Việc cần làm còn lại là chia khối và giải mã theo CBC.
```python3
def scramble(move, cube): 
    rounds = 1 
    if len(move) > 1: 
        if move[1] == '\'': 
            rounds = 3 
        elif move[1] == '2': 
            rounds = 2 
    U = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9] 
    U1 = [0, 1, 2, 5, 8, 7, 6, 3] 
    D = [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44] 
    D1 = [45, 46, 47, 50, 53, 52, 51, 48] 
    L = [0, 3, 6, 12, 24, 36, 45, 48, 51, 44, 32, 20] 
    L1 = [9, 10, 11, 23, 35, 34, 33, 21] 
    R = [53, 50, 47, 38, 26, 14, 8, 5, 2, 18, 30, 42] 
    R1 = [15, 16, 17, 29, 41, 40, 39, 27] 
    F = [6, 7, 8, 15, 27, 39, 47, 46, 45, 35, 23, 11] 
    F1 = [12, 13, 14, 26, 38, 37, 36, 24] 
    B = [2, 1, 0, 9, 21, 33, 51, 52, 53, 41, 29, 17] 
    B1 = [18, 19, 20, 32, 44, 43, 42, 30] 
    if move[0] == 'U': 
        old = U 
        old1 = U1 
    elif move[0] == 'D': 
        old = D 
        old1 = D1 
    elif move[0] == 'L': 
        old = L 
        old1 = L1 
    elif move[0] == 'R': 
        old = R 
        old1 = R1 
    elif move[0] == 'F': 
        old = F 
        old1 = F1 
    elif move[0] == 'B': 
        old = B 
        old1 = B1 
    else: 
        return 
    new = old[-rounds*3:] + old[:-rounds*3] 
    new1 = old1[-rounds*2:] + old1[:-rounds*2] 
    new = [cube[i] for i in new] 
    new1 = [cube[i] for i in new1] 
    cube = list(cube) 
    for i, c in zip(old, new): 
        cube[i] = c 
    for i, c in zip(old1, new1): 
        cube[i] = c 
    return bytes(cube)

def decrypt(ciphertext, move):
    IV = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv"

    ciphertext_blocks = [ciphertext[i*54:i*54+54] for i in range(len(ciphertext)//54)]
    
    out = b""
    
    for block in ciphertext_blocks:
        tmp = block
        for i in move.split(" "):
            block = scramble(i, block)
        pt = bytes([_a ^ _b for _a, _b in zip(block, IV)])
        out += pt
        IV = tmp

    return out

moves = "D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"
ciphertext = b';V".24$9\x0cw`\x02 \x16\x0b9j:2F\x128-x?\x05C\x1b3$\nShX*W\x01,\x025\x01\x0e\x17\x17\x01\x1c>X\x02C=\x00<\x1a0\x18>\x06\x00JE\x1e\x00\x16X\x0b \x0c\x1d\x08\r9\x0b0\x12q\x1fRS7\x0f3\x01tfa)\x07\x0ee3\n(<\x163j\x0b0.Z%%q8j$2'

print(decrypt(ciphertext, moves))
```
Flag: CHH{wh0_kn3w_rub1k_puzzl3_c4n_b3_u53d_f0r_3ncryp710n_t00?}
### RSA Percent Leak
Hệ thống mã hóa RSA đã vô tình để lộ quan hệ giữa p và q (thể hiện bởi l), sử dụng l để tái tạo p, q, và thu hồi flag.\
**Format FLAG: CHH{XXX}**

Attachment:
server.py
```python=
from Crypto.Util.number import *
from secret import flag
 
if __name__ == '__main__':
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    l = (p & q) * (p ^ q) | 0x1337
    c = pow(bytes_to_long(flag), 65537, n)
 
    print(f'n = {hex(n)}\n')
    # n = 0xa7643b16219097b5cc47af0acfbb208b2717aa2c2dbdbd37a3e6f6f40ae12b77e8d129eb672d660b6e146682a32d70c01f8e481b90b5ec710dabb57e8de2661fd49ec9d3a23d159bd5fb397047a1e053bbbf579d996e7fe7af56332753b816f4a5353966bfe50b7e0d95d9f235f5edfd59e23d3a7523cd25ea6e34a6f16f2d14b21c43f3bb7b68a8b2237a77fb6cb4cf3ba3987c478a39391b0f42a0d0230846a054599fea4effe27fcd9b514f711831b38f0288db256deef967f3d3d20b9e0071027b99cae1b0a3bd452efd654d1a4a431291ba8a99743d44a35afcb1db267a8c63574ac1ef32c8e71de473cc98aea927e3de0daf5819600818edac66b74b9b
    print(f'l = {hex(l)}\n')
    # l = 0x168b7f77f276e7f9f55df25d096cd5abbf632f22eae79ba72bad2d60ebccb03c6b614be2c682d58655a335277afa171fb085b40519311be7e74d26d37a066d9487ce511ad72e54779225534ca37c2714e51aca763676590dc2fb1e70c66dc8113704e168d46ab91fd8cdc77738314be6e1b20fc5664b747dddc94ff17f2fc7c80e75bcdc1c3618c54144070f13e698b31ff3d601559a1dafb62904c1079d7ba69ec5d024068dd3b2e6c2d71e4a81589734a5c6e4d4a05335edaf42e9aacf339f930ffb909fa100398eff29a61cb2e58eeff756b5a7b101d69f1e11fa989431bc175e0d59264da400f2d63dfaf1b2ba27ee9698a6a9a83bfe57aab0c069089fff
    print(f'c = {hex(c)}\n')
    # c = 0x56b894058c86db8641f2586a94794662520de144dbfbd0d3ad36a50b81b6d70a6a1d6f3e7faf2b37b1c53127e5684d235191664741ff2f0516c3d7596f3995abdd16a171be43f5660c9d4620db64f2430ae8c314f5576d912aae2e643517466b3fb409b4589b4726f12f3c376de45960dafdb658279b232118e6a9b1383ef600cdef465c499d330776c89cc5e0d02ec97a0614bc1d557f4e53595772bf02310105fe0ff8e27ba0376500990e6e8b2eb318bfa20f46b62c8841e8f97e8b649a2b18e4d6dc1bc2184184288559f8e43043bbff6f27479aa7846dac4f1d9e62ee3167fe511a6606f4ff69fb61bb4d2610913bc85e57144b0fe58cfca8e8b2ba996e

```
Ở đây, challenge đã cho mình sẵn n, l, c. Việc cần làm của mình ở đây là tìm ra d để có thể giải mã RSA. Để tìm được d thì phải biết phi, nghĩa là phải tính được p,q.  Tuy nhiên, vấn đề ở chỗ p và q là 2 số nguyên tố lớn vl (1024-bit). Để mà factor được n dường như là điều không thể. Vậy thì tìm p,q thế nào bây giờ?

Có một dữ kiện được leak ra là l = (p & q) * (p ^ q) | 0x1337. Với
