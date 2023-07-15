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

### Rubic Cipher

### RSA Percent Leak
