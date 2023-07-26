from sage.all import *
import gmpy2

data = [752589857254588976778, 854606763225554935934, 102518422244000685572, 779286449062901931327, 
        424602910997772742508, 1194307203769437983433, 501056821915021871618, 691835640758326884371, 
        778501969928317687301, 1260460302610253211574, 833211399330573153864, 223847974292916916557]

p = 1341161101353773850779
e = 2
mul = 2898124289
shift = 3442055609

def rev_pow_func(data,e,p):
    Zn = Zmod(p)
    return  Zn(data).sqrt(all=True)

def rev_exp_func(data,e,p):
    G = Integers(p)
    return G(data).log(G(e))

def generate_array(a, b):
    return [b[i] if a[i] > 670000000000000000000 and b[i] < 670000000000000000000 else a[i] for i in range(min(len(a), len(b)))]

def rev_xor_shift_right_func(data):
    data = format(data, "032b")
    cal_data = [0]
    for i in range(32):
        cal_data.append(cal_data[i] ^ int(data[i]))
    return int("".join(str(i) for i in cal_data[1:]), 2)

def rev_mul_func(data, mul):
    return (data * int(gmpy2.invert(mul, 0xffffffff + 1))) & 0xffffffff

def rev_plus_func(data, shift):
    return (data - shift) & 0xffffffff

def join_blocks(blocks):
    return b''.join(block.to_bytes((block.bit_length() + 7) // 8, 'little') for block in blocks)

def unpadding_pkcs7(padded_data):
    padding_size = padded_data[-1]
    return padded_data[:-padding_size]


data1 = [rev_pow_func(x,e,p) for x in data]
data2 = generate_array([rev_exp_func(x[0],e,p) for x in data1], [rev_exp_func(x[1],e,p) for x in data1])
data3 = [rev_xor_shift_right_func(x) for x in data2]
data4 = [rev_mul_func(x, mul) for x in data3]
data5 = [rev_plus_func(x, shift) for x in data4]
data6 = join_blocks(data5)

print(unpadding_pkcs7(data6))
