# **Digital_Dragons_CTF_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### MD5 Hash Collision
Generate the collision and uncover the two inputs, submit them to reveal the flag. The flag is a unique string that signifies your victory in this conquest.

Note : The flag format is typically **CTF{...}** where the content inside the curly braces is the solution to the challenge.

https://y2g1twq1.astonchain.com/

Giao diện của challenge là một trang web cho phép người dùng up lên 2 file:

![Screenshot 2023-08-09 001106](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/30d91581-d8c7-4c49-a2c8-649a3d0bafa0)
Theo như mình thấy thì trang web sẽ so sánh 2 mã hash của 2 file mình up lên, nếu chúng giống nhau thì sẽ trả về flag. Vì vậy mình thử up cùng 1 file lên và kết quả trả về như sau:

![Screenshot 2023-08-09 001427](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/fb28fa9e-cb2a-4cc4-881a-93f35c4f608a)
Có vẻ không được (đương nhiên là thế rồi :v). Mình thử để xem bài có handle được trường hợp đó không chứ theo như giao diện trang web thì ở đây mã hash được sử dụng là MD5, thứ mà đã xuất hiện collision (xung đột). Nôm na là với hai chuỗi dữ liệu khác nhau, ta lại tạo ra được cùng một giá trị băm MD5. 
Mình sẽ sử dụng 2 file *erase.exe* và *hello.exe* trong link [này](https://www.mscs.dal.ca/~selinger/md5collision/) để khai thác được lỗ hổng MD5 collision và lấy flag

![Screenshot 2023-08-09 002103](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/290bf080-f866-4fdb-a447-ea6d7f932310)

Flag: CTF{Md5_h@$h_c0ll15i0n_1z_3zy!!!}

### MooMoo
Can you crack this unpredictable secret language used between two drug cartels?

Note : The flag format is typically **flag{...}** where the content inside the curly braces is the solution to the challenge.

Attachment: *MooMoommmoooo_1.txt*
```
OOOMoOMoOMoOMoOMoOMoOMoOMoOMMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOo
MMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOoMMMmoOMMMMMMmoOMMMMOOMOomOo
MoOmoOmooOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoO
MMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMM
moOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoO
MoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoomOoOOO
moOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoO
MoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoO
moOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoo
mOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMM
MOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoo
mOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoO
MMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOo
MMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoomOoOOOmoOOOOmOomOoMMM
moOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoO
MoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMM
MOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoO
MoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMM
moOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOo
moomoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOo
moomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOo
MMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMM
MOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMM
moOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOo
mOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoO
MoOmOomoomoOMoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOo
moomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoO
OOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoO
mOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOO
mOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOo
moomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoomOoOOO
moOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoo
mOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOO
MOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoO
MoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoO
MoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOo
OOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOo
moOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoO
MoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMM
moOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOo
MMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOo
MMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoomOoOOOmoOOOOmOomOo
MMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoO
MoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoO
MMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoO
MoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoO
moOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoO
MMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoO
MoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOo
mOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoo
mOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoomOoOOOmoOOOOmOo
mOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOo
moomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoO
MMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoO
MoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOo
MMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoO
MoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMM
MOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoomOo
OOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOo
moOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOO
moOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoO
MoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoO
moOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoomOo
```
Bài này sử dụng một ngôn ngữ khá hay ho mà mình đã từng sử dụng để tạo ra một challenge trong giải HolaCTF 2023. Các bạn có thể xem write-up của mình tại [đây](https://github.com/AcceleratorHTH/CTF-Writeup/tree/main/Hola%20CTF%202023). Nôm na thì nó là COW programming language, ngôn ngữ con bò :v. Mình sẽ sử dụng trang web [này](https://www.cachesleuth.com/cow.html) để decode nó

![Screenshot 2023-08-09 002931](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/4ace3dd7-596a-4dac-a3bb-694e55784851)

Flag: flag{c0ngratulat10ns_y0u_l3arnt_c0w_lang}

### Trial Challenge - Before Qualifying Round
This code challenges participants to decrypt a given block cipher ciphertext using a specific decryption algorithm.

Participants are required to understand the decryption process, implement the necessary functions, and apply their knowledge of bitwise operations and block ciphers to obtain the original plaintext.

Note : The flag format is typically **flag{...}** where the content inside the curly braces is the solution to the challenge.

Attachment: *BlockCIpher.py*
```python
import struct
import sys
import base64

def process_data(data):
    padding = 4 - len(data) % 4
    if padding != 0:
        data += "\x00" * padding

    result = []
    blocks = struct.unpack("I" * (len(data) // 4), data.encode())
    for block in blocks:
        result.append(block ^ block >> 16)

    output = b''
    for block in result:
        output += struct.pack("I", block)

    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: {} data".format(sys.argv[0]))
        sys.exit(1)

    data = sys.argv[1]
    encoded_output = process_data(data)
    b64_encoded_output = base64.b64encode(encoded_output).decode()
    print(b64_encoded_output)

if __name__ == "__main__":
    main()

#BwthZ0gbM2wOVW1lbyswX0Btc1ktOnJ5DVR9AA==
```
Ở đây, flag bị chia ra thành từng khối 4-bytes, mỗi khối được mã hóa bằng cách XOR khối đó với khối đó dịch phải 16-bits. Vậy phải giải mã như nào đây?

Ở đây, do khối được dịch phải 16-bits mà 1 khối là 32-bits, ta có thể thấy 16-bits đầu của khối ta thu được sẽ là 16-bits cuối của khối ban đầu sau khi dịch phải. Để dễ hình dung thì:

Giả sử:
block: **0110011101100001**0000101100000111\
block>>16: 0000000000000000**0110011101100001**\
=> XOR: **0110011101100001**0110110001100110

Vậy ta hoàn toàn có thể tạo ra block>>16 từ kết quả và xor nó với kết quả để lấy được block ban đầu nhờ tính đối xứng của XOR. Ghép các khối đó lại, ta sẽ có được flag. Dưới đây là code python cho bài này
```python
import base64
from Crypto.Util.number import *

def rev_xor_shift_right_func(data):
    data = format(data, "032b")
    data_shift = '0'*16 + data[:16]
    res = []
    for i in range(32):
        res.append(int(data_shift[i]) ^ int(data[i]))
    return int("".join(str(i) for i in res), 2)

def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))

def join_blocks(blocks):
    return b''.join(block.to_bytes((block.bit_length() + 7) // 8, 'little') for block in blocks)

cipher = "BwthZ0gbM2wOVW1lbyswX0Btc1ktOnJ5DVR9AA=="
cipher = base64.b64decode(cipher)

flag = join_blocks([rev_xor_shift_right_func(block) for block in split_block(cipher, 4)])
print(flag)
```

Flag: flag{w3lc0me_t0_34sY_CrypT}

**© 2023,Pham Quoc Trung. All rights reserved.**
