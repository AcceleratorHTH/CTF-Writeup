# **TFC\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**

### MAYDAY!

We are sinking! The nearest ship got our SOS call, but they replied in pure gobbledygook! Are ye savvy enough to decode the message, or will we be sleepin' with the fish tonight? All hands on deck!

*Whiskey Hotel Four Tango Dash Alpha Romeo Three Dash Yankee Oscar Uniform Dash Sierra One November Kilo India November Golf Dash Four Bravo Zero Uniform Seven*

Flag format: **TFCCTF{RESUL7-H3R3}**

Ở bài này, tác giả đã sử dụng bảng chữ cái ngữ âm NATO. Các bạn có thể tìm hiểu thêm về nó thông qua Google. Cũng có rất nhiều công cụ có thể giải nó, tuy nhiên ở đây mình sẽ viết code Python để tiện sau này sử dụng.

```python3
NATO_PHONETIC_ALPHABET = {
    "A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo", "F": "Foxtrot",
    "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett", "K": "Kilo", "L": "Lima",
    "M": "Mike", "N": "November", "O": "Oscar", "P": "Papa", "Q": "Quebec", "R": "Romeo",
    "S": "Sierra", "T": "Tango", "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "X-ray",
    "Y": "Yankee", "Z": "Zulu", "-": "Dash", ".": "Stop", "0": "Zero", "1": "One",
    "2": "Two", "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven", 
    "8": "Eight", "9": "Nine",
}

REVERSE_NATO = {v: k for k, v in NATO_PHONETIC_ALPHABET.items()}

def encode_to_nato(message):
    return ' '.join(NATO_PHONETIC_ALPHABET.get(i.upper(), i) for i in message)

def decode_from_nato(nato_message):
    return ''.join(REVERSE_NATO.get(i.capitalize(), i) for i in nato_message.split())

cipher = "Whiskey Hotel Four Tango Dash Alpha Romeo Three Dash Yankee Oscar Uniform Dash Sierra One November Kilo India November Golf Dash Four Bravo Zero Uniform Seven"
print("TFCCTF{" + decode_from_nato(cipher) + "}")
```
Flag: TFCCTF{WH4T-AR3-YOU-S1NKING-4B0U7}

### DIZZY
Embark on 'Dizzy', a carousel ride through cryptography! This warmup challenge spins you around the basics of ciphers and keys. Sharpen your mind, find the flag, and remember - in crypto, it's fun to get a little dizzy!

*T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24*

Thoạt nhìn qua thì mình cũng chưa hiểu lắm. Sau khi search trên mạng một lúc cũng như nhìn kĩ lại, mình nhận ra flag đã bị tách từng ký tự ra. Các ký tự được liệt kê đi kèm vị trí index của nó trong flag. Từ đây, việc ghép lại flag hoàn toàn có thể làm bằng tay, nhưng ở đây mình sẽ sử dụng python cho việc đó.

```python3
def process_string(input_string):
    reversed_string = input_string[::-1]
    result = " ".join([f"{char}{i+1}" for i, char in enumerate(reversed_string)])
    return result

def reverse_process_string(input_string): 
    input_list = input_string.split()
    sorted_list = sorted(input_list, key=lambda x: int(x[1:]), reverse=True)
    result = ''.join([i[0] for i in sorted_list])
    result = result[::-1]
    return result

cipher = "T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24"
print(reverse_process_string(cipher))
```
Flag: TFCCTF{th15_ch4ll3ng3_m4k3s_m3_d1zzy_;d}

### RABID
There might be a little **extra** piece of information here.

Attachment: rabid.txt
```
VEZDQ1RGe13kwdV9yNGIxZF9kMGc/IT8hPyE/IT8hPi8+Pz4/PjEyMzkwamNhcHNrZGowOTFyYW5kb21sZXR0ZXJzYW5kbnVtYmVyc3JlZWVlMmozfQ==
```
Ở đây, mình thử ném vào CyberChef và nhận ra đoạn "VEZDQ1RGe1" giải mã thành "TFCCTF{", là format của flag. Vậy giờ mình cần phải xử lí đoạn còn lại bao gồm
```
3kwdV9yNGIxZF9kMGc/IT8hPyE/IT8hPi8+Pz4/PjEyMzkwamNhcHNrZGowOTFyYW5kb21sZXR0ZXJzYW5kbnVtYmVyc3JlZWVlMmozfQ==
```
Đoạn này không giải mã ra gì cả. Mình để ý đề bài có tô đậm chữ "extra". Có vẻ đoạn này bị thiếu hoặc thừa gì đó. Trong CyberChef, mình có thấy rằng đoạn này chỉ có 107-bits. Có thể bạn không biết thì số bit của Base64 sẽ phải chia hết cho 6. Dựa vào đó, mình đã thử thêm 1 bit bất kì vào đầu của đoạn mã trên và giải mã được nó.
```
13kwdV9yNGIxZF9kMGc/IT8hPyE/IT8hPi8+Pz4/PjEyMzkwamNhcHNrZGowOTFyYW5kb21sZXR0ZXJzYW5kbnVtYmVyc3JlZWVlMmozfQ==
=> ×y0u_r4b1d_d0g?!?!?!?!?!>/>?>?>12390jcapskdj091randomlettersandnumbersreeee2j3}
```
Kết hợp format flag với đoạn trên, mình ra được flag khá dài :v

Flag: TFCCTF{y0u_r4b1d_d0g?!?!?!?!?!>/>?> >12390jcapskdj091randomlettersandnumbersreeee2j3}

### AES CTF TOOL V1
Behold, digital warriors, and prepare to take a wild dive into the thrilling vortex of AES encryption! Get ready to decipher a challenge designed to baffle the brightest, all while giving a shameless shout-out to our creator's GitHub creation.

Your mission, should you choose to accept it, is to navigate the labyrinthine depths of GitHub and discover the holy grail of tools - my very own, lovingly crafted AES decryption gizmo. Why, you ask? Because nothing says 'modern age quest' like using a home-brewed tool to solve a problem that I've arbitrarily created for your torment...I mean, amusement.

https://github.com/hofill/AES-CTF-Tool
```
nc challs.tfcctf.com 30670
```
Ở đây, tác giả cung cấp cho mình một công cụ để giải mã hóa AES do chính tác giả viết ra. Mình có biết đến RSACTFTool, nhưng đây là công cụ đầu tiên mình thấy giành cho AES. Có vẻ sẽ giúp ích nhiều cho về sau vì sau khi sử dụng mình thấy nó khá đỉnh (Shout out for Hofill)

Quay lại thử thách của chúng ta, ở đây khi mình netcat thì giao diện không có gì ngoài 2 dòng encrypt và quit. Không hề có cipher ở đây. Thiết nghĩ không thể làm thử thách này một cách bình thường mà phải remote qua python rồi.

Đầu tiên, đây là hướng dẫn sử dụng của tác giả:
```
Usage
A file similar to main.py must be created. init_server and encrypt must be implemented.

init_server
This method must return an object/process/handle that can be used to encrypt/decrypt data.

encrypt
This method must be implemented such that it uses the process returned from init_server and encrypts it. It must return a hex string that is the result of the encryption.

decrypt
This method is not necessary to be implemented, unless you're running a Padding Oracle attack.

After these methods have been implemented, you start the detector by running begin() on the newly created instance of BCDetector
```

Mình thử mở file main.py trong tool:
```python3
from BCDetector import BCDetector
from pwn import *

from exceptions import BadPaddingException

context.log_level = 'critical'


class Det(BCDetector):
    def __init__(self):
        super().__init__(save_to_file=True, server=True)

    def decrypt(self, data, server: process):
        server.recvuntil(b"> ")
        server.sendline(b"2")
        server.recvuntil(b": ")
        server.sendline(data.encode())
        response = server.readline().strip()
        if response == b"Padding is incorrect.":
            raise BadPaddingException
        return response.decode()

    def encrypt(self, data, server: process):
        server.recvuntil(b"> ")
        server.sendline(b"1")
        server.sendline(data.encode())
        return server.readline().strip().split(b": ")[1].decode()

    def init_server(self):
        return process(["./test_servers/ecb.py"])


if __name__ == "__main__":
    detector = Det()
    detector.begin()
```
Ở đây mình thấy có function init_server trả về việc thực thi file ecb.py. Khả năng để giải được challenge thì mình phải tìm cách cho nó connect đến server ở đây. Vì đã sử dụng qua pwntools khi còn học chơi pwnable, mình thử sửa code thành như sau:
```python3
 def init_server(self):
        return remote('challs.tfcctf.com', 30670)
```

Thử chạy code, mọi thứ đều ổn áp, và mình chỉ cần ngồi đợi cho tool giải mã ra flag. Mode ở đây được detect là ECB (Không biết do mình xài WSL hay gì mà có vẻ hơi lâu :v. Các bạn có thể thử test nhé)

Flag: TFCCTF{gu355_th4t_w4s_345y...Wh4(chưa xong)

### AES CTF TOOL V2
Same as the last one, but V2!

https://github.com/hofill/AES-CTF-Tool
```
nc challs.tfcctf.com 30670
```

Khác với challenge trước, ở challenge này khi mình netcat đến thì server in ra cho mình một đoạn hex cipher. Việc của mình chỉ cần là giải mã nó.

Với công cụ mạnh mẽ trong tay, mình chỉ cần thử giải mã nó với từng mode. Ở đây flag được tìm thấy khi mình sử dụng mode CBC
```python3
def init_server(self):
        return process(["./test_servers/cbc.py"])
```
![Screenshot 2023-07-31 003013](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/5924ec84-b09d-4bb5-8454-6d857fcf28d3)
![Screenshot 2023-07-31 003110](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/2adb77d1-9004-4b32-97f6-ac01e93b4425)


Flag: TFCCTF{W3ll..._th15_0n3_w4s_4ls0_easy!}

### CYPHEREHPYC
Evil is a name of a foeman, as I live.

Attachment: cypherehpyc.py
```python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"redacted" * 2

FLAG = "redacted"

initial_cipher = bytes.fromhex(input("Initial HEX: ").strip())

cipher = AES.new(KEY, AES.MODE_ECB).encrypt(pad(initial_cipher, 16))
print(cipher.hex())
cipher = AES.new(KEY, AES.MODE_ECB).encrypt(pad(cipher, 16))
print(cipher.hex())

cipher = AES.new(KEY, AES.MODE_ECB).encrypt(pad(cipher, 16))
print(cipher.hex())
result = bytes.fromhex(input("Result HEX: ").strip())

if cipher == result:
    print(FLAG)
else:
    print("Not quite...")
```
Với challenge này, flag được mã hóa sử dụng AES.MODE_ECB. Khi netcat, server bắt người dùng nhập vào một đoạn hex. Nó sẽ in ra 2 output khi mã hóa đoạn hex đó lần 1 và lần 2. Tiếp theo, chương trình bắt chúng ta phải nhập vào đoạn mã hóa khi mã hóa lần 3. Nếu đúng, ta sẽ có được flag.
![Screenshot 2023-07-31 005902](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/30dfad20-f61b-460b-ba9b-3ad830000a06)

Đầu tiên, mình đã định sử dụng các điểm yếu trong ECB để giải nhưng có vẻ không khả thi. Sau cùng, mình nhận ra thử thách này dễ hơn mình nghĩ do ở đây, KEY là cố định. Vì vậy, mình chỉ cần nhập 1 đoạn hex bất kì vào là sẽ có được output mã hóa lần 1,2. Mình mở một connect khác vào server và nhập vào đoạn mã hóa lần 2 thu được ban nãy, chương trình sẽ trả về cho mình mã hóa lần 3,4 của đoạn hex ban đầu mình nhập
![Screenshot 2023-07-31 005908](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/9ed95202-a7f2-472e-8f91-28f89f610a46)
Giờ việc còn lại chỉ là copy kết quả lần 3 và paste vô, mình sẽ có được flag
![Screenshot 2023-07-31 005915](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/8c91548b-e37e-4dd0-936c-d03e5462cbc4)

Flag: TFCCTF{3v3ryth1ng_1s_r3v3rs3d_1n_th3_3nd}

### ALIEN MUSIC
We've intercepted an alien transmission that seems to be composed of sheet music notes. Our lead translator is tone-deaf, our pianist can't spell 'binary', and the guitarist keeps shouting 'hex' in his sleep! Can you help us decode the tune?

*DC# C#D# C#C C#C DC# C#D# E2 C#5 CA EC# CC DE CA EB EC# D#F EF# D6 D#4 CC EC EC CC# D#E CC E4*

Flag format: **TFCCTF{l33t_t3xt_h3r3}**

Ở bài này, mình thử áp flag format vào đoạn code trên thì trông nó có vẻ khá hợp lý
```
DC# C#D# C#C C#C DC# C#D# E2
T   F    C   C   T   F    {
```
Vậy giờ nhiệm vụ là tìm ra sự liên hệ đằng sau những kí tự này. Ở đây, tác giả có đề cập tới "hex" và "binary". Vì vậy, mình thử nhìn vào bảng mã ASCII và có được như sau:
```
ct:   DC# C#D# C#C C#C DC# C#D# E2
text: T   F    C   C   T   F    {
hex:  54  46   43  43  54  46   7B
```
Từ những thứ trên, mình có thể suy ra được một bảng mã như sau
```
D# = 6
D = 5
C# = 4
C = 3
E = 7
2 = B
```
Dựa trên bảng mã hex, mình có thể tạo ra bảng mã hoàn chỉnh dạng như sau.
```
A = 0
A# = 1
B = 2
C = 3
C# = 4
D = 5
D# = 6
E = 7
F = 8
F# = 9
1 = A
2 = B
3 = C
4 = D
5 = E
6 = F
```
Sau khi chuyển đoạn mã của challenge theo bảng trên, ta sẽ ra được một đoạn hex như sau:
```
54 46 43 43 54 46 7B 4E 30 74 33 57 30 72 74 68 79 5F 6D 33 73 73 34 67 33 7D
```
Sử dụng bảng mã ASCII, ta ra được flag. Dưới đây là code để thực hiện thử thách này
```python3
input_string = "DC# C#D# C#C C#C DC# C#D# E2 C#5 CA EC# CC DE CA EB EC# D#F EF# D6 D#4 CC EC EC CC# D#E CC E4"

mapping_dict = {
    "A": '0', 
    "A#": '1', 
    "B": '2', 
    "C": '3', 
    "C#": '4', 
    "D": '5', 
    "D#": '6', 
    "E": '7', 
    "F": '8', 
    "F#": '9', 
    "1": 'A', 
    "2": 'B', 
    "3": 'C', 
    "4": 'D', 
    "5": 'E', 
    "6": 'F'
}

input_list = list(input_string)

output_list = []

i = 0
while i < len(input_list):

    if i < len(input_list) - 1 and input_list[i] + input_list[i + 1] in mapping_dict:
        output_list.append(mapping_dict[input_list[i] + input_list[i + 1]])
        i += 2

    elif input_list[i] in mapping_dict:
        output_list.append(mapping_dict[input_list[i]])
        i += 1

    elif input_list[i] == ' ':
        output_list.append(' ')
        i += 1

output_string = "".join(output_list)

output_ascii = bytes.fromhex(output_string.replace(' ', '')).decode('utf-8')

print(output_ascii)
```
Flag: TFCCTF{N0t3W0rthy_m3ss4g3}

### FERMENTATION
Welcome to **FERMENTATION**, a wacky world where pickling isn't just for cucumbers and AES isn't a gloomy cipher! In this cryptic concoction, expect to decrypt pickled objects and juggle AES keys. So, dust off your coder's hat and jump into this zesty challenge – it's time to get yourself into a real pickle!

Attachment: server.py
```python3
#!/usr/bin/env python3
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = 'redacted'

header = input("Header: ")
name = input("Name: ")
is_admin = False

data = header.encode() + pickle.dumps((name, is_admin))

encrypted = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(data, 16))
print(encrypted.hex())

while True:
    data = bytes.fromhex(input().strip())
    try:
        if pickle.loads(unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(data),16)[len(header):])[1] == 1:
            print(FLAG)
        else:
            print("Wait a minute, who are you?")
    except:
        print("Wait a minute, who are you?")
```

```
nc challs.tfcctf.com 31040
```
