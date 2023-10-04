# **Buckeye CTF 2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### My First
Here's your flag: **8f163b472e2164f66a5cd751098783f9** Psyc! Its encrypted. You think I'd give it to you that easily? Definitely don't look at my code tho -><- (when you find the flag, put it in **bctf{}** format)

Bài này khá đơn giản, mình chỉ cần ném đoạn mã md5 kia lên trên một trang web giải mã bất kì trên Google. Ở đây mình sử dụng trang [này](https://hashes.com/en/decrypt/hash).

Flag: *bctf{orchestra}*

### Rivest-Shamir-Adleman
Big numbers make big security

Attachment: *dist.py*
```python3
message = b"[REDACTED]"

m = int.from_bytes(message, "big")

p = 3782335750369249076873452958462875461053
q = 9038904185905897571450655864282572131579
e = 65537

n = p * q
et = (p - 1) * (q - 1)
d = pow(e, -1, et)

c = pow(m, e, n)

print(f"e = {e}")
print(f"n = {n}")
print(f"c = {c}")


# OUTPUT:
# e = 65537
# n = 34188170446514129546929337540073894418598952490293570690399076531159358605892687
# c = 414434392594516328988574008345806048885100152020577370739169085961419826266692
```

Bài này là về RSA. Do đã có đủ p,q nên mọi việc không có gì khó cả. Mình chỉ cần áp dụng công thức *m=pow(c,d,n)* là ra được flag.

```python3
from Crypto.Util.number import *

p = 3782335750369249076873452958462875461053
q = 9038904185905897571450655864282572131579
e = 65537
n = 34188170446514129546929337540073894418598952490293570690399076531159358605892687
c = 414434392594516328988574008345806048885100152020577370739169085961419826266692

et = (p - 1) * (q - 1)
d = pow(e, -1, et)

print(long_to_bytes(pow(c,d,n)))
```

Flag: *bctf{1_u53d_y0ur_k3y_7h4nk5}*

### Secret Code
Here's your flag again: **1:10:d0:10:42:41:34:20:b5:40:03:30:91:c5:e1:e3:d2:a2:72:d1:61:d0:10:e3:a0:43:c1:01:10:b1:b1:b0:b1:40:9** LOL you **snub_wrestle**. Good luck trying to undo my xor key I used on each character of the flag.

Nhìn vào đoạn mã trên khi bỏ dấu ":" đi mình thấy nó khá giống hex, đề bài lại đề cập tới XOR nên mình thử luôn. Ý tưởng là mình sẽ XOR đoạn mã trên với "snub_wrestle". Đây là code để thực hiện:

```python3
from pwn import *

flag = "1:10:d0:10:42:41:34:20:b5:40:03:30:91:c5:e1:e3:d2:a2:72:d1:61:d0:10:e3:a0:43:c1:01:10:b1:b1:b0:b1:40:9"
flag = flag.replace(":","")
flag = bytes.fromhex(flag)
key = b'snub_wrestle'

print(xor(flag, key))
```

Và mình ra được flag thật :v  
Flag: *bctf{d0n't_lo0k_uP_snub_wResTling}*

### Electronical
I do all my ciphering electronically

https://electronical.chall.pwnoh.io

Dưới đây là đoạn code của trang web trên:
```python3
from Crypto.Cipher import AES
from flask import Flask, request, abort, send_file
import math
import os

app = Flask(__name__)

key = os.urandom(32)
flag = os.environ.get('FLAG', 'bctf{fake_flag_fake_flag_fake_flag_fake_flag}')

cipher = AES.new(key, AES.MODE_ECB)

def encrypt(message: str) -> bytes:
    length = math.ceil(len(message) / 16) * 16
    padded = message.encode().ljust(length, b'\0')
    return cipher.encrypt(padded)

@app.get('/encrypt')
def handle_encrypt():
    param = request.args.get('message')

    if not param:
        return abort(400, "Bad")
    if not isinstance(param, str):
        return abort(400, "Bad")

    return encrypt(param + flag).hex()

@app.get('/source')
def handle_source():
    return send_file(__file__, "text/plain")

@app.get('/')
def handle_home():
    return """
        <style>
            form {
                display: flex;
                flex-direction: column;
                max-width: 20em;
                gap: .5em;
            }

            input {
                padding: .4em;
            }
        </style>
        <form action="/encrypt">
            <h2><i>ELECTRONICAL</i></h2>
            <label for="message">Message to encrypt:</label>
            <input id="message" name="message"></label>
            <input type="submit" value="Submit">
            <a href="/source">Source code</a>
        </form>
    """

if __name__ == "__main__":
    app.run()
```

Nôm na là mình sẽ nhập gì đó vào input. Chương trình sẽ trả về cho mình một đoạn mã hóa của (input + flag) sử dụng AES_ECB. Vì vậy, mình sẽ sử dụng kĩ thuật Padding Oracle Attack.

Đầu tiên mình xác định độ dài của flag (Thật ra là không cần thiết :v)
```python3
import requests

url = 'https://electronical.chall.pwnoh.io/'

payload = "A"
while(True):
    response = requests.get(f'{url}/encrypt', params={'message': payload})
    print(response.text)
    if(len(response.text) > 96):
        print(payload, len(payload))
        break
    payload += 'A'
```
Ở đây mình tìm ra được flag dài 40 bytes.
Đối với AES_ECB, mỗi block sẽ dài 16 bytes, tương đương 32 ký tự hex. Ý tưởng sẽ là như vầy:
```
Khi input 16 chữ 'A':
AAAAAAAAAAAAAAAA bctf{xxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxx00000000

Vì flag có dạng bctf{, mình nhập 10 chữ 'A':
AAAAAAAAAAxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xx00000000000000

Với i chạy từ 45 -> 125 trong bảng mã ascii, gửi payload bao gồm 10 chữ A + bctf{ + i:
AAAAAAAAAAbctf{i xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxx0000000

Với mỗi i, so sánh kết quả trả về nhận được với khi mình nhập 10 chữ 'A'. Nếu trùng khớp, ta sẽ có được kí tự đầu tiên

Làm tương tự, mình sẽ leak được toàn bộ flag.
```

Code thực hiện ý tưởng:
```python3
import requests

url = 'https://electronical.chall.pwnoh.io/'

flag = 'bctf{'

count = 15
for i in range(0,96,32):
    while(True):
        payload = "0"*(count-len(flag))
        response = requests.get(f'{url}/encrypt', params={'message': payload})
        print(i)


        for j in range(45, 125):
            print('Testing Character:' + chr(j))
            print("Flag: ", flag)
            print('Sending....: ' + payload + flag + chr(j))
            response2 = requests.get(f'{url}/encrypt', params={'message': payload + flag + chr(j)})
            print('Compare: ' + (response2.text)[i:i+32] + ' with: ' + (response.text)[i:i+32])

            if (response2.text)[i:i+32] == (response.text)[i:i+32]:
                flag += chr(j)
                print("Flag: ", flag)
                break
        
        if(len(flag) == 15 or len(flag) == 31 or len(flag) == 39):
            count += 16
            break
    
    if len(flag) == 40:
        break
print(flag)
```
Và mình ra được flag. Tuy nhiên, đoạn code trên chạy khá lâu vì với mỗi kí tự cần test, mình lại phải gửi 1 request.

(Não đang load để viết solve mới)

Flag: *bctf{1_c4n7_b3l13v3_u_f0und_my_c0d3b00k}*

**© 2023,Pham Quoc Trung. All rights reserved.**







