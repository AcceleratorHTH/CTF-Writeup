# TetCTF 2024

## **TetCTF 2024**

## **CRYPTOGRAPHY WRITEUP**

### **Author:**

* Pham Quoc Trung

### **Used Language:**

* Python3

### **Problem Solving:**

### flip

> Chall name: flip&#x20;
>
> Category: Crypto&#x20;
>
> Author: ndh&#x20;
>
> Description: You are allowed to inject a software fault.&#x20;
>
> Server: `nc 139.162.24.230 31339`&#x20;
>
> Material: `flip.zip`

_encrypt.c_

```c
// To compile:
// git clone https://github.com/kokke/tiny-AES-c
// gcc encrypt.c tiny-AES-c/aes.c
#include "tiny-AES-c/aes.h"
#include <unistd.h>

uint8_t plaintext[16] = {0x20, 0x24};
uint8_t key[16] = {0x20, 0x24};

int main() {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, plaintext);
    write(STDOUT_FILENO, plaintext, 16);
    return 0;
}
```

_main.py_

```python
# Please ensure that you solved the challenge properly at the local.
# If things do not run smoothly, you generally won't be allowed to make another attempt.
from secret.network_util import check_client, ban_client

import sys
import os
import subprocess
import tempfile

OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020


def main():
    if not check_client():
        return

    key = os.urandom(16)
    with open("encrypt", "rb") as f:
        content = bytearray(f.read())

    # input format: hex(plaintext) i j
    try:
        plaintext_hex, i_str, j_str = input().split()
        pt = bytes.fromhex(plaintext_hex)
        assert len(pt) == 16
        i = int(i_str)
        assert 0 <= i < len(content)
        j = int(j_str)
        assert 0 <= j < 8
    except Exception as err:
        print(err, file=sys.stderr)
        # ban_client()
        return

    # update key, plaintext, and inject the fault
    content[OFFSET_KEY:OFFSET_KEY + 16] = key
    content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
    content[i] ^= (1 << j)

    tmpfile = tempfile.NamedTemporaryFile(delete=True)
    with open(tmpfile.name, "wb") as f:
        f.write(content)
    os.chmod(tmpfile.name, 0o775)
    tmpfile.file.close()

    # execute the modified binary
    try:
        ciphertext = subprocess.check_output(tmpfile.name, timeout=1.0)
        print(ciphertext.hex())
    except Exception as err:
        print(err, file=sys.stderr)
        ban_client()
        return

    # please guess the AES key
    if bytes.fromhex(input()) == key:
        with open("secret/flag.txt") as f:
            print(f.read())
        from datetime import datetime
        print(datetime.now(), plaintext_hex, i, j, file=sys.stderr)


main()
```

#### Recon

Sau một hồi đọc code thì mình thấy được bài này sẽ cho người dùng nhập vào input dạng `hex(plaintext) i j`, với `plaintext` dài 16 bytes, `i` là một số từ 0 tới độ dài nội dung file binary `check` và `j` chạy từ 0 tới 7. Hệ thống sẽ tiến hành ghi `plaintext` và `key` (được gen từ hàm os.random(16)) vào offset của nó trong file `check` sau đó lưu thành một file tạm và khởi chạy. Kết quả sẽ trả về ciphertext của nó được mã hóa bằng AES\_ECB. Yêu cầu của chúng ta là phải nhập đúng `key` và chương trình sẽ trả về flag.

Về 2 giá trị `i` và `j`, nó được sử dụng ở đoạn code `content[i] ^= (1 << j)`, có nghĩa rằng chúng ta được quyền sửa 1 byte bất kì ở trong đoạn file binary trước khi nó được khởi chạy. Hẳn sẽ có cách nào đó để ta có thể làm chương trình in ra `key` hoặc tạo ra ciphertext gì đó dễ dàng tính được `key`? Nghe vế đầu sẽ có vẻ khả thi hơn.

Lưu ý một điều nữa là ở đoạn code khởi chạy file binary tạm thời

```python
# execute the modified binary
    try:
        ciphertext = subprocess.check_output(tmpfile.name, timeout=1.0)
        print(ciphertext.hex())
    except Exception as err:
        print(err, file=sys.stderr)
        ban_client()
        return
```

Có thể thấy nếu có lỗi xảy ra trong quá trình khởi chạy, hàm `ban_client()` sẽ được thực thi. Ta không biết nó sẽ làm gì, cơ mà không nên chơi liều. Challenge có cho sẵn Dockerfile nên ta có thể dựng lại và xóa dòng đó đi cho an toàn để thử nghiệm payload.

#### Unintended solution

Vì ở bài này, ta chỉ được quyền sửa duy nhất 1 byte, và nội dung của file binary ngoài phần `key` và `plaintext` ra thì mọi thứ luôn không đổi vì nó được lấy từ file `check`. Chắc chắn sẽ có 1 byte khiến cho file binary này hoạt động không như mong muốn và giúp ta có được key. Nhưng để biết là byte nào thì mình không biết, cho nên mình đã nghĩ tới chuyện là sẽ thử thay đổi từng byte một và quan sát output trả về.

Mình sử dụng một đoạn code như sau:

```python
import os
import subprocess
import tempfile
from tqdm import tqdm

OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020


def main():

    key = os.urandom(16)
    
    for i in tqdm(range(0, 21032)):
        for j in range(0, 8):
            with open("encrypt", "rb") as f:
                content = bytearray(f.read())
            
            plaintext_hex = ''0' * 32'
            pt = bytes.fromhex(plaintext_hex)

            content[OFFSET_KEY:OFFSET_KEY + 16] = key
            content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
            content[i] ^= (1 << j)

            tmpfile = tempfile.NamedTemporaryFile(delete=True)
            with open(tmpfile.name, "wb") as f:
                f.write(content)
            os.chmod(tmpfile.name, 0o775)
            tmpfile.file.close()
            
            try:
                ciphertext = subprocess.check_output(tmpfile.name, timeout=0.001)
                if(key in ciphertext):
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
                    print("Found key! Position i = " + str(i) + " j = " + str(j))
            except:
                continue

main()
```

Mình sử dụng rất nhiều hàm `print()` là do khi sửa đổi các bit của file binary có thể sẽ xảy ra lỗi khi thực thi (không phải lỗi từ python nên mình không chưa tìm ra cách bắt exception). In ra nhiều như vậy sẽ dễ dàng để nhận ra lúc nào có kết quả hơn.

Các kết quả mình thu được là

```
Found key! Position i = 4539 j = 2
Found key! Position i = 4551 j = 5
Found key! Position i = 5463 j = 1
Found key! Position i = 8871 j = 2
```

Tiếp theo mình sẽ dựng Docker để test xem khi nhập payload nó sẽ hiện ra như nào. Mình cũng sửa lại file main một chút để nó in ra key cho mình so sánh

```
docker build -t flip .
docker run -p 31339:31339 --name flip flip
```

Với payload đầu

```
Key:  417c6136abdc1613544eae683d789618
00000000000000000000000000000000 4539 2
Output:  8a1e8d6fcda9afb20cfc64a044934c54417c6136abdc1613544eae683d789618000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Payload thứ hai

```
Key:  acc71f8fc25dca86c4d1a973e38693b1
00000000000000000000000000000000 4551 5
Output:  acc71f8fc25dca86c4d1a973e38693b1
```

Payload thứ ba

```
Key:  5ead98e1634d9f0dd793eeb1c0431b81
00000000000000000000000000000000 5463 1
Output:  5ead98e1634d9f0dd793eeb1c0431b81
```

Payload cuối

```
Key:  dcd2cd3f4a6f29039fcc3863f2bf6566
00000000000000000000000000000000 8871 2
Output:  dcd2cd3f4a6f29039fcc3863f2bf6566
```

Có thể thấy các payload sau đều chỉ in ra `key` luôn chứ không in thêm những thứ không quan trọng như payload đầu. Mình sẽ thử dùng payload thứ hai để lấy flag

```python
from pwn import *

conn = remote('139.162.24.230' ,31339)

pt = '0' * 32
i = 4551
j = 5

payload = pt + " " + str(i) + " " + str(j)

conn.sendline(payload.encode())

key = conn.recvline().decode().strip() 

conn.sendline(key.encode())

print("Flag:" ,conn.recvline().decode())
```

```bash
[x] Opening connection to 139.162.24.230 on port 31339
[x] Opening connection to 139.162.24.230 on port 31339: Trying 139.162.24.230
[+] Opening connection to 139.162.24.230 on port 31339: Done
Flag: TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry}
```

Flag: _TetCTF{fr0m\_0n3\_b1t\_fl1pp3d\_t0\_full\_k3y\_r3c0v3ry}_

> Thật ra là mình đã ăn may khi sử dụng plaintext = 00000000000000000000000000000000 để bruteforce. Khi phân tích kĩ trong intended solution, kết quả trả về từ server là key^plaintext. Điều này là do một số giai đoạn của mã hóa AES. Khi mình dùng plaintext là 00000000000000000000000000000000 thì khi XOR với key nó vẫn sẽ là key nên mình lấy được flag.

> Faster bruteforce and some explain: [Link](https://sigflag.at/blog/2024/writeup-tetctf-flip/)

### flip v2

> Chall name: flip v2&#x20;
>
> Category: Crypto&#x20;
>
> Author: ndh&#x20;
>
> Description: Changing in main() is not allowed.&#x20;
>
> Server: `nc 139.162.24.230 31340`&#x20;
>
> Material: `main.py`

_main.py_

```python
# Please ensure that you solved the challenge properly at the local.
# If things do not run smoothly, you generally won't be allowed to make another attempt.
from secret.network_util import check_client, ban_client

import sys
import os
import subprocess
import tempfile

OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020
OFFSET_MAIN_START = 0x1169
OFFSET_MAIN_END = 0x11ed

def main():
    if not check_client():
        return

    key = os.urandom(16)
    with open("encrypt", "rb") as f:
        content = bytearray(f.read())

    # input format: hex(plaintext) i j
    try:
        plaintext_hex, i_str, j_str = input().split()
        pt = bytes.fromhex(plaintext_hex)
        assert len(pt) == 16
        i = int(i_str)
        assert 0 <= i < len(content)
        assert not OFFSET_MAIN_START <= i < OFFSET_MAIN_END
        j = int(j_str)
        assert 0 <= j < 8
    except Exception as err:
        print(err, file=sys.stderr)
        # ban_client()
        return

    # update key, plaintext, and inject the fault
    content[OFFSET_KEY:OFFSET_KEY + 16] = key
    content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
    content[i] ^= (1 << j)

    tmpfile = tempfile.NamedTemporaryFile(delete=True)
    with open(tmpfile.name, "wb") as f:
        f.write(content)
    os.chmod(tmpfile.name, 0o775)
    tmpfile.file.close()

    # execute the modified binary
    try:
        ciphertext = subprocess.check_output(tmpfile.name, timeout=1.0)
        print(ciphertext.hex())
    except Exception as err:
        print(err, file=sys.stderr)
        ban_client()
        return

    # please guess the AES key
    if bytes.fromhex(input()) == key:
        with open("secret/flag.txt") as f:
            print(f.read())
        from datetime import datetime
        print(datetime.now(), plaintext_hex, i, j, file=sys.stderr)


main()

```

#### Recon

Bài này thì code vẫn giống y nguyên bài trước chỉ khác là có thêm 2 trường `OFFSET_MAIN_START = 0x1169` và `OFFSET_MAIN_END = 0x11ed`. Đây là đánh dấu cho offset của hàm `main`. Giờ đây thì `i` sẽ có điều kiện là `assert not OFFSET_MAIN_START <= i < OFFSET_MAIN_END`, nghĩa là `i` không được nằm trong `main`, hay ta không thể tác động tới byte nào ở trong `main`.

#### Unintended Solution

Như bài trước thì mình đã tìm ra 4 payload để có thể lấy được `key`. Ở đây với `0x1169 <= i < 0x11ed` hay `4457 <= i < 4589` thì sẽ bị Exception. Vậy chỉ cần lấy payload có `i` nằm ngoài khoảng đó thôi, cụ thể là mình có `i = 5463 j = 1` và `i = 8871 j = 2`

Code lấy flag:

```python
from pwn import *

conn = remote('139.162.24.230' ,31340)

pt = '0' * 32
i = 5463
j = 1

payload = pt + " " + str(i) + " " + str(j)

conn.sendline(payload.encode())

key = conn.recvline().decode().strip() 

# If use another plaintext
# key = conn.recvline().decode()
# key = xor(bytes.fromhex(key), bytes.fromhex(pt))
# key = key.hex()

conn.sendline(key.encode())

print("Flag:" ,conn.recvline().decode())
```

```bash
[x] Opening connection to 139.162.24.230 on port 31340
[x] Opening connection to 139.162.24.230 on port 31340: Trying 139.162.24.230
[+] Opening connection to 139.162.24.230 on port 31340: Done
Flag: TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry_d043a7ff4cf6285a}
```

Flag: _TetCTF{fr0m\_0n3\_b1t\_fl1pp3d\_t0\_full\_k3y\_r3c0v3ry\_d043a7ff4cf6285a}_
